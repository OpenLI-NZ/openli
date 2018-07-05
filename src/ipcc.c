/*
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * OpenLI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * OpenLI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libwandder.h>
#include <libwandder_etsili.h>
#include <libtrace_parallel.h>

#include "logger.h"
#include "collector.h"
#include "collector_export.h"
#include "etsili_core.h"

static void dump_export_msg(openli_exportmsg_t *msg) {

    uint32_t enclen = msg->msgbody->len - msg->ipclen;
    uint32_t i;

    for (i = 0; i < enclen; i++) {
        printf("%02x ", msg->msgbody->encoded[i]);
        if ((i % 16) == 15) {
            printf("\n");
        }
    }

    if ((i % 16) != 15) {
        printf("\n");
    }

    if (msg->ipcontents != NULL) {
        for (i = 0; i < msg->ipclen; i++) {
            printf("%02x ", msg->ipcontents[i]);
            if ((i % 16) == 15) {
                printf("\n");
            }
        }
        if ((i % 16) != 15) {
            printf("\n");
        }
    }

}

int encode_ipcc(wandder_encoder_t **encoder, openli_ipcc_job_t *job,
        exporter_intercept_msg_t *intdetails, uint32_t seqno,
        openli_exportmsg_t *msg) {

    struct timeval tv = trace_get_timeval(job->packet);
    wandder_etsipshdr_data_t hdrdata;
   	void *l3;
    uint32_t rem;
    uint16_t ethertype;

    if (*encoder == NULL) {
        *encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(*encoder);
    }

    l3 = trace_get_layer3(job->packet, &ethertype, &rem);

    hdrdata.liid = intdetails->liid;
    hdrdata.liid_len = intdetails->liid_len;
    hdrdata.authcc = intdetails->authcc;
    hdrdata.authcc_len = intdetails->authcc_len;
    hdrdata.delivcc = intdetails->delivcc;
    hdrdata.delivcc_len = intdetails->delivcc_len;
    hdrdata.operatorid = job->colinfo->operatorid;
    hdrdata.operatorid_len = job->colinfo->operatorid_len;
    hdrdata.networkelemid = job->colinfo->networkelemid;
    hdrdata.networkelemid_len = job->colinfo->networkelemid_len;
    hdrdata.intpointid = job->colinfo->intpointid;
    hdrdata.intpointid_len = job->colinfo->intpointid_len;

    memset(msg, 0, sizeof(openli_exportmsg_t));

    msg->msgbody = encode_etsi_ipcc(*encoder, &hdrdata,
            (int64_t)job->cin, (int64_t)seqno, &tv, l3, rem, job->dir);

    msg->encoder = *encoder;
    msg->ipcontents = (uint8_t *)l3;
    msg->ipclen = rem;
    msg->header = construct_netcomm_protocol_header(msg->msgbody->len,
            OPENLI_PROTO_ETSI_CC, 0, &(msg->hdrlen));

    return 0;

}

static inline void make_ipcc_job(openli_export_recv_t *msg,
        ipsession_t *sess, libtrace_packet_t *pkt, uint8_t dir,
        shared_global_info_t *info) {

    memset(msg, 0, sizeof(openli_export_recv_t));

    msg->type = OPENLI_EXPORT_IPCC;
    msg->destid = sess->common.destid;
    msg->data.ipcc.liid = strdup(sess->common.liid);
    msg->data.ipcc.packet = pkt;
    msg->data.ipcc.cin = sess->cin;
    msg->data.ipcc.dir = dir;
    msg->data.ipcc.colinfo = info;

}

static inline void make_static_ipcc_job(openli_export_recv_t *msg,
        staticipsession_t *sess, libtrace_packet_t *pkt, uint8_t dir,
        shared_global_info_t *info) {

    memset(msg, 0, sizeof(openli_export_recv_t));

    msg->type = OPENLI_EXPORT_IPCC;
    msg->destid = sess->common.destid;
    msg->data.ipcc.liid = strdup(sess->common.liid);
    msg->data.ipcc.packet = pkt;
    msg->data.ipcc.cin = sess->cin;
    msg->data.ipcc.dir = dir;
    msg->data.ipcc.colinfo = info;

}

static inline int lookup_static_ranges(struct sockaddr_in *cmp,
        libtrace_packet_t *pkt, uint8_t dir,
        shared_global_info_t *info, colthread_local_t *loc) {

    int matched = 0, queueused = 0;
    patricia_node_t *pnode;
    prefix_t prefix;
    openli_export_recv_t msg;

    if (New_Prefix2(AF_INET, (void *)&(cmp->sin_addr), 32, &prefix) == NULL) {
        return 0;
    }
    pnode = patricia_search_best2(loc->staticv4ranges, &prefix, 1);

    while (pnode) {
        liid_set_t **all, *sliid, *tmp2;

        all = (liid_set_t **)(&(pnode->data));
        HASH_ITER(hh, *all, sliid, tmp2) {
            staticipsession_t *matchsess;
            char key[128];

            snprintf(key, 127, "%s-%u", sliid->liid, sliid->cin);
            HASH_FIND(hh, loc->activestaticintercepts, key, strlen(key),
                    matchsess);
            if (!matchsess) {
                logger(LOG_DAEMON,
                        "OpenLI: matched an IP range for intercept %s but this is not present in activestaticintercepts",
                        key);
            } else {
                matched ++;
                make_static_ipcc_job(&msg, matchsess, pkt, dir, info);
                trace_increment_packet_refcount(pkt);
                queueused = export_queue_put_by_liid(loc->exportqueues,
                        &msg, sliid->liid);
                loc->export_used[queueused] = 1;
            }
        }
        pnode = pnode->parent;
    }

    return matched;
}

int ipv4_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip_t *ip,
        uint32_t rem, shared_global_info_t *info, colthread_local_t *loc) {

    struct sockaddr_in *intaddr, *cmp;
    openli_export_recv_t msg;
    int matched = 0, queueused = 0;
    ipv4_target_t *tgt;
    ipsession_t *sess, *tmp;

    if (rem < sizeof(libtrace_ip_t)) {
        /* Truncated IP header */
        logger(LOG_DAEMON, "OpenLI: Got IPv4 packet with truncated header?");
        return 0;
    }

    /* Check if ipsrc or ipdst match any of our active intercepts.
     * NOTE: a packet can match multiple intercepts so don't break early.
     */

    cmp = (struct sockaddr_in *)(&pinfo->srcip);
    HASH_FIND(hh, loc->activeipv4intercepts, &(cmp->sin_addr.s_addr),
            sizeof(cmp->sin_addr.s_addr), tgt);

    if (tgt) {
        HASH_ITER(hh, tgt->intercepts, sess, tmp) {
            matched ++;
            make_ipcc_job(&msg, sess, pkt, 0, info);
            trace_increment_packet_refcount(pkt);
            queueused = export_queue_put_by_liid(loc->exportqueues,
                    &msg, sess->common.liid);
            loc->export_used[queueused] = 1;
        }
    }

    cmp = (struct sockaddr_in *)(&pinfo->destip);
    HASH_FIND(hh, loc->activeipv4intercepts, &(cmp->sin_addr.s_addr),
            sizeof(cmp->sin_addr.s_addr), tgt);

    if (tgt) {
        HASH_ITER(hh, tgt->intercepts, sess, tmp) {
            matched ++;
            make_ipcc_job(&msg, sess, pkt, 1, info);
            trace_increment_packet_refcount(pkt);
            queueused = export_queue_put_by_liid(loc->exportqueues,
                    &msg, sess->common.liid);
            loc->export_used[queueused] = 1;
        }
    }

    if (loc->staticv4ranges == NULL) {
        goto ipv4ccdone;
    }

    matched += lookup_static_ranges((struct sockaddr_in *)(&pinfo->srcip),
            pkt, 0, info, loc);
    matched += lookup_static_ranges((struct sockaddr_in *)(&pinfo->destip),
            pkt, 1, info, loc);


ipv4ccdone:
    return matched;

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
