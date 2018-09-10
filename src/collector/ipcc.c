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

    wandder_etsipshdr_data_t hdrdata;

    if (*encoder == NULL) {
        *encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(*encoder);
    }

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
            (int64_t)job->cin, (int64_t)seqno, &(job->tv), job->ipcontent,
            job->ipclen, job->dir);

    msg->liid = intdetails->liid;
    msg->liidlen = intdetails->liid_len;
    msg->encoder = *encoder;
    msg->ipcontents = (uint8_t *)job->ipcontent;
    msg->ipclen = job->ipclen;
    msg->header = construct_netcomm_protocol_header(
            msg->msgbody->len + msg->liidlen + sizeof(msg->liidlen),
            OPENLI_PROTO_ETSI_CC, 0, &(msg->hdrlen));

    return 0;

}

static inline openli_export_recv_t *make_ipcc_job(
        ipsession_t *sess, libtrace_packet_t *pkt, uint8_t dir,
        shared_global_info_t *info) {

   	void *l3;
    uint32_t rem;
    uint16_t ethertype;
    openli_export_recv_t *msg;

    msg = calloc(1, sizeof(openli_export_recv_t));
    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    msg->type = OPENLI_EXPORT_IPCC;
    msg->destid = sess->common.destid;
    msg->data.ipcc.liid = strdup(sess->common.liid);
    msg->data.ipcc.ipcontent = (uint8_t *)calloc(1, rem);
    msg->data.ipcc.ipclen = rem;
    msg->data.ipcc.cin = sess->cin;
    msg->data.ipcc.dir = dir;
    msg->data.ipcc.colinfo = info;
    msg->data.ipcc.tv = trace_get_timeval(pkt);

    memcpy(msg->data.ipcc.ipcontent, l3, rem);
    return msg;
}

static inline openli_export_recv_t *make_static_ipcc_job(
        staticipsession_t *sess, libtrace_packet_t *pkt, uint8_t dir,
        shared_global_info_t *info) {

   	void *l3;
    uint32_t rem;
    uint16_t ethertype;
    openli_export_recv_t *msg;

    msg = calloc(1, sizeof(openli_export_recv_t));
    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    msg->type = OPENLI_EXPORT_IPCC;
    msg->destid = sess->common.destid;
    msg->data.ipcc.liid = strdup(sess->common.liid);
    msg->data.ipcc.ipcontent = (uint8_t *)calloc(1, rem);
    msg->data.ipcc.ipclen = rem;
    msg->data.ipcc.cin = sess->cin;
    msg->data.ipcc.dir = dir;
    msg->data.ipcc.colinfo = info;
    msg->data.ipcc.tv = trace_get_timeval(pkt);

    memcpy(msg->data.ipcc.ipcontent, l3, rem);
    return msg;
}

/*
static void dump_ptree(patricia_node_t *ptree) {
    char foo[128];
    if (ptree->l) {
        dump_ptree(ptree->l);
    }

    if (ptree->prefix) {
        inet_ntop(AF_INET6, &(ptree->prefix->add.sin6), foo, 128);
        printf("%s/%u\n", foo, ptree->prefix->bitlen);
    }

    if (ptree->r) {
        dump_ptree(ptree->r);
    }
}
*/

static inline static_ipcache_t *find_static_cached(prefix_t *prefix,
        colthread_local_t *loc) {

    static_ipcache_t *found;
    HASH_FIND(hh, loc->staticcache, prefix, sizeof(prefix_t), found);

    if (found) {
        /* Push it back to the front of the queue so it doesn't expire */
        HASH_DELETE(hh, loc->staticcache, found);
        HASH_ADD_KEYPTR(hh, loc->staticcache, &(found->prefix),
                sizeof(prefix_t), found);
    }
    return found;

}

static inline int add_static_cached(prefix_t *prefix, patricia_node_t *pnode,
        colthread_local_t *loc) {

    static_ipcache_t *ent, *tmp;

    ent = (static_ipcache_t *)malloc(sizeof(static_ipcache_t));
    memcpy(&(ent->prefix), prefix, sizeof(prefix_t));
    ent->pnode = pnode;

    HASH_ADD_KEYPTR(hh, loc->staticcache, &(ent->prefix), sizeof(prefix_t),
            ent);

    if (HASH_COUNT(loc->staticcache) >= 1000000) {
        HASH_ITER(hh, loc->staticcache, ent, tmp) {
            HASH_DELETE(hh, loc->staticcache, ent);
            free(ent);
            break;
        }
    }
    return 0;
}

static inline int lookup_static_ranges(struct sockaddr *cmp,
        int family, libtrace_packet_t *pkt,
        uint8_t dir, shared_global_info_t *info, colthread_local_t *loc) {

    int matched = 0, queueused = 0;
    patricia_node_t *pnode = NULL;
    prefix_t prefix;
    openli_export_recv_t *msg;
    static_ipcache_t *cached = NULL;

    memset(&prefix, 0, sizeof(prefix_t));

    if (family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)cmp;
        memcpy(&(prefix.add.sin), &(in->sin_addr), 4);
        prefix.bitlen = 32;
        prefix.family = AF_INET;
        prefix.ref_count = 0;
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)cmp;
        memcpy(&(prefix.add.sin6), &(in6->sin6_addr), 16);
        prefix.bitlen = 128;
        prefix.family = AF_INET6;
        prefix.ref_count = 0;
    }


    //cached = find_static_cached(&prefix, loc);
    if (cached) {
        pnode = cached->pnode;
    } else {
        if (family == AF_INET) {
            pnode = patricia_search_best2(loc->staticv4ranges, &prefix, 1);
        } else {
            pnode = patricia_search_best2(loc->staticv6ranges, &prefix, 1);
        }
        //add_static_cached(&prefix, pnode, loc);
    }

    while (pnode) {
        liid_set_t **all, *sliid, *tmp2;

        all = (liid_set_t **)(&(pnode->data));
        HASH_ITER(hh, *all, sliid, tmp2) {
            staticipsession_t *matchsess;
            HASH_FIND(hh, loc->activestaticintercepts, sliid->key,
                    sliid->keylen, matchsess);
            if (!matchsess) {
                logger(LOG_INFO,
                        "OpenLI: matched an IP range for intercept %s but this is not present in activestaticintercepts",
                        sliid->key);
            } else {
                matched ++;
                msg = make_static_ipcc_job(matchsess, pkt, dir, info);
                export_queue_put_by_liid(loc->zmq_pubsocks, msg,
                        matchsess->common.liid, loc->numexporters);
            }
        }
        pnode = pnode->parent;
    }
    return matched;
}

int ipv6_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip6_t *ip, uint32_t rem, shared_global_info_t *info,
        colthread_local_t *loc) {

    struct sockaddr_in6 *intaddr, *cmp;
    openli_export_recv_t *msg = NULL;
    int matched = 0, queueused = 0;
    ipv6_target_t *tgt;
    ipsession_t *sess, *tmp;

    if (rem < sizeof(libtrace_ip6_t)) {
        /* Truncated IP header */
        logger(LOG_INFO, "OpenLI: Got IPv6 packet with truncated header?");
        return 0;
    }

    /* Check if ipsrc or ipdst match any of our active intercepts.
     * NOTE: a packet can match multiple intercepts so don't break early.
     */

    cmp = (struct sockaddr_in6 *)(&pinfo->srcip);
    HASH_FIND(hh, loc->activeipv6intercepts, &(cmp->sin6_addr.s6_addr),
            sizeof(cmp->sin6_addr.s6_addr), tgt);

    if (tgt) {
        HASH_ITER(hh, tgt->intercepts, sess, tmp) {
            matched ++;
            msg = make_ipcc_job(sess, pkt, 0, info);
            export_queue_put_by_liid(loc->zmq_pubsocks, msg,
                    sess->common.liid, loc->numexporters);
        }
    }

    cmp = (struct sockaddr_in6 *)(&pinfo->destip);
    HASH_FIND(hh, loc->activeipv6intercepts, &(cmp->sin6_addr.s6_addr),
            sizeof(cmp->sin6_addr.s6_addr), tgt);

    if (tgt) {
        HASH_ITER(hh, tgt->intercepts, sess, tmp) {
            matched ++;
            msg = make_ipcc_job(sess, pkt, 1, info);
            export_queue_put_by_liid(loc->zmq_pubsocks, msg,
                    sess->common.liid, loc->numexporters);
        }
    }

    if (loc->staticv6ranges == NULL) {
        goto ipv6ccdone;
    }

    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->srcip),
            AF_INET6, pkt, 0, info, loc);
    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->destip),
            AF_INET6, pkt, 1, info, loc);


ipv6ccdone:
    return matched;

}


int ipv4_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip_t *ip,
        uint32_t rem, shared_global_info_t *info, colthread_local_t *loc) {

    struct sockaddr_in *intaddr, *cmp;
    openli_export_recv_t *msg = NULL;
    int matched = 0, queueused = 0;
    ipv4_target_t *tgt;
    ipsession_t *sess, *tmp;

    if (rem < sizeof(libtrace_ip_t)) {
        /* Truncated IP header */
        logger(LOG_INFO, "OpenLI: Got IPv4 packet with truncated header?");
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
            msg = make_ipcc_job(sess, pkt, 0, info);
            export_queue_put_by_liid(loc->zmq_pubsocks, msg,
                    sess->common.liid, loc->numexporters);
        }
    }

    cmp = (struct sockaddr_in *)(&pinfo->destip);
    HASH_FIND(hh, loc->activeipv4intercepts, &(cmp->sin_addr.s_addr),
            sizeof(cmp->sin_addr.s_addr), tgt);

    if (tgt) {
        HASH_ITER(hh, tgt->intercepts, sess, tmp) {
            matched ++;
            msg = make_ipcc_job(sess, pkt, 1, info);
            export_queue_put_by_liid(loc->zmq_pubsocks, msg,
                    sess->common.liid, loc->numexporters);
        }
    }

    if (loc->staticv4ranges == NULL) {
        goto ipv4ccdone;
    }

    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->srcip),
            AF_INET, pkt, 0, info, loc);
    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->destip),
            AF_INET, pkt, 1, info, loc);


ipv4ccdone:
    return matched;

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
