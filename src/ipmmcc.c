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
#include <libtrace.h>
#include <libtrace_parallel.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "collector_export.h"
#include "etsili_core.h"


int encode_ipmmcc(wandder_encoder_t **encoder, openli_ipmmcc_job_t *job,
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
    msg->msgbody = encode_etsi_ipmmcc(*encoder, &hdrdata,
                (int64_t)job->cin, (int64_t)seqno, &tv, l3, rem, job->dir);

    /* Unfortunately, the packet body is not the last item in our message so
     * we can't easily use our zero-copy shortcut :( */
    msg->encoder = *encoder;
    msg->ipcontents = NULL;
    msg->ipclen = 0;
    msg->header = construct_netcomm_protocol_header(msg->msgbody->len,
                OPENLI_PROTO_ETSI_CC, 0, &(msg->hdrlen));

    return 0;
}

static inline int form_ipmmcc_job(openli_export_recv_t *msg,
        char *liid, shared_global_info_t *info, libtrace_packet_t *packet,
        uint32_t cin, uint8_t dir, colthread_local_t *loc, uint32_t destid) {

    int queueused;

    msg->type = OPENLI_EXPORT_IPMMCC;
    msg->destid = destid;
    msg->data.ipmmcc.liid = strdup(liid);
    msg->data.ipmmcc.packet = packet;
    msg->data.ipmmcc.cin = cin;
    msg->data.ipmmcc.dir = dir;
    msg->data.ipmmcc.colinfo = info;
    trace_increment_packet_refcount(packet);
    queueused = export_queue_put_by_liid(loc->exportqueues, msg, liid);
    loc->export_used[queueused] = 1;
}

int ip4mm_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip_t *ip,
        uint32_t rem, shared_global_info_t *info, colthread_local_t *loc) {

    struct sockaddr_in *targetaddr, *cmp, *otheraddr;
    openli_export_recv_t msg;
    rtpstreaminf_t *rtp, *tmp;
    int matched = 0, queueused;

    memset(&msg, 0, sizeof(openli_export_recv_t));

    if (rem < sizeof(libtrace_ip_t)) {
        logger(LOG_DAEMON, "OpenLI: Got IPv4 RTP packet with truncated header?");
        return 0;
    }

    if (ip->ip_p != TRACE_IPPROTO_UDP) {
        return 0;
    }

    if (pinfo->srcport == 0 || pinfo->destport == 0) {
        logger(LOG_DAEMON, "OpenLI: IPv4 RTP packet is missing a port number.");
        return 0;
    }

    /* TODO change active RTP so we can look up by 5 tuple? */
    HASH_ITER(hh, loc->activertpintercepts, rtp, tmp) {
        if (!rtp->active) {
            continue;
        }
        targetaddr = (struct sockaddr_in *)(rtp->targetaddr);
        otheraddr = (struct sockaddr_in *)(rtp->otheraddr);

        if (targetaddr == NULL || otheraddr == NULL) {
            continue;
        }

        if (pinfo->srcip.ss_family != rtp->ai_family) {
            continue;
        }

        /* Check for src = target, dst = other */
        if (pinfo->srcport == rtp->targetport &&
                pinfo->destport == rtp->otherport) {
            cmp = (struct sockaddr_in *)(&pinfo->srcip);

            if (targetaddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                cmp = (struct sockaddr_in *)(&pinfo->destip);
                if (otheraddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                    form_ipmmcc_job(&msg, rtp->common.liid, info, pkt, rtp->cin,
                            ETSI_DIR_FROM_TARGET, loc, rtp->common.destid);
                    matched ++;
                    continue;
                }
            }
        }

        /* Check for dst = target, src = other */
        if (pinfo->destport == rtp->targetport &&
                    pinfo->srcport == rtp->otherport) {
            cmp = (struct sockaddr_in *)(&pinfo->srcip);

            if (otheraddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                cmp = (struct sockaddr_in *)(&pinfo->destip);
                if (targetaddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                    form_ipmmcc_job(&msg, rtp->common.liid, info, pkt, rtp->cin,
                            ETSI_DIR_TO_TARGET, loc, rtp->common.destid);
                    matched ++;
                    continue;
                }
            }
        }

    }

    return matched;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
