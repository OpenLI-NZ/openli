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
#include "util.h"

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
    msg->liid = intdetails->liid;
    msg->liidlen = intdetails->liid_len;
    msg->encoder = *encoder;
    msg->ipcontents = NULL;
    msg->ipclen = 0;
    msg->header = construct_netcomm_protocol_header(
            msg->msgbody->len + msg->liidlen + sizeof(msg->liidlen),
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

static inline int generic_mm_comm_contents(int family, libtrace_packet_t *pkt,
        packet_info_t *pinfo, shared_global_info_t *info,
        colthread_local_t *loc) {

    openli_export_recv_t msg;
    rtpstreaminf_t *rtp, *tmp;
    int matched = 0, queueused;
    struct sockaddr *cmp, *tgt, *other;

    memset(&msg, 0, sizeof(openli_export_recv_t));

    /* TODO change active RTP so we can look up by 5 tuple? */
    HASH_ITER(hh, loc->activertpintercepts, rtp, tmp) {
        if (!rtp->active) {
            continue;
        }

        if (rtp->targetaddr == NULL || rtp->otheraddr == NULL) {
            continue;
        }

        if (pinfo->srcip.ss_family != rtp->ai_family) {
            continue;
        }

        tgt = (struct sockaddr *)(rtp->targetaddr);
        other = (struct sockaddr *)(rtp->otheraddr);

        /* Check for src = target, dst = other */
        if ((pinfo->srcport == rtp->targetport &&
                pinfo->destport == rtp->otherport) ||
                (pinfo->srcport == rtp->targetport + 1 &&
                 pinfo->destport == rtp->otherport + 1)) {
            cmp = (struct sockaddr *)(&pinfo->srcip);

            if (sockaddr_match(family, cmp, tgt)) {
                cmp = (struct sockaddr *)(&pinfo->destip);
                if (sockaddr_match(family, cmp, other)) {
                    form_ipmmcc_job(&msg, rtp->common.liid, info, pkt, rtp->cin,
                            ETSI_DIR_FROM_TARGET, loc, rtp->common.destid);
                    matched ++;
                    continue;
                }
            }
        }

        /* Check for dst = target, src = other */
        if ((pinfo->destport == rtp->targetport &&
                    pinfo->srcport == rtp->otherport) ||
                    (pinfo->destport == rtp->targetport + 1 &&
                     pinfo->srcport == rtp->otherport + 1)) {
            cmp = (struct sockaddr *)(&pinfo->srcip);

            if (sockaddr_match(family, cmp, other)) {
                cmp = (struct sockaddr *)(&pinfo->destip);
                if (sockaddr_match(family, cmp, tgt)) {
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

int ip4mm_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip_t *ip,
        uint32_t rem, shared_global_info_t *info, colthread_local_t *loc) {


    if (rem < sizeof(libtrace_ip_t)) {
        logger(LOG_INFO, "OpenLI: Got IPv4 RTP packet with truncated header?");
        return 0;
    }

    if (ip->ip_p != TRACE_IPPROTO_UDP) {
        return 0;
    }

    if (pinfo->srcport == 0 || pinfo->destport == 0) {
        /* IPv4 RTP packet is missing a port number, probably a fragment
         * for a frame where we've missed the first fragment.
         */
        return 0;
    }


    return generic_mm_comm_contents(AF_INET, pkt, pinfo, info, loc);
}

int ip6mm_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip6_t *ip6,
        uint32_t rem, shared_global_info_t *info, colthread_local_t *loc) {


    if (rem < sizeof(libtrace_ip6_t)) {
        logger(LOG_INFO, "OpenLI: Got IPv6 RTP packet with truncated header?");
        return 0;
    }

    if (ip6->nxt != TRACE_IPPROTO_UDP) {
        return 0;
    }

    if (pinfo->srcport == 0 || pinfo->destport == 0) {
        logger(LOG_INFO, "OpenLI: IPv6 RTP packet is missing a port number.");
        return 0;
    }


    return generic_mm_comm_contents(AF_INET6, pkt, pinfo, info, loc);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
