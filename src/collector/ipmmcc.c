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
#include "collector_publish.h"
#include "etsili_core.h"
#include "util.h"
#include "ipmmcc.h"

int encode_ipmmcc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipcc_job_t *job,
        uint32_t seqno, struct timeval *tv,  openli_encoded_result_t *msg) {

    uint32_t liidlen = precomputed[OPENLI_PREENCODE_LIID].vallen;
    reset_wandder_encoder(encoder);

    memset(msg, 0, sizeof(openli_encoded_result_t));
    msg->msgbody = encode_etsi_ipmmcc(encoder, precomputed,
            (int64_t)job->cin, (int64_t)seqno, tv, job->ipcontent,
            job->ipclen, job->dir);

    /* Unfortunately, the packet body is not the last item in our message so
     * we can't easily use our zero-copy shortcut :( */
    msg->ipcontents = NULL;
    msg->ipclen = 0;
    msg->header.magic = htonl(OPENLI_PROTO_MAGIC);
    msg->header.bodylen = htons(msg->msgbody->len + liidlen + sizeof(uint16_t));
    msg->header.intercepttype = htons(OPENLI_PROTO_ETSI_CC);
    msg->header.internalid = 0;
    return 0;
}

static inline int generic_mm_comm_contents(int family, libtrace_packet_t *pkt,
        packet_info_t *pinfo, colthread_local_t *loc) {

    openli_export_recv_t *msg;
    rtpstreaminf_t *rtp, *tmp;
    int matched = 0, queueused;
    struct sockaddr *cmp, *tgt, *other;

    /* TODO change active RTP so we can look up by 5 tuple? */
    HASH_ITER(hh, loc->activertpintercepts, rtp, tmp) {
        if (!rtp->active) {
            continue;
        }

        if (rtp->targetaddr == NULL || rtp->otheraddr == NULL) {
            continue;
        }

        if (pinfo->family != rtp->ai_family) {
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
                    msg = create_ipcc_job(&(loc->ipcc_freemessages),
                            rtp->cin, rtp->common.liid,
                            rtp->common.destid, pkt, ETSI_DIR_FROM_TARGET);
                    msg->type = OPENLI_EXPORT_IPMMCC;
                    publish_openli_msg(loc->zmq_pubsocks[0], msg); // FIXME
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
                    msg = create_ipcc_job(&(loc->ipcc_freemessages),
                            rtp->cin, rtp->common.liid,
                            rtp->common.destid, pkt, ETSI_DIR_TO_TARGET);
                    msg->type = OPENLI_EXPORT_IPMMCC;
                    publish_openli_msg(loc->zmq_pubsocks[0], msg); // FIXME
                    matched ++;
                    continue;
                }
            }
        }

    }
    return matched;
}

int ip4mm_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip_t *ip, uint32_t rem, colthread_local_t *loc) {


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


    return generic_mm_comm_contents(AF_INET, pkt, pinfo, loc);
}

int ip6mm_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip6_t *ip6, uint32_t rem, colthread_local_t *loc) {


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


    return generic_mm_comm_contents(AF_INET6, pkt, pinfo, loc);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
