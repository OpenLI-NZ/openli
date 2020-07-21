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

#include "config.h"

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

#ifdef HAVE_BER_ENCODING

int encode_ipmmcc_ber(
        openli_ipcc_job_t *job, uint32_t seqno, struct timeval *tv,
        openli_encoded_result_t *msg, wandder_etsili_child_t *child,
        wandder_encoder_t *encoder) {

    uint32_t liidlen = (uint32_t)((size_t)child->owner->preencoded[WANDDER_PREENCODE_LIID_LEN]);

    memset(msg, 0, sizeof(openli_encoded_result_t));

    wandder_encode_etsi_ipmmcc_ber(   //new way
        (int64_t)job->cin,
        (int64_t)seqno,
        tv, 
        job->ipcontent,
        job->ipclen, 
        job->dir, 
        child);

    msg->msgbody = malloc(sizeof(wandder_encoded_result_t));

    msg->msgbody->encoder = NULL;
    msg->msgbody->encoded = child->buf;
    msg->msgbody->len = child->len;
    msg->msgbody->alloced = child->alloc_len;
    msg->msgbody->next = NULL;

    msg->ipcontents = NULL;
    msg->ipclen = 0;

    /* Unfortunately, the packet body is not the last item in our message so
     * we can't easily use our zero-copy shortcut :( */
    // msg->ipcontents = NULL;
    // msg->ipclen = 0;

    msg->header.magic = htonl(OPENLI_PROTO_MAGIC);
    msg->header.bodylen = htons(msg->msgbody->len + liidlen + sizeof(uint16_t));
    msg->header.intercepttype = htons(OPENLI_PROTO_ETSI_CC);
    msg->header.internalid = 0;

    return 0;
}

#endif

static inline uint8_t is_rtp_comfort_noise(libtrace_packet_t *packet) {

    void *transport, *payload;
    uint8_t proto;
    uint8_t *pl;
    uint32_t rem;

    transport = trace_get_transport(packet, &proto, &rem);

    if (transport == NULL || proto != TRACE_IPPROTO_UDP) {
        return 0;
    }

    payload = trace_get_payload_from_udp((libtrace_udp_t *)transport, &rem);
    if (payload == NULL || rem < 12) {
        return 0;
    }

    pl = (uint8_t *)payload;

    /* 0x0d == Payload type: Comfort Noise */
    if (pl[1] == 0x0d) {
        return 1;
    }
    return 0;
}

static inline int match_rtp_stream(rtpstreaminf_t *rtp, uint16_t porta,
        uint16_t portb, struct sockaddr *ipa, struct sockaddr *ipb,
        uint8_t *is_comfort, libtrace_packet_t *pkt) {

    struct sockaddr *tgt, *other;
    int i;

    tgt = (struct sockaddr *)(rtp->targetaddr);
    other = (struct sockaddr *)(rtp->otheraddr);

    for (i = 0; i < rtp->streamcount; i++) {

        if ((rtp->mediastreams[i].targetport == porta &&
                rtp->mediastreams[i].otherport == portb) ||
                (rtp->mediastreams[i].targetport + 1 == porta &&
                rtp->mediastreams[i].otherport + 1 == portb)) {

            if (sockaddr_match(rtp->ai_family, ipa, tgt) &&
                    sockaddr_match(rtp->ai_family, ipb, other)) {

                if (rtp->skip_comfort) {
                    if (*is_comfort == 255) {
                        *is_comfort = is_rtp_comfort_noise(pkt);
                    }
                    if (*is_comfort == 1) {
                        return 0;
                    }
                }

                return 1;
            }
        }
    }
    return 0;
}

static inline int generic_mm_comm_contents(int family, libtrace_packet_t *pkt,
        packet_info_t *pinfo, colthread_local_t *loc) {

    openli_export_recv_t *msg;
    rtpstreaminf_t *rtp, *tmp;
    int matched = 0;
    uint8_t is_comfort = 255;

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

        /* Check for src = target, dest = other */
        if (match_rtp_stream(rtp, pinfo->srcport, pinfo->destport,
                (struct sockaddr *)(&pinfo->srcip),
                (struct sockaddr *)(&pinfo->destip), &is_comfort, pkt)) {

            msg = create_ipcc_job(rtp->cin, rtp->common.liid,
                    rtp->common.destid, pkt, ETSI_DIR_FROM_TARGET);
            msg->type = OPENLI_EXPORT_IPMMCC;
            publish_openli_msg(loc->zmq_pubsocks[0], msg); // FIXME
            matched ++;
            continue;
        }

        /* Check for dst = target, src = other */
        if (match_rtp_stream(rtp, pinfo->destport, pinfo->srcport,
                (struct sockaddr *)(&pinfo->destip),
                (struct sockaddr *)(&pinfo->srcip), &is_comfort, pkt)) {

            msg = create_ipcc_job(rtp->cin, rtp->common.liid,
                    rtp->common.destid, pkt, ETSI_DIR_TO_TARGET);
            msg->type = OPENLI_EXPORT_IPMMCC;
            publish_openli_msg(loc->zmq_pubsocks[0], msg); // FIXME
            matched ++;
            continue;
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
