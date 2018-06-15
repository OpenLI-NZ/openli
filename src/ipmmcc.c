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


static openli_export_recv_t form_ipmmcc(shared_global_info_t *info,
        colthread_local_t *loc, rtpstreaminf_t *rtp,
        libtrace_packet_t *pkt, void *l3, uint32_t rem, uint8_t dir) {

    struct timeval tv = trace_get_timeval(pkt);
    openli_exportmsg_t msg;
    openli_export_recv_t exprecv;
    wandder_etsipshdr_data_t hdrdata;

    if (loc->encoder == NULL) {
        loc->encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(loc->encoder);
    }

    hdrdata.liid = rtp->common.liid;
    hdrdata.liid_len = rtp->common.liid_len;
    hdrdata.authcc = rtp->common.authcc;
    hdrdata.authcc_len = rtp->common.authcc_len;
    hdrdata.delivcc = rtp->common.delivcc;
    hdrdata.delivcc_len = rtp->common.delivcc_len;
    hdrdata.operatorid = info->operatorid;
    hdrdata.operatorid_len = info->operatorid_len;
    hdrdata.networkelemid = info->networkelemid;
    hdrdata.networkelemid_len = info->networkelemid_len;
    hdrdata.intpointid = info->intpointid;
    hdrdata.intpointid_len = info->intpointid_len;

    memset(&msg, 0, sizeof(openli_exportmsg_t));
    msg.msgbody = encode_etsi_ipmmcc(loc->encoder, &hdrdata,
                (int64_t)rtp->cin, (int64_t)rtp->seqno, &tv, l3, rem, dir);

    /* Unfortunately, the packet body is not the last item in our message so
     * we can't easily use our zero-copy shortcut :( */
    msg.encoder = loc->encoder;
    msg.ipcontents = NULL;
    msg.ipclen = 0;
    msg.destid = rtp->common.destid;
    msg.header = construct_netcomm_protocol_header(msg.msgbody->len,
                OPENLI_PROTO_ETSI_CC, 0, &(msg.hdrlen));

    memset(&exprecv, 0, sizeof(openli_export_recv_t));

    rtp->seqno ++;
    return exprecv;
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

                    msg.type = OPENLI_EXPORT_IPMMCC;
                    msg.data.ipmmcc.liid = strdup(rtp->common.liid);
                    msg.data.ipmmcc.packet = pkt;
                    msg.data.ipmmcc.cin = rtp->cin;
                    msg.data.ipmmcc.dir = ETSI_DIR_FROM_TARGET;
                    queueused = export_queue_put_by_liid(loc->exportqueues,
                            &msg, rtp->common.liid);
                    loc->export_used[queueused] = 1;

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
                    msg.type = OPENLI_EXPORT_IPMMCC;
                    msg.data.ipmmcc.liid = strdup(rtp->common.liid);
                    msg.data.ipmmcc.packet = pkt;
                    msg.data.ipmmcc.cin = rtp->cin;
                    msg.data.ipmmcc.dir = ETSI_DIR_TO_TARGET;
                    queueused = export_queue_put_by_liid(loc->exportqueues,
                            &msg, rtp->common.liid);
                    loc->export_used[queueused] = 1;

                    matched ++;
                    continue;
                }
            }
        }

    }

    return matched;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
