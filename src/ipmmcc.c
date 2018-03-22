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
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "collector_export.h"
#include "etsili_core.h"


static openli_export_recv_t form_ipmmcc(collector_global_t *glob,
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

    hdrdata.liid = rtp->parent->liid;
    hdrdata.liid_len = rtp->parent->liid_len;
    hdrdata.authcc = rtp->parent->authcc;
    hdrdata.authcc_len = rtp->parent->authcc_len;
    hdrdata.delivcc = rtp->parent->delivcc;
    hdrdata.delivcc_len = rtp->parent->delivcc_len;
    hdrdata.operatorid = glob->operatorid;
    hdrdata.operatorid_len = glob->operatorid_len;
    hdrdata.networkelemid = glob->networkelemid;
    hdrdata.networkelemid_len = glob->networkelemid_len;
    hdrdata.intpointid = glob->intpointid;
    hdrdata.intpointid_len = glob->intpointid_len;

    msg.msgbody = encode_etsi_ipmmcc(&(msg.msglen), loc->encoder, &hdrdata,
                (int64_t)rtp->cin, (int64_t)rtp->seqno, &tv, l3, rem, dir);

    /* Unfortunately, the packet body is not the last item in our message so
     * we can't easily use our zero-copy shortcut :( */
    msg.ipcontents = NULL;
    msg.ipclen = 0;
    msg.destid = rtp->parent->destid;
    msg.header = construct_netcomm_protocol_header(msg.msglen,
                OPENLI_PROTO_ETSI_CC, rtp->parent->internalid, &(msg.hdrlen));

    exprecv.type = OPENLI_EXPORT_ETSIREC;
    exprecv.data.toexport = msg;

    rtp->seqno ++;
    return exprecv;
}

int ip4mm_comm_contents(libtrace_packet_t *pkt, libtrace_ip_t *ip,
        uint32_t rem, collector_global_t *glob, colthread_local_t *loc) {

    libtrace_list_node_t *n = loc->activertpintercepts->head;
    struct sockaddr_storage ipsrc;
    struct sockaddr_storage ipdst;
    struct sockaddr_in *targetaddr, *cmp, *otheraddr;
    openli_export_recv_t msg;
    int matched = 0;
    uint16_t srcport, dstport;

    if (rem < sizeof(libtrace_ip_t)) {
        logger(LOG_DAEMON, "OpenLI: Got IPv4 RTP packet with truncated header?");
        return 0;
    }

    if (trace_get_source_address(pkt, (struct sockaddr *)(&ipsrc)) == NULL) {
        return 0;
    }

    if (trace_get_destination_address(pkt, (struct sockaddr *)(&ipdst)) ==
            NULL) {
        return 0;
    }

    srcport = trace_get_source_port(pkt);
    dstport = trace_get_destination_port(pkt);

    if (srcport == 0 || dstport == 0) {
        logger(LOG_DAEMON, "OpenLI: IPv4 RTP packet is missing a port number.");
        return 0;
    }

    if (ip->ip_p != TRACE_IPPROTO_UDP) {
        return 0;
    }

    while (n) {
        rtpstreaminf_t *rtp = (rtpstreaminf_t *)(n->data);
        n = n->next;
        if (!rtp->active) {
            continue;
        }
        targetaddr = (struct sockaddr_in *)(rtp->targetaddr);
        otheraddr = (struct sockaddr_in *)(rtp->otheraddr);

        if (targetaddr == NULL || otheraddr == NULL) {
            continue;
        }

        if (ipsrc.ss_family != rtp->ai_family) {
            continue;
        }

        /* Check for src = target, dst = other */
        if (srcport == rtp->targetport && dstport == rtp->otherport) {
            cmp = (struct sockaddr_in *)(&ipsrc);

            if (targetaddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                cmp = (struct sockaddr_in *)(&ipdst);
                if (otheraddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                    matched ++;
                    msg = form_ipmmcc(glob, loc, rtp, pkt, ip, rem,
                            ETSI_DIR_FROM_TARGET);
                    libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
                    continue;
                }
            }
        }

        /* Check for dst = target, src = other */
        if (dstport == rtp->targetport && srcport == rtp->otherport) {
            cmp = (struct sockaddr_in *)(&ipsrc);

            if (otheraddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                cmp = (struct sockaddr_in *)(&ipdst);
                if (targetaddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                    matched ++;
                    msg = form_ipmmcc(glob, loc, rtp, pkt, ip, rem,
                            ETSI_DIR_TO_TARGET);
                    libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
                    continue;
                }
            }
        }

    }

    if (matched > 0) {
        msg.type = OPENLI_EXPORT_PACKET_FIN;
        msg.data.packet = pkt;
        libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
    }

    return matched;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
