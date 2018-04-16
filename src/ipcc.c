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

    uint32_t enclen = msg->msglen - msg->ipclen;
    uint32_t i;

    for (i = 0; i < enclen; i++) {
        printf("%02x ", msg->msgbody[i]);
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

static openli_export_recv_t form_ipcc(collector_global_t *glob,
		colthread_local_t *loc, ipintercept_t *ipint,
        libtrace_packet_t *pkt, void *l3, uint32_t rem) {

    struct timeval tv = trace_get_timeval(pkt);
    openli_exportmsg_t msg;
    openli_export_recv_t exprecv;
    wandder_etsipshdr_data_t hdrdata;

    if (loc->encoder == NULL) {
        loc->encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(loc->encoder);
    }

    hdrdata.liid = ipint->liid;
    hdrdata.liid_len = ipint->liid_len;
    hdrdata.authcc = ipint->authcc;
    hdrdata.authcc_len = ipint->authcc_len;
    hdrdata.delivcc = ipint->delivcc;
    hdrdata.delivcc_len = ipint->delivcc_len;
    hdrdata.operatorid = glob->operatorid;
    hdrdata.operatorid_len = glob->operatorid_len;
    hdrdata.networkelemid = glob->networkelemid;
    hdrdata.networkelemid_len = glob->networkelemid_len;
    hdrdata.intpointid = glob->intpointid;
    hdrdata.intpointid_len = glob->intpointid_len;

    msg.msgbody = encode_etsi_ipcc(&(msg.msglen), loc->encoder, &hdrdata,
            (int64_t)ipint->cin, (int64_t)ipint->nextseqno, &tv, l3, rem);

    msg.ipcontents = (uint8_t *)l3;
    msg.ipclen = rem;
    msg.destid = ipint->destid;
    msg.header = construct_netcomm_protocol_header(msg.msglen,
            OPENLI_PROTO_ETSI_CC, ipint->internalid, &(msg.hdrlen));

    exprecv.type = OPENLI_EXPORT_ETSIREC;
    exprecv.data.toexport = msg;

    ipint->nextseqno ++;

    return exprecv;

}
int ipv4_comm_contents(libtrace_packet_t *pkt, libtrace_ip_t *ip,
        uint32_t rem, collector_global_t *glob, colthread_local_t *loc) {

    struct sockaddr_storage ipsrc;
    struct sockaddr_storage ipdst;
    struct sockaddr_in *intaddr, *cmp;
    openli_export_recv_t msg;
    int matched = 0;
    ipintercept_t *tmp, *ipint;

    if (rem < sizeof(libtrace_ip_t)) {
        /* Truncated IP header */
        logger(LOG_DAEMON, "OpenLI: Got IPv4 packet with truncated header?");
        return 0;
    }

    if (trace_get_source_address(pkt, (struct sockaddr *)(&ipsrc)) == NULL) {
        return 0;
    }

    if (trace_get_destination_address(pkt, (struct sockaddr *)(&ipdst)) ==
                NULL) {
        return 0;
    }

    /* Check if ipsrc or ipdst match any of our active intercepts.
     * NOTE: a packet can match multiple intercepts so don't break early.
     */

    HASH_ITER(hh_liid, loc->activeipintercepts, ipint, tmp) {

        if (!ipint->active) {
            continue;
        }

        intaddr = (struct sockaddr_in *)(ipint->ipaddr);

        if (intaddr == NULL) {
            /* Intercept with no associated IP address?? */
            continue;
        }

        if (ipsrc.ss_family == ipint->ai_family) {
            cmp = (struct sockaddr_in *)(&ipsrc);

            if (intaddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                /* Match */
                matched ++;
                msg = form_ipcc(glob, loc, ipint, pkt, ip, rem);
                libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
                continue;
            }
        }

        if (ipdst.ss_family == ipint->ai_family) {
            cmp = (struct sockaddr_in *)(&ipdst);

            if (intaddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                /* Match */
                matched ++;
                msg = form_ipcc(glob, loc, ipint, pkt, ip, rem);
                libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
                continue;
            }
        }
    }

    if (matched > 0) {
        msg.type = OPENLI_EXPORT_PACKET_FIN;
        msg.data.packet = pkt;
        trace_increment_packet_refcount(pkt);
        libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
    }

    return matched;

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
