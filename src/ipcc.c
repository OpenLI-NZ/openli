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
 * GNU Lesser General Public License for more details.
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

#include "logger.h"
#include "collector.h"
#include "etsili_const.h"


#define ENC_USEQUENCE(enc) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_UNIVERSAL_CONSTRUCT, WANDDER_TAG_SEQUENCE, NULL, 0)

#define ENC_CSEQUENCE(enc, x) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_CONTEXT_CONSTRUCT, x, NULL, 0)


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

    /* Trying to decide between copying the packet contents into the IP CC
     * message or trying a zero-copy approach.
     *
     * Good reasons for copying:
     * 1. zero copy is only feasible as long as the packet contents are the
     *    last field in the entire message -- true for ETSI LI but may not be
     *    so in other use cases -- therefore this is difficult to fit into
     *    a generic library such as libwandder.
     * 2. zero copy will mean that we are holding on to packets right up
     *    until they are successfully exported, preventing the underlying
     *    capture method from using that space for reading new packets off
     *    the wire.
     *
     * Good reasons for zero copy:
     * 1. Copying from kernel to user space memory is going to be costly
     *    performance-wise. If we are exporting a lot of packets, this may
     *    become an issue.
     */

    if (loc->encoder == NULL) {
        loc->encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(loc->encoder);
    }

    ENC_USEQUENCE(loc->encoder);

    ENC_CSEQUENCE(loc->encoder, 1);
    wandder_encode_next(loc->encoder, WANDDER_TAG_OID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, etsi_lipsdomainid,
            sizeof(etsi_lipsdomainid));
    wandder_encode_next(loc->encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, ipint->liid,
            ipint->liid_len);
    wandder_encode_next(loc->encoder, WANDDER_TAG_PRINTABLE,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, ipint->authcc,
            ipint->authcc_len);

    ENC_CSEQUENCE(loc->encoder, 3);

    ENC_CSEQUENCE(loc->encoder, 0);
    wandder_encode_next(loc->encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, glob->operatorid,
            glob->operatorid_len);

    wandder_encode_next(loc->encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, glob->networkelemid,
            glob->networkelemid_len);
    wandder_encode_endseq(loc->encoder);

    wandder_encode_next(loc->encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(ipint->cin),
            sizeof(uint64_t));
    wandder_encode_next(loc->encoder, WANDDER_TAG_PRINTABLE,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, ipint->delivcc,
            ipint->delivcc_len);
    wandder_encode_endseq(loc->encoder);

    wandder_encode_next(loc->encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(ipint->nextseqno),
            sizeof(uint64_t));
    wandder_encode_next(loc->encoder, WANDDER_TAG_GENERALTIME,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, &tv,
            sizeof(struct timeval));

    if (glob->intpointid) {
        wandder_encode_next(loc->encoder, WANDDER_TAG_PRINTABLE,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, glob->intpointid,
                glob->intpointid_len);
    }
    wandder_encode_endseq(loc->encoder);

    ENC_CSEQUENCE(loc->encoder, 2);
    ENC_CSEQUENCE(loc->encoder, 1);
    ENC_USEQUENCE(loc->encoder);
    ENC_CSEQUENCE(loc->encoder, 2);
    ENC_CSEQUENCE(loc->encoder, 2);

    wandder_encode_next(loc->encoder, WANDDER_TAG_RELATIVEOID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, etsi_ipccoid,
            sizeof(etsi_ipccoid));
    ENC_CSEQUENCE(loc->encoder, 1);
    wandder_encode_next(loc->encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, l3, rem);


    wandder_encode_endseq(loc->encoder);
    wandder_encode_endseq(loc->encoder);
    wandder_encode_endseq(loc->encoder);
    wandder_encode_endseq(loc->encoder);
    wandder_encode_endseq(loc->encoder);
    wandder_encode_endseq(loc->encoder);
    wandder_encode_endseq(loc->encoder);

    msg.msgbody = wandder_encode_finish(loc->encoder, &(msg.msglen));
    msg.ipcontents = (uint8_t *)l3;
    msg.ipclen = rem;
    msg.destid = ipint->destid;

    exprecv.type = OPENLI_EXPORT_ETSIREC;
    exprecv.data.toexport = msg;

    ipint->nextseqno ++;

    return exprecv;

}
int ipv4_comm_contents(libtrace_packet_t *pkt, libtrace_ip_t *ip,
        uint32_t rem, collector_global_t *glob, colthread_local_t *loc) {

    libtrace_list_node_t *n = loc->activeipintercepts->head;
    struct sockaddr_storage ipsrc;
    struct sockaddr_storage ipdst;
    struct sockaddr_in *intaddr, *cmp;
    openli_export_recv_t msg;
    int matched = 0;

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

    while (n) {
        ipintercept_t *ipint = (ipintercept_t *)(n->data);

        if (!ipint->active) {
            n = n->next;
            continue;
        }

        intaddr = (struct sockaddr_in *)(ipint->ipaddr);

        if (ipsrc.ss_family == ipint->ai_family) {
            cmp = (struct sockaddr_in *)(&ipsrc);

            if (intaddr->sin_addr.s_addr == cmp->sin_addr.s_addr) {
                /* Match */
                matched ++;
                msg = form_ipcc(glob, loc, ipint, pkt, ip, rem);
                libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
                n = n->next;
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
                n = n->next;
                continue;
            }
        }

        n = n->next;
    }

    if (matched > 0) {
        msg.type = OPENLI_EXPORT_PACKET_FIN;
        msg.data.packet = pkt;
        libtrace_message_queue_put(&(loc->exportq), (void *)&msg);
    }

    return matched;

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
