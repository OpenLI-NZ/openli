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

#include <assert.h>
#include <libtrace.h>
#include <libtrace_parallel.h>

#include "alushim_parser.h"
#include "intercept.h"
#include "coreserver.h"
#include "logger.h"
#include "etsili_core.h"
#include "util.h"

typedef struct alushimhdr {
    uint32_t interceptid;
    uint32_t sessionid;
} PACKED alushimhdr_t;

static inline uint32_t alushim_get_interceptid(alushimhdr_t *aluhdr) {
    uint32_t intid = ntohl(aluhdr->interceptid);

    if ((intid & 0xc0000000) == 0) {
        /* 30bit intercept id */
        return (intid & 0x3fffffff);
    }

    if ((intid & 0xc0000000) == (0x40000000)) {
        /* 29bit intercept id */
        return (intid & 0x1fffffff);
    }

    /* Unknown version, assume 30bit intercept id */
    return (intid & 0x3fffffff);
}

static inline int alushim_get_direction(alushimhdr_t *aluhdr) {

    uint32_t intid = ntohl(aluhdr->interceptid);

    /* In ETSI, 0 = from target, 1 = to target, 2 = unknown */
    /* In ALU, 0 = ingress (from subscriber), 1 = egress (to subscriber) */

    if ((intid & 0xc0000000) == 0) {
        /* MHV (2b) == 0 means no direction info */
        return 2;
    }

    if ((intid & 0xe0000000) == 0x40000000) {
        /* MHV == 1, dir bit = 0 */
        return 0;
    }

    if ((intid & 0xe0000000) == 0x60000000) {
        /* MHV == 1, dir bit = 1 */
        return 1;
    }

    /* Invalid combination of bits? */
    return 2;
}

alushimhdr_t *get_alushim_header(libtrace_packet_t *packet, uint32_t *rem) {

    uint8_t proto;
    void *transport, *udppayload;

    transport = trace_get_transport(packet, &proto, rem);
    if (rem == 0 || transport == NULL) {
        return NULL;
    }
    if (proto != TRACE_IPPROTO_UDP) {
        return NULL;
    }

    udppayload = trace_get_payload_from_udp((libtrace_udp_t *)transport,
            rem);
    if (*rem < sizeof(alushimhdr_t)) {
        return NULL;
    }
    return (alushimhdr_t *)(udppayload);
}

static void push_alu_ipcc_job(colthread_local_t *loc, libtrace_packet_t *packet,
        aluintercept_t *alu, uint8_t dir, collector_identity_t *info,
        void *l3, uint32_t rem) {

    openli_export_recv_t *msg;
    int queueused;

    msg = calloc(1, sizeof(openli_export_recv_t));

    msg->type = OPENLI_EXPORT_IPCC;
    msg->ts = trace_get_timeval(packet);
    msg->destid = alu->common.destid;
    msg->data.ipcc.liid = strdup(alu->common.liid);
    msg->data.ipcc.cin = alu->cin;
    msg->data.ipcc.dir = dir;
    msg->data.ipcc.ipcontent = (uint8_t *)calloc(1, rem);
    msg->data.ipcc.ipclen = rem;

    memcpy(msg->data.ipcc.ipcontent, l3, rem);

    publish_openli_msg(loc->zmq_pubsocks[0], msg);  //FIXME

}

int check_alu_intercept(collector_identity_t *info, colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        coreserver_t *alusources, aluintercept_t *aluints) {

    coreserver_t *cs, *tmp;
    aluintercept_t *alu;
    int alumatched = 0;
    uint16_t ethertype;
    alushimhdr_t *aluhdr = NULL;
    uint32_t rem = 0, shimintid;
    void *l3, *l2;
    openli_export_recv_t msg;
    struct timeval tv;
    int aludir;

    if (pinfo->destport == 0) {
        return 0;
    }

    /* Is this packet from any of our known ALU mirrors? */
    HASH_ITER(hh, alusources, cs, tmp) {
       	if (cs->info == NULL) {
            cs->info = populate_addrinfo(cs->ipstr, cs->portstr, SOCK_DGRAM);
            if (!cs->info) {
                logger(LOG_INFO,
                        "Removing %s:%s from %s ALU source list due to getaddrinfo error",
                        cs->ipstr, cs->portstr,
                        coreserver_type_to_string(cs->servertype));
                HASH_DELETE(hh, alusources, cs);
                continue;
            }
            if (cs->info->ai_family == AF_INET) {
                cs->portswapped = ntohs(CS_TO_V4(cs)->sin_port);
            } else if (cs->info->ai_family == AF_INET6) {
                cs->portswapped = ntohs(CS_TO_V6(cs)->sin6_port);
            }
        }

        if (cs->info->ai_family == AF_INET) {
            struct sockaddr_in *sa;
            sa = (struct sockaddr_in *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V4(cs, sa, pinfo->destport)) {
                alumatched = 1;
                break;
            }
        } else if (cs->info->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6;
            sa6 = (struct sockaddr_in6 *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V6(cs, sa6, pinfo->destport)) {
                alumatched = 1;
                break;
            }
        }
    }

    if (!alumatched) {
        return 0;
    }

    /* Extract the intercept ID, direction and session ID */
    aluhdr = get_alushim_header(packet, &rem);
    if (!aluhdr) {
        return 0;
    }
    shimintid = alushim_get_interceptid(aluhdr);

    /* See if the intercept ID is in our set of intercepts */
    HASH_FIND(hh, aluints, &shimintid, sizeof(shimintid), alu);
    if (alu == NULL) {
        logger(LOG_INFO,
                "Warning: received packet from ALU mirror %s:%s with intercept ID %u, but that ID does not match an OpenLI intercept...",
                cs->ipstr, cs->portstr, shimintid);
        return 0;
    }

    /* Strip the extra headers + shim */
    tv = trace_get_timeval(packet);
    l2 = ((char *)aluhdr) + sizeof(alushimhdr_t);
    rem -= sizeof(alushimhdr_t);

    /* TODO add support for layer 3 only intercepts? */
    l3 = trace_get_payload_from_layer2(l2, TRACE_TYPE_ETH, &ethertype, &rem);
    while (1) {
        if (l3 == NULL || rem == 0) {
            break;
        }
        switch(ethertype) {
            case TRACE_ETHERTYPE_8021Q:
                l3 = trace_get_payload_from_vlan(l3, &ethertype, &rem);
                continue;
            case TRACE_ETHERTYPE_MPLS:
                l3 = trace_get_payload_from_mpls(l3, &ethertype, &rem);
                if (l3 && ethertype == 0) {
                    l3 = trace_get_payload_from_layer2(l3, TRACE_TYPE_ETH,
                            &ethertype, &rem);
                }
                continue;
            case TRACE_ETHERTYPE_PPP_SES:
                l3 = trace_get_payload_from_pppoe(l3, &ethertype, &rem);
                continue;
            default:
                break;
        }
        break;
    }

    if (!l3 || rem == 0) {
        logger(LOG_INFO,
                "Warning: unable to find IP header of ALU-intercepted packet from mirror %s:%s (ID: %u)",
                cs->ipstr, cs->portstr, shimintid);
        return -1;
    }

    /* Direction 0 = ingress (i.e. coming from the subscriber) */

    /* Use the session ID from the shim as the CIN */
    /* TODO double check that this will be available in the RADIUS stream */
    alu->cin = ntohl(aluhdr->sessionid);

    /* Create an appropriate IPCC and export it */
    push_alu_ipcc_job(loc, packet, alu, alushim_get_direction(aluhdr), info,
            l3, rem);

    return 1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
