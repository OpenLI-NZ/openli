/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

int check_alu_intercept(colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        coreserver_t *alusources, vendmirror_intercept_list_t *aluints) {

    coreserver_t *cs;
    vendmirror_intercept_t *alu, *tmp;
    vendmirror_intercept_list_t *vmilist;
    uint16_t ethertype;
    alushimhdr_t *aluhdr = NULL;
    uint32_t rem = 0, shimintid, cin;
    void *l3, *l2;

    if ((cs = match_packet_to_coreserver(alusources, pinfo, 1)) == NULL) {
        return 0;
    }

    /* Extract the intercept ID, direction and session ID */
    aluhdr = (alushimhdr_t *)get_udp_payload(packet, &rem, NULL, NULL);
    if (!aluhdr || rem < sizeof(alushimhdr_t)) {
        return 0;
    }

    shimintid = alushim_get_interceptid(aluhdr);

    /* See if the intercept ID is in our set of intercepts */
    HASH_FIND(hh, aluints, &shimintid, sizeof(shimintid), vmilist);
    if (vmilist == NULL) {
        return 0;
    }

    /* Strip the extra headers + shim */
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
            case TRACE_ETHERTYPE_ARP:
                /* Probably shouldn't be intercepting ARP */
                return 0;
            case TRACE_ETHERTYPE_IP:
            case TRACE_ETHERTYPE_IPV6:
                break;
            default:
                return 0;
        }
        break;
    }

    if (!l3 || rem == 0) {
        logger(LOG_INFO,
                "Warning: unable to find IP header of ALU-intercepted packet from mirror (ID: %u)",
                cs->serverkey, shimintid);
        return -1;
    }

    /* Direction 0 = ingress (i.e. coming from the subscriber) */

    /* Use the session ID from the shim as the CIN */
    /* TODO double check that this will be available in the RADIUS stream */
    cin = ntohl(aluhdr->sessionid);

    HASH_ITER(hh, vmilist->intercepts, alu, tmp) {
        if (pinfo->tv.tv_sec < alu->common.tostart_time) {
            continue;
        }
        if (alu->common.toend_time > 0 &&
                alu->common.toend_time < pinfo->tv.tv_sec) {
            continue;
        }

        /* Create an appropriate IPCC and export it */
        if (push_vendor_mirrored_ipcc_job(loc->zmq_pubsocks[0], &(alu->common),
                trace_get_timeval(packet), cin, alushim_get_direction(aluhdr),
                l3, rem) == 0) {
            /* for some reason, we failed to create or send the IPCC to
             * the sequencing thread? */

        }
    }

    return 1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
