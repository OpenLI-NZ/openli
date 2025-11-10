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

#include "jmirror_parser.h"
#include "logger.h"
#include "etsili_core.h"
#include "util.h"
#include "coreserver.h"

typedef struct jmirror_hdr {
    uint32_t interceptid;
    uint32_t sessionid;
} PACKED jmirrorhdr_t;

static inline uint32_t jmirror_get_interceptid(jmirrorhdr_t *header) {
    /* Intercept IDs are always the lower 30 bits */
    return (ntohl(header->interceptid) & 0x3fffffff);
}

uint8_t *decode_jmirror_from_udp_payload(uint8_t *payload, uint32_t plen,
        uint32_t *cin, uint32_t *shimintid, uint32_t *bodylen) {

    jmirrorhdr_t *header;
    uint32_t rem = plen;
    uint8_t *l3;

    header = (jmirrorhdr_t *)payload;
    if (!header || rem < sizeof(jmirrorhdr_t)) {
        return NULL;
    }

    *shimintid = jmirror_get_interceptid(header);
    *cin = ntohl(header->sessionid);

    rem -= sizeof(jmirrorhdr_t);
    l3 = ((uint8_t *)header) + sizeof(jmirrorhdr_t);

    if (rem == 0) {
        return NULL;
    }
    *bodylen = rem;
    return l3;
}

int check_jmirror_intercept(colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        coreserver_t *jmirror_sources,
        vendmirror_intercept_list_t *jmirror_ints) {

    coreserver_t *cs;
    uint32_t rem = 0, cept_id, cin, bodylen;
    vendmirror_intercept_t *cept, *tmp;
    vendmirror_intercept_list_t *vmilist;
    uint8_t *l3, *start;

    if ((cs = match_packet_to_coreserver(jmirror_sources, pinfo, 1)) == NULL) {
        return 0;
    }

    start = get_udp_payload(packet, &rem, NULL, NULL);
    l3 = decode_jmirror_from_udp_payload(start, rem, &cin, &cept_id,
            &bodylen);
    if (l3 == NULL) {
        return 0;
    }

    HASH_FIND(hh, jmirror_ints, &cept_id, sizeof(cept_id), vmilist);
    if (vmilist == NULL) {
        return 0;
    }

    HASH_ITER(hh, vmilist->intercepts, cept, tmp) {
        if (pinfo->tv.tv_sec < cept->common.tostart_time) {
            continue;
        }
        if (cept->common.toend_time > 0 &&
                cept->common.toend_time < pinfo->tv.tv_sec) {
            continue;
        }
                /* Create an appropriate IPCC and export it */
        if (push_vendor_mirrored_ipcc_job(
                loc->zmq_pubsocks[cept->common.seqtrackerid], &(cept->common),
                trace_get_timeval(packet), cin, ETSI_DIR_INDETERMINATE,
                l3, bodylen) == 0) {
            /* for some reason, we failed to create or send the IPCC to
             * the sequencing thread? */

        }
    }
    return 1;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
