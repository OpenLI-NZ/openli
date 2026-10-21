/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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
#include <string.h>
#include <libtrace.h>
#include <libtrace_parallel.h>

#include "cisco_parser.h"
#include "logger.h"
#include "etsili_core.h"
#include "util.h"
#include "coreserver.h"

typedef struct ciscomirror_hdr {
    uint32_t interceptid;
} PACKED ciscomirror_hdr_t;

static inline uint32_t ciscomirror_get_intercept_id(ciscomirror_hdr_t *hdr) {

    uint32_t id;
    memcpy(&id, &hdr->interceptid, sizeof(id));
    return ntohl(id);
}

uint8_t *decode_cisco_from_udp_payload(uint8_t *payload, uint32_t plen,
        uint32_t *shimintid, uint32_t *bodylen) {

    ciscomirror_hdr_t *header;
    uint32_t rem;
    uint8_t *l3;

    if (payload == NULL || plen < sizeof(ciscomirror_hdr_t)) {
        return NULL;
    }
    rem = plen;
    header = (ciscomirror_hdr_t *)payload;
    *shimintid = ciscomirror_get_intercept_id(header);

    rem -= sizeof(ciscomirror_hdr_t);
    l3 = ((uint8_t *)header) + sizeof(ciscomirror_hdr_t);

    /* PCLI carries a complete inner IP packet. Never export a truncated
     * first outer fragment or a malformed inner header as CC. Trailing mirror
     * padding is retained for compatibility with the unfragmented path. */
    if (rem < 1) return NULL;
    if ((l3[0] >> 4) == 4) {
        uint32_t h = (l3[0] & 15) * 4;
        if (rem < 20 || h < 20 || h > rem ||
                (((uint32_t)l3[2] << 8) | l3[3]) < h ||
                (((uint32_t)l3[2] << 8) | l3[3]) > rem) return NULL;
    } else if ((l3[0] >> 4) == 6) {
        if (rem < 40 || 40U + (((uint32_t)l3[4] << 8) | l3[5]) > rem)
            return NULL;
    } else return NULL;
    *bodylen = rem;
    return l3;
}

/** Converts a Cisco LI-mirrored packet directly into a CC encoding job for
 *  any intercepts that have requested its vendor mirror ID.
 *
 *  The vendor mirror ID is used as the CIN for this intercept, as there is
 *  no useful session identifier in the headers applied by Cisco.
 *
 * @param loc           The thread-specific state for the thread calling this
 *                      function.
 * @param packet        The packet to be intercepted.
 * @param pinfo         Details about the packet (source and dest IPs, ports,
 *                      timestamp).
 * @param ciscomirrors  The list of IP intercepts that are using a vendor
 *                      mirror ID to nominate their target.
 *
 * @return 1 if a CC encoding job is successfully created and actioned. Returns
 *         0 otherwise.
 */
int generate_cc_from_cisco(colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        vendmirror_intercept_list_t *ciscomirrors) {

    void *payload;
    uint32_t rem = 0;

    payload = get_udp_payload(packet, &rem, NULL, NULL);
    return generate_cc_from_cisco_payload(loc, payload, rem, pinfo,
            ciscomirrors);
}

int generate_cc_from_cisco_payload(colthread_local_t *loc, uint8_t *payload,
        uint32_t length, packet_info_t *pinfo,
        vendmirror_intercept_list_t *ciscomirrors) {
    uint32_t cept_id, bodylen;
    uint8_t *l3;
    vendmirror_intercept_t *cept, *tmp;
    vendmirror_intercept_list_t *vmilist;
    openli_cc_prefix_filter_t *cc_exclude;

    l3 = decode_cisco_from_udp_payload(payload, length, &cept_id, &bodylen);
    if (!l3) return 0;

    HASH_FIND(hh, ciscomirrors, &cept_id, sizeof(cept_id), vmilist);
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

        cc_exclude = lookup_cc_prefix_filter(loc, cept->common.liid);
        if (cc_exclude) {
            if (openli_cc_prefix_filter_match_l3(cc_exclude, l3, bodylen)) {
                continue;
            }
        }

        /* Create an appropriate IPCC and export it */
        if (push_vendor_mirrored_ipcc_job(
                loc->zmq_pubsocks[cept->common.seqtrackerid], &(cept->common),
                pinfo->tv, cept_id, ETSI_DIR_INDETERMINATE,
                l3, bodylen) == 0) {
            /* for some reason, we failed to create or send the IPCC to
             * the sequencing thread? */

        }
    }
    return 1;
}

/** Given a packet that has been mirrored by a Cisco device using its LI mode,
 *  this function will return the packet that is encapsulated within the
 *  LI shim header, as a libtrace packet.
 *
 *  Note that the returned packet is created by this function and will
 *  need to be destroyed explicitly once you are done with it.
 *
 *  @param pkt          The mirrored packet as seen by the "mediation server"
 *                      that received it, including the mirroring headers.
 *
 *  @return another libtrace packet that represents the packet that is
 *          encapsulated inside the mirroring headers, or NULL if no such
 *          packet can be found.
 */
libtrace_packet_t *strip_cisco_mirror_header(libtrace_packet_t *pkt) {

    libtrace_packet_t *stripped;
    void *payload;
    uint32_t rem;

    payload = get_udp_payload(pkt, &rem, NULL, NULL);

    if (payload == NULL || rem <= 4) {
        return NULL;
    }

    stripped = trace_create_packet();
    trace_construct_packet(stripped, TRACE_TYPE_NONE, payload + 4, rem - 4);

    return stripped;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
