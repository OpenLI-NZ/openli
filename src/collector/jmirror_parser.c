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

int check_jmirror_intercept(collector_identity_t *info, colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        coreserver_t *jmirror_sources,
        vendmirror_intercept_list_t *jmirror_ints) {

    coreserver_t *cs;
    jmirrorhdr_t *header = NULL;
    uint32_t rem = 0, cept_id, cin;
    vendmirror_intercept_t *cept, *tmp;
    vendmirror_intercept_list_t *vmilist;
    char *l3;

    if ((cs = match_packet_to_coreserver(jmirror_sources, pinfo)) == NULL) {
        return 0;
    }

    header = (jmirrorhdr_t *)get_udp_payload(packet, &rem, NULL, NULL);
    if (rem < sizeof(jmirrorhdr_t) || header == NULL) {
        return 0;
    }

    cept_id = jmirror_get_interceptid(header);

    HASH_FIND(hh, jmirror_ints, &cept_id, sizeof(cept_id), vmilist);
    if (vmilist == NULL) {
        return 0;
    }

    rem -= sizeof(jmirrorhdr_t);
    l3 = ((char *)header) + sizeof(jmirrorhdr_t);

    if (rem == 0) {
        return 0;
    }
    cin = ntohl(header->sessionid);

    HASH_ITER(hh, vmilist->intercepts, cept, tmp) {
        if (pinfo->tv.tv_sec < cept->common.tostart_time) {
            continue;
        }
        if (cept->common.toend_time > 0 &&
                cept->common.toend_time < pinfo->tv.tv_sec) {
            continue;
        }
                /* Create an appropriate IPCC and export it */
        if (push_vendor_mirrored_ipcc_job(loc->zmq_pubsocks[0], &(cept->common),
                trace_get_timeval(packet), cin, ETSI_DIR_INDETERMINATE,
                l3, rem) == 0) {
            /* for some reason, we failed to create or send the IPCC to
             * the sequencing thread? */

        }
    }
    return 1;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
