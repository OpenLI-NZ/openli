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

static void push_jmirror_ipcc_job(colthread_local_t *loc,
        libtrace_packet_t *packet, vendmirror_intercept_t *cept,
        collector_identity_t *info, void *l3, uint32_t rem) {

    openli_export_recv_t *msg;

	msg = calloc(1, sizeof(openli_export_recv_t));

    msg->type = OPENLI_EXPORT_IPCC;
    msg->ts = trace_get_timeval(packet);
    msg->destid = cept->common.destid;
    msg->data.ipcc.liid = strdup(cept->common.liid);
    msg->data.ipcc.cin = cept->cin;
    msg->data.ipcc.dir = ETSI_DIR_INDETERMINATE;
    msg->data.ipcc.ipcontent = (uint8_t *)calloc(1, rem);
    msg->data.ipcc.ipclen = rem;

    memcpy(msg->data.ipcc.ipcontent, l3, rem);

    publish_openli_msg(loc->zmq_pubsocks[0], msg);  //FIXME

}

int check_jmirror_intercept(collector_identity_t *info, colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        coreserver_t *jmirror_sources, vendmirror_intercept_t *jmirror_ints) {

    coreserver_t *cs;
    jmirrorhdr_t *header = NULL;
    uint32_t rem = 0, cept_id;
    vendmirror_intercept_t *cept;
    char *l3;

    if ((cs = match_packet_to_coreserver(jmirror_sources, pinfo)) == NULL) {
        return 0;
    }

    header = (jmirrorhdr_t *)get_udp_payload(packet, &rem);
    if (rem < sizeof(jmirrorhdr_t) || header == NULL) {
        return 0;
    }

    cept_id = jmirror_get_interceptid(header);

    HASH_FIND(hh, jmirror_ints, &cept_id, sizeof(cept_id), cept);
    if (cept == NULL) {
        return 0;
    }

    rem -= sizeof(jmirrorhdr_t);
    l3 = ((char *)header) + sizeof(jmirrorhdr_t);

    if (rem == 0) {
        return 0;
    }

    cept->cin = ntohl(header->sessionid);
    push_jmirror_ipcc_job(loc, packet, cept, info, l3, rem);
    return 1;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
