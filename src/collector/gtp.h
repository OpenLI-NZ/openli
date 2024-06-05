/*
 *
 * Copyright (c) 2024 Searchlight New Zealand Ltd.
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
#ifndef OPENLI_GTP_H_
#define OPENLI_GTP_H_

/* Need these GTP header definitions in multiple places, so they go in
 * here rather than being confined to the GTP plugin...
 */
typedef struct gtpv1_header {
    uint8_t octet1;
    uint8_t msgtype;
    uint16_t msglen;
    uint32_t teid;
    uint16_t seqno;
    uint8_t npdu;
    uint8_t next_ext;
} PACKED gtpv1_header_t;

typedef struct gtpv2_header_teid {
    uint8_t octet1;
    uint8_t msgtype;
    uint16_t msglen;
    uint32_t teid;
    uint32_t seqno;
} PACKED gtpv2_header_teid_t;

enum {
    GTPV1_CREATE_PDP_CONTEXT_REQUEST = 16,
    GTPV1_CREATE_PDP_CONTEXT_RESPONSE = 17,
    GTPV1_UPDATE_PDP_CONTEXT_REQUEST = 18,
    GTPV1_UPDATE_PDP_CONTEXT_RESPONSE = 19,
    GTPV1_DELETE_PDP_CONTEXT_REQUEST = 20,
    GTPV1_DELETE_PDP_CONTEXT_RESPONSE = 21,

    GTPV2_CREATE_SESSION_REQUEST = 32,
    GTPV2_CREATE_SESSION_RESPONSE = 33,
    GTPV2_DELETE_SESSION_REQUEST = 36,
    GTPV2_DELETE_SESSION_RESPONSE = 37,
};

uint8_t gtp_get_parsed_version(void *parseddata);

#endif
