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

#ifndef OPENLI_IPIRI_H_
#define OPENLI_IPIRI_H_

#include <uthash.h>
#include <libtrace.h>
#include <libwandder.h>
#include <libwandder_etsili.h>
#include "collector.h"
#include "intercept.h"
#include "internetaccess.h"
#include "etsili_core.h"

enum {
    IPIRI_CONTENTS_ACCESS_EVENT_TYPE = 0,
    IPIRI_CONTENTS_TARGET_USERNAME = 1,
    IPIRI_CONTENTS_INTERNET_ACCESS_TYPE = 2,
    IPIRI_CONTENTS_IPVERSION = 3,
    IPIRI_CONTENTS_TARGET_IPADDRESS = 4,
    IPIRI_CONTENTS_TARGET_NETWORKID = 5,
    IPIRI_CONTENTS_TARGET_CPEID = 6,
    IPIRI_CONTENTS_TARGET_LOCATION = 7,
    IPIRI_CONTENTS_POP_PORTNUMBER = 8,
    IPIRI_CONTENTS_CALLBACK_NUMBER = 9,
    IPIRI_CONTENTS_STARTTIME = 10,
    IPIRI_CONTENTS_ENDTIME = 11,
    IPIRI_CONTENTS_ENDREASON = 12,
    IPIRI_CONTENTS_OCTETS_RECEIVED = 13,
    IPIRI_CONTENTS_OCTETS_TRANSMITTED = 14,
    IPIRI_CONTENTS_RAW_AAA_DATA = 15,
    IPIRI_CONTENTS_EXPECTED_ENDTIME = 16,
    IPIRI_CONTENTS_POP_PHONENUMBER = 17,
    IPIRI_CONTENTS_POP_IDENTIFIER = 18,
    IPIRI_CONTENTS_POP_IPADDRESS = 19,
    IPIRI_CONTENTS_NATIONAL_IPIRI_PARAMETERS = 20,
    IPIRI_CONTENTS_ADDITIONAL_IPADDRESS = 21,
    IPIRI_CONTENTS_AUTHENTICATION_TYPE = 22,
    IPIRI_CONTENTS_OTHER_TARGET_IDENTIFIERS = 23,
};

enum {
    IPIRI_ACCESS_ATTEMPT = 0,
    IPIRI_ACCESS_ACCEPT = 1,
    IPIRI_ACCESS_REJECT = 2,
    IPIRI_ACCESS_FAILED = 3,
    IPIRI_SESSION_START = 4,
    IPIRI_SESSION_END = 5,
    IPIRI_INTERIM_UPDATE = 6,
    IPIRI_START_WHILE_ACTIVE = 7,
    IPIRI_ACCESS_END = 8,
    IPIRI_END_WHILE_ACTIVE = 9,
    IPIRI_ACCESS_UNKNOWN = 10,
};

enum {
    IPIRI_ACCESS_TYPE_UNDEFINED = 0,
    IPIRI_ACCESS_TYPE_DIALUP = 1,
    IPIRI_ACCESS_TYPE_XDSL = 2,
    IPIRI_ACCESS_TYPE_CABLE = 3,
    IPIRI_ACCESS_TYPE_LAN = 4,
    IPIRI_ACCESS_TYPE_WIRELESS_LAN = 5,
    IPIRI_ACCESS_TYPE_FTTX = 6,
    IPIRI_ACCESS_TYPE_WIMAX = 7,
    IPIRI_ACCESS_TYPE_SATELLITE = 8,
    IPIRI_ACCESS_TYPE_WIRELESS_OTHER = 9,
};

enum {
    IPIRI_IPVERSION_4 = 1,
    IPIRI_IPVERSION_6 = 2,
    IPIRI_IPVERSION_4AND6 = 3,
};


enum {
    IPIRI_END_REASON_UNDEFINED = 0,
    IPIRI_END_REASON_REGULAR = 1,
    IPIRI_END_REASON_CONNECTION_LOSS = 2,
    IPIRI_END_REASON_CONNECTION_TIMEOUT = 3,
    IPIRI_END_REASON_LEASE_EXPIRED = 4,
};

enum {
    IPIRI_AUTHTYPE_UNKNOWN = 0,
    IPIRI_AUTHTYPE_STATIC = 1,
    IPIRI_AUTHTYPE_RADIUS = 2,
    IPIRI_AUTHTYPE_DHCP = 3,
    IPIRI_AUTHTYPE_DIAMETER = 4,
};

enum {
    IPIRI_ID_PRINTABLE = 0,
    IPIRI_ID_MAC = 1,
    IPIRI_ID_IPADDR = 2,
};

typedef struct ipiri_id {
    uint8_t type;
    union {
        char *printable;
        uint8_t mac[6];
        etsili_ipaddress_t *ip;
    } content;
} ipiri_id_t;

int ip_iri(collector_identity_t *info, wandder_encoder_t **encoder,
                libtrace_message_queue_t *q, access_session_t *sess,
                ipintercept_t *ipint, etsili_iri_type_t iritype,
                struct timeval *tv, etsili_generic_t *params);

int encode_ipiri(wandder_encoder_t *encoder,
        etsili_generic_freelist_t *freegenerics,
        wandder_encode_job_t *precomputed,
        openli_ipiri_job_t *job, uint32_t seqno,
        openli_encoded_result_t *res);

#ifdef HAVE_BER_ENCODING
int encode_ipiri_ber(
        openli_ipiri_job_t *job,
        etsili_generic_freelist_t *freegenerics,
        uint32_t seqno, struct timeval *tv,
        openli_encoded_result_t *res,
        wandder_etsili_child_t *child, 
        wandder_encoder_t *encoder);
#endif

/* TODO consider adding free lists to these APIs to avoid excess mallocs */
int ipiri_create_id_printable(char *idstr, int length, ipiri_id_t *ipiriid);
int ipiri_create_id_mac(uint8_t *macaddr, ipiri_id_t *ipiriid);
int ipiri_create_id_ipv4(uint32_t addrnum, uint8_t slashbits,
        ipiri_id_t *ipiriid);

void ipiri_free_id(ipiri_id_t *iriid);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
