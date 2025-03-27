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

#ifndef OPENLI_X2X3_INGEST_H_
#define OPENLI_X2X3_INGEST_H_

#include <uthash.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "collector_util.h"
#include "sipparsing.h"

typedef struct x2x3_base_header {

    uint16_t version;
    uint16_t pdutype;
    uint32_t hdrlength;
    uint32_t payloadlength;
    uint16_t payloadfmt;
    uint16_t payloaddir;
    uuid_t xid;
    uint64_t correlation;
} PACKED x2x3_base_header_t;

enum {
    X2X3_PDUTYPE_X2 = 1,
    X2X3_PDUTYPE_X3 = 2,
    X2X3_PDUTYPE_KEEPALIVE = 3,
    X2X3_PDUTYPE_KEEPALIVE_ACK = 4,
    X2X3_PDUTYPE_LAST
};

enum {
    X2X3_DIRECTION_RESERVED = 0,
    X2X3_DIRECTION_UNKNOWN = 1,
    X2X3_DIRECTION_TO_TARGET = 2,
    X2X3_DIRECTION_FROM_TARGET = 3,
    X2X3_DIRECTION_MULTIPLE = 4,
    X2X3_DIRECTION_NA = 5,
};

enum {
    X2X3_COND_ATTR_ETSI_102232 = 1,
    X2X3_COND_ATTR_3GPP_33128 = 2,
    X2X3_COND_ATTR_3GPP_33108 = 3,
    X2X3_COND_ATTR_PROPRIETARY = 4,
    X2X3_COND_ATTR_DOMAINID = 5,
    X2X3_COND_ATTR_NFID = 6,
    X2X3_COND_ATTR_IPID = 7,
    X2X3_COND_ATTR_SEQNO = 8,
    X2X3_COND_ATTR_TIMESTAMP = 9,
    X2X3_COND_ATTR_SOURCE_IPV4_ADDRESS = 10,
    X2X3_COND_ATTR_DEST_IPV4_ADDRESS = 11,
    X2X3_COND_ATTR_SOURCE_IPV6_ADDRESS = 12,
    X2X3_COND_ATTR_DEST_IPV6_ADDRESS = 13,
    X2X3_COND_ATTR_SOURCE_PORT = 14,
    X2X3_COND_ATTR_DEST_PORT = 15,
    X2X3_COND_ATTR_IPPROTO = 16,
    X2X3_COND_ATTR_MATCHED_TARGETID = 17,
    X2X3_COND_ATTR_OTHER_TARGETID = 18,
    X2X3_COND_ATTR_MIME_CONTENT_TYPE = 19,
    X2X3_COND_ATTR_MIME_CONTENT_ENCODING = 20,
    X2X3_COND_ATTR_ADDITIONAL_XID_RELATED = 21,
    X2X3_COND_ATTR_SDP_SESSION_DESC = 22,
    X2X3_COND_ATTR_LAST
};

enum {
    X2X3_PAYLOAD_FORMAT_ETSI_102232 = 1,
    X2X3_PAYLOAD_FORMAT_3GPP_33128 = 2,
    X2X3_PAYLOAD_FORMAT_3GPP_33108 = 3,
    X2X3_PAYLOAD_FORMAT_PROPRIETARY = 4,
    X2X3_PAYLOAD_FORMAT_IPV4_PACKET = 5,
    X2X3_PAYLOAD_FORMAT_IPV6_PACKET = 6,
    X2X3_PAYLOAD_FORMAT_ETHERNET = 7,
    X2X3_PAYLOAD_FORMAT_RTP = 8,
    X2X3_PAYLOAD_FORMAT_SIP = 9,
    X2X3_PAYLOAD_FORMAT_DHCP = 10,
    X2X3_PAYLOAD_FORMAT_RADIUS = 11,
    X2X3_PAYLOAD_FORMAT_GTP_U = 12,
    X2X3_PAYLOAD_FORMAT_MSRP = 13,
    X2X3_PAYLOAD_FORMAT_EPSIRI = 14,
    X2X3_PAYLOAD_FORMAT_MIME = 15,
    X2X3_PAYLOAD_FORMAT_UNSTRUCTURED = 16,
    X2X3_PAYLOAD_FORMAT_LAST
};

enum {
    X2X3_SIP_SESSION_TYPE_CALL,
    X2X3_SIP_SESSION_TYPE_MESSAGE,
    X2X3_SIP_SESSION_TYPE_REGISTER,
    X2X3_SIP_SESSION_TYPE_OTHER,
};

typedef struct x2x3_sip_session {
    char *callid;
    uint8_t sesstype;
    time_t lastseen;

    char *byecseq;
    uint8_t byematched;

    UT_hash_handle hh;

} x2x3_sip_session_t;

typedef struct x2x3_conditional_attribute {
    uint16_t type;
    uint16_t length;
    uint32_t sub_id;
    uint8_t *body;
    uint8_t is_parsed;

    union {
        char *as_string;
        uint32_t as_u32;
        uint16_t as_u16;
        uint64_t as_u64;
        uint8_t *as_octets;
        uint8_t as_u8;
    } parsed;

    UT_hash_handle hh;
} x2x3_cond_attr_t;

typedef struct x_input_client {
    SSL *ssl;
    int fd;
    char *clientip;

    uint8_t *buffer;
    size_t buffer_size;
    size_t bufread;
    size_t bufwrite;
} x_input_client_t;

typedef struct x_input_sync {
    void *zmq_socket;
    char *identifier;

    UT_hash_handle hh;
} x_input_sync_t;

typedef struct x_input {

    uint8_t running;
    pthread_t threadid;

    char *identifier;
    char *listenaddr;
    char *listenport;

    uint8_t use_tls;
    SSL_CTX *ssl_ctx;
    uint8_t ssl_ctx_bad;
    uint8_t reset_listener;
    pthread_mutex_t sslmutex;

    int listener_fd;
    x_input_client_t *clients;
    size_t client_count;
    size_t client_array_size;
    size_t dead_clients;

    void *zmq_ctxt;

    void *zmq_ctrlsock;
    void **zmq_fwdsocks;
    void **zmq_pubsocks;

    /* TODO we need ZMQs that allow us to pass on packets to the
     * various worker threads based on the payload format in the X2/X3
     * PDU header
     *
     *  - sync (for RADIUS)
     *  - gtp workers (GTP-U) 
     *  - sip workers (for SIP) 
     *  - col processing threads (for IP / RTP / Ethernet)
     *
     * XXX GTP-C is not a payload format? I guess that comes as EPSIRIContent.
     */

    int tracker_threads;
    int forwarding_threads;

    /* Hash map of known intercepts, keyed by the LIID */
    ipintercept_t *ipintercepts;
    voipintercept_t *voipintercepts;

    /* Hash map of known intercepts, keyed by the XID */
    ipintercept_t *ipxids;
    voipintercept_t *voipxids;

    /* Parser for extracting information from SIP messages */
    openli_sip_parser_t *sipparser;

    x2x3_sip_session_t *sip_active_calls;
    x2x3_sip_session_t *sip_registrations;
    x2x3_sip_session_t *sip_active_messages;
    x2x3_sip_session_t *sip_other_sessions;

    /* Shared state used to track when X2/X3 threads have halted */
    halt_info_t *haltinfo;

    UT_hash_handle hh;

} x_input_t;

void destroy_x_input(x_input_t *xinp);
void *start_x2x3_ingest_thread(void *param);

int parse_x2x3_conditional_attributes(uint8_t *hdrstart, uint32_t hlen,
        x2x3_cond_attr_t **attrs);
void free_x2x3_conditional_attributes(x2x3_cond_attr_t **attrs);

#endif
