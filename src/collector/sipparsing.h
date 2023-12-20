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

#ifndef OPENLI_SIPPARSING_H_
#define OPENLI_SIPPARSING_H_

#include <libtrace.h>
#include <libtrace/linked_list.h>
#include <osip2/osip.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/sdp_message.h>

#include "intercept.h"
#include "reassembler.h"
#include "location.h"

typedef enum {
    SIP_IPV4_TCP,
    SIP_IPV4_UDP,
    SIP_IPV6_TCP,
    SIP_IPv6_UDP
} sipproto_t;

enum {
    SIP_MATCH_FROMURI,
    SIP_MATCH_TOURI,
    SIP_MATCH_VIAURI
};

enum {
    SIP_ACTION_ERROR,
    SIP_ACTION_IGNORE,
    SIP_ACTION_USE_PACKET,
    SIP_ACTION_REASSEMBLE_TCP,
    SIP_ACTION_REASSEMBLE_IPFRAG,
};

typedef struct sipserverdetails {
    sipproto_t proto;
    union {
        uint32_t ip4;
        uint8_t ip6[16];
    } addr;
    uint16_t port;
} sipserverdetails_t;

typedef enum {
    OPENLI_SIP_KEEPALIVE,

} openli_sipmsg_type_t;

typedef struct openli_sip_identity_set {
    openli_sip_identity_t touriid;
    openli_sip_identity_t fromuriid;
    openli_sip_identity_t remotepartyid;
    openli_sip_identity_t passertid;
    openli_sip_identity_t *proxyauths;
    openli_sip_identity_t *regauths;
    int proxyauthcount;
    int regauthcount;
} openli_sip_identity_set_t;

typedef struct openli_sip_parser {

    osip_message_t *osip;
    sdp_message_t *sdp;
    tcp_reassembler_t *tcpreass;
    ipfrag_reassembler_t *ipreass;

    uint8_t sipalloced;
    char *sipmessage;
    uint16_t sipoffset;
    uint16_t siplen;
    tcp_reassemble_stream_t *thisstream;

} openli_sip_parser_t;

int add_sip_packet_to_parser(openli_sip_parser_t **parser,
        libtrace_packet_t *packet, uint8_t logallowed);
int parse_sip_content(openli_sip_parser_t *parser, uint8_t *sipcontent,
        uint16_t siplen);
int parse_next_sip_message(openli_sip_parser_t *parser,
        libtrace_packet_t *packet);
void release_sip_parser(openli_sip_parser_t *parser);

char *get_sip_contents(openli_sip_parser_t *parser, uint16_t *siplen);

char *get_sip_from_uri(openli_sip_parser_t *parser);
char *get_sip_to_uri(openli_sip_parser_t *parser);
char *get_sip_to_uri_username(openli_sip_parser_t *parser);
char *get_sip_from_uri_username(openli_sip_parser_t *parser);
char *get_sip_to_uri_realm(openli_sip_parser_t *parser);
char *get_sip_from_uri_realm(openli_sip_parser_t *parser);
int get_sip_to_uri_identity(openli_sip_parser_t *parser,
        openli_sip_identity_t *sipid);
int get_sip_from_uri_identity(openli_sip_parser_t *parser,
        openli_sip_identity_t *sipid);
int get_sip_auth_identity(openli_sip_parser_t *parser, int index,
        int *authcount, openli_sip_identity_t *sipid,
        uint8_t logallowed);
int get_sip_proxy_auth_identity(openli_sip_parser_t *parser, int index,
        int *authcount, openli_sip_identity_t *sipid,
        uint8_t logallowed);
int get_sip_paccess_network_info(openli_sip_parser_t *parser,
        openli_location_t *loc);
int get_sip_passerted_identity(openli_sip_parser_t *parser,
        openli_sip_identity_t *sipid);
int get_sip_remote_party(openli_sip_parser_t *parser,
        openli_sip_identity_t *sipid);
char *get_sip_cseq(openli_sip_parser_t *parser);
char *get_sip_branch_id(openli_sip_parser_t *parser);
char *get_sip_callid(openli_sip_parser_t *parser);
char *get_sip_session_id(openli_sip_parser_t *parser);
char *get_sip_session_address(openli_sip_parser_t *parser);
char *get_sip_session_username(openli_sip_parser_t *parser);
char *get_sip_session_version(openli_sip_parser_t *parser);
char *get_sip_media_ipaddr(openli_sip_parser_t *parser);
char *get_sip_media_port(openli_sip_parser_t *parser, int index);
char *get_sip_media_type(openli_sip_parser_t *parser, int index);
char *get_sip_message_body(openli_sip_parser_t *parser, size_t *length);
int sip_is_invite(openli_sip_parser_t *parser);
int sip_is_register(openli_sip_parser_t *parser);
int sip_is_200ok(openli_sip_parser_t *parser);
int sip_is_183sessprog(openli_sip_parser_t *parser);
int sip_is_180ringing(openli_sip_parser_t *parser);
int sip_is_bye(openli_sip_parser_t *parser);
int sip_is_cancel(openli_sip_parser_t *parser);

int extract_sip_identities(openli_sip_parser_t *parser,
        openli_sip_identity_set_t *idset, uint8_t log_error);
openli_sip_identity_t *match_sip_target_against_identities(
        libtrace_list_t *targets, openli_sip_identity_set_t *idset,
        uint8_t trust_from);
void release_openli_sip_identity_set(openli_sip_identity_set_t *idset);
#endif


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

