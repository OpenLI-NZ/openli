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

typedef struct openli_sip_parser {

    osip_message_t *osip;
    sdp_message_t *sdp;

} openli_sip_parser_t;

int parse_sip_packet(openli_sip_parser_t **parser, libtrace_packet_t *packet);
void release_sip_parser(openli_sip_parser_t *parser);
char *get_sip_from_uri(openli_sip_parser_t *parser);
char *get_sip_to_uri(openli_sip_parser_t *parser);
char *get_sip_cseq(openli_sip_parser_t *parser);
char *get_sip_callid(openli_sip_parser_t *parser);
char *get_sip_session_id(openli_sip_parser_t *parser);
char *get_sip_session_version(openli_sip_parser_t *parser);
char *get_sip_media_ipaddr(openli_sip_parser_t *parser);
char *get_sip_media_port(openli_sip_parser_t *parser);
int sip_is_invite(openli_sip_parser_t *parser);
int sip_is_200ok(openli_sip_parser_t *parser);
int sip_is_183sessprog(openli_sip_parser_t *parser);
int sip_is_bye(openli_sip_parser_t *parser);

#endif


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

