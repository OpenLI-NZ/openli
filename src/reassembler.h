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

#ifndef OPENLI_REASSEMBLER_H_
#define OPENLI_REASSEMBLER_H_

#include <uthash.h>
#include <libtrace.h>

typedef enum {
    OPENLI_REASSEMBLE_SIP,
} reassembly_method_t;

enum {
    TCP_STATE_OPENING,
    TCP_STATE_ESTAB,
    TCP_STATE_CLOSING
};

typedef struct reass_segment {
    uint32_t seqno;
    uint16_t offset;
    uint16_t length;
    uint8_t *content;
    UT_hash_handle hh;
} tcp_reass_segment_t;

typedef struct tcp_stream_id {
    struct sockaddr_storage srcip;
    struct sockaddr_storage destip;
} tcp_streamid_t;

typedef struct reass_stream {
    tcp_streamid_t streamid;
    uint32_t lastts;
    uint32_t expectedseqno;
    tcp_reass_segment_t *segments;
    uint8_t sorted;
    uint8_t established;
    UT_hash_handle hh;
} tcp_reassemble_stream_t;

typedef struct tcp_reassember {
    tcp_reassemble_stream_t *knownstreams;
    reassembly_method_t method;
    uint32_t nextpurge;
} tcp_reassembler_t;

tcp_reassembler_t *create_new_tcp_reassembler(reassembly_method_t method);
void destroy_tcp_reassembler(tcp_reassembler_t *reass);
tcp_reassemble_stream_t *get_tcp_reassemble_stream(tcp_reassembler_t *reass,
        libtrace_packet_t *pkt);
void remove_tcp_reassemble_stream(tcp_reassembler_t *reass,
        tcp_reassemble_stream_t *stream);


tcp_reassemble_stream_t *create_new_tcp_reassemble_stream(
        reassembly_method_t method, tcp_streamid_t *streamid, uint32_t synseq);
void destroy_tcp_reassemble_stream(tcp_reassemble_stream_t *reass);
int update_tcp_reassemble_stream(tcp_reassemble_stream_t *reass,
        uint8_t *content, uint16_t plen, uint32_t seqno);
int get_next_tcp_reassembled(tcp_reassemble_stream_t *reass, char **content,
        uint16_t *len);


#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

