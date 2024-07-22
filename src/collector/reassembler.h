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
    uint8_t srcip[16];
    uint8_t destip[16];
    uint16_t srcport;
    uint16_t destport;
    int ipfamily;
} tcp_streamid_t;

typedef struct reass_stream {
    tcp_streamid_t *streamid;
    uint32_t lastts;
    uint32_t expectedseqno;
    tcp_reass_segment_t *segments;
    libtrace_packet_t **packets;
    int pkt_cnt;
    int pkt_alloc;
    uint8_t sorted;
    uint8_t established;
    UT_hash_handle hh;
} tcp_reassemble_stream_t;

typedef struct tcp_reassembler {
    tcp_reassemble_stream_t *knownstreams;
    reassembly_method_t method;
    uint32_t nextpurge;
} tcp_reassembler_t;


typedef struct ip_reass_fragment {
    uint16_t fragoff;
    uint16_t length;
    uint8_t *content;
    UT_hash_handle hh;
} ip_reass_fragment_t;

typedef struct ip_streamid {
    uint8_t srcip[16];
    uint8_t destip[16];
    uint16_t ipid;
    int ipfamily;
} ip_streamid_t;

typedef struct ip_reass_stream {
    ip_streamid_t streamid;
    uint32_t lastts;
    uint16_t nextfrag;
    uint8_t sorted;
    uint16_t endfrag;
    uint8_t subproto;
    ip_reass_fragment_t *fragments;
    UT_hash_handle hh;
} ip_reassemble_stream_t;

typedef struct ipfrag_reassembler {
    ip_reassemble_stream_t *knownstreams;
    uint32_t nextpurge;
} ipfrag_reassembler_t;

tcp_reassembler_t *create_new_tcp_reassembler(reassembly_method_t method);
void destroy_tcp_reassembler(tcp_reassembler_t *reass);
tcp_reassemble_stream_t *get_tcp_reassemble_stream(tcp_reassembler_t *reass,
        tcp_streamid_t *id, libtrace_tcp_t *tcp, struct timeval *tv,
        uint32_t tcprem);

void remove_tcp_reassemble_stream(tcp_reassembler_t *reass,
        tcp_reassemble_stream_t *stream);


tcp_reassemble_stream_t *create_new_tcp_reassemble_stream(
        tcp_streamid_t *streamid, uint32_t synseq);
void destroy_tcp_reassemble_stream(tcp_reassemble_stream_t *reass);
int update_tcp_reassemble_stream(tcp_reassemble_stream_t *reass,
        uint8_t *content, uint16_t plen, uint32_t seqno,
        libtrace_packet_t *pkt);
int get_next_tcp_reassembled(tcp_reassemble_stream_t *reass, char **content,
        uint16_t *len, libtrace_packet_t ***packets, int *pkt_cnt);


ipfrag_reassembler_t *create_new_ipfrag_reassembler(void);
void destroy_ipfrag_reassembler(ipfrag_reassembler_t *reass);
ip_reassemble_stream_t *get_ipfrag_reassemble_stream(
        ipfrag_reassembler_t *reass, libtrace_packet_t *pkt);
void remove_ipfrag_reassemble_stream(ipfrag_reassembler_t *reass,
        ip_reassemble_stream_t *stream);

ip_reassemble_stream_t *create_new_ipfrag_reassemble_stream(
        ip_streamid_t *ipid, uint8_t proto);
void destroy_ip_reassemble_stream(ip_reassemble_stream_t *stream);
int get_next_ip_reassembled(ip_reassemble_stream_t *stream, char **content,
        uint16_t *len, uint8_t *proto);
int update_ipfrag_reassemble_stream(ip_reassemble_stream_t *stream,
        libtrace_packet_t *pkt, uint16_t fragoff, uint8_t moreflag);
int is_ip_reassembled(ip_reassemble_stream_t *stream);
int get_ipfrag_ports(ip_reassemble_stream_t *stream, uint16_t *src,
        uint16_t *dest);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

