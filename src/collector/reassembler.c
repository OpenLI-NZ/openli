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

#define _GNU_SOURCE

#include <assert.h>
#include <string.h>

#include "reassembler.h"
#include "logger.h"
#include "util.h"

#define TCP_STREAM_MAX_GAP 65536

const char *SIP_END_SEQUENCE = "\x0d\x0a\x0d\x0a";
const char *SIP_CONTENT_LENGTH_FIELD = "Content-Length: ";
const char *SINGLE_CRLF = "\x0d\x0a";

/* Compares two sequence numbers, dealing appropriate with wrapping.
 *
 * Parameters:
 *      seq_a - the first sequence number to compare
 *      seq_b - the second sequence number to compare
 *
 * Returns:
 *      the result of subtracting seq_b from seq_a (seq_a - seq_b, in other
 *      words), taking sequence number wraparound into account
 */
static int seq_cmp (uint32_t seq_a, uint32_t seq_b) {

    if (seq_a == seq_b) return 0;

    if (seq_a > seq_b)
        return (int)(seq_a - seq_b);
    else
        return (int)(UINT32_MAX - ((seq_b - seq_a) - 1));

}

static int tcpseg_sort(tcp_reass_segment_t *a, tcp_reass_segment_t *b) {
    return seq_cmp(a->seqno, b->seqno);
}

static int ipfrag_sort(ip_reass_fragment_t *a, ip_reass_fragment_t *b) {
    return ((int)(a->fragoff) - (int)(b->fragoff));
}

tcp_reassembler_t *create_new_tcp_reassembler(reassembly_method_t method) {

    tcp_reassembler_t *reass;

    reass = (tcp_reassembler_t *)calloc(1, sizeof(tcp_reassembler_t));
    reass->method = method;
    reass->knownstreams = NULL;
    reass->nextpurge = 0;

    return reass;
}

ipfrag_reassembler_t *create_new_ipfrag_reassembler(void) {
    ipfrag_reassembler_t *reass;
    reass = (ipfrag_reassembler_t *)calloc(1, sizeof(ipfrag_reassembler_t));
    reass->knownstreams = NULL;
    reass->nextpurge = 0;

    return reass;
}

void destroy_tcp_reassembler(tcp_reassembler_t *reass) {
    tcp_reassemble_stream_t *iter, *tmp;

    HASH_ITER(hh, reass->knownstreams, iter, tmp) {
        HASH_DELETE(hh, reass->knownstreams, iter);
        destroy_tcp_reassemble_stream(iter);
    }
    free(reass);
}

void destroy_ipfrag_reassembler(ipfrag_reassembler_t *reass) {
    ip_reassemble_stream_t *iter, *tmp;

    HASH_ITER(hh, reass->knownstreams, iter, tmp) {
        HASH_DELETE(hh, reass->knownstreams, iter);
        destroy_ip_reassemble_stream(iter);
    }
    free(reass);
}

void remove_tcp_reassemble_stream(tcp_reassembler_t *reass,
        tcp_reassemble_stream_t *stream) {

    tcp_reassemble_stream_t *existing;

    HASH_FIND(hh, reass->knownstreams, stream->streamid,
            sizeof(tcp_streamid_t), existing);

    if (existing) {
        HASH_DELETE(hh, reass->knownstreams, existing);
        destroy_tcp_reassemble_stream(existing);
    } else {
        destroy_tcp_reassemble_stream(stream);
    }

}

void remove_ipfrag_reassemble_stream(ipfrag_reassembler_t *reass,
        ip_reassemble_stream_t *stream) {
    ip_reassemble_stream_t *existing;

    HASH_FIND(hh, reass->knownstreams, &(stream->streamid),
            sizeof(stream->streamid), existing);
    if (existing) {
        HASH_DELETE(hh, reass->knownstreams, existing);
        destroy_ip_reassemble_stream(existing);
    } else {
        destroy_ip_reassemble_stream(stream);
    }
}


static void purge_inactive_tcp_streams(tcp_reassembler_t *reass, uint32_t ts) {

    tcp_reassemble_stream_t *iter, *tmp;
    /* Not overly fine-grained, but we only really need this to
     * periodically prune obviously dead or idle streams so we don't
     * slowly use up memory over time.
     */

    if (reass->nextpurge == 0) {
        reass->nextpurge = ts + 300;
        return;
    }

    if (ts < reass->nextpurge) {
        return;
    }

    HASH_ITER(hh, reass->knownstreams, iter, tmp) {
        if (iter->established != TCP_STATE_ESTAB) {
            if (iter->lastts < reass->nextpurge - 300) {
                HASH_DELETE(hh, reass->knownstreams, iter);
                destroy_tcp_reassemble_stream(iter);
            }
        } else if (iter->lastts < reass->nextpurge - 1800) {
            HASH_DELETE(hh, reass->knownstreams, iter);
            destroy_tcp_reassemble_stream(iter);
        }
    }

    reass->nextpurge = ts + 300;
}

static void purge_inactive_ip_streams(ipfrag_reassembler_t *reass,
        uint32_t ts) {

    ip_reassemble_stream_t *iter, *tmp;
    /* Not overly fine-grained, but we only really need this to
     * periodically prune obviously dead or idle streams so we don't
     * slowly use up memory over time.
     */

    if (reass->nextpurge == 0) {
        reass->nextpurge = ts + 300;
        return;
    }

    if (ts < reass->nextpurge) {
        return;
    }

    HASH_ITER(hh, reass->knownstreams, iter, tmp) {
        if (iter->lastts < reass->nextpurge - 300) {
            HASH_DELETE(hh, reass->knownstreams, iter);
            destroy_ip_reassemble_stream(iter);
        }
    }

    reass->nextpurge = ts + 300;
}

tcp_reassemble_stream_t *get_tcp_reassemble_stream(tcp_reassembler_t *reass,
        tcp_streamid_t *id, libtrace_tcp_t *tcp, struct timeval *tv,
        uint32_t tcprem) {

    tcp_reassemble_stream_t *existing;

    HASH_FIND(hh, reass->knownstreams, id, sizeof(tcp_streamid_t), existing);
    if (existing) {
        if (tcp->syn) {
            HASH_DELETE(hh, reass->knownstreams, existing);
            destroy_tcp_reassemble_stream(existing);
            existing = create_new_tcp_reassemble_stream(id, ntohl(tcp->seq));
            HASH_ADD_KEYPTR(hh, reass->knownstreams, existing->streamid,
                    sizeof(tcp_streamid_t), existing);
        } else if (tcprem > 0 && !tcp->syn &&
                existing->established == TCP_STATE_OPENING) {
            existing->established = TCP_STATE_ESTAB;
        } else if (existing->established == TCP_STATE_ESTAB &&
                (tcp->fin || tcp->rst)) {
            existing->established = TCP_STATE_CLOSING;
        }

        existing->lastts = tv->tv_sec;
        purge_inactive_tcp_streams(reass, tv->tv_sec);
        return existing;
    }

    if (tcp->rst) {
        return NULL;
    }

    if (tcp->syn) {
        existing = create_new_tcp_reassemble_stream(id, ntohl(tcp->seq));
    } else {
        existing = create_new_tcp_reassemble_stream(id, ntohl(tcp->seq) - 1);
        if (tcp->fin) {
            existing->established = TCP_STATE_CLOSING;
        } else {
            existing->established = TCP_STATE_ESTAB;
        }
    }

    purge_inactive_tcp_streams(reass, tv->tv_sec);
    HASH_ADD_KEYPTR(hh, reass->knownstreams, existing->streamid,
            sizeof(tcp_streamid_t), existing);
    existing->lastts = tv->tv_sec;
    return existing;
}

ip_reassemble_stream_t *create_new_ipfrag_reassemble_stream(
        ip_streamid_t *ipid, uint8_t proto) {

    ip_reassemble_stream_t *stream;

    stream = (ip_reassemble_stream_t *)calloc(1,
            sizeof(ip_reassemble_stream_t));
    stream->streamid = *ipid;
    stream->lastts = 0;
    stream->nextfrag = 0;
    stream->sorted = 0;
    stream->endfrag = 0;
    stream->fragments = NULL;
    stream->subproto = proto;

    return stream;
}

void destroy_ip_reassemble_stream(ip_reassemble_stream_t *stream) {
    ip_reass_fragment_t *seg, *tmp;

    HASH_ITER(hh, stream->fragments, seg, tmp) {
        HASH_DELETE(hh, stream->fragments, seg);
        free(seg->content);
        free(seg);
    }
    free(stream);
}

ip_reassemble_stream_t *get_ipfrag_reassemble_stream(
        ipfrag_reassembler_t *reass, libtrace_packet_t *pkt) {

    ip_streamid_t ipid;
    libtrace_ip_t *iphdr;
    ip_reassemble_stream_t *existing;
    struct timeval tv;

    memset(&ipid, 0, sizeof(ipid));
    if (extract_ip_addresses(pkt, ipid.srcip, ipid.destip, &(ipid.ipfamily))
            != 0) {
        logger(LOG_INFO,
                "OpenLI: error while extracting IP addresses from fragment.");
        return NULL;
    }

    iphdr = trace_get_ip(pkt);
    if (!iphdr) {
        logger(LOG_INFO,
                "OpenLI: trace_get_ip() failed for IP fragment?");
        return NULL;
    }

    ipid.ipid = ntohs(iphdr->ip_id);

    tv = trace_get_timeval(pkt);
    HASH_FIND(hh, reass->knownstreams, &ipid, sizeof(ipid), existing);
    if (existing) {
        existing->lastts = tv.tv_sec;
        purge_inactive_ip_streams(reass, tv.tv_sec);
        return existing;
    }

    existing = create_new_ipfrag_reassemble_stream(&ipid, iphdr->ip_p);

    purge_inactive_ip_streams(reass, tv.tv_sec);
    HASH_ADD_KEYPTR(hh, reass->knownstreams, &(existing->streamid),
            sizeof(existing->streamid), existing);
    existing->lastts = tv.tv_sec;
    return existing;
}

tcp_reassemble_stream_t *create_new_tcp_reassemble_stream(
        tcp_streamid_t *streamid, uint32_t synseq) {

    tcp_reassemble_stream_t *stream;

    stream = (tcp_reassemble_stream_t *)calloc(1, sizeof(tcp_reassemble_stream_t));
    stream->segments = NULL;
    stream->expectedseqno = synseq + 1;
    stream->sorted = 1;
    stream->streamid = calloc(1, sizeof(tcp_streamid_t));
    memcpy(stream->streamid, streamid, sizeof(tcp_streamid_t));
    stream->lastts = 0;
    stream->established = TCP_STATE_OPENING;
    stream->packets = calloc(4, sizeof(libtrace_packet_t *));
    stream->pkt_alloc = 4;
    stream->pkt_cnt = 0;

    return stream;
}

static void reset_tcp_reassemble_stream(tcp_reassemble_stream_t *stream,
        uint32_t newseqno) {

    /* Remove any existing saved segments, packets, etc. for a
     * stream and blank slate it to the current sequence number.
     */
    tcp_reass_segment_t *iter, *tmp;
    int i;

    HASH_ITER(hh, stream->segments, iter, tmp) {
        HASH_DELETE(hh, stream->segments, iter);
        free(iter->content);
        free(iter);
    }

    if (stream->packets) {
        for (i = 0; i < stream->pkt_cnt; i++) {
            if (stream->packets[i]) {
                trace_destroy_packet(stream->packets[i]);
            }
        }
    }
    stream->pkt_cnt = 0;
    stream->expectedseqno = newseqno;
    stream->lastts = 0;
}

void destroy_tcp_reassemble_stream(tcp_reassemble_stream_t *stream) {
    tcp_reass_segment_t *iter, *tmp;
    int i;

    HASH_ITER(hh, stream->segments, iter, tmp) {
        HASH_DELETE(hh, stream->segments, iter);
        free(iter->content);
        free(iter);
    }

    if (stream->packets) {
        for (i = 0; i < stream->pkt_cnt; i++) {
            if (stream->packets[i]) {
                trace_destroy_packet(stream->packets[i]);
            }
        }
        free(stream->packets);
    }
    free(stream->streamid);
    free(stream);
}

/**
 * Given received SIP content in a buffer, attempt to find the end of the
 * the first SIP message in the buffer.
 *
 * Due to TCP segmentation, aggregation or general IP fragmentation, we
 * cannot guarantee that each packet we receive corresponds to one entire
 * SIP message. There may be multiple messages in the packet, or a message
 * may be spread across multiple packets.
 *
 * This function will determine if there is a complete SIP message in the
 * given buffer and return a pointer to the first byte of the FOLLOWING
 * message.
 *
 * @param content   The buffer containing received SIP payload
 * @param contlen   The amount of SIP payload in the buffer
 *
 * @return NULL if there is no complete SIP message in the buffer, otherwise
 * a pointer to the byte AFTER the end of the first complete SIP message.
 */
static uint8_t *find_sip_message_end(uint8_t *content, uint16_t contlen) {

    uint8_t *crlf;
    uint8_t *clengthfield, *clengthend, *clengthstart;
    char clenstr[12];
    unsigned long int clenval;
    uint8_t *ptr = content;
    uint16_t contleft = contlen;

    /* Any \r\n or \x00 bytes at the front of the content are probably
     * the result of SIP keep alives.
     */
    while (ptr - content < contlen) {
        /* keep alives have varying lengths depending on the implementor,
         * so let's just aggregate them into a single "message" for
         * protocol parsing purposes.
         */
        contleft = contlen - (ptr - content);
        if (contleft >= 2 && memcmp(ptr, "\x0d\x0a", 2) == 0) {
            ptr += 2;
            continue;
        }

        if (*ptr == 0x00) {
            ptr ++;
            continue;
        }

        break;
    }

    if (ptr != content) {
        return ptr;
    }

    /* Some SIP messages, e.g. INVITE, will also have SDP content after the
     * SIP header. The Content-Length field in the SIP header will tell us
     * how much SDP content there is going to be.
     */
    clengthfield = memmem(ptr, contleft, SIP_CONTENT_LENGTH_FIELD,
            strlen(SIP_CONTENT_LENGTH_FIELD));
    if (clengthfield == NULL) {
        return NULL;
    }

    /* The value of Content-Length is an integer encoded as ASCII text,
     * sandwiched between "Content-Length: " and "\r\n"
     */
    clengthstart = clengthfield + strlen(SIP_CONTENT_LENGTH_FIELD);

    clengthend = memmem(clengthstart, contleft - (clengthstart - ptr),
            SINGLE_CRLF, strlen(SINGLE_CRLF));

    if (clengthend == NULL) {
        return NULL;
    }

    /* Copy the value into a nulled blob of memory, so that it will be
     * null-terminated and can be parsed using strtoul to get the number
     * as an integer.
     */
    assert(clengthend - clengthstart < 12);
    memset(clenstr, 0, 12);
    memcpy(clenstr, (char *)clengthstart, clengthend - clengthstart);
    clenval = strtoul(clenstr, NULL, 10);

    /* Our message is only complete if we have both the SIP header and any
     * SDP payload in the buffer.
     */

    /* Look for a double \r\n to indicate the end of the SIP header */
    crlf = memmem(clengthend, contleft - (clengthend - ptr), SIP_END_SEQUENCE,
            strlen(SIP_END_SEQUENCE));
    if (crlf == NULL) {
        return NULL;
    }
    crlf += strlen(SIP_END_SEQUENCE);

    if (crlf + clenval > ptr + contleft) {
        /* Some message payload is in an upcoming segment, so return NULL to
         * let the caller know that the message is incomplete.
         */
        return NULL;
    }
    return crlf + clenval;
}

int update_ipfrag_reassemble_stream(ip_reassemble_stream_t *stream,
        libtrace_packet_t *pkt, uint16_t fragoff, uint8_t moreflag) {

    libtrace_ip_t *ipheader;
    uint16_t ethertype, iprem;
    uint32_t rem;
    void *transport;
    ip_reass_fragment_t *newfrag;

    /* assumes we already know pkt is IPv4 */
    ipheader = (libtrace_ip_t *)trace_get_layer3(pkt, &ethertype, &rem);

    if (rem < sizeof(libtrace_ip_t) || ipheader == NULL) {
        return -1;
    }

    if (ethertype == TRACE_ETHERTYPE_IPV6) {
        return 1;
    }

    if (moreflag == 0 && fragoff == 0) {
        /* No fragmentation, just use packet as is */
        return 1;
    }

    /* This is a fragment, add it to our fragment list */
    if (rem <= 4 * ipheader->ip_hl) {
        return -1;
    }

    transport = ((char *)ipheader) + (4 * ipheader->ip_hl);

    if (ipheader->ip_len == 0) {
        /* XXX can we tell if there is a FCS present and remove that? */
        iprem = rem - (4 * ipheader->ip_hl);
    } else {
        iprem = ntohs(ipheader->ip_len) - 4 * (ipheader->ip_hl);
    }

    HASH_FIND(hh, stream->fragments, &(fragoff), sizeof(fragoff), newfrag);
    if (!newfrag) {
        newfrag = (ip_reass_fragment_t *)calloc(1, sizeof(ip_reass_fragment_t));
        newfrag->fragoff = fragoff;
        newfrag->length = iprem;
        newfrag->content = (uint8_t *)malloc(iprem);
        memcpy(newfrag->content, transport, iprem);

        HASH_ADD_KEYPTR(hh, stream->fragments, &(newfrag->fragoff),
                sizeof(newfrag->fragoff), newfrag);
    }

    if (!moreflag) {
        stream->endfrag = newfrag->fragoff + newfrag->length;
    }
    stream->sorted = 0;
    return 0;
}


int update_tcp_reassemble_stream(tcp_reassemble_stream_t *stream,
        uint8_t *content, uint16_t plen, uint32_t seqno,
        libtrace_packet_t *pkt, uint8_t allow_fastpath) {


    tcp_reass_segment_t *seg, *existing;
    uint8_t *endptr;
    int i;

    HASH_FIND(hh, stream->segments, &seqno, sizeof(seqno), existing);
    if (existing) {
        /* retransmit? check for size difference... */
        if (plen == existing->length) {
            if (pkt) {
                /* this is an entire packet, so we can ignore it */
                return -1;
            } else {
                /* this could be just part of a packet, so we need to tell
                 * the caller that the packet should not be freed
                 */
                return 0;
            }
        }

        /* segment is longer? try to add the "extra" bit as a new segment */
        if (plen > existing->length) {
            plen -= existing->length;
            seqno += existing->length;
            content = content + existing->length;
        } else {
            /* segment is shorter? remove the larger segment because presumably
             * everything is going to be retransmitted anyway? */
            HASH_DELETE(hh, stream->segments, existing);
            free(existing->content);
            free(existing);
        }
        if (pkt && stream->pkt_cnt > 0) {
            if (stream->packets[stream->pkt_cnt - 1] != NULL) {
                trace_destroy_packet(stream->packets[stream->pkt_cnt - 1]);
            }
            stream->packets[stream->pkt_cnt - 1] = pkt;
        }
        /* Go around again -- if we are shorter, then this will add
         * the shorter segment in place of the one we just removed.
         * If we are longer, this should add a new segment containing
         * just the additional payload.
         */
        return update_tcp_reassemble_stream(stream, content, plen, seqno,
                NULL, 0);
    } else {

        if (seq_cmp(seqno, stream->expectedseqno) < 0) {
            if (seq_cmp(seqno + plen, stream->expectedseqno) > 0) {
                /* retransmit with extra payload, but we've already
                 * processed the original segment */
                plen -= (stream->expectedseqno - seqno);
                content = content + (stream->expectedseqno - seqno);
                seqno = stream->expectedseqno;
                return update_tcp_reassemble_stream(stream, content, plen,
                        seqno, pkt, 0);
            }

            return -1;
        }

        /* If the gap between this segment and the expected one is very
         * large, let's assume that the processing thread dropped the
         * packet and therefore this stream is never going to be able
         * to be reassembled.
         */
        if (seq_cmp(seqno, stream->expectedseqno + TCP_STREAM_MAX_GAP) >= 0) {
            reset_tcp_reassemble_stream(stream, seqno);
        }


        /* fast path, check if the segment is a complete message AND
         * has our expected sequence number -- if yes, we can tell the caller
         * to just use the packet payload directly without memcpying
         *
         * ... but only if the segment doesn't look like a keep alive
         * i.e. begins with \r\n or \x00
         */
        if (allow_fastpath && seq_cmp(seqno, stream->expectedseqno) == 0 &&
                *content != 0x0d && *content != 0x00) {
            endptr = find_sip_message_end(content, plen);
            if (endptr == content + plen) {
                stream->expectedseqno += plen;
                return 1;
            }
        }
    }

    seg = (tcp_reass_segment_t *)calloc(1, sizeof(tcp_reass_segment_t));

    seg->seqno = seqno;
    seg->offset = 0;
    seg->length = plen;
    seg->content = (uint8_t *)malloc(plen);
    memcpy(seg->content, content, plen);

    if (pkt) {
        if (stream->pkt_cnt == stream->pkt_alloc) {
            stream->packets = realloc(stream->packets,
                    (stream->pkt_alloc + 4) * sizeof(libtrace_packet_t *));
            for (i = stream->pkt_alloc; i < stream->pkt_alloc + 4; i++) {
                stream->packets[i] = NULL;
            }
            stream->pkt_alloc += 4;
        }
        stream->packets[stream->pkt_cnt] = pkt;
        stream->pkt_cnt ++;
    }

    HASH_ADD_KEYPTR_INORDER(hh, stream->segments, &(seg->seqno),
		    sizeof(seg->seqno), seg, tcpseg_sort);
    //stream->sorted = 0;
    return 0;
}

int get_ipfrag_ports(ip_reassemble_stream_t *stream, uint16_t *src,
        uint16_t *dest) {

    ip_reass_fragment_t *first;

    if (stream == NULL) {
        return -1;
    }

    if (!stream->sorted) {
        HASH_SORT(stream->fragments, ipfrag_sort);
        stream->sorted = 1;
    }

    *src = 0;
    *dest = 0;

    first = stream->fragments;
    if (first->fragoff > 0) {
        return 0;
    }

    if (first->length < 4) {
        logger(LOG_INFO,
                "OpenLI: initial IP fragment is less than four bytes?");
        return 0;
    }

    *src = ntohs(*((uint16_t *)first->content));
    *dest = ntohs(*((uint16_t *)(first->content + 2)));
    return 1;

}

int is_ip_reassembled(ip_reassemble_stream_t *stream) {
    ip_reass_fragment_t *iter, *tmp;
    uint16_t expfrag = 0;

    if (stream == NULL) {
        return 0;
    }

    if (!stream->sorted) {
        HASH_SORT(stream->fragments, ipfrag_sort);
        stream->sorted = 1;
    }

    HASH_ITER(hh, stream->fragments, iter, tmp) {
        assert(iter->fragoff >= expfrag);
        if (iter->fragoff != expfrag) {
            return 0;
        }

        expfrag += iter->length;
    }

    if (expfrag != stream->endfrag || stream->endfrag == 0) {
        /* Still not seen the last fragment */
        return 0;
    }
    return 1;
}

int get_next_ip_reassembled(ip_reassemble_stream_t *stream, char **content,
        uint16_t *len, uint8_t *proto) {

    ip_reass_fragment_t *iter, *tmp;
    uint16_t expfrag = 0;
    uint16_t contalloced = 0;

    if (stream == NULL) {
        return 0;
    }

    if (!stream->sorted) {
        HASH_SORT(stream->fragments, ipfrag_sort);
        stream->sorted = 1;
    }

    *proto = 0;
    *len = 0;
    HASH_ITER(hh, stream->fragments, iter, tmp) {
        assert(iter->fragoff >= expfrag);
        if (iter->fragoff != expfrag) {
            *len = 0;
            return 0;
        }

        if (*content == NULL || contalloced < expfrag + iter->length) {
            *content = realloc(*content, expfrag + (iter->length * 2));
            contalloced = expfrag + (iter->length * 2);

            if (*content == NULL) {
                logger(LOG_INFO, "OpenLI: OOM while allocating %u bytes to store reassembled IP fragments.", contalloced);
                return -1;
            }
        }

        memcpy((*content) + expfrag, iter->content, iter->length);
        *len += iter->length;
        expfrag += iter->length;
    }

    if (expfrag != stream->endfrag || stream->endfrag == 0) {
        /* Still not seen the last fragment */
        *len = 0;
        return 0;
    }

    *proto = stream->subproto;
    return 1;
}

int get_next_tcp_reassembled(tcp_reassemble_stream_t *stream, char **content,
        uint16_t *len, libtrace_packet_t ***packets, int *pkt_cnt) {

    tcp_reass_segment_t *iter, *tmp;
    uint16_t contused = 0;
    uint32_t used = 0;
    uint32_t expseqno;
    uint8_t *endfound = NULL;
    uint8_t *contstart = NULL;

    if (stream == NULL || stream->established == TCP_STATE_LOSS) {
        return 0;
    }

    expseqno = stream->expectedseqno;
    if (!stream->sorted) {
        HASH_SORT(stream->segments, tcpseg_sort);
        stream->sorted = 1;
    }

    HASH_ITER(hh, stream->segments, iter, tmp) {
        if (seq_cmp(iter->seqno, expseqno) < 0) {
            HASH_DELETE(hh, stream->segments, iter);
            free(iter->content);
            free(iter);
            continue;
        }

        if (seq_cmp(iter->seqno, expseqno) > 0) {
            break;
        }

        if (*content == NULL || *len < contused + iter->length) {
            *content = realloc(*content, contused + (iter->length * 2));
            *len = contused + (iter->length * 2);

            if (*content == NULL) {
                logger(LOG_INFO, "OpenLI: OOM while allocating %u bytes to store reassembled TCP stream.", *len);
                return -1;
            }
        }

        contstart = (uint8_t *)((*content) + contused);

        memcpy(contstart, iter->content + iter->offset,
                iter->length);

        endfound = find_sip_message_end((uint8_t *)(*content),
                (contused + iter->length));

        if (endfound) {
            assert(endfound <= contstart + iter->length);
            assert(endfound > contstart);

            used = endfound - contstart;
            stream->expectedseqno += (used + contused);

            /* give all of the packets thus far back to the caller, so
             * they can decide if they need to "intercept" them -- the
             * raw packets are only required for pcapdisk intercepts, but
             * we may not be able to know if the packets are part of a
             * pcapdisk intercept until after we have reassembled the
             * initial INVITE.
             */
            if (packets) {
                *packets = NULL;
                *pkt_cnt = 0;
            }

            if (packets && stream->pkt_cnt > 0) {
                *packets = stream->packets;
                *pkt_cnt = stream->pkt_cnt;
                stream->packets = calloc(4, sizeof(libtrace_packet_t *));
                stream->pkt_cnt = 0;
                stream->pkt_alloc = 4;
            }

            if (contstart + iter->length == endfound) {
                /* We've used the entire segment */
                *len = contused + iter->length;
                HASH_DELETE(hh, stream->segments, iter);
                free(iter->content);
                free(iter);
                return 1;
            }

            /* Some of the segment is not part of this message, so we need
             * to update the offset */
            iter->seqno += used;
            iter->offset += used;
            assert(used < iter->length);
            iter->length -= used;

            *len = contused + used;
            return 1;
        }

        /* Used up all of iter with no end in sight */
        HASH_DELETE(hh, stream->segments, iter);
        contused += iter->length;
        expseqno += iter->length;

        free(iter->content);
        free(iter);

    }

    /* If we get here, we've either run out of segments or we've found a
     * gap in the segments we have. We need to put our in-progress segment
     * back into the map since we've been removing its components as we
     * went.
     */
    if (contused > 0 || expseqno > stream->expectedseqno) {
        update_tcp_reassemble_stream(stream, (uint8_t *)(*content),
                contused, stream->expectedseqno, NULL, 0);
    }
    *len = 0;
    return 0;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
