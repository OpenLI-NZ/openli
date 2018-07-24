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

#define _GNU_SOURCE

#include <assert.h>
#include <string.h>

#include "reassembler.h"
#include "logger.h"

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

tcp_reassembler_t *create_new_tcp_reassembler(reassembly_method_t method) {

    tcp_reassembler_t *reass;

    reass = (tcp_reassembler_t *)calloc(1, sizeof(tcp_reassembler_t));
    reass->method = method;
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

void remove_tcp_reassemble_stream(tcp_reassembler_t *reass,
        tcp_reassemble_stream_t *stream) {

    tcp_reassemble_stream_t *existing;

    HASH_FIND(hh, reass->knownstreams, &(stream->streamid),
            sizeof(stream->streamid), existing);

    if (existing) {
        HASH_DELETE(hh, reass->knownstreams, existing);
        destroy_tcp_reassemble_stream(existing);
    } else {
        destroy_tcp_reassemble_stream(stream);
    }

}

static void purge_inactive_streams(tcp_reassembler_t *reass, uint32_t ts) {

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

tcp_reassemble_stream_t *get_tcp_reassemble_stream(tcp_reassembler_t *reass,
        libtrace_packet_t *pkt) {

    tcp_streamid_t id;
    void *transport;
    libtrace_tcp_t *tcp;
    uint32_t rem;
    uint8_t proto;
    tcp_reassemble_stream_t *existing;
    struct timeval tv;

    memset(&id, 0, sizeof(id));
    if (trace_get_source_address(pkt, (struct sockaddr *)(&id.srcip)) == NULL) {
        return NULL;
    }

    if (trace_get_destination_address(pkt,
            (struct sockaddr *)(&id.destip)) == NULL) {
        return NULL;
    }

    transport = trace_get_transport(pkt, &proto, &rem);
    if (rem < sizeof(libtrace_tcp_t) || transport == NULL ||
            proto != TRACE_IPPROTO_TCP) {
        return NULL;
    }

    tcp = (libtrace_tcp_t *)transport;
    tv = trace_get_timeval(pkt);

    HASH_FIND(hh, reass->knownstreams, &id, sizeof(id), existing);
    if (existing) {
        if (trace_get_payload_length(pkt) > 0 && !tcp->syn &&
                existing->established == TCP_STATE_OPENING) {
            existing->established = TCP_STATE_ESTAB;
        }

        if (existing->established == TCP_STATE_ESTAB &&
                (tcp->fin || tcp->rst)) {
            existing->established = TCP_STATE_CLOSING;
        }

        existing->lastts = tv.tv_sec;
        purge_inactive_streams(reass, tv.tv_sec);
        return existing;
    }

    if (tcp->rst) {
        return NULL;
    }

    if (tcp->syn) {
        existing = create_new_tcp_reassemble_stream(reass->method, &id,
                ntohl(tcp->seq));
    } else {
        existing = create_new_tcp_reassemble_stream(reass->method, &id,
                ntohl(tcp->seq) - 1);
        if (tcp->fin) {
            existing->established = TCP_STATE_CLOSING;
        } else {
            existing->established = TCP_STATE_ESTAB;
        }
    }

    purge_inactive_streams(reass, tv.tv_sec);
    HASH_ADD_KEYPTR(hh, reass->knownstreams, &(existing->streamid),
            sizeof(existing->streamid), existing);
    existing->lastts = tv.tv_sec;
    return existing;
}


tcp_reassemble_stream_t *create_new_tcp_reassemble_stream(
        reassembly_method_t method, tcp_streamid_t *streamid, uint32_t synseq) {

    tcp_reassemble_stream_t *stream;

    stream = (tcp_reassemble_stream_t *)calloc(1, sizeof(tcp_reassemble_stream_t));
    stream->segments = NULL;
    stream->expectedseqno = synseq + 1;
    stream->sorted = 0;
    stream->streamid = *streamid;
    stream->lastts = 0;
    stream->established = TCP_STATE_OPENING;

    return stream;
}

void destroy_tcp_reassemble_stream(tcp_reassemble_stream_t *stream) {
    tcp_reass_segment_t *iter, *tmp;

    HASH_ITER(hh, stream->segments, iter, tmp) {
        HASH_DELETE(hh, stream->segments, iter);
        free(iter->content);
        free(iter);
    }

    free(stream);
}

static uint8_t *find_sip_message_end(uint8_t *content, uint16_t contlen) {

    uint8_t *crlf;
    uint8_t *clengthfield, *clengthend, *clengthstart;
    uint8_t *endptr;
    char clenstr[12];
    unsigned long int clenval;

    crlf = memmem(content, contlen, SIP_END_SEQUENCE, strlen(SIP_END_SEQUENCE));
    if (crlf == NULL) {
        return NULL;
    }
    crlf += strlen(SIP_END_SEQUENCE);

    clengthfield = memmem(content, contlen, SIP_CONTENT_LENGTH_FIELD,
            strlen(SIP_CONTENT_LENGTH_FIELD));
    if (clengthfield == NULL) {
        return NULL;
    }

    clengthstart = clengthfield + strlen(SIP_CONTENT_LENGTH_FIELD);

    clengthend = memmem(clengthstart, contlen - (clengthstart - content),
            SINGLE_CRLF, strlen(SINGLE_CRLF));

    assert(clengthend - clengthstart < 12);
    memset(clenstr, 0, 12);
    memcpy(clenstr, (char *)clengthstart, clengthend - clengthstart);
    clenval = strtoul(clenstr, NULL, 10);

    assert(crlf + clenval <= content + contlen);

    return crlf + clenval;
}

int update_tcp_reassemble_stream(tcp_reassemble_stream_t *stream,
        uint8_t *content, uint16_t plen, uint32_t seqno) {


    tcp_reass_segment_t *seg, *existing;
    uint8_t *endptr;

    HASH_FIND(hh, stream->segments, &seqno, sizeof(seqno), existing);
    if (existing) {
        /* retransmit? check for size difference... */
        if (plen == seg->length) {
            return -1;
        }

        /* segment is longer? try to add the "extra" bit as a new segment */
        if (plen > seg->length) {
            plen -= seg->length;
            seqno += seg->length;
            content = content + seg->length;
            return update_tcp_reassemble_stream(stream, content, plen, seqno);
        }

        /* segment is shorter? probably don't care... */
        return 0;
    }

    if (seq_cmp(seqno, stream->expectedseqno) < 0) {
        return -1;
    }

    endptr = find_sip_message_end(content, plen);
    /* fast path, check if the segment is a complete message AND
     * has our expected sequence number -- if yes, we can tell the caller
     * to just use the packet payload directly without memcpying
     */

    if (seq_cmp(seqno, stream->expectedseqno) == 0) {
        if (endptr == content + plen) {
            stream->expectedseqno += plen;
            return 1;
        }
    }

    seg = (tcp_reass_segment_t *)calloc(1, sizeof(tcp_reass_segment_t));

    seg->seqno = seqno;
    seg->offset = 0;
    seg->length = plen;
    seg->content = (uint8_t *)malloc(plen);
    memcpy(seg->content, content, plen);

    HASH_ADD_KEYPTR(hh, stream->segments, &(seg->seqno), sizeof(seg->seqno),
            seg);
    stream->sorted = 0;
    return 0;
}

int get_next_tcp_reassembled(tcp_reassemble_stream_t *stream, char **content,
        uint16_t *len) {

    tcp_reass_segment_t *iter, *tmp;
    uint16_t contused = 0;
    uint16_t checked = 0;
    uint32_t used = 0;
    uint32_t expseqno;
    char *endfound = NULL;

    if (stream == NULL) {
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
                logger(LOG_DAEMON, "OpenLI: OOM while allocating %u bytes to store reassembled TCP stream.", *len);
                return -1;
            }
        }

        memcpy((*content) + contused, iter->content + iter->offset,
                iter->length);

        endfound = find_sip_message_end((*content) + checked,
                (contused - checked) + iter->length);

        if (endfound) {
            assert(endfound <= (*content) + contused + iter->length);
            assert(endfound > ((*content) + contused));

            used = endfound - ((*content) + contused);

            stream->expectedseqno += used;
            if (((*content) + contused + iter->length)  == (endfound)) {
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
        checked = contused;

    }

    /* If we get here, we've either run out of segments or we've found a
     * gap in the segments we have. We need to put our in-progress segment
     * back into the map since we've been removing its components as we
     * went.
     */
    if (contused > 0 || expseqno > stream->expectedseqno) {
        update_tcp_reassemble_stream(stream, *content, contused,
                stream->expectedseqno);
    }
    *len = 0;
    return 0;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
