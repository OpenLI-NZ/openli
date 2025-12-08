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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <libtrace.h>
#include <osip2/osip.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/sdp_message.h>
#include "sipparsing.h"
#include "sip_worker.h"
#include "logger.h"
#include "util.h"
#include "location.h"

static int parse_tcp_sip_packet(openli_sip_parser_t *p, libtrace_packet_t *pkt,
        libtrace_tcp_t *tcp, uint32_t tcprem, tcp_streamid_t *tcpid,
        struct timeval *tv) {

    tcp_reassemble_stream_t *stream;
    void *payload = NULL;
    int ret = -1;

    payload = trace_get_payload_from_tcp(tcp, &tcprem);
    if (payload == NULL || (tcprem == 0 && !tcp->syn)) {
        return -1;
    }

    stream = get_tcp_reassemble_stream(p->tcpreass, tcpid, tcp, tv, tcprem);
    if (stream == NULL) {
        return -1;
    }

    p->thisstream = stream;
    if (tcprem > 0) {
        ret = update_tcp_reassemble_stream(stream, (uint8_t *)payload,
	        tcprem, ntohl(tcp->seq), pkt, 1);
    }

    return ret;

}

static int parse_udp_sip_packet(libtrace_udp_t *udp, uint32_t udprem) {

    void *payload = NULL;

    payload = trace_get_payload_from_udp(udp, &udprem);
    if (payload == NULL || udprem == 0) {
        return -1;
    }

    /* Check for a CRLF keep alive */
    if (udprem == 4 && memcmp(payload, "\x0d\x0a\x0d\x0a", 4) == 0) {
        return -1;
    }

    if (udprem == 2 && memcmp(payload, "\x0d\x0a", 2) == 0) {
        return -1;
    }

    if (udprem == 1 && memcmp(payload, "\x20", 1) == 0) {
        return -1;
    }

    /* Yet another keep alive pattern */
    if (udprem == 1 && memcmp(payload, "\x00", 1) == 0) {
        return -1;
    }

    /* eXosip keep alive */
    if (udprem >= 4 && memcmp(payload, "\x6a\x61\x4b\x00", 4) == 0) {
        return -1;
    }

    /* 00 00 00 00 seems to be some sort of keep alive as well? */
    if (udprem == 4 && memcmp(payload, "\x00\x00\x00\x00", 4) == 0) {
        return -1;
    }

    if (udprem == 8 && memcmp(payload, "\x00\x00\x00\x00\x00\x00\x00\x00",
                8) == 0) {
        return -1;
    }

    return 1;
}

char *get_sip_contents(openli_sip_parser_t *p, uint16_t *siplen) {
    *siplen = p->siplen;
    return p->sipmessage + p->sipoffset;
}

int parse_sip_content(openli_sip_parser_t *p, uint8_t *sipcontent,
        uint16_t contentlen) {

    int ret;
    /* sipcontent MUST be a complete SIP message -- so only use this
     * method on a SIP message that has already been through a parser
     * instance (i.e. already been reassembled and then had
     * get_sip_contents() called on it).
     */

    if (p->osip) {
        osip_message_free(p->osip);
        p->osip = NULL;
    }

    if (p->sdp) {
        sdp_message_free(p->sdp);
        p->sdp = NULL;
    }

    osip_message_init(&(p->osip));
    ret = osip_message_parse(p->osip, (const char *)sipcontent, contentlen);
    if (ret != 0) {
        return -1;
    }
    return 1;
}

int parse_next_sip_message(openli_sip_parser_t *p,
        libtrace_packet_t ***packets, int *pkt_cnt) {

    int i, ret, gottcpsip = 0;

    if (p->osip) {
        osip_message_free(p->osip);
        p->osip = NULL;
    }

    if (p->sdp) {
        sdp_message_free(p->sdp);
        p->sdp = NULL;
    }

    if (packets != NULL && (*packets) == NULL) {

        if (!p->sipalloced) {
            p->sipmessage = NULL;
        }

        if (p->thisstream) {
            do {
                ret = get_next_tcp_reassembled(p->thisstream, &(p->sipmessage),
                        &(p->siplen), packets, pkt_cnt);
                if (p->sipmessage != NULL) {
                    p->sipalloced = 1;
                }

                if (ret <= 0) {
                    return ret;
                }
                p->sipoffset = 0;
                if (*(p->sipmessage) == 0x0d || *(p->sipmessage) == 0x00) {
                    /* keep-alive(s), skip them */
                    if (*packets) {
                        for (i = 0; i < *pkt_cnt; i++) {
                            if ((*packets)[i]) {
                                trace_destroy_packet((*packets)[i]);
                            }
                        }
                        free(*packets);
                        *packets = NULL;
                    }
                    continue;
                }
                gottcpsip = 1;
            } while (!gottcpsip);
        }
    }


    if (p->siplen > 0) {
        osip_message_init(&(p->osip));
        ret = osip_message_parse(p->osip,
                (const char *)(p->sipmessage + p->sipoffset), p->siplen);
        p->badsip = 0;
        if (ret != 0) {
            if (p->thisstream) {
                /* reassembled stream is probably in a bad state, so let's
                 * try to "reset" the stream until we see a segment
                 * that lines up with the start of a SIP message.
                 */
                remove_tcp_reassemble_stream(p->tcpreass, p->thisstream);
                p->thisstream = NULL;
                return 0;
            }
            return -1;
        }
    }

    /* Don't do an SDP parse until it is required -- collector processing
     * threads won't need to look at SDP, for instance. */
    return 1;
}


static int _add_sip_packet(openli_sip_parser_t *p, libtrace_packet_t *packet,
        struct timeval *tv) {

    uint32_t rem, plen;
    void *transport;
    uint8_t proto;
    int ret;

    transport = trace_get_transport(packet, &proto, &rem);
    if (transport == NULL) {
        return SIP_ACTION_ERROR;
    }
    plen = trace_get_payload_length(packet);

    if (proto == TRACE_IPPROTO_UDP) {
        if (plen + sizeof(libtrace_udp_t) < rem) {
            rem = plen + sizeof(libtrace_udp_t);
        }
        ret = parse_udp_sip_packet((libtrace_udp_t *)transport, rem);
        if (ret < 0) {
            return SIP_ACTION_IGNORE;
        }

        if (p->sipalloced) {
            free(p->sipmessage);
            p->sipalloced = 0;
        }
        p->thisstream = NULL;
        p->sipmessage = ((char *)transport);
        p->siplen = rem - sizeof(libtrace_udp_t);
        p->sipoffset = sizeof(libtrace_udp_t);
        return SIP_ACTION_USE_PACKET;
    }

    if (proto == TRACE_IPPROTO_TCP) {
        libtrace_tcp_t *tcp = (libtrace_tcp_t *)transport;
        tcp_streamid_t tcpid;

        if (rem < sizeof(libtrace_tcp_t)) {
            return SIP_ACTION_IGNORE;
        }

        memset(&tcpid, 0, sizeof(tcpid));
        tcpid.srcport = ntohs(tcp->source);
        tcpid.destport = ntohs(tcp->dest);
        if (extract_ip_addresses(packet, tcpid.srcip, tcpid.destip,
                &(tcpid.ipfamily)) != 0) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting IP addresses from SIP packet.");
            return SIP_ACTION_ERROR;
        }

        if (plen + (tcp->doff * 4) < rem) {
            rem = plen + (tcp->doff * 4);
        }
        ret = parse_tcp_sip_packet(p, packet, tcp, rem, &tcpid, tv);
        if (ret == -1) {
            return SIP_ACTION_IGNORE;
        } else if (ret == 0) {
            return SIP_ACTION_REASSEMBLE_TCP;
        } else {
            if (p->sipalloced) {
                free(p->sipmessage);
                p->sipalloced = 0;
            }
            p->sipmessage = (char *)tcp;
            p->siplen = rem - (tcp->doff * 4);
            p->sipoffset = (tcp->doff * 4);
            return SIP_ACTION_USE_PACKET;
        }
    }

    return SIP_ACTION_IGNORE;
}

static int _add_sip_fragment(openli_sip_parser_t *p,
        ip_reassemble_stream_t *stream, char *completefrag, uint16_t fraglen,
        struct timeval *tv) {

    int ret;

    if (stream->subproto == TRACE_IPPROTO_UDP) {
        ret = parse_udp_sip_packet((libtrace_udp_t *)completefrag,
                fraglen);
        if (ret < 0) {
            return SIP_ACTION_IGNORE;
        }

        if (p->sipalloced) {
            free(p->sipmessage);
        }
        p->thisstream = NULL;
        p->sipmessage = completefrag;
        p->sipalloced = 1;
        p->siplen = fraglen - sizeof(libtrace_udp_t);
        p->sipoffset = sizeof(libtrace_udp_t);
        return SIP_ACTION_REASSEMBLE_IPFRAG;
    }

    if (stream->subproto == TRACE_IPPROTO_TCP) {
        libtrace_tcp_t *tcp = (libtrace_tcp_t *)completefrag;
        tcp_streamid_t tcpid;

        if (fraglen < sizeof(libtrace_tcp_t)) {
            return SIP_ACTION_IGNORE;
        }

        memset(&tcpid, 0, sizeof(tcpid));
        tcpid.srcport = ntohs(tcp->source);
        tcpid.destport = ntohs(tcp->dest);
        tcpid.ipfamily = stream->streamid.ipfamily;
        memcpy(tcpid.srcip, stream->streamid.srcip, 16);
        memcpy(tcpid.destip, stream->streamid.destip, 16);

        ret = parse_tcp_sip_packet(p, NULL, tcp, fraglen, &tcpid, tv);
        if (ret == -1) {
            return SIP_ACTION_IGNORE;
        } else if (ret == 0) {
            return SIP_ACTION_REASSEMBLE_TCP;
        }
        if (p->sipalloced) {
            free(p->sipmessage);
        }
        p->sipmessage = (char *)tcp;
        p->sipalloced = 1;
        p->siplen = fraglen - (tcp->doff * 4);
        p->sipoffset = (tcp->doff * 4);
        return SIP_ACTION_REASSEMBLE_IPFRAG;
    }

    return SIP_ACTION_IGNORE;

}

int add_sip_content_to_parser(openli_sip_parser_t **parser, uint8_t *content,
        uint32_t contentlen) {

    openli_sip_parser_t *p;

    if (*parser == NULL) {
    	p = (openli_sip_parser_t *)malloc(sizeof(openli_sip_parser_t));

        p->osip = NULL;
        p->sdp = NULL;
        p->tcpreass = create_new_tcp_reassembler(OPENLI_REASSEMBLE_SIP);
        p->ipreass = create_new_ipfrag_reassembler();
        p->sipmessage = NULL;
        p->siplen = 0;
        p->sipoffset = 0;
        p->thisstream = NULL;
        p->sipalloced = 0;
        *parser = p;
    } else {
        p = *parser;
        p->thisstream = NULL;
    }

    if (p->sipalloced) {
        free(p->sipmessage);
        p->sipalloced = 0;
    }
    p->thisstream = NULL;
    p->sipmessage = ((char *)content);
    p->siplen = contentlen;
    p->sipoffset = 0;

    return SIP_ACTION_USE_PACKET;
}

int add_sip_packet_to_parser(openli_sip_parser_t **parser,
        libtrace_packet_t *packet, uint8_t logallowed) {

    char *completefrag = NULL;
    uint8_t proto, moreflag, isfrag;
    int ret;
    openli_sip_parser_t *p;
    uint16_t fragoff, fraglen;
    struct timeval tstamp;
    ip_reassemble_stream_t *ipstream = NULL;

    if (*parser == NULL) {
    	p = (openli_sip_parser_t *)malloc(sizeof(openli_sip_parser_t));

        p->osip = NULL;
        p->sdp = NULL;
        p->tcpreass = create_new_tcp_reassembler(OPENLI_REASSEMBLE_SIP);
        p->ipreass = create_new_ipfrag_reassembler();
        p->sipmessage = NULL;
        p->siplen = 0;
        p->sipoffset = 0;
        p->thisstream = NULL;
        p->sipalloced = 0;
        *parser = p;
    } else {
        p = *parser;
        p->thisstream = NULL;
    }

    /* First step, is this packet a fragment and if so, have we got enough
     * to complete the original frame? */

    /* Simple case: packet == message,
     *      return USE_PACKET
     * Others:
     *      packet is not fragment, but requires TCP assembly:
     *          update TCP assembler, return REASSEMBLE_TCP
     *      packet is a fragment, but no TCP assembly required:
     *          set p->sipmessage to contain reass fragment
     *          return REASSEMBLE_IPFRAG
     *      packet is a fragment and THEN requires TCP assembly:
     *          update TCP assembler using complete fragment
     *          return REASSEMBLE_TCP
     */

    isfrag = 0;
    fragoff = trace_get_fragment_offset(packet, &moreflag);
    if (moreflag != 0 || fragoff > 0) {

        ipstream = get_ipfrag_reassemble_stream(p->ipreass, packet);
        if (ipstream == NULL) {
            if (logallowed) {
                logger(LOG_INFO, "OpenLI: unable to find IP stream for received SIP packet.");
            }
            return SIP_ACTION_ERROR;
        }

        ret = update_ipfrag_reassemble_stream(ipstream, packet, fragoff,
                moreflag);
        if (ret < 0) {
            if (logallowed) {
                logger(LOG_INFO, "OpenLI: unable to update IP stream for received SIP packet.");
            }
            return SIP_ACTION_ERROR;
        }
        if (ret == 0) {
            ret = get_next_ip_reassembled(ipstream, &completefrag, &fraglen,
                    &proto);
            if (ret < 0) {
                return SIP_ACTION_ERROR;
            } else if (ret == 0) {
                /* incomplete fragment */
                if (completefrag) {
                    free(completefrag);
                }
                return SIP_ACTION_IGNORE;
            }
            /* complete fragment in completefrag */
            isfrag = 1;
        }
    }

    tstamp = trace_get_timeval(packet);

    if (!isfrag) {
        return _add_sip_packet(p, packet, &tstamp);
    } else {
        assert(ipstream != NULL);
        ret = _add_sip_fragment(p, ipstream, completefrag, fraglen, &tstamp);
        remove_ipfrag_reassemble_stream(p->ipreass, ipstream);
        return ret;
    }

    return SIP_ACTION_ERROR;

}

void release_sip_parser(openli_sip_parser_t *parser) {

    if (parser->osip) {
        osip_message_free(parser->osip);
    }
    if (parser->sdp) {
        sdp_message_free(parser->sdp);
    }
    if (parser->tcpreass) {
        destroy_tcp_reassembler(parser->tcpreass);
    }
    if (parser->ipreass) {
        destroy_ipfrag_reassembler(parser->ipreass);
    }
    if (parser->sipmessage && parser->sipalloced) {
        free(parser->sipmessage);
    }
    free(parser);

}

static inline char *strip_sip_uri(char *uristr) {

    char *firstcol = NULL;
    char *chop = NULL;

    /* Examples of URIs that need stripping:
     *   sip:francisco@bestel.com:55060     (remove :55060)
     *   sip:200.57.7.195:55061;user=phone  (remove :50061;user=phone)
     */

    /* firstcol should point to the colon at the end of 'sip:<name>' portion
     * of the URI */
    firstcol = strchr((const char *)uristr, ':');
    if (firstcol == NULL) {
        return NULL;
    }

    /* A port (if present) will always come before '?' or ';' (i think!) */
    chop = strchr((const char *)(firstcol+1), ':');
    if (chop != NULL) {
        *chop = '\0';
        return uristr;
    }

    chop = strchr((const char *)(firstcol+1), ';');
    if (chop != NULL) {
        *chop = '\0';
    }

    chop = strchr((const char *)(firstcol+1), '?');
    if (chop != NULL) {
        *chop = '\0';
    }

    return uristr;
}

char *get_sip_cseq(openli_sip_parser_t *parser) {

    osip_cseq_t *cseq = osip_message_get_cseq(parser->osip);
    char *cseqstr;

    if (cseq == NULL) {
        return NULL;
    }

    if (osip_cseq_to_str(cseq, &cseqstr) != 0) {
        return NULL;
    }

    return cseqstr;
}

char *get_sip_from_uri(openli_sip_parser_t *parser) {

    char *uristr;
    osip_from_t *from = osip_message_get_from(parser->osip);

    if (from == NULL) {
        return NULL;
    }

    if (osip_uri_to_str_canonical(osip_from_get_url(from), &uristr) != 0) {
        return NULL;
    }

    /* Need to strip any extra uri components (e.g. port numbers,
     * additional arguments etc. */
    uristr = strip_sip_uri(uristr);

    return uristr;
}

char *get_sip_to_uri(openli_sip_parser_t *parser) {

    char *uristr;
    osip_to_t *to = osip_message_get_to(parser->osip);

    if (to == NULL) {
        return NULL;
    }

    if (osip_uri_to_str_canonical(osip_to_get_url(to), &uristr) != 0) {
        return NULL;
    }

    /* Need to strip any extra uri components (e.g. port numbers,
     * additional arguments etc. */
    uristr = strip_sip_uri(uristr);
    return uristr;
}

char *get_sip_from_uri_username(openli_sip_parser_t *parser) {

    char *uriuser;
    char *semicolon;
    osip_uri_t *uri;

    osip_from_t *from = osip_message_get_from(parser->osip);

    if (from == NULL) {
        return NULL;
    }

    uri = osip_from_get_url(from);
    if (uri == NULL) {
        return NULL;
    }

    /* I have (rarely) seen SIP URIs where there is no username, just
     * an IP address -- in this case, it is probably best to just assume
     * that the IP address is a suitable username?
     *
     * Note that this will mean username and realm will end up having the
     * same value -- probably not a big deal, as anyone who uses an IP
     * address for SIP identity is probably going to want to declare it as
     * the username and leave the realm option blank.
     */
    if ((uriuser = osip_uri_get_username(uri)) == NULL) {
        uriuser = osip_uri_get_host(uri);
    }

    if (uriuser == NULL) {
        return NULL;
    }

    semicolon = strchr(uriuser, ';');
    if (semicolon) {
        *semicolon = '\0';
    }

    return uriuser;
}

char *get_sip_to_uri_scheme(openli_sip_parser_t *parser) {

    char *scheme;

    osip_uri_t *uri;
    osip_to_t *to = osip_message_get_to(parser->osip);

    if (to == NULL) {
        return NULL;
    }
    uri = osip_to_get_url(to);
    if (uri == NULL) {
        return NULL;
    }
    scheme = osip_uri_get_scheme(uri);
    return scheme;
}

char *get_sip_from_uri_scheme(openli_sip_parser_t *parser) {

    char *scheme;

    osip_uri_t *uri;
    osip_to_t *from = osip_message_get_from(parser->osip);

    if (from == NULL) {
        return NULL;
    }
    uri = osip_to_get_url(from);
    if (uri == NULL) {
        return NULL;
    }
    scheme = osip_uri_get_scheme(uri);
    return scheme;
}

char *parse_tel_uri(osip_uri_t *uri) {

    char *buf;
    int r;
    char *semicolon;
    char *start;

    r = osip_uri_to_str(uri, &buf);
    if (r != 0) {
        return NULL;
    }

    if (strncmp(buf, "tel:", 4) != 0) {
        logger(LOG_INFO, "Unexpected SIP URI for tel scheme: %s\n", buf);
        return NULL;
    }
    start = buf + 4;
    start = strdup(start);
    semicolon = strchr(start, ';');
    if (semicolon) {
        *semicolon = '\0';
    }
    free(buf);
    return start;

}

char *get_sip_from_uri_telnumber(openli_sip_parser_t *parser) {
    osip_uri_t *uri;
    osip_from_t *from = osip_message_get_from(parser->osip);
    if (from == NULL) {
        return NULL;
    }
    uri = osip_from_get_url(from);
    if (uri == NULL) {
        return NULL;
    }

    return parse_tel_uri(uri);
}

char *get_sip_to_uri_telnumber(openli_sip_parser_t *parser) {
    osip_uri_t *uri;
    osip_to_t *to = osip_message_get_to(parser->osip);
    if (to == NULL) {
        return NULL;
    }
    uri = osip_to_get_url(to);
    if (uri == NULL) {
        return NULL;
    }

    return parse_tel_uri(uri);
}

char *get_sip_to_uri_username(openli_sip_parser_t *parser) {

    char *uriuser;
    char *semicolon;
    osip_uri_t *uri;
    osip_to_t *to = osip_message_get_to(parser->osip);

    if (to == NULL) {
        return NULL;
    }
    uri = osip_to_get_url(to);
    if (uri == NULL) {
        return NULL;
    }

    /* I have (rarely) seen SIP URIs where there is no username, just
     * an IP address -- in this case, it is probably best to just assume
     * that the IP address is a suitable username?
     *
     * Note that this will mean username and realm will end up having the
     * same value -- probably not a big deal, as anyone who uses an IP
     * address for SIP identity is probably going to want to declare it as
     * the username and leave the realm option blank.
     */
    if ((uriuser = osip_uri_get_username(uri)) == NULL) {
        uriuser = osip_uri_get_host(uri);
    }

    if (uriuser == NULL) {
        return NULL;
    }

    semicolon = strchr(uriuser, ';');
    if (semicolon) {
        *semicolon = '\0';
    }

    return uriuser;
}

char *get_sip_to_uri_realm(openli_sip_parser_t *parser) {
    /* I use the term 'realm' here to be consistent with Authorization
     * header fields, but really this part of a To: uri is generally
     * called a 'host'.
     */
    char *urihost;
    osip_to_t *to = osip_message_get_to(parser->osip);

    if (to == NULL) {
        return NULL;
    }

    urihost = osip_uri_get_host(osip_to_get_url(to));
    return urihost;
}

char *get_sip_from_uri_realm(openli_sip_parser_t *parser) {
    /* I use the term 'realm' here to be consistent with Authorization
     * header fields, but really this part of a To: uri is generally
     * called a 'host'.
     */
    char *urihost;
    osip_from_t *from = osip_message_get_from(parser->osip);

    if (from == NULL) {
        return NULL;
    }

    urihost = osip_uri_get_host(osip_to_get_url(from));
    return urihost;
}

int get_sip_to_uri_identity(openli_sip_parser_t *parser,
        openli_sip_identity_t *sipid) {

    char *scheme = get_sip_to_uri_scheme(parser);
    if (scheme == NULL) {
        return -1;
    }

    if (strcmp(scheme, "tel") == 0) {
        /* libosip2 doesn't seem to handle tel nicely, so we'll have to
         * parse the tel: URI ourselves
         */

        sipid->realm = NULL;
        sipid->realm_len = 0;

        sipid->username = NULL;
        sipid->username_len = 0;
        sipid->active = 0;

        sipid->username = get_sip_to_uri_telnumber(parser);
        if (sipid->username == NULL) {
            return -1;
        }
        sipid->username_len = strlen(sipid->username);
        sipid->realm = NULL;
        sipid->realm_len = 0;

    } else if (strcmp(scheme, "sip") == 0 || strcmp(scheme, "sips") == 0) {
        sipid->username = get_sip_to_uri_username(parser);
        if (sipid->username == NULL) {
            return -1;
        }
        sipid->username = strdup(sipid->username);
        sipid->username_len = strlen(sipid->username);

        sipid->realm = get_sip_to_uri_realm(parser);
        if (sipid->realm == NULL) {
            return -1;
        }
        sipid->realm = strdup(sipid->realm);
        sipid->realm_len = strlen(sipid->realm);
    } else {
        logger(LOG_INFO, "OpenLI: unexpected SIP scheme '%s', ignoring",
                scheme);
        sipid->realm = NULL;
        sipid->realm_len = 0;

        sipid->username = NULL;
        sipid->username_len = 0;
        sipid->active = 0;
    }
    return 1;
}

int get_sip_from_uri_identity(openli_sip_parser_t *parser,
        openli_sip_identity_t *sipid) {

    char *scheme = get_sip_from_uri_scheme(parser);
    if (scheme == NULL) {
        return -1;
    }

    if (strcmp(scheme, "tel") == 0) {
        /* libosip2 doesn't seem to handle tel nicely, so we'll have to
         * parse the tel: URI ourselves
         */

        sipid->realm = NULL;
        sipid->realm_len = 0;

        sipid->username = NULL;
        sipid->username_len = 0;
        sipid->active = 0;

        sipid->username = get_sip_from_uri_telnumber(parser);
        if (sipid->username == NULL) {
            return -1;
        }
        sipid->username_len = strlen(sipid->username);
        sipid->realm = NULL;
        sipid->realm_len = 0;

    } else if (strcmp(scheme, "sip") == 0 || strcmp(scheme, "sips") == 0) {
        sipid->username = get_sip_from_uri_username(parser);
        if (sipid->username == NULL) {
            return -1;
        }
        sipid->username = strdup(sipid->username);
        sipid->username_len = strlen(sipid->username);

        sipid->realm = get_sip_from_uri_realm(parser);
        if (sipid->realm == NULL) {
            return -1;
        }
        sipid->realm = strdup(sipid->realm);
        sipid->realm_len = strlen(sipid->realm);
    } else {
        logger(LOG_INFO, "OpenLI: unexpected SIP scheme '%s', ignoring",
                scheme);
        sipid->realm = NULL;
        sipid->realm_len = 0;

        sipid->username = NULL;
        sipid->username_len = 0;
        sipid->active = 0;
    }
    return 1;
}

static inline void strip_quotes(openli_sip_identity_t *sipid) {

    /* The removal of the trailing " is permanent, so we need to
     * be careful about detecting cases where we call strip_quotes
     * again on a term that will now only have a beginning quote,
     * e.g. "username
     */

    if (sipid->username && sipid->username[0] == '"') {
        if (sipid->username[sipid->username_len - 1] == '"') {
            sipid->username[sipid->username_len - 1] = '\0';
            sipid->username_len --;
        }
        sipid->username ++;
        sipid->username_len --;
    }

    if (sipid->realm && sipid->realm[0] == '"') {
        if (sipid->realm[sipid->realm_len - 1] == '"') {
            sipid->realm[sipid->realm_len - 1] = '\0';
            sipid->realm_len --;
        }
        sipid->realm ++;
        sipid->realm_len --;
    }

}

int get_sip_auth_identity(openli_sip_parser_t *parser, int index,
        int *authcount, openli_sip_identity_t *sipid,
        uint8_t logallowed) {

    osip_authorization_t *auth;

    *authcount = osip_list_size(&(parser->osip->authorizations));

    if (*authcount == 0) {
        return 0;
    }

    if (index >= *authcount) {
        if (logallowed) {
            logger(LOG_INFO,
                "OpenLI: Error, requested auth username %d but packet only has %d auth headers.",
                index, *authcount);
        }
        return -1;
    }

    if (osip_message_get_authorization(parser->osip, index, &auth) != 0) {
        if (logallowed) {
            logger(LOG_INFO,
                "OpenLI: Error while extracting auth header from SIP packet.");
        }
        return -1;
    }

    sipid->username = osip_authorization_get_username(auth);
    if (sipid->username) {
        sipid->username_len = strlen(sipid->username);
    } else {
        sipid->username_len = 0;
    }
    sipid->realm = osip_authorization_get_realm(auth);
    if (sipid->realm) {
        sipid->realm_len = strlen(sipid->realm);
    } else {
        sipid->realm_len = 0;
    }

    strip_quotes(sipid);

    return 1;

}

int get_sip_proxy_auth_identity(openli_sip_parser_t *parser, int index,
        int *authcount, openli_sip_identity_t *sipid,
        uint8_t logallowed) {

    osip_proxy_authorization_t *auth;

    *authcount = osip_list_size(&(parser->osip->proxy_authorizations));

    if (*authcount == 0) {
        return 0;
    }

    if (index >= *authcount) {
        if (logallowed) {
            logger(LOG_INFO,
                "OpenLI: Error, requested proxy auth username %d but packet only has %d auth headers.",
                index, *authcount);
        }
        return -1;
    }

    if (osip_message_get_proxy_authorization(parser->osip, index, &auth) != 0) {
        if (logallowed) {
            logger(LOG_INFO,
                "OpenLI: Error while extracting proxy auth header from SIP packet.");
        }
        return -1;
    }

    sipid->username = osip_proxy_authorization_get_username(auth);
    sipid->username_len = strlen(sipid->username);
    sipid->realm = osip_proxy_authorization_get_realm(auth);
    sipid->realm_len = strlen(sipid->realm);

    strip_quotes(sipid);
    return 1;
}

char *get_sip_branch_id(openli_sip_parser_t *parser) {
    osip_generic_param_t *param;
    osip_via_t *via;

    via = (osip_via_t *) osip_list_get(&(parser->osip->vias), 0);
    if (via == NULL) {
        return NULL;
    }

    osip_via_param_get_byname(via, "branch", &param);
    if (param == NULL) {
        return NULL;
    }
    return (char *)param->gvalue;
}

char *get_sip_callid(openli_sip_parser_t *parser) {
    char *callidstr;
    osip_call_id_t *cid;

    cid = osip_message_get_call_id(parser->osip);
    if (cid == NULL) {
        return NULL;
    }

    callidstr = osip_call_id_get_number(cid);
    return callidstr;
}

static inline int extract_identity(openli_sip_identity_t *sipid, char *start) {
    char *idstring, *at, *end, *ptr;
    uint8_t saw_wrapping = 0;

    /* Make sure we strip the '<' and '>' that wrap the identity value */
    idstring = strchr((const char *)start, '<');
    if (idstring != NULL) {
        idstring = strdup(idstring + 1);
        saw_wrapping = 1;
    } else {
        idstring = strdup(start);
    }

    ptr = strip_sip_uri(idstring);
    if (ptr == NULL) {
        free(idstring);
        return -1;
    }

    ptr = strchr((const char *)ptr, ':');
    if (ptr == NULL) {
        free(idstring);
        return -1;
    }

    ptr += 1;
    if (saw_wrapping) {
        end = strchr((const char *)ptr, '>');
        if (end != NULL) {
            *end = '\0';
        }

        if (ptr[strlen(ptr) - 1] == '>') {
            ptr[strlen(ptr) - 1] = '\0';
        }
    }

    at = strchr((const char *)ptr, '@');
    if (at == NULL) {
        sipid->realm = NULL;
        sipid->realm_len = 0;
        sipid->username_len = strlen(ptr);
        sipid->username = strdup(ptr);
    } else {
        sipid->realm = strdup(at + 1);
        sipid->realm_len = strlen(sipid->realm);
        sipid->username_len = at - ptr;
        sipid->username = strdup(ptr);
        sipid->username[sipid->username_len] = '\0';
    }

    free(idstring);

    return 1;
}

int get_sip_paccess_network_info(openli_sip_parser_t *parser,
        openli_location_t **loc, int *loc_cnt) {

    char *start;
    char *copy, *tok;
    osip_header_t *hdr;

    osip_message_header_get_byname(parser->osip, "P-Access-Network-Info", 0,
            &hdr);
    if (hdr == NULL) {
        return 0;
    }
    start = osip_header_get_value(hdr);
    if (start == NULL) {
        return 0;
    }

    copy = strdup(start);
    tok = strtok(copy, ";");
    if (tok == NULL) {
        free(copy);
        return -1;
    }
    /* access-type */
    if (strcasecmp(tok, "3GPP-E-UTRAN-FDD") == 0) {
        tok = strtok(NULL, ";");
        if (parse_e_utran_fdd_field(tok, loc, loc_cnt) < 0) {
            free(copy);
            return -1;
        }
    }

    free(copy);
    return *loc_cnt;
}

int get_sip_identity_by_header_name(openli_sip_parser_t *parser,
        openli_sip_identity_t *sipid, const char *header) {

    char *start;
    osip_header_t *hdr;

    osip_message_header_get_byname(parser->osip, header, 0, &hdr);
    if (hdr == NULL) {
        return 0;
    }

    /* dangerously assuming that this will be null terminated... */
    start = osip_header_get_value(hdr);
    if (start == NULL) {
        return 0;
    }
    return extract_identity(sipid, start);
}

static inline int parse_sdp_body(openli_sip_parser_t *parser) {
    osip_body_t *body;
    sdp_message_init(&(parser->sdp));
    if (osip_message_get_body(parser->osip, 0, &body) != 0) {
        return -1;
    }
    if (sdp_message_parse(parser->sdp, body->body) != 0) {
        return -1;
    }
    return 0;
}

char *get_sip_message_body(openli_sip_parser_t *parser, size_t *length) {
    osip_body_t *body;
    int r;
    if ((r = osip_message_get_body(parser->osip, 0, &body)) != 0) {
        return NULL;
    }
    *length = body->length;
    return body->body;
}

char *get_sip_session_id(openli_sip_parser_t *parser) {

    char *sessid;

    if (!parser->sdp) {
        if (parse_sdp_body(parser) == -1) {
            return NULL;
        }
    }
    sessid = sdp_message_o_sess_id_get(parser->sdp);
    return sessid;
}

char *get_sip_session_address(openli_sip_parser_t *parser) {
    char *sessaddr;

    if (!parser->sdp) {
        if (parse_sdp_body(parser) == -1) {
            return NULL;
        }
    }
    sessaddr = sdp_message_o_addr_get(parser->sdp);
    return sessaddr;
}

char *get_sip_session_username(openli_sip_parser_t *parser) {
    char *sessuname;

    if (!parser->sdp) {
        if (parse_sdp_body(parser) == -1) {
            return NULL;
        }
    }
    sessuname = sdp_message_o_username_get(parser->sdp);
    return sessuname;
}

char *get_sip_session_version(openli_sip_parser_t *parser) {

    char *sessv;

    if (!parser->sdp) {
        if (parse_sdp_body(parser) == -1) {
            return NULL;
        }
    }
    sessv = sdp_message_o_sess_version_get(parser->sdp);
    return sessv;
}

char *get_sip_media_ipaddr(openli_sip_parser_t *parser) {
    char *ipaddr;

    if (!parser->sdp) {
        if (parse_sdp_body(parser) == -1) {
            return NULL;
        }
    }
    ipaddr = sdp_message_c_addr_get(parser->sdp, -1, 0);
    if (ipaddr == NULL) {
        /* sdp_message_c_addr_get() only returns an IP address if
         * osip thinks the c field is the "global" connection, i.e.
         * "c=" appears before any "m=" lines. If "c=" comes after
         * an "m=", then osip decides the connection info is applied
         * only to that media and so we have to go walk the list of
         * known media to find the address we want...
         *
         */
        int pos = 0;
        while (!osip_list_eol(&(parser->sdp->m_medias), pos)) {
            sdp_media_t *hdr = (sdp_media_t *) osip_list_get(
                    &(parser->sdp->m_medias), pos);

            /* If there are multiple media, try to get the address
             * from the audio media if possible.
             *
             * Of course, if the 'c=' and 'm=' ordering is just
             * due to dodgy SIP implementation, there is a chance
             * that the address we need could be associated with
             * another media but I'll worry about that if it ever
             * comes up.
             */
            if (osip_list_size(&(hdr->c_connections)) &&
                    strcmp(hdr->m_media, "audio") == 0) {
                sdp_connection_t *c = (sdp_connection_t *)osip_list_get(
                        &(hdr->c_connections), 0);

                ipaddr = c->c_addr;
                break;
            }
            pos ++;
        }
    }

    return ipaddr;
}

char *get_sip_media_port(openli_sip_parser_t *parser, int index) {
    char *port;

    if (!parser->sdp) {
        if (parse_sdp_body(parser) == -1) {
            return NULL;
        }
    }
    port = sdp_message_m_port_get(parser->sdp, index);
    return port;
}

char *get_sip_media_type(openli_sip_parser_t *parser, int index) {
    char *media;

    if (!parser->sdp) {
        if (parse_sdp_body(parser) == -1) {
            return NULL;
        }
    }
    media = sdp_message_m_media_get(parser->sdp, index);
    return media;
}

int sip_is_invite(openli_sip_parser_t *parser) {
    if (MSG_IS_INVITE(parser->osip)) {
        return 1;
    }
    return 0;
}

int sip_is_message(openli_sip_parser_t *parser) {
    if (MSG_IS_MESSAGE(parser->osip)) {
        return 1;
    }
    return 0;
}

int sip_is_register(openli_sip_parser_t *parser) {
    if (MSG_IS_REGISTER(parser->osip)) {
        return 1;
    }
    return 0;
}

int sip_is_response(openli_sip_parser_t *parser) {
    if (MSG_IS_RESPONSE(parser->osip)) {
        return 1;
    }
    return 0;
}

int sip_is_200ok(openli_sip_parser_t *parser) {

    if (MSG_IS_RESPONSE(parser->osip)) {
        if (osip_message_get_status_code(parser->osip) == 200) {
            return 1;
        }
    }

    return 0;
}

int sip_is_183sessprog(openli_sip_parser_t *parser) {

    if (MSG_IS_RESPONSE(parser->osip)) {
        if (osip_message_get_status_code(parser->osip) == 183) {
            return 1;
        }
    }

    return 0;
}

int sip_is_180ringing(openli_sip_parser_t *parser) {

    if (MSG_IS_RESPONSE(parser->osip)) {
        if (osip_message_get_status_code(parser->osip) == 180) {
            return 1;
        }
    }

    return 0;
}

int sip_is_bye(openli_sip_parser_t *parser) {
    if (MSG_IS_BYE(parser->osip)) {
        return 1;
    }
    return 0;
}

int sip_is_cancel(openli_sip_parser_t *parser) {
    if (MSG_IS_CANCEL(parser->osip)) {
        return 1;
    }
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
