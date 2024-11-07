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
    int ret;

    stream = get_tcp_reassemble_stream(p->tcpreass, tcpid, tcp, tv, tcprem);
    if (stream == NULL) {
        return -1;
    }

    p->thisstream = stream;
    payload = trace_get_payload_from_tcp(tcp, &tcprem);
    if (payload == NULL || tcprem == 0) {
        return -1;
    }

    ret = update_tcp_reassemble_stream(stream, (uint8_t *)payload, tcprem,
            ntohl(tcp->seq), pkt, 1);

    if (stream->established == TCP_STATE_LOSS) {
        remove_tcp_reassemble_stream(p->tcpreass, p->thisstream);
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
        if (ret != 0) {
            if (p->thisstream) {
                /* reassembled stream is probably in a bad state, so let's
                 * try to "reset" the stream until we see a segment
                 * that lines up with the start of a SIP message.
                 */
                remove_tcp_reassemble_stream(p->tcpreass, p->thisstream);
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
        /* TODO do we need to support targets using tel: ?
         * Would be slightly annoying because libosip2 doesn't seem
         * to handle tel nicely.
         */

        /* For now, just ignore tel: URIs */
        sipid->realm = NULL;
        sipid->realm_len = 0;

        sipid->username = NULL;
        sipid->username_len = 0;
        sipid->active = 0;
    } else if (strcmp(scheme, "sip") == 0 || strcmp(scheme, "sips") == 0) {
        sipid->username = get_sip_to_uri_username(parser);
        if (sipid->username == NULL) {
            return -1;
        }
        sipid->username_len = strlen(sipid->username);

        sipid->realm = get_sip_to_uri_realm(parser);
        if (sipid->realm == NULL) {
            return -1;
        }
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
        /* TODO do we need to support targets using tel: ?
         * Would be slightly annoying because libosip2 doesn't seem
         * to handle tel nicely.
         */

        /* For now, just ignore tel: URIs */
        sipid->realm = NULL;
        sipid->realm_len = 0;

        sipid->username = NULL;
        sipid->username_len = 0;
        sipid->active = 0;
    } else if (strcmp(scheme, "sip") == 0 || strcmp(scheme, "sips") == 0) {
        sipid->username = get_sip_from_uri_username(parser);
        if (sipid->username == NULL) {
            return -1;
        }
        sipid->username_len = strlen(sipid->username);

        sipid->realm = get_sip_from_uri_realm(parser);
        if (sipid->realm == NULL) {
            return -1;
        }
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

static openli_sip_identity_t *sipid_matches_target(libtrace_list_t *targets,
        openli_sip_identity_t *sipid) {

    libtrace_list_node_t *n;

    if (sipid->username == NULL) {
        return NULL;
    }

    n = targets->head;
    while (n) {
        openli_sip_identity_t *x = *((openli_sip_identity_t **) (n->data));
        n = n->next;

        if (x->active == 0) {
            continue;
        }

        if (x->username == NULL || strlen(x->username) == 0) {
            continue;
        }

        /* treat a '*' at the beginning of a SIP username as a wildcard,
         * so users can specify phone numbers as targets without worrying
         * about all possible combinations of (with area codes, without
         * area codes, with '+', without '+', etc.)
         */
        if (x->username[0] == '*') {
            int termlen = strlen(x->username) - 1;
            int idlen = strlen(sipid->username);

            if (idlen < termlen) {
                continue;
            }
            if (strncmp(x->username + 1, sipid->username + (idlen - termlen),
                    termlen) != 0) {
                continue;
            }
        } else if (strcmp(x->username, sipid->username) != 0) {
            continue;
        }

        if (x->realm == NULL || strcmp(x->realm, sipid->realm) == 0) {
            return x;
        }
    }
    return NULL;
}

int extract_sip_identities(openli_sip_parser_t *parser,
        openli_sip_identity_set_t *idset, uint8_t log_error) {

    int i, unused;
    openli_sip_identity_t authid;

    memset(idset, 0, sizeof(openli_sip_identity_set_t));

    if (get_sip_to_uri_identity(parser, &(idset->touriid)) < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: unable to derive SIP identity from To: URI");
        }
        return -1;
    }

    if (get_sip_from_uri_identity(parser, &(idset->fromuriid)) < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: unable to derive SIP identity from From: URI");
        }
        return -1;
    }

    if (get_sip_proxy_auth_identity(parser, 0, &(idset->proxyauthcount),
            &authid, log_error) < 0) {
        return -1;
    }

    if (idset->proxyauthcount > 0) {
        idset->proxyauths = calloc(idset->proxyauthcount,
                sizeof(openli_sip_identity_t));
        memcpy(&(idset->proxyauths[0]), &authid, sizeof(openli_sip_identity_t));

        for (i = 1; i < idset->proxyauthcount; i++) {
            if (get_sip_proxy_auth_identity(parser, i, &unused,
                    &(idset->proxyauths[i]), log_error) < 0) {
                return -1;
            }
        }
    }

    if (get_sip_auth_identity(parser, 0, &(idset->regauthcount),
            &authid, log_error) < 0) {
        return -1;
    }

    if (idset->regauthcount > 0) {
        idset->regauths = calloc(idset->regauthcount,
                sizeof(openli_sip_identity_t));
        memcpy(&(idset->regauths[0]), &authid, sizeof(openli_sip_identity_t));

        for (i = 1; i < idset->regauthcount; i++) {
            if (get_sip_auth_identity(parser, i, &unused,
                    &(idset->regauths[i]), log_error) < 0) {
                return -1;
            }
        }
    }

    if (get_sip_identity_by_header_name(parser, &(idset->passertid),
                "P-Asserted-Identity") < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting P-Asserted-Identity from SIP message");
        }
        return -1;
    }

    if (get_sip_identity_by_header_name(parser, &(idset->ppreferredid),
                "P-Preferred-Identity") < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting P-Preferred-Identity from SIP message");
        }
        return -1;
    }

    if (get_sip_identity_by_header_name(parser, &(idset->remotepartyid),
                "Remote-Party-ID") < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting Remote-Party from SIP message");
        }
        return -1;
    }

    return 0;
}

openli_sip_identity_t *match_sip_target_against_identities(
        libtrace_list_t *targets, openli_sip_identity_set_t *idset,
        uint8_t trust_from) {

    int i;
    openli_sip_identity_t *matched = NULL;

    /* Try the To: uri first */
    if ((matched = sipid_matches_target(targets, &(idset->touriid)))) {
        return matched;
    }
    if ((matched = sipid_matches_target(targets, &(idset->passertid)))) {
        return matched;
    }
    if ((matched = sipid_matches_target(targets, &(idset->remotepartyid)))) {
        return matched;
    }
    for (i = 0; i < idset->proxyauthcount; i++) {
        if ((matched = sipid_matches_target(targets, &(idset->proxyauths[i]))))
        {
            return matched;
        }
    }
    for (i = 0; i < idset->regauthcount; i++) {
        if ((matched = sipid_matches_target(targets, &(idset->regauths[i]))))
        {
            return matched;
        }
    }

    if (trust_from && (matched = sipid_matches_target(targets, &(idset->ppreferredid)))) {
        return matched;
    }

    if (trust_from && (matched = sipid_matches_target(targets,
            &(idset->fromuriid)))) {
        return matched;
    }

    return NULL;
}

void release_openli_sip_identity_set(openli_sip_identity_set_t *idset) {
    if (idset->proxyauthcount > 0) {
        free(idset->proxyauths);
    }
    if (idset->regauthcount > 0) {
        free(idset->regauths);
    }
    if (idset->passertid.username) {
        free(idset->passertid.username);
    }
    if (idset->passertid.realm) {
        free(idset->passertid.realm);
    }
    if (idset->ppreferredid.username) {
        free(idset->ppreferredid.username);
    }
    if (idset->ppreferredid.realm) {
        free(idset->ppreferredid.realm);
    }
    if (idset->remotepartyid.username) {
        free(idset->remotepartyid.username);
    }
    if (idset->remotepartyid.realm) {
        free(idset->remotepartyid.realm);
    }
}

static void populate_sdp_identifier(openli_sip_parser_t *sipparser,
        sip_sdp_identifier_t *sdpo, uint8_t log_bad_sip, char *callid) {

    char *sessid, *sessversion, *sessaddr, *sessuser;

    memset(sdpo->address, 0, sizeof(sdpo->address));
    memset(sdpo->username, 0, sizeof(sdpo->username));

    sessid = get_sip_session_id(sipparser);
    sessversion = get_sip_session_version(sipparser);
    sessaddr = get_sip_session_address(sipparser);
    sessuser = get_sip_session_username(sipparser);

    if (sessid != NULL) {
        errno = 0;
        sdpo->sessionid = strtoul(sessid, NULL, 0);
        if (errno != 0) {
            if (log_bad_sip) {
                logger(LOG_INFO, "OpenLI: SIP worker saw an invalid session ID in SIP packet %s", sessid);
            }
            sessid = NULL;
            sdpo->sessionid = 0;
        }
    } else {
        sdpo->sessionid = 0;
    }

    if (sessversion != NULL) {
        errno = 0;
        sdpo->version = strtoul(sessversion, NULL, 0);
        if (errno != 0) {
            if (log_bad_sip) {
                logger(LOG_INFO, "OpenLI: invalid version in SIP packet %s",
                        sessid);
            }
            sessversion = NULL;
            sdpo->version = 0;
        }
    } else {
        sdpo->version = 0;
    }

    if (sessaddr != NULL) {
        strncpy(sdpo->address, sessaddr, sizeof(sdpo->address) - 1);
    } else {
        strncpy(sdpo->address, callid, sizeof(sdpo->address) - 1);
    }

    if (sessuser != NULL) {
        strncpy(sdpo->username, sessaddr, sizeof(sdpo->username) - 1);
    } else {
        strncpy(sdpo->username, "unknown", sizeof(sdpo->username) - 1);
    }


}

static voipsdpmap_t *update_cin_sdp_map(voipintercept_t *vint,
        sip_sdp_identifier_t *sdpo, voipintshared_t *vshared, char *targetuser,
        char *targetrealm) {

    voipsdpmap_t *newsdpmap;

    newsdpmap = (voipsdpmap_t *)calloc(1, sizeof(voipsdpmap_t));
    if (!newsdpmap) {
        exit(-2);
    }
    newsdpmap->sdpkey.sessionid = sdpo->sessionid;
    newsdpmap->sdpkey.version = sdpo->version;

    /* because we use the contents of the sdpkey structure as a key in
     * a uthash map, we cannot just strdup the address and username fields
     * here as we need a fixed size char array inside the structure
     * rather than a pointer.
     */

    /* make sure we null terminate if the address or username is very long */
    strncpy(newsdpmap->sdpkey.address, sdpo->address,
            sizeof(newsdpmap->sdpkey.address));
    newsdpmap->sdpkey.address[sizeof(newsdpmap->sdpkey.address) - 1] = '\0';
    strncpy(newsdpmap->sdpkey.username, sdpo->username,
            sizeof(newsdpmap->sdpkey.username) - 1);
    newsdpmap->sdpkey.username[sizeof(newsdpmap->sdpkey.username) - 1] = '\0';

    newsdpmap->username = strdup(targetuser);
    if (targetrealm) {
        newsdpmap->realm = strdup(targetrealm);
    } else {
        newsdpmap->realm = NULL;
    }
    newsdpmap->shared = vshared;
    if (newsdpmap->shared) {
        newsdpmap->shared->refs ++;
    }

    HASH_ADD_KEYPTR(hh_sdp, vint->cin_sdp_map, &(newsdpmap->sdpkey),
            sizeof(sip_sdp_identifier_t), newsdpmap);

    return newsdpmap;
}


static voipcinmap_t *update_cin_callid_map(voipcinmap_t **cinmap,
        char *callid, voipintshared_t *vshared,
        char *targetuser, char *targetrealm, struct timeval *tv) {

    voipcinmap_t *newcinmap;

    HASH_FIND(hh_callid, *cinmap, callid, strlen(callid), newcinmap);
    if (newcinmap) {
        return newcinmap;
    }

    newcinmap = (voipcinmap_t *)malloc(sizeof(voipcinmap_t));
    if (!newcinmap) {
        logger(LOG_INFO,
                "OpenLI: out of memory in SIP worker thread");
        logger(LOG_INFO,
                "OpenLI: forcing collector to halt immediately.");
        exit(-2);
    }
    newcinmap->lastsip = tv->tv_sec;
    newcinmap->callid = strdup(callid);
    newcinmap->username = strdup(targetuser);
    if (targetrealm) {
        newcinmap->realm = strdup(targetrealm);
    } else {
        newcinmap->realm = NULL;
    }
    newcinmap->shared = vshared;
    if (newcinmap->shared) {
        newcinmap->shared->refs ++;
    }
    newcinmap->smsonly = 1;     // for now...

    HASH_ADD_KEYPTR(hh_callid, *cinmap, newcinmap->callid,
            strlen(newcinmap->callid), newcinmap);
    return newcinmap;
}

static void remove_cin_callid_from_map(voipcinmap_t **cinmap, char *callid) {

    voipcinmap_t *c;
    HASH_FIND(hh_callid, *cinmap, callid, strlen(callid), c);
    if (c) {
        HASH_DELETE(hh_callid, *cinmap, c);
        if (c->shared) {
            c->shared->refs --; 
            if (c->shared->refs == 0) {
                free(c->shared);
            }
        }
        if (c->username) {
            free(c->username);
        }
        if (c->realm) {
            free(c->realm);
        }
        free(c->callid);
        free(c);
    }
}

static rtpstreaminf_t *create_new_voipcin(rtpstreaminf_t **activecins,
        uint32_t cin_id, voipintercept_t *vint) {

    rtpstreaminf_t *newcin;

    newcin = create_rtpstream(vint, cin_id);
    if (!newcin) {
        logger(LOG_INFO,
                "OpenLI: out of memory while creating new RTP stream in SIP worker thread");
        logger(LOG_INFO,
                "OpenLI: forcing collector to halt.");
        exit(-2);
    }

    HASH_ADD_KEYPTR(hh, *activecins, newcin->streamkey,
            strlen(newcin->streamkey), newcin);
    return newcin;
}

static voipintshared_t *create_new_voip_session(openli_sip_worker_t *sipworker,
        char *callid, sip_sdp_identifier_t *sdpo, voipintercept_t *vint,
        openli_sip_identity_t *targetuser, rtpstreaminf_t **thisrtp,
        struct timeval *tv) {

    uint32_t cin_id = 0;
    voipintshared_t *vshared = NULL;

    cin_id = hashlittle(callid, strlen(callid), 0xceefface);
    cin_id = (cin_id % (uint32_t)(pow(2, 31)));

    (*thisrtp) = create_new_voipcin(&(vint->active_cins), cin_id, vint);
    if (*thisrtp == NULL) {
        return NULL;
    }

    logger(LOG_INFO,
            "OpenLI: SIP worker %d is creating a new VOIP session for LIID %s (callID=%s)",
            sipworker->workerid, vint->common.liid, callid);

    vshared = (voipintshared_t *)malloc(sizeof(voipintshared_t));
    vshared->cin = cin_id;
    vshared->refs = 0;

    if (update_cin_callid_map(&(vint->cin_callid_map), callid,
                vshared, targetuser->username, targetuser->realm, tv) == NULL) {
        free(vshared);
        return NULL;
    }

    if (update_cin_callid_map(&(sipworker->knowncallids), callid, NULL,
                targetuser->username, targetuser->realm, tv) == NULL) {
        remove_cin_callid_from_map(&(vint->cin_callid_map), callid);
        free(vshared);
        return NULL;
    }

    if (sdpo && update_cin_sdp_map(vint, sdpo, vshared,
                targetuser->username, targetuser->realm) == NULL) {
        remove_cin_callid_from_map(&(vint->cin_callid_map), callid);
        remove_cin_callid_from_map(&(sipworker->knowncallids), callid);

        free(vshared);
        return NULL;
    }
    return vshared;
}

static sipregister_t *create_new_voip_registration(
        openli_sip_worker_t *sipworker, voipintercept_t *vint,
        char *callid, openli_sip_identity_t *targetuser, struct timeval *tv) {

    sipregister_t *newreg = NULL;
    uint32_t cin_id = 0;
    voipcinmap_t *newcin = NULL;

    newcin = update_cin_callid_map(&(sipworker->knowncallids), callid, NULL,
            targetuser->username, targetuser->realm, tv);
    if (newcin == NULL) {
        remove_cin_callid_from_map(&(vint->cin_callid_map), callid);
        return NULL;
    }
    newcin->smsonly = 0;

    HASH_FIND(hh, vint->active_registrations, callid, strlen(callid), newreg);
    if (!newreg) {
        cin_id = hashlittle(callid, strlen(callid), 0xceefface);
        cin_id = (cin_id % (uint32_t)(pow(2, 31)));
        newreg = create_sipregister(vint, callid, cin_id);

        HASH_ADD_KEYPTR(hh, vint->active_registrations, newreg->callid,
                strlen(newreg->callid), newreg);
    }

    return newreg;
}

static int process_sip_register(openli_sip_worker_t *sipworker, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt,
        openli_location_t *locptr, int loc_cnt) {

    openli_sip_identity_t *matched = NULL;
    voipintercept_t *vint, *tmp;
    sipregister_t *sipreg;
    int exportcount = 0;
    uint8_t trust_sip_from;
    struct timeval tv;

    openli_sip_identity_set_t all_identities;

    locptr = NULL;
    loc_cnt = 0;

    if (extract_sip_identities(sipworker->sipparser, &all_identities,
            sipworker->debug.log_bad_sip) < 0) {
        sipworker->debug.log_bad_sip = 0;
        return -1;
    }

    pthread_rwlock_rdlock(sipworker->shared_mutex);
    trust_sip_from = sipworker->shared->trust_sip_from;
    pthread_rwlock_unlock(sipworker->shared_mutex);

    gettimeofday(&tv, NULL);
    HASH_ITER(hh_liid, sipworker->voipintercepts, vint, tmp) {
        sipreg = NULL;

        matched = match_sip_target_against_identities(vint->targets,
                &all_identities, trust_sip_from);
        if (matched == NULL) {
            continue;
        }
        sipreg = create_new_voip_registration(sipworker, vint, callid, matched,
                &tv);
        if (!sipreg) {
            continue;
        }
        create_sip_ipmmiri(sipworker, vint, irimsg, ETSILI_IRI_REPORT,
                sipreg->cin, locptr, loc_cnt, pkts, pkt_cnt);
        exportcount += 1;
    }

    release_openli_sip_identity_set(&all_identities);

    return exportcount;

}

static rtpstreaminf_t *match_call_to_intercept(openli_sip_worker_t *sipworker,
        voipintercept_t *vint, char *callid, sip_sdp_identifier_t *sdpo,
        etsili_iri_type_t *iritype, uint32_t *cin, uint8_t trust_sip_from,
        struct timeval *tv, openli_sip_identity_set_t *all_identities) {

    openli_sip_identity_t *matched = NULL;
    voipintshared_t *vshared;
    voipcinmap_t *lookup;
    rtpstreaminf_t *thisrtp;
    voipsdpmap_t *lookup_sdp = NULL;
    char rtpkey[256];

    vshared = NULL;
    HASH_FIND(hh_callid, vint->cin_callid_map, callid, strlen(callid),
            lookup);

    if (!sipworker->ignore_sdpo_matches && sdpo != NULL) {
        HASH_FIND(hh_sdp, vint->cin_sdp_map, sdpo,
                sizeof(sip_sdp_identifier_t), lookup_sdp);
    }

    if (lookup) {
        if (lookup_sdp) {
            if (lookup->shared->cin != lookup_sdp->shared->cin) {
                if (sipworker->debug.log_bad_sip) {
                    logger(LOG_INFO, "OpenLI: mismatched CINs for call %s and SDP identifier %u:%u:%s:%s",
                            callid, sdpo->sessionid, sdpo->version,
                            sdpo->username, sdpo->address);
                }
                return NULL;
            }
        }
        if (sdpo) {
            update_cin_sdp_map(vint, sdpo, lookup->shared, lookup->username,
                    lookup->realm);
        }
        lookup->lastsip = tv->tv_sec;
        *iritype = ETSILI_IRI_CONTINUE;
        vshared = lookup->shared;
    } else if (lookup_sdp) {
        /* The SDP identifiers match but the call ID is new, so this must
         * be a new leg for a call we have already seen
         */
        update_cin_callid_map(&(vint->cin_callid_map), callid,
                lookup_sdp->shared, lookup_sdp->username, lookup_sdp->realm,
                tv);
        vshared = lookup_sdp->shared;
        *iritype = ETSILI_IRI_CONTINUE;
    } else {
        /* Call is definitely new, so check if any of the identities in the
         * SIP message match any of the targets for this intercept
         */
        matched = match_sip_target_against_identities(vint->targets,
                all_identities, trust_sip_from);
        if (matched == NULL) {
            return NULL;
        }
        vshared = create_new_voip_session(sipworker, callid, NULL, vint,
                matched, &thisrtp, tv);
        *iritype = ETSILI_IRI_BEGIN;
    }

    if (*iritype != ETSILI_IRI_BEGIN) {
        /* Grab the existing RTP stream instance for this call */
        snprintf(rtpkey, 256, "%s-%u", vint->common.liid, vshared->cin);
        HASH_FIND(hh, vint->active_cins, rtpkey, strlen(rtpkey), thisrtp);

        if (thisrtp == NULL) {
            if (sipworker->debug.log_bad_sip) {
                logger(LOG_INFO, "OpenLI: SIP worker %d was unable to find %u inthe active call list for LIID %s",
                        sipworker->workerid, vshared->cin, vint->common.liid);
            }
            return NULL;
        }
    }

    *cin = vshared->cin;
    return thisrtp;

}

static int process_sip_message(openli_sip_worker_t *sipworker, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt,
        openli_location_t *locptr, int loc_cnt) {

    voipintercept_t *vint, *tmp;
    uint8_t trust_sip_from;
    etsili_iri_type_t iritype = ETSILI_IRI_BEGIN;
    rtpstreaminf_t *thisrtp;
    uint32_t cin = 0;
    struct timeval tv;
    int exportcount = 0;
    openli_sip_identity_set_t all_identities;

    if (extract_sip_identities(sipworker->sipparser, &all_identities,
            sipworker->debug.log_bad_sip) < 0) {
        sipworker->debug.log_bad_sip = 0;
        return -1;
    }

    pthread_rwlock_rdlock(sipworker->shared_mutex);
    trust_sip_from = sipworker->shared->trust_sip_from;
    pthread_rwlock_unlock(sipworker->shared_mutex);

    gettimeofday(&tv, NULL);

    HASH_ITER(hh_liid, sipworker->voipintercepts, vint, tmp) {
        thisrtp = match_call_to_intercept(sipworker, vint, callid, NULL,
                &iritype, &cin, trust_sip_from, &tv, &all_identities);
        if (thisrtp == NULL) {
            continue;
        }
        if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
            /* TODO set a flag so that the encoder knows we need to use
             * iRIOnlySIPMessage as our IPMMIRIContents
             */
            mask_sms_message_content(irimsg->data.ipmmiri.content,
                    irimsg->data.ipmmiri.contentlen);
        }

        create_sip_ipmmiri(sipworker, vint, irimsg, iritype,
                (int64_t)cin, locptr, loc_cnt, pkts, pkt_cnt);
        exportcount ++;
    }

    release_openli_sip_identity_set(&all_identities);
    return exportcount;
}

static inline int lookup_sip_callid(openli_sip_worker_t *sipworker,
        char *callid) {

    voipcinmap_t *lookup;

    HASH_FIND(hh_callid, sipworker->knowncallids, callid, strlen(callid),
            lookup);
    if (!lookup) {
        return 0;
    }
    return 1;
}


int sipworker_update_sip_state(openli_sip_worker_t *sipworker,
        libtrace_packet_t **pkts,
        int pkt_cnt, openli_export_recv_t *irimsg) {


    char *callid;
    sip_sdp_identifier_t sdpo;
    int iserr = 0;
    int ret = 0;
    openli_location_t *locptr;
    int loc_cnt = 0;

    callid = get_sip_callid(sipworker->sipparser);

    if (callid == NULL) {
        if (sipworker->debug.log_bad_sip) {
            logger(LOG_INFO, "OpenLI: SIP packet has no Call ID?");
        }
        iserr = 1;
        goto sipgiveup;
    }

    get_sip_paccess_network_info(sipworker->sipparser, &locptr, &loc_cnt);

    populate_sdp_identifier(sipworker->sipparser, &sdpo,
            sipworker->debug.log_bad_sip, callid);

    if (sip_is_message(sipworker->sipparser)) {
        if (( ret = process_sip_message(sipworker, callid, irimsg, pkts,
                        pkt_cnt, locptr, loc_cnt)) < 0) {
            iserr = 1;
            if (sipworker->debug.log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error in SIP worker thread %d while processing MESSAGE message", sipworker->workerid);
            }
            goto sipgiveup;
        }
    } else if (sip_is_invite(sipworker->sipparser)) {

    } else if (sip_is_register(sipworker->sipparser)) {
        if (( ret = process_sip_register(sipworker, callid, irimsg, pkts,
                        pkt_cnt, locptr, loc_cnt)) < 0) {
            iserr = 1;
            if (sipworker->debug.log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error in SIP worker thread %d while processing REGISTER message", sipworker->workerid);
            }
            goto sipgiveup;
        }
    } else if (lookup_sip_callid(sipworker, callid) != 0) {

    }

sipgiveup:
    if (locptr) {
        free(locptr);
    }
    if (iserr) {
        pthread_mutex_lock(sipworker->stats_mutex);
        sipworker->stats->bad_sip_packets ++;
        pthread_mutex_unlock(sipworker->stats_mutex);
        return -1;
    }
    return 1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
