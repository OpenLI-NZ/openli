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

#include "util.h"
#include "logger.h"
#include "x2x3_ingest.h"
#include "collector_publish.h"
#include "netcomms.h"
#include "openli_tls.h"
#include "collector.h"
#include "intercept.h"
#include "ipmmiri.h"

#include <sys/timerfd.h>
#include <unistd.h>
#include <zmq.h>

#define MAX_ZPOLL_X2X3 (1024)

static inline int64_t x2x3_correlation_to_cin(uint64_t correlation) {

    return (int64_t)(hashlittle(&correlation, sizeof(correlation), 78877));
}

static int x2x3_ssl_read_error(const char *str, size_t len, void *userdata) {

    (void)userdata;
    (void)len;

    logger(LOG_INFO, "OpenLI: SSL_read() error was '%s'", str);
    return 1;
}

static int x2x3_ssl_write_error(const char *str, size_t len, void *userdata) {

    (void)userdata;
    (void)len;

    logger(LOG_INFO, "OpenLI: SSL_write() error was '%s'", str);
    return 1;
}

static int setup_zmq_sockets_for_x2x3(x_input_t *xinp) {
    int zero = 0;
    char sockname[1024];

    xinp->zmq_ctrlsock = zmq_socket(xinp->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 1024, "inproc://openlix2x3_sync-%s", xinp->identifier);
    if (zmq_bind(xinp->zmq_ctrlsock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: X2X3 thread %s failed to bind to control ZMQ: %s",
                xinp->identifier, strerror(errno));
        return -1;
    }

    if (zmq_setsockopt(xinp->zmq_ctrlsock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO,
                "OpenLI: X2X3 thread %s failed to configure control ZMQ: %s",
                xinp->identifier, strerror(errno));
        return -1;
    }

    xinp->zmq_pubsocks = calloc(xinp->tracker_threads, sizeof(void *));
    init_zmq_socket_array(xinp->zmq_pubsocks, xinp->tracker_threads,
            "inproc://openlipub", xinp->zmq_ctxt, -1);

    return 0;
}

static void purge_dead_clients(x_input_t *xinp) {
    size_t i, newsize, newcnt;

    x_input_client_t *replace;

    if (xinp->clients == NULL || xinp->client_count == 0) {
        return;
    }

    if (xinp->dead_clients < 4) {
        return;
    }

    newcnt = 0;
    newsize = xinp->client_count;
    replace = calloc(xinp->client_count, sizeof(x_input_client_t));

    for (i = 0; i < xinp->client_count; i++) {
        if (xinp->clients[i].fd == -1 && xinp->clients[i].ssl == NULL &&
                xinp->clients[i].buffer == NULL) {
            continue;
        }

        memcpy(&replace[newcnt], &(xinp->clients[i]), sizeof(x_input_client_t));
        newcnt ++;
    }
    free(xinp->clients);
    xinp->clients = replace;
    xinp->client_count = newcnt;
    xinp->dead_clients = 0;
    xinp->client_array_size = newsize;

}

static void free_single_x2x3_sip_session(x2x3_sip_session_t *xs) {
    if (xs == NULL) {
        return;
    }
    if (xs->callid) {
        free(xs->callid);
    }
    if (xs->byecseq) {
        free(xs->byecseq);
    }
    free(xs);
}

static void clear_x2x3_sessions(x2x3_sip_session_t **sesslist) {
    x2x3_sip_session_t *xs, *tmp;

    HASH_ITER(hh, *sesslist, xs, tmp) {
        HASH_DELETE(hh, *sesslist, xs);
        free_single_x2x3_sip_session(xs);
    }
}

static void tidyup_x2x3_ingest_thread(x_input_t *xinp) {
    /* close all client connections */
    /* close listening socket */
    /* close push ZMQs */
    /* close pull ZMQ */
    /* free remaining state */

    size_t i;
    ipintercept_t *x_ip, *iptmp;
    voipintercept_t *x_voip, *voiptmp;

    HASH_ITER(hh_xid, xinp->ipxids, x_ip, iptmp) {
        HASH_DELETE(hh_xid, xinp->ipxids, x_ip);
    }

    HASH_ITER(hh_xid, xinp->voipxids, x_voip, voiptmp) {
        HASH_DELETE(hh_xid, xinp->voipxids, x_voip);
    }

    free_all_ipintercepts(&(xinp->ipintercepts));
    free_all_voipintercepts(&(xinp->voipintercepts));

    clear_x2x3_sessions(&(xinp->sip_active_calls));
    clear_x2x3_sessions(&(xinp->sip_registrations));
    clear_x2x3_sessions(&(xinp->sip_active_messages));
    clear_x2x3_sessions(&(xinp->sip_other_sessions));

    if (xinp->clients) {
        for (i = 0; i < xinp->client_count; i++) {
            if (xinp->clients[i].fd != -1) {
                close(xinp->clients[i].fd);
            }
            if (xinp->clients[i].ssl) {
                SSL_free(xinp->clients[i].ssl);
            }
            if (xinp->clients[i].buffer) {
                free(xinp->clients[i].buffer);
            }
            if (xinp->clients[i].clientip) {
                free(xinp->clients[i].clientip);
            }
        }
        free(xinp->clients);
    }

    if (xinp->zmq_ctrlsock) {
        zmq_close(xinp->zmq_ctrlsock);
    }
    clear_zmq_socket_array(xinp->zmq_pubsocks, xinp->tracker_threads);

    if (xinp->listener_fd != -1) {
        close(xinp->listener_fd);
    }

    if (xinp->sipparser) {
        release_sip_parser(xinp->sipparser);
    }

    /* Let the sync thread know that this thread is ready to join */
    if (xinp->haltinfo) {
        pthread_mutex_lock(&(xinp->haltinfo->mutex));
        xinp->haltinfo->halted ++;
        pthread_cond_signal(&(xinp->haltinfo->cond));
        pthread_mutex_unlock(&(xinp->haltinfo->mutex));
    }
}

#define UPDATE_STRING_FIELD(dst, src, dstlen) \
    if (dst) { \
        if (src == NULL) { \
            free(dst); dst = NULL; \
        } else if (strcmp(dst,src) != 0) { \
            free(dst); dst = src; src = NULL; dstlen=strlen(dst); \
        } \
    } else { \
        dst = src; src = NULL; dstlen=strlen(dst); \
    }

static inline void update_intercept_common(published_intercept_msg_t *src,
        intercept_common_t *dst, uint32_t destid) {

    int unused;

    UPDATE_STRING_FIELD(dst->authcc, src->authcc, dst->authcc_len)
    UPDATE_STRING_FIELD(dst->delivcc, src->delivcc, dst->delivcc_len)
    UPDATE_STRING_FIELD(dst->encryptkey, src->encryptkey, unused)
    UPDATE_STRING_FIELD(dst->targetagency, src->targetagency, unused)

    dst->destid = destid;
    dst->seqtrackerid = src->seqtrackerid;
    dst->encrypt = src->encryptmethod;
    uuid_copy(dst->xid, src->xid);
    (void)unused;
}

static inline void populate_intercept_common(published_intercept_msg_t *src,
        intercept_common_t *dst, uint32_t destid) {

    dst->liid = src->liid;
    dst->authcc = src->authcc;
    dst->delivcc = src->delivcc;
    dst->destid = destid;
    dst->targetagency = src->targetagency;
    dst->seqtrackerid = src->seqtrackerid;
    dst->encrypt = src->encryptmethod;
    dst->encryptkey = src->encryptkey;
    uuid_copy(dst->xid, src->xid);

    if (dst->liid) {
        dst->liid_len = strlen(dst->liid);
    }
    if (dst->authcc) {
        dst->authcc_len = strlen(dst->authcc);
    }
    if (dst->delivcc) {
        dst->delivcc_len = strlen(dst->delivcc);
    }

    src->liid = NULL;
    src->authcc = NULL;
    src->delivcc = NULL;
    src->encryptkey = NULL;
    src->targetagency = NULL;
}

static inline uint8_t x2x3dir_to_etsidir(uint16_t xdir) {
    switch(xdir) {
        case X2X3_DIRECTION_RESERVED:
        case X2X3_DIRECTION_MULTIPLE:
        case X2X3_DIRECTION_UNKNOWN:
        case X2X3_DIRECTION_NA:
            return ETSI_DIR_INDETERMINATE;
        case X2X3_DIRECTION_TO_TARGET:
            return ETSI_DIR_TO_TARGET;
        case X2X3_DIRECTION_FROM_TARGET:
            return ETSI_DIR_FROM_TARGET;
    }
    return ETSI_DIR_INDETERMINATE;
}

static int send_x2x3_ka_response(x_input_t *xinp,
        x_input_client_t *client, uint32_t seqno) {

    uint8_t buf[1024];
    x2x3_base_header_t *hdr = (x2x3_base_header_t *)buf;
    uint16_t *ptr;
    uint32_t *ptrseq;
    int r;

    hdr->version = htons(0x0005);
    hdr->pdutype = htons(X2X3_PDUTYPE_KEEPALIVE_ACK);
    hdr->hdrlength = htonl(sizeof(x2x3_base_header_t) + 8);
    hdr->payloadlength = 0;
    hdr->payloadfmt = 0;
    hdr->payloaddir = 0;
    uuid_clear(hdr->xid);
    hdr->correlation = 0;

    ptr = (uint16_t *)(buf + sizeof(x2x3_base_header_t));
    *ptr = htons(X2X3_COND_ATTR_SEQNO);
    ptr ++;
    *ptr = htons(sizeof(uint32_t));
    ptr ++;

    ptrseq = (uint32_t *)ptr;
    *ptrseq = htonl(seqno);

    if (xinp->use_tls && client->ssl) {
        if ((r = SSL_write(client->ssl, buf, ntohl(hdr->hdrlength))) < 0) {
            int err = SSL_get_error(client->ssl, r);
            if (err == SSL_ERROR_SSL) {
                ERR_print_errors_cb(x2x3_ssl_write_error, NULL);
                return -1;
            } else if (err == SSL_ERROR_ZERO_RETURN) {
                logger(LOG_INFO,
                        "OpenLI: X2/X3 connection closed by remote peer");
                return -1;
            } else if (err == SSL_ERROR_SYSCALL) {
                logger(LOG_INFO, "OpenLI: X2/X3 connection reported error when sending keepalive: %s", strerror(errno));
                return -1;
            }
            return 0;
        }
    } else if (client->fd != -1) {
        if ((r = send(client->fd, buf, ntohl(hdr->hdrlength), 0)) <= 0) {
            logger(LOG_INFO, "OpenLI: X2/X3 instance %s was unable to send a keepalive response to %s: %s",
                    xinp->identifier, client->clientip, strerror(errno));
            return -1;
        }
    }

    return 1;
}

static inline int get_x2x3_pdu_seqno(x2x3_cond_attr_t **cond_attrs,
        uint32_t *seqno) {

    if (cond_attrs[X2X3_COND_ATTR_SEQNO] == NULL ||
            cond_attrs[X2X3_COND_ATTR_SEQNO]->is_parsed == 0) {
        return -1;
    }

    *seqno = cond_attrs[X2X3_COND_ATTR_SEQNO]->parsed.as_u32;
    return 1;
}

static inline void get_x2x3_pdu_timestamp(struct timeval *tv,
        x2x3_cond_attr_t **cond_attrs) {

    if (cond_attrs[X2X3_COND_ATTR_TIMESTAMP] == NULL ||
            cond_attrs[X2X3_COND_ATTR_TIMESTAMP]->is_parsed == 0) {
        gettimeofday(tv, NULL);
    } else {
        tv->tv_sec = cond_attrs[X2X3_COND_ATTR_TIMESTAMP]->parsed.as_u64;
        tv->tv_usec = cond_attrs[X2X3_COND_ATTR_TIMESTAMP]->parsed.as_u64;

        tv->tv_sec = (tv->tv_sec >> 32);
        tv->tv_usec = (tv->tv_usec & 0xFFFFFFFF) / 1000;
    }
}

static x2x3_sip_session_t *create_x2x3_sip_session(char *callid,
        uint8_t sesstype) {

    x2x3_sip_session_t *xs;

    xs = calloc(1, sizeof(x2x3_sip_session_t));
    xs->callid = strdup(callid);
    xs->sesstype = sesstype;
    xs->lastseen = 0;
    xs->byecseq = NULL;
    xs->byematched = 0;

    return xs;
}

static void copy_source_address_into_ipmmiri_job(openli_export_recv_t *msg,
        x2x3_cond_attr_t **cond_attrs) {

    if (cond_attrs[X2X3_COND_ATTR_SOURCE_IPV4_ADDRESS] &&
            cond_attrs[X2X3_COND_ATTR_SOURCE_IPV4_ADDRESS]->is_parsed) {

        msg->data.ipmmiri.ipfamily = AF_INET;
        memcpy(msg->data.ipmmiri.ipsrc,
                cond_attrs[X2X3_COND_ATTR_SOURCE_IPV4_ADDRESS]->parsed.as_octets,
                16);
    } else if (cond_attrs[X2X3_COND_ATTR_SOURCE_IPV6_ADDRESS] &&
            cond_attrs[X2X3_COND_ATTR_SOURCE_IPV6_ADDRESS]->is_parsed) {

        msg->data.ipmmiri.ipfamily = AF_INET6;
        memcpy(msg->data.ipmmiri.ipsrc,
                cond_attrs[X2X3_COND_ATTR_SOURCE_IPV6_ADDRESS]->parsed.as_octets,
                16);

    }

}

static void copy_dest_address_into_ipmmiri_job(openli_export_recv_t *msg,
        x2x3_cond_attr_t **cond_attrs) {

    if (cond_attrs[X2X3_COND_ATTR_DEST_IPV4_ADDRESS] &&
            cond_attrs[X2X3_COND_ATTR_DEST_IPV4_ADDRESS]->is_parsed) {

        msg->data.ipmmiri.ipfamily = AF_INET;
        memcpy(msg->data.ipmmiri.ipdest,
                cond_attrs[X2X3_COND_ATTR_DEST_IPV4_ADDRESS]->parsed.as_octets,
                16);
    } else if (cond_attrs[X2X3_COND_ATTR_DEST_IPV6_ADDRESS] &&
            cond_attrs[X2X3_COND_ATTR_DEST_IPV6_ADDRESS]->is_parsed) {

        msg->data.ipmmiri.ipfamily = AF_INET6;
        memcpy(msg->data.ipmmiri.ipdest,
                cond_attrs[X2X3_COND_ATTR_DEST_IPV6_ADDRESS]->parsed.as_octets,
                16);

    }

}

static int x2x3_process_sip_message(x_input_t *xinp, char *callid,
        etsili_iri_type_t *iritype, x2x3_cond_attr_t **cond_attrs) {

    x2x3_sip_session_t *xs;
    struct timeval tv;

    HASH_FIND(hh, xinp->sip_active_messages, callid, strlen(callid), xs);
    if (!xs) {
        xs = create_x2x3_sip_session(callid, X2X3_SIP_SESSION_TYPE_MESSAGE);
        if (!xs) {
            return -1;
        }
        HASH_ADD_KEYPTR(hh, xinp->sip_active_messages, xs->callid,
                strlen(xs->callid), xs);
        *iritype = ETSILI_IRI_BEGIN;
    } else {
        *iritype = ETSILI_IRI_CONTINUE;
    }

    get_x2x3_pdu_timestamp(&tv, cond_attrs);
    xs->lastseen = tv.tv_sec;
    return 1;
}

static int x2x3_process_sip_invite(x_input_t *xinp, char *callid,
        etsili_iri_type_t *iritype, x2x3_cond_attr_t **cond_attrs) {

    x2x3_sip_session_t *xs;
    struct timeval tv;

    HASH_FIND(hh, xinp->sip_active_calls, callid, strlen(callid), xs);
    if (!xs) {
        xs = create_x2x3_sip_session(callid, X2X3_SIP_SESSION_TYPE_CALL);
        if (!xs) {
            return -1;
        }
        HASH_ADD_KEYPTR(hh, xinp->sip_active_calls, xs->callid,
                strlen(xs->callid), xs);
        *iritype = ETSILI_IRI_BEGIN;
    } else {
        // re-invites should be a CONTINUE
        *iritype = ETSILI_IRI_CONTINUE;
    }

    get_x2x3_pdu_timestamp(&tv, cond_attrs);
    xs->lastseen = tv.tv_sec;
    return 1;
}

static int x2x3_process_sip_register(x_input_t *xinp, char *callid,
        etsili_iri_type_t *iritype, x2x3_cond_attr_t **cond_attrs) {

    x2x3_sip_session_t *xs;
    struct timeval tv;

    *iritype = ETSILI_IRI_REPORT;

    HASH_FIND(hh, xinp->sip_registrations, callid, strlen(callid), xs);
    if (!xs) {
        xs = create_x2x3_sip_session(callid, X2X3_SIP_SESSION_TYPE_REGISTER);
        if (!xs) {
            return -1;
        }
        HASH_ADD_KEYPTR(hh, xinp->sip_registrations, xs->callid,
                strlen(xs->callid), xs);
    }

    get_x2x3_pdu_timestamp(&tv, cond_attrs);
    xs->lastseen = tv.tv_sec;
    return 1;
}

static int x2x3_process_sip_other(x_input_t *xinp, char *callid,
        etsili_iri_type_t *iritype, x2x3_cond_attr_t **cond_attrs) {

    x2x3_sip_session_t *xs;
    struct timeval tv;

    *iritype = ETSILI_IRI_CONTINUE;

    HASH_FIND(hh, xinp->sip_active_calls, callid, strlen(callid), xs);
    if (xs) {
        /* continuation of a call that started with an INVITE */
        if (sip_is_bye(xinp->sipparser) || sip_is_cancel(xinp->sipparser)) {
            if (xs->byematched) {
                *iritype = ETSILI_IRI_REPORT;
            } else {
                if (xs->byecseq) {
                    free(xs->byecseq);
                }
                xs->byecseq = get_sip_cseq(xinp->sipparser);
                *iritype = ETSILI_IRI_CONTINUE;
            }
            goto endother;
        }

        if (sip_is_200ok(xinp->sipparser)) {
            if (xs->byecseq && xs->byematched == 0) {
                char *cseqstr = get_sip_cseq(xinp->sipparser);
                if (strcmp(cseqstr, xs->byecseq) == 0) {
                    *iritype = ETSILI_IRI_END;
                    xs->byematched = 1;
                }
                free(cseqstr);
            } else {
                *iritype = ETSILI_IRI_CONTINUE;
            }
            goto endother;
        }
        *iritype = ETSILI_IRI_CONTINUE;
        goto endother;
    }

    HASH_FIND(hh, xinp->sip_registrations, callid, strlen(callid), xs);
    if (xs) {
        /* continuation of a REGISTER */
        *iritype = ETSILI_IRI_REPORT;
        if (sip_is_200ok(xinp->sipparser)) {
            /* registration successful, we can probably remove this callid? */
            HASH_DELETE(hh, xinp->sip_registrations, xs);
            free_single_x2x3_sip_session(xs);
            xs = NULL;
        }
        goto endother;
    }

    HASH_FIND(hh, xinp->sip_active_messages, callid, strlen(callid), xs);
    if (xs) {
        /* probably the reply to a MESSAGE */
        if (sip_is_response(xinp->sipparser)) {
            *iritype = ETSILI_IRI_END;
            HASH_DELETE(hh, xinp->sip_active_messages, xs);
            free_single_x2x3_sip_session(xs);
            xs = NULL;
        } else {
            /* shouldn't really happen but whatever... */
            *iritype = ETSILI_IRI_CONTINUE;
        }
        goto endother;
    }

    HASH_FIND(hh, xinp->sip_other_sessions, callid, strlen(callid), xs);
    if (xs) {
        *iritype = ETSILI_IRI_CONTINUE;
    } else {
        xs = create_x2x3_sip_session(callid, X2X3_SIP_SESSION_TYPE_OTHER);
        if (!xs) {
            return -1;
        }
        HASH_ADD_KEYPTR(hh, xinp->sip_other_sessions, xs->callid,
                strlen(xs->callid), xs);
        *iritype = ETSILI_IRI_BEGIN;
    }

endother:
    if (xs) {
        get_x2x3_pdu_timestamp(&tv, cond_attrs);
        xs->lastseen = tv.tv_sec;
    }
    return 1;

}

static int x2x3_update_sip_state(x_input_t *xinp,
        openli_export_recv_t *irimsg, voipintercept_t *vint,
        x2x3_base_header_t *hdr, x2x3_cond_attr_t **cond_attrs) {

    /* mostly borrowed from sip_worker.c, but without having to keep track
     * of the RTP side of things...
     */

    char *callid;
    openli_location_t *locptr = NULL;
    int loc_cnt = 0, ret = 0;
    etsili_iri_type_t iritype = ETSILI_IRI_CONTINUE;
    uint8_t *content;

    callid = get_sip_callid(xinp->sipparser);
    if (callid == NULL) {
        logger(LOG_INFO, "OpenLI: SIP message received over X2 has no Call ID");
        return -1;
    }

    get_sip_paccess_network_info(xinp->sipparser, &locptr, &loc_cnt);
    if (sip_is_message(xinp->sipparser)) {
        ret = x2x3_process_sip_message(xinp, callid, &iritype, cond_attrs);
    } else if (sip_is_invite(xinp->sipparser)) {
        ret = x2x3_process_sip_invite(xinp, callid, &iritype, cond_attrs);
    } else if (sip_is_register(xinp->sipparser)) {
        ret = x2x3_process_sip_register(xinp, callid, &iritype, cond_attrs);
    } else {
        ret = x2x3_process_sip_other(xinp, callid, &iritype, cond_attrs);
    }

    if (ret == -1) {
        goto endsipupdate;
    }

    irimsg->destid = vint->common.destid;
    irimsg->data.ipmmiri.liid = strdup(vint->common.liid);
    irimsg->data.ipmmiri.iritype = iritype;
    irimsg->data.ipmmiri.cin = x2x3_correlation_to_cin(hdr->correlation);
    copy_source_address_into_ipmmiri_job(irimsg, cond_attrs);
    copy_dest_address_into_ipmmiri_job(irimsg, cond_attrs);
    copy_location_into_ipmmiri_job(irimsg, locptr, loc_cnt);

    content = (uint8_t *)get_sip_contents(xinp->sipparser,
            &(irimsg->data.ipmmiri.contentlen));
    if (content) {
        irimsg->data.ipmmiri.content = malloc(irimsg->data.ipmmiri.contentlen);
        memcpy(irimsg->data.ipmmiri.content, content,
                irimsg->data.ipmmiri.contentlen);
    }

    publish_openli_msg(xinp->zmq_pubsocks[vint->common.seqtrackerid],
            irimsg);

endsipupdate:
    if (locptr) {
        free(locptr);
    }

    return ret;
}

static int handle_x2_sip_pdu(x_input_t *xinp, x2x3_base_header_t *hdr,
        uint8_t *payload, uint32_t plen, x2x3_cond_attr_t **cond_attrs) {

    voipintercept_t *vint;
    openli_export_recv_t *msg;
    struct timeval tv;
    int ret;

    HASH_FIND(hh_xid, xinp->voipxids, hdr->xid, sizeof(uuid_t), vint);
    if (!vint) {
        /* We don't know this XID (or at least, it is not for a VoIP
         * intercept) so ignore it */
        return 0;
    }
    if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        return 0;
    }
    get_x2x3_pdu_timestamp(&tv, cond_attrs);

    if (vint->common.tostart_time > tv.tv_sec) {
        return 0;
    }

    if (vint->common.toend_time > 0 && vint->common.toend_time <=
            tv.tv_sec) {
        return 0;
    }

    if (vint->common.targetagency == NULL || strcmp(vint->common.targetagency,
                "pcapdisk") == 0) {
        return 0;
    }

    ret = add_sip_content_to_parser(&(xinp->sipparser), payload, plen);
    if (ret == SIP_ACTION_ERROR) {
        logger(LOG_INFO, "OpenLI: X2/X3 thread %s failed to add SIP PDU to internal parser", xinp->identifier);
        return -1;
    } else if (ret == SIP_ACTION_REASSEMBLE_TCP ||
            ret == SIP_ACTION_REASSEMBLE_IPFRAG) {
        /* these should not happen! */
        logger(LOG_INFO, "OpenLI: X2/X3 thread %s unexpectedly requested reassembly when adding SIP PDU to internal parser", xinp->identifier);
        return -1;
    } else if (ret != SIP_ACTION_USE_PACKET) {
        logger(LOG_INFO, "OpenLI: X2/X3 thread %s got unexpected return value from call to add_sip_content_to_parser(): %d", xinp->identifier, ret);
        return -1;
    }

    ret = parse_next_sip_message(xinp->sipparser, NULL, NULL);
    if (ret == 0) {
        return 0;
    }

    if (ret < 0) {
        logger(LOG_INFO, "OpenLI: X2/X3 thread %s failed to parse a SIP message received via X2, ignoring...", xinp->identifier);
        return 0;
    }

    msg = calloc(1, sizeof(openli_export_recv_t));
    msg->type = OPENLI_EXPORT_IPMMIRI;
    msg->data.ipmmiri.ipmmiri_style = OPENLI_IPMMIRI_SIP;
    msg->ts = tv;
    if (x2x3_update_sip_state(xinp, msg, vint, hdr, cond_attrs) < 0) {
        free_published_message(msg);
        return 0;
    }

    return 1;
}


static int handle_x3_rtp_pdu(x_input_t *xinp, x2x3_base_header_t *hdr,
        uint8_t *payload, uint32_t plen, x2x3_cond_attr_t **cond_attrs) {

    voipintercept_t *vint;
    openli_export_recv_t *msg;
    struct timeval tv;

    HASH_FIND(hh_xid, xinp->voipxids, hdr->xid, sizeof(uuid_t), vint);
    if (!vint) {
        /* We don't know this XID (or at least, it is not for a VoIP
         * intercept) so ignore it */
        return 0;
    }

    if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
        return 0;
    }
    get_x2x3_pdu_timestamp(&tv, cond_attrs);

    if (vint->common.tostart_time > tv.tv_sec) {
        return 0;
    }

    if (vint->common.toend_time > 0 && vint->common.toend_time <=
            tv.tv_sec) {
        return 0;
    }

    if (vint->common.targetagency == NULL || strcmp(vint->common.targetagency,
                "pcapdisk") == 0) {
        return 0;
    }

    msg = create_ipmmcc_job_from_rtp(
            x2x3_correlation_to_cin(hdr->correlation),
            vint->common.liid, vint->common.destid, payload, plen,
            x2x3dir_to_etsidir(ntohs(hdr->payloaddir)), tv);
    publish_openli_msg(xinp->zmq_pubsocks[vint->common.seqtrackerid], msg);

    return 1;
}

static int handle_x2_pdu(x_input_t *xinp, x2x3_base_header_t *hdr,
        uint32_t hlen, uint32_t plen, x2x3_cond_attr_t **cond_attrs,
        char *clientip) {

    uint8_t *payload;
    uint16_t pload_fmt;

    payload = ((uint8_t *)hdr) + hlen;

    pload_fmt = ntohs(hdr->payloadfmt);

    switch(pload_fmt) {
        case X2X3_PAYLOAD_FORMAT_SIP:
            if (handle_x2_sip_pdu(xinp, hdr, payload, plen, cond_attrs) < 0) {
                logger(LOG_INFO, "OpenLI: X2/X3 thread %s encountered an error while handling X2-SIP PDU from %s", xinp->identifier, clientip);
                return -1;
            }
            break;
        case X2X3_PAYLOAD_FORMAT_DHCP:
        case X2X3_PAYLOAD_FORMAT_RADIUS:
        case X2X3_PAYLOAD_FORMAT_EPSIRI:
        case X2X3_PAYLOAD_FORMAT_ETSI_102232:
        case X2X3_PAYLOAD_FORMAT_3GPP_33128:
        case X2X3_PAYLOAD_FORMAT_3GPP_33108:
        case X2X3_PAYLOAD_FORMAT_PROPRIETARY:
        case X2X3_PAYLOAD_FORMAT_IPV4_PACKET:
        case X2X3_PAYLOAD_FORMAT_IPV6_PACKET:
        case X2X3_PAYLOAD_FORMAT_MIME:
            // TODO support these payload types
            break;
        case X2X3_PAYLOAD_FORMAT_ETHERNET:
        case X2X3_PAYLOAD_FORMAT_RTP:
        case X2X3_PAYLOAD_FORMAT_GTP_U:
        case X2X3_PAYLOAD_FORMAT_MSRP:
        case X2X3_PAYLOAD_FORMAT_UNSTRUCTURED:
        case X2X3_PAYLOAD_FORMAT_LAST:
            // these types are not allowed in X3 PDUs
            logger(LOG_INFO, "OpenLI: X2/X3 thread %s has seen an X2 PDU with an invalid payload format from %s: %u", xinp->identifier, clientip, pload_fmt);
            return -1;
    }

    return 0;
}

static int handle_x3_pdu(x_input_t *xinp, x2x3_base_header_t *hdr,
        uint32_t hlen, uint32_t plen, x2x3_cond_attr_t **cond_attrs,
        char *clientip) {

    uint8_t *payload;
    uint16_t pload_fmt;

    payload = ((uint8_t *)hdr) + hlen;

    pload_fmt = ntohs(hdr->payloadfmt);

    switch(pload_fmt) {
        case X2X3_PAYLOAD_FORMAT_RTP:
            if (handle_x3_rtp_pdu(xinp, hdr, payload, plen, cond_attrs) < 0) {
                logger(LOG_INFO, "OpenLI: X2/X3 thread %s encountered an error while handling X3-RTP PDU from %s", xinp->identifier, clientip);
                return -1;
            }
            break;

        case X2X3_PAYLOAD_FORMAT_ETSI_102232:
        case X2X3_PAYLOAD_FORMAT_3GPP_33128:
        case X2X3_PAYLOAD_FORMAT_3GPP_33108:
        case X2X3_PAYLOAD_FORMAT_PROPRIETARY:
        case X2X3_PAYLOAD_FORMAT_IPV4_PACKET:
        case X2X3_PAYLOAD_FORMAT_IPV6_PACKET:
        case X2X3_PAYLOAD_FORMAT_ETHERNET:
        case X2X3_PAYLOAD_FORMAT_GTP_U:
        case X2X3_PAYLOAD_FORMAT_MSRP:
        case X2X3_PAYLOAD_FORMAT_MIME:
        case X2X3_PAYLOAD_FORMAT_UNSTRUCTURED:
            // TODO support these payload types
            break;

        case X2X3_PAYLOAD_FORMAT_SIP:
        case X2X3_PAYLOAD_FORMAT_DHCP:
        case X2X3_PAYLOAD_FORMAT_RADIUS:
        case X2X3_PAYLOAD_FORMAT_EPSIRI:
        case X2X3_PAYLOAD_FORMAT_LAST:
            // these types are not allowed in X3 PDUs
            logger(LOG_INFO, "OpenLI: X2/X3 thread %s has seen an X3 PDU with an invalid payload format from %s: %u", xinp->identifier, clientip, pload_fmt);
            return -1;
    }

    return 0;
}

static int parse_received_x2x3_msg(x_input_t *xinp, x_input_client_t *client) {
    size_t bufavail = client->bufwrite - client->bufread;
    x2x3_base_header_t *hdr;
    uint16_t pdutype;
    uint32_t hlen, plen;
    uint32_t seqno = 0;

    x2x3_cond_attr_t *cond_attrs[X2X3_COND_ATTR_LAST];

    memset(cond_attrs, 0, sizeof(x2x3_cond_attr_t *) * X2X3_COND_ATTR_LAST);
    /* start with the required header fields */
    if (bufavail < sizeof(x2x3_base_header_t)) {
        return 0;
    }

    hdr = (x2x3_base_header_t *)(client->buffer + client->bufread);
    pdutype = ntohs(hdr->pdutype);

    hlen = ntohl(hdr->hdrlength);
    plen = ntohl(hdr->payloadlength);

    if (bufavail < hlen + plen) {
        // not enough content for the whole message
        return 0;
    }

    if (hlen > sizeof(x2x3_base_header_t)) {
        // we have some conditional attribute to parse
        if (parse_x2x3_conditional_attributes((uint8_t *)hdr, hlen,
                    cond_attrs) < 0) {
            logger(LOG_INFO,
                    "OpenLI: %s encountered an error in parse_conditional_attributes in PDU sent by %s",
                    xinp->identifier, client->clientip);
            goto parsingfailure;
        }
    }

    switch(pdutype) {
        case X2X3_PDUTYPE_X2:
            if (handle_x2_pdu(xinp, hdr, hlen, plen, cond_attrs,
                        client->clientip) < 0) {
                logger(LOG_INFO, "OpenLI: X2X3 thread %s has been unable to parse an X2 PDU from %s", client->clientip);
                goto parsingfailure;
            }
            break;

        case X2X3_PDUTYPE_X3:
            if (handle_x3_pdu(xinp, hdr, hlen, plen, cond_attrs,
                        client->clientip) < 0) {
                logger(LOG_INFO, "OpenLI: X2X3 thread %s has been unable to parse an X3 PDU from %s", client->clientip);
                goto parsingfailure;
            }
            break;

        case X2X3_PDUTYPE_KEEPALIVE:
            if (plen != 0) {
                logger(LOG_INFO, "OpenLI: X2X3 thread %s has received a keepalive with an invalid payload length from %s.", xinp->identifier, client->clientip);
                goto parsingfailure;
            }

            if (get_x2x3_pdu_seqno(cond_attrs, &seqno) < 0) {
                /* no sequence number in the KA, ignore it because we can't
                 * send a valid reply */
                break;
            }
            /* send a keepalive response */
            if (send_x2x3_ka_response(xinp, client, seqno) < 0) {
                logger(LOG_INFO, "OpenLI: X2X3 thread %s failed to send keep alive response to %s", xinp->identifier, client->clientip);
                goto parsingfailure;
            }
            break;

        case X2X3_PDUTYPE_KEEPALIVE_ACK:
            if (plen != 0) {
                logger(LOG_INFO, "OpenLI: X2X3 thread %s has received a keepalive response with an invalid payload length from %s.", xinp->identifier,
                        client->clientip);
                goto parsingfailure;
            }

            // we shouldn't receive KA Acks, but we'll just silently ignore
            // them for now
            break;

        default:
            logger(LOG_INFO, "OpenLI: X2X3 thread %s has received a unexpected PDU type from %s: %u", xinp->identifier, pdutype, client->clientip);
            goto parsingfailure;
    }

    client->bufread += (hlen + plen);

    if (client->bufread >= client->buffer_size * 0.75) {
        bufavail = client->bufwrite - client->bufread;
        if (bufavail > 0) {
            memmove(client->buffer, client->buffer + client->bufread, bufavail);
        }
        client->bufread = 0;
        client->bufwrite = bufavail;
    }

    free_x2x3_conditional_attributes(cond_attrs);
    if (client->bufread == client->bufwrite) {
        return 0;
    }
    return 1;

parsingfailure:
    free_x2x3_conditional_attributes(cond_attrs);
    logger(LOG_INFO, "OpenLI: X2X3 thread %s is dropping client %s",
            xinp->identifier, client->clientip);
    return -1;

}

static void withdraw_xid_ipintercept(x_input_t *xinp,
        openli_export_recv_t *msg) {

    ipintercept_t *found, *x_found;

    if (msg->data.cept.liid == NULL) {
        return;
    }

    HASH_FIND(hh_liid, xinp->ipintercepts, msg->data.cept.liid,
            strlen(msg->data.cept.liid), found);
    if (!found) {
        return;
    }

    HASH_DELETE(hh_liid, xinp->ipintercepts, found);

    HASH_FIND(hh_xid, xinp->ipxids, found->common.xid, sizeof(uuid_t),
            x_found);
    if (x_found) {
        HASH_DELETE(hh_xid, xinp->ipxids, x_found);
    }
    free_single_ipintercept(found);

}

static void withdraw_xid_voipintercept(x_input_t *xinp,
        openli_export_recv_t *msg) {

    voipintercept_t *found, *x_found;

    if (msg->data.cept.liid == NULL) {
        return;
    }

    HASH_FIND(hh_liid, xinp->voipintercepts, msg->data.cept.liid,
            strlen(msg->data.cept.liid), found);
    if (!found) {
        return;
    }

    HASH_DELETE(hh_liid, xinp->voipintercepts, found);
    HASH_FIND(hh_xid, xinp->voipxids, found->common.xid, sizeof(uuid_t),
            x_found);
    if (x_found) {
        HASH_DELETE(hh_xid, xinp->voipxids, x_found);
    }
    free_single_voipintercept(found);

}

static void add_or_update_xid_voipintercept(x_input_t *xinp,
        openli_export_recv_t *msg) {

    voipintercept_t *found;

    if (msg->data.cept.liid == NULL) {
        return;
    }

    HASH_FIND(hh_liid, xinp->voipintercepts, msg->data.cept.liid,
            strlen(msg->data.cept.liid), found);
    if (found) {
        update_intercept_common(&(msg->data.cept), &(found->common),
                msg->destid);
    } else {
        found = calloc(1, sizeof(voipintercept_t));
        populate_intercept_common(&(msg->data.cept), &(found->common),
                msg->destid);
        HASH_ADD_KEYPTR(hh_liid, xinp->voipintercepts, found->common.liid,
                found->common.liid_len, found);
        HASH_ADD_KEYPTR(hh_xid, xinp->voipxids, found->common.xid,
                sizeof(uuid_t), found);
    }
}

static void add_or_update_xid_ipintercept(x_input_t *xinp,
        openli_export_recv_t *msg) {

    ipintercept_t *found;

    if (msg->data.cept.liid == NULL) {
        return;
    }

    HASH_FIND(hh_liid, xinp->ipintercepts, msg->data.cept.liid,
            strlen(msg->data.cept.liid), found);
    if (found) {
        update_intercept_common(&(msg->data.cept), &(found->common),
                msg->destid);
        UPDATE_STRING_FIELD(found->username, msg->data.cept.username,
                found->username_len);

        found->accesstype = msg->data.cept.accesstype;

    } else {
        found = calloc(1, sizeof(ipintercept_t));
        populate_intercept_common(&(msg->data.cept), &(found->common),
                msg->destid);

        found->username = msg->data.cept.username;
        msg->data.cept.username = NULL;
        found->accesstype = msg->data.cept.accesstype;

        if (found->username) {
            found->username_len = strlen(found->username);
        }
        HASH_ADD_KEYPTR(hh_liid, xinp->ipintercepts, found->common.liid,
                found->common.liid_len, found);
        HASH_ADD_KEYPTR(hh_xid, xinp->ipxids, found->common.xid,
                sizeof(uuid_t), found);
    }

}

static size_t setup_x2x3_pollset(x_input_t *xinp, zmq_pollitem_t **topoll,
        size_t *topoll_size, size_t *index_map, int timerfd) {

    size_t topoll_req = 0, i, ind;

    memset(index_map, 0, sizeof(size_t) * MAX_ZPOLL_X2X3 * 2);
    topoll_req = (3 + xinp->client_count - xinp->dead_clients);

    if (topoll_req > *topoll_size) {
        free(*topoll);
        *topoll = calloc(topoll_req + 32, sizeof(zmq_pollitem_t));
        *topoll_size = topoll_req + 32;
    }

    (*topoll)[0].socket = xinp->zmq_ctrlsock;
    (*topoll)[0].events = ZMQ_POLLIN;

    (*topoll)[1].socket = NULL;
    (*topoll)[1].fd = xinp->listener_fd;
    (*topoll)[1].events = ZMQ_POLLIN;

    (*topoll)[2].socket = NULL;
    (*topoll)[2].fd = timerfd;
    (*topoll)[2].events = ZMQ_POLLIN;

    ind = 3;

    for (i = 0; i < xinp->client_count; i++) {
        if (xinp->clients[i].fd < 0) {
            continue;
        }
        index_map[ind] = i;
        (*topoll)[ind].socket = NULL;
        (*topoll)[ind].fd = xinp->clients[i].fd;
        (*topoll)[ind].events = ZMQ_POLLIN;
        ind ++;
    }

    return topoll_req;
}

static int x2x3_process_sync_thread_message(x_input_t *xinp) {
    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(xinp->zmq_ctrlsock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error receiving message from sync thread in X2/X3 ingest thread %s: %s",
                    xinp->identifier, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            xinp->haltinfo = (halt_info_t *)(msg->data.haltinfo);
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_INTERCEPT_DETAILS) {
            if (msg->data.cept.cepttype == OPENLI_INTERCEPT_TYPE_IP) {
                add_or_update_xid_ipintercept(xinp, msg);
            }
            if (msg->data.cept.cepttype == OPENLI_INTERCEPT_TYPE_VOIP) {
                add_or_update_xid_voipintercept(xinp, msg);
            }
        }

        if (msg->type == OPENLI_EXPORT_INTERCEPT_OVER) {
            if (msg->data.cept.cepttype == OPENLI_INTERCEPT_TYPE_IP) {
                withdraw_xid_ipintercept(xinp, msg);
            }
            if (msg->data.cept.cepttype == OPENLI_INTERCEPT_TYPE_VOIP) {
                withdraw_xid_voipintercept(xinp, msg);
            }
        }

        /* TODO other messages (X1 intercepts, mainly) */
        free_published_message(msg);
    } while (x > 0);

    return 1;
}

#define X2X3_CLIENT_BUFSIZE (32 * 1024)        // TODO make this larger ;)

static int add_new_x2x3_client(x_input_t *xinp, SSL *newssl, int newfd,
        char *clientip) {

    while (xinp->client_count >= xinp->client_array_size) {
        x_input_client_t *replace = calloc(xinp->client_count + 8,
                sizeof(x_input_client_t));

        if (xinp->client_count > 0) {
            memcpy(replace, xinp->clients,
                    sizeof(x_input_client_t) * xinp->client_count);
            free(xinp->clients);
        }
        xinp->clients = replace;
        xinp->client_array_size = xinp->client_count + 8;
    }

    xinp->clients[xinp->client_count].ssl = newssl;
    xinp->clients[xinp->client_count].fd = newfd;
    xinp->clients[xinp->client_count].buffer = malloc(X2X3_CLIENT_BUFSIZE);
    xinp->clients[xinp->client_count].buffer_size = X2X3_CLIENT_BUFSIZE;
    xinp->clients[xinp->client_count].bufread = 0;
    xinp->clients[xinp->client_count].bufwrite = 0;
    xinp->clients[xinp->client_count].clientip = strdup(clientip);
    xinp->client_count ++;
    return 1;
}

static int x2x3_accept_nontls_client_connection(x_input_t *xinp) {
    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];

    newfd = accept(xinp->listener_fd, (struct sockaddr *)&saddr, &socklen);
    if (newfd == -1) {
        logger(LOG_INFO, "OpenLI: error while accepting client connection in X2-X3 thread %s: %s", xinp->identifier, strerror(errno));
        return -1;
    }
    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
                0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_INFO, "OpenLI: getnameinfo error when accepting an X2/X3 client connection: %s", strerror(errno));
        close(newfd);
        return -1;
    }

    add_new_x2x3_client(xinp, NULL, newfd, strbuf);
    return 1;
}

static int x2x3_accept_client_connection(x_input_t *xinp) {

    int r, newfd;
    SSL *newc;
    openli_ssl_config_t sslconf;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];

    newfd = accept(xinp->listener_fd, (struct sockaddr *)&saddr, &socklen);
    if (newfd == -1) {
        logger(LOG_INFO, "OpenLI: error while accepting client connection in X2-X3 thread %s: %s", xinp->identifier, strerror(errno));
        return -1;
    }
    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
                0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_INFO, "OpenLI: getnameinfo error when accepting an X2/X3 client connection: %s", strerror(errno));
        close(newfd);
        return -1;
    }

    pthread_mutex_lock(&(xinp->sslmutex));
    if (xinp->ssl_ctx == NULL) {
        if (xinp->ssl_ctx_bad == 0) {
            logger(LOG_INFO, "OpenLI: cannot accept X2-X3 connection for %s because this collector has no usable TLS configuration", xinp->identifier);
            xinp->ssl_ctx_bad = 1;
        }
        close(newfd);
        pthread_mutex_unlock(&(xinp->sslmutex));
        return -1;
    }

    sslconf.ctx = xinp->ssl_ctx;
    r = listen_ssl_socket(&sslconf, &newc, newfd);
    pthread_mutex_unlock(&(xinp->sslmutex));

    if (r == OPENLI_SSL_CONNECT_FAILED) {
        logger(LOG_INFO, "OpenLI: client %s failed to complete SSL handshake",
                strbuf);
        close(newfd);
        SSL_free(newc);
        return -1;
    }

    add_new_x2x3_client(xinp, newc, newfd, strbuf);
    return 1;
}


static int create_x2x3_listening_socket(x_input_t *xinp) {
    int sockfd;

    if (xinp->listenaddr == NULL || xinp->listenport == NULL) {
        return -1;
    }


    sockfd = create_listener(xinp->listenaddr, xinp->listenport,
            "X2-X3 listener");
    if (sockfd == -1) {
        return -1;
    }
    if (fd_set_block(sockfd) < 0) {
        return -1;
    }
    xinp->listener_fd = sockfd;
    return xinp->listener_fd;
}

static int log_ssl_read_error(x_input_t *xinp, x_input_client_t *client,
        int sslret) {

    int err = SSL_get_error(client->ssl, sslret);
    switch(err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return 0;
        case SSL_ERROR_SYSCALL:
            logger(LOG_INFO,
                    "OpenLI: X2/X3 client %s has been disconnected from %s due to an error: %s",
                    client->clientip, xinp->identifier,
                    strerror(errno));
            break;
        case SSL_ERROR_SSL:
            logger(LOG_INFO,
                    "OpenLI: X2/X3 client %s has been disconnected from %s due to an error in SSL_read()",
                    client->clientip, xinp->identifier);
            ERR_print_errors_cb(x2x3_ssl_read_error, NULL);
            break;
        case SSL_ERROR_ZERO_RETURN:

            logger(LOG_INFO,
                    "OpenLI: X2/X3 client %s has been disconnected from %s",
                    client->clientip, xinp->identifier);
            break;
    }
    return -1;
}

static int receive_client_data(x_input_t *xinp, size_t client_ind) {

    x_input_client_t *client = &(xinp->clients[client_ind]);
    size_t maxread = 0;
    int r;

    if (client_ind >= xinp->client_count || client->fd == -1 ||
            (client->ssl == NULL && xinp->use_tls)) {
        return 0;
    }

    maxread = client->buffer_size - client->bufwrite;
    if (xinp->use_tls) {
        r = SSL_read(client->ssl, client->buffer + client->bufwrite, maxread);
    } else {
        r = recv(client->fd, client->buffer + client->bufwrite, maxread,
                MSG_DONTWAIT);
    }

    if (r <= 0) {
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        if (r <= 0) {
            if (xinp->use_tls) {
                if (log_ssl_read_error(xinp, client, r) == 0) {
                    /* TLS equivalent of EAGAIN */
                    return 0;
                }
            } else {
                logger(LOG_INFO, "OpenLI: (%s) error receiving data from X2/X3 client %s: %s",
                        xinp->identifier, client->clientip, strerror(errno));
            }
        }
        /* other end is no longer connected */
        goto dropclient;
    }

    client->bufwrite += r;

    /* try to parse the data that we have in our buffer */
    do {
        r = parse_received_x2x3_msg(xinp, client);
        if (r < 0) {
            goto dropclient;
        }
    } while (r != 0);

    if (client->bufwrite >= client->buffer_size) {
        /* Buffer has filled up but we don't have a parseable X2/X3 PDU?
         * Let's drop this client because they must be sending us something
         * we don't understand (either garbage or something we don't
         * support). Either way, we can't keep buffering stuff forever so
         * better to kill it off now.
         */
        logger(LOG_INFO,
                "OpenLI: X2/X3 client %s has been disconnected from %s due to sending unknown content",
                client->clientip, xinp->identifier);
        goto dropclient;
    }

    return r;

dropclient:
    xinp->dead_clients ++;
    if (client->ssl) {
        SSL_free(client->ssl);
    }
    client->ssl = NULL;
    if (client->clientip) {
        free(client->clientip);
        client->clientip = NULL;
    }
    close(client->fd);
    client->fd = -1;
    free(client->buffer);
    client->buffer = NULL;
    return 0;
}

void x2x3_ingest_main(x_input_t *xinp) {

    zmq_pollitem_t *topoll;
    size_t topoll_size, topoll_cnt, i;
    int rc, x;
    size_t client_index_map[MAX_ZPOLL_X2X3 * 2];
    sync_epoll_t clientpurgetimer;
    struct itimerspec its;

    if (create_x2x3_listening_socket(xinp) < 0) {
        logger(LOG_INFO, "OpenLI: failed to create listening socket for X2-X3 input %s, unable to accept connections!", xinp->identifier);
        xinp->listener_fd = -1;
    }

    topoll = calloc(128, sizeof(zmq_pollitem_t));
    topoll_size = 128;

    its.it_value.tv_sec = 300;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    clientpurgetimer.fdtype = 0;
    clientpurgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(clientpurgetimer.fd, 0, &its, NULL);

    while (1) {
        topoll_cnt = setup_x2x3_pollset(xinp, &topoll, &topoll_size,
                client_index_map, clientpurgetimer.fd);

        if (topoll_cnt < 1) {
            break;
        }

        rc = zmq_poll(topoll, topoll_cnt, 50);
        if (rc < 0) {
            logger(LOG_INFO,
                    "OpenLI: error in zmq_poll in X2/X3 ingestor %s: %s",
                    xinp->identifier, strerror(errno));
            break;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            /* got a message from the sync thread */
            x = x2x3_process_sync_thread_message(xinp);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            // if this fails, we don't really care?
            if (xinp->use_tls) {
                x2x3_accept_client_connection(xinp);
            } else {
                x2x3_accept_nontls_client_connection(xinp);
            }

            topoll[1].revents = 0;
        }

        if (topoll[2].revents & ZMQ_POLLIN) {
            topoll[2].revents = 0;
            close(topoll[2].fd);

            purge_dead_clients(xinp);

            clientpurgetimer.fdtype = 0;
            clientpurgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(clientpurgetimer.fd, 0, &its, NULL);
        }

        for (i = 3; i < topoll_cnt; i++) {
            if (topoll[i].fd > 0 && topoll[i].revents & ZMQ_POLLIN) {
                receive_client_data(xinp, client_index_map[i]);
            }
        }
    }
    close(clientpurgetimer.fd);
    free(topoll);
}

void *start_x2x3_ingest_thread(void *param) {
    x_input_t *xinp = (x_input_t *)param;

    /* set up pull ZMQ to get instructions from the sync thread */
    /* set up push ZMQs */
    if (setup_zmq_sockets_for_x2x3(xinp) < 0) {
        goto haltx2x3;
    }

    /* main loop == zmq_poll on all ZMQs + listening socket + connected
     * client sockets */
    x2x3_ingest_main(xinp);


    /* shutdown */
haltx2x3:
    logger(LOG_INFO, "OpenLI: halting X2/X3 ingestor %s\n", xinp->identifier);
    tidyup_x2x3_ingest_thread(xinp);
    pthread_exit(NULL);
}

void destroy_x_input(x_input_t *xinp) {
    pthread_mutex_destroy(&(xinp->sslmutex));

    if (xinp->listenaddr) {
        free(xinp->listenaddr);
    }
    if (xinp->listenport) {
        free(xinp->listenport);
    }
    if (xinp->identifier) {
        free(xinp->identifier);
    }

    free(xinp);
}
