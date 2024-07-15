/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <amqp_tcp_socket.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <Judy.h>
#include <b64/cencode.h>
#include <openssl/evp.h>

#include "util.h"
#include "logger.h"
#include "collector_base.h"
#include "collector_publish.h"
#include "email_worker.h"
#include "netcomms.h"
#include "intercept.h"
#include "timed_intercept.h"
#include "collector.h"

static inline const char *email_type_to_string(openli_email_type_t t) {
    if (t == OPENLI_EMAIL_TYPE_POP3) {
        return "POP3";
    }
    if (t == OPENLI_EMAIL_TYPE_SMTP) {
        return "SMTP";
    }
    if (t == OPENLI_EMAIL_TYPE_IMAP) {
        return "IMAP";
    }
    return "UNKNOWN";
}

static struct sockaddr_storage *construct_sockaddr(char *ip, char *port,
        int *family) {

    struct sockaddr_storage *saddr;
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(ip, port, &hints, &res);
    if (err != 0) {
        logger(LOG_INFO, "OpenLI: error in email worker thread converting %s:%s into a socket address: %s", ip, port, strerror(errno));
        return NULL;
    }

    if (!res) {
        logger(LOG_INFO, "OpenLI: email worker thread was unable to convert %s:%s into a valid socket address?", ip, port);
        return NULL;
    }

    /* Just use the first result -- there should only be one anyway... */

    if (family) {
        *family = res->ai_family;
    }
    saddr = calloc(1, sizeof(struct sockaddr_storage));
    memcpy(saddr, res->ai_addr, res->ai_addrlen);

    char host[256];
    char serv[256];

    getnameinfo((struct sockaddr *)saddr, sizeof(struct sockaddr_storage),
            host, 256, serv, 256, NI_NUMERICHOST | NI_NUMERICSERV);

    freeaddrinfo(res);
    return saddr;
}

void replace_email_session_serveraddr(emailsession_t *sess,
        char *server_ip, char *server_port) {

    struct sockaddr_storage *repl = NULL;

    if (strcmp(server_port, "0") == 0) {
        return;
    }

    if (strcmp(server_ip, "") == 0) {
        return;
    }

    repl = construct_sockaddr(server_ip, server_port, &(sess->ai_family));
    if (repl == NULL) {
        return;
    }
    if (sess->serveraddr) {
        free(sess->serveraddr);
    }
    sess->serveraddr = repl;

}

void replace_email_session_clientaddr(emailsession_t *sess,
        char *client_ip, char *client_port) {

    struct sockaddr_storage *repl = NULL;

    if (strcmp(client_port, "0") == 0) {
        return;
    }

    if (strcmp(client_ip, "") == 0) {
        return;
    }

    repl = construct_sockaddr(client_ip, client_port, &(sess->ai_family));
    if (repl == NULL) {
        return;
    }
    if (sess->clientaddr) {
        free(sess->clientaddr);
    }
    sess->clientaddr = repl;
}

struct fraginfo {
    char *fragbuffer;
    char *posttcp;
    uint32_t plen;
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t fragoff;
    uint8_t moreflag;
};

static int handle_fragments(openli_email_worker_t *state,
        libtrace_packet_t *pkt, struct fraginfo *fraginfo) {

    libtrace_tcp_t *tcp;
    ip_reassemble_stream_t *ipstream;
    uint16_t fraglen = 0;
    uint8_t proto;
    int r;
    uint32_t rem;

    ipstream = get_ipfrag_reassemble_stream(state->fragreass, pkt);
    if (!ipstream) {
        logger(LOG_INFO, "OpenLI: error trying to reassemble IP fragment inside email worker thread");
        return -1;
    }

    r = update_ipfrag_reassemble_stream(ipstream, pkt, fraginfo->fragoff,
            fraginfo->moreflag);
    if (r < 0) {
        logger(LOG_INFO, "OpenLI: error while trying to reassemble IP fragment in email worker thread");
        return -1;
    }

    fraginfo->src_port = fraginfo->dest_port = 0;

    if ((r = get_next_ip_reassembled(ipstream, &(fraginfo->fragbuffer),
            &(fraglen), &proto)) <= 0) {
        return r;
    }

    /* packet must be reassembled at this point */
    assert(fraginfo->fragbuffer);
    tcp = (libtrace_tcp_t *)(fraginfo->fragbuffer);
    rem = fraglen;
    if (rem < sizeof(libtrace_tcp_t)) {
        logger(LOG_INFO, "OpenLI: reassembled IP fragment in email worker thread does not have a complete TCP header");
        return -1;
    }
    fraginfo->src_port = ntohs(tcp->source);
    fraginfo->dest_port = ntohs(tcp->dest);
    fraginfo->posttcp = (char *)trace_get_payload_from_tcp(tcp, &rem);
    fraginfo->plen = rem;

    remove_ipfrag_reassemble_stream(state->fragreass, ipstream);
    return 1;
}

static int convert_packet_to_email_captured(openli_email_worker_t * state,
        libtrace_packet_t *pkt,
        uint8_t emailtype, openli_email_captured_t **cap) {

    char space[256];
    int spacelen = 256;
    char ip_a[INET6_ADDRSTRLEN];
    char ip_b[INET6_ADDRSTRLEN];
    char portstr[16];
    libtrace_tcp_t *tcp;
    uint32_t rem, plen;
    uint8_t proto;
    char *posttcp = NULL;
    uint8_t pktsender = 0;
    uint8_t moreflag;
    uint16_t fragoff = 0;

    struct fraginfo fraginfo;

    uint16_t src_port, dest_port, rem_port, host_port;

    /* account for possible fragmentation */
    memset(&fraginfo, 0, sizeof(struct fraginfo));

    fragoff = trace_get_fragment_offset(pkt, &moreflag);
    if (moreflag || fragoff > 0) {
        int r;
        if ((r = handle_fragments(state, pkt, &fraginfo)) <= 0) {
            if (fraginfo.fragbuffer) {
                free(fraginfo.fragbuffer);
            }
            return r;
        }
        posttcp = fraginfo.posttcp;
        plen = fraginfo.plen;
        src_port = fraginfo.src_port;
        dest_port = fraginfo.dest_port;

    } else {
        src_port = trace_get_source_port(pkt);
        dest_port = trace_get_destination_port(pkt);
        tcp = (libtrace_tcp_t *)(trace_get_transport(pkt, &proto, &rem));
        if (tcp == NULL || proto != TRACE_IPPROTO_TCP || rem == 0) {
            return -1;
        }

        plen = trace_get_payload_length(pkt);
        posttcp = (char *)trace_get_payload_from_tcp(tcp, &rem);
        if (rem < plen) {
            plen = rem;
        }
    }

    if (src_port == 0 || dest_port == 0) {
        logger(LOG_INFO, "OpenLI: unable to derive port numbers for packet seen in email worker thread");
        goto errstate;
    }

    /* Ensure that bi-directional flows return the same session ID by
     * always putting the IP and port for the endpoint with the smallest of
     * the two ports first...
     */

    if (src_port < dest_port) {
        if (trace_get_source_address_string(pkt, ip_a, INET6_ADDRSTRLEN)
                == NULL) {
            goto errstate;
        }
        if (trace_get_destination_address_string(pkt, ip_b, INET6_ADDRSTRLEN)
                == NULL) {
            goto errstate;
        }

        rem_port = dest_port;
        host_port = src_port;
        pktsender = OPENLI_EMAIL_PACKET_SENDER_SERVER;
    } else {
        if (trace_get_source_address_string(pkt, ip_b, INET6_ADDRSTRLEN)
                == NULL) {
            goto errstate;
        }
        if (trace_get_destination_address_string(pkt, ip_a, INET6_ADDRSTRLEN)
                == NULL) {
            goto errstate;
        }
        host_port = dest_port;
        rem_port = src_port;
        pktsender = OPENLI_EMAIL_PACKET_SENDER_CLIENT;
    }

    snprintf(space, spacelen, "%s-%s-%u-%u", ip_a, ip_b, host_port,
            rem_port);

    (*cap) = calloc(1, sizeof(openli_email_captured_t));
    if (emailtype == OPENLI_UPDATE_SMTP) {
        (*cap)->type = OPENLI_EMAIL_TYPE_SMTP;
    } else if (emailtype == OPENLI_UPDATE_IMAP) {
        (*cap)->type = OPENLI_EMAIL_TYPE_IMAP;
    } else if (emailtype == OPENLI_UPDATE_POP3) {
        (*cap)->type = OPENLI_EMAIL_TYPE_POP3;
    } else {
        (*cap)->type = OPENLI_EMAIL_TYPE_UNKNOWN;
    }

    (*cap)->session_id = strdup(space);
    (*cap)->target_id = NULL;
    (*cap)->datasource = NULL;
    (*cap)->remote_ip = strdup(ip_b);
    (*cap)->host_ip = strdup(ip_a);
    (*cap)->part_id = 0xFFFFFFFF;
    (*cap)->pkt_sender = pktsender;
    (*cap)->direction = OPENLI_EMAIL_DIRECTION_UNKNOWN;

    snprintf(portstr, 16, "%u", rem_port);
    (*cap)->remote_port = strdup(portstr);
    snprintf(portstr, 16, "%u", host_port);
    (*cap)->host_port = strdup(portstr);

    (*cap)->timestamp = (trace_get_seconds(pkt) * 1000);
    (*cap)->mail_id = 0;
    (*cap)->msg_length = plen;

    if (fraginfo.fragbuffer) {
        (*cap)->own_content = 1;
        if (posttcp && (*cap)->msg_length > 0) {
            (*cap)->content = calloc((*cap)->msg_length, sizeof(char));
            memcpy((*cap)->content, posttcp, (*cap)->msg_length);
        } else {
            (*cap)->content = NULL;
        }
        free(fraginfo.fragbuffer);
    } else {
        (*cap)->own_content = 0;
        if ((*cap)->msg_length > 0 && posttcp != NULL) {
            (*cap)->content = (uint8_t *)posttcp;
        } else {
            (*cap)->content = NULL;
        }
    }
    return 1;

errstate:
    if (fraginfo.fragbuffer) {
        free(fraginfo.fragbuffer);
    }
    return -1;
}

static void init_email_session(emailsession_t *sess,
        openli_email_captured_t *cap, char *sesskey,
        openli_email_worker_t *state) {

    sess->key = strdup(sesskey);
    sess->cin = hashlittle(cap->session_id, strlen(cap->session_id),
            1872422);
    sess->session_id = strdup(cap->session_id);

    if (cap->type == OPENLI_EMAIL_TYPE_SMTP ||
            cap->type == OPENLI_EMAIL_TYPE_IMAP ||
            cap->type == OPENLI_EMAIL_TYPE_POP3) {
        sess->serveraddr = construct_sockaddr(cap->host_ip, cap->host_port,
                &sess->ai_family);
        sess->clientaddr = construct_sockaddr(cap->remote_ip, cap->remote_port,
                NULL);
    } else {
        /* TODO */
    }

    pthread_rwlock_rdlock(state->glob_config_mutex);
    if (cap->target_id && (*state->email_ingest_use_targetid)) {
        sess->ingest_target_id = strdup(cap->target_id);
    } else {
        sess->ingest_target_id = NULL;
    }
    pthread_rwlock_unlock(state->glob_config_mutex);

    sess->ingest_direction = cap->direction;

    if (cap->type == OPENLI_EMAIL_TYPE_IMAP) {
        pthread_rwlock_rdlock(state->glob_config_mutex);
        sess->mask_credentials = *(state->mask_imap_creds);
        pthread_rwlock_unlock(state->glob_config_mutex);
    } else if (cap->type == OPENLI_EMAIL_TYPE_POP3) {
        pthread_rwlock_rdlock(state->glob_config_mutex);
        sess->mask_credentials = *(state->mask_pop3_creds);
        pthread_rwlock_unlock(state->glob_config_mutex);
    } else {
        sess->mask_credentials = 0;
    }

    memset(&(sess->sender), 0, sizeof(email_participant_t));
    sess->participants = NULL;
    sess->protocol = cap->type;
    sess->currstate = 0;
    sess->compressed = 0;
    sess->timeout_ev = NULL;
    sess->proto_state = NULL;
    sess->server_octets = 0;
    sess->client_octets = 0;
    sess->held_captured = calloc(16, sizeof(void **));
    sess->held_captured_size = 16;
    sess->next_expected_captured = 0;
    sess->handle_compress = OPENLI_EMAILINT_DELIVER_COMPRESSED_NOT_SET;
    sess->ccs_sent = NULL;
    sess->iris_sent = NULL;
    sess->iricount = 0;
}

int extract_email_sender_from_body(openli_email_worker_t *state,
        emailsession_t *sess, char *bodycontent, char **extracted) {

    char fromaddr[2048];
    int found = 0;
    char *lt, *gt;
    char *fromstart, *search, *next;

    memset(fromaddr, 0, 2048);
    search = bodycontent;

    while (search) {
        next = strstr(search, "\r\n");

        if (strncasecmp(search, "From: ", 6) == 0) {
            if (next - search > 2048) {
                next = search + 2048;
            }
            memcpy(fromaddr, (search + 6), next - (search + 6));
            found = 1;
            break;
        }
        if (next) {
            search = (next + 2);
        } else {
            search = next;
        }
    }

    if (!found) {
        return 0;
    }
    /* Account for From: fields which take the form:
     *  John Smith <john.smith@example.org>
     */

    /* Note: addresses that contain '<' or '>' within quotes are going
     * to cause problems for this code...
     */
    lt = strchr(fromaddr, '<');
    gt = strrchr(fromaddr, '>');

    if (!lt || !gt || lt > gt) {
        fromstart = fromaddr;
    } else {
        fromstart = (lt + 1);
        *gt = '\0';
    }

    *extracted = strdup(fromstart);
    return 1;
}


void add_email_participant(emailsession_t *sess, char *address, int issender) {

    email_participant_t *part;

    if (!issender) {
        HASH_FIND(hh, sess->participants, address, strlen(address), part);
        if (!part) {
            part = calloc(1, sizeof(email_participant_t));
            part->emailaddr = address;
            part->is_sender = 0;
            HASH_ADD_KEYPTR(hh, sess->participants, part->emailaddr,
                    strlen(part->emailaddr), part);

        }
    } else {
        if (sess->sender.emailaddr) {
            free(sess->sender.emailaddr);
        }
        sess->sender.emailaddr = address;
        sess->sender.is_sender = 1;
    }

}

void clear_email_participant_list(emailsession_t *sess) {

    email_participant_t *part, *tmp;

    if (!sess) {
        return;
    }
    HASH_ITER(hh, sess->participants, part, tmp) {
        HASH_DELETE(hh, sess->participants, part);
        if (part->emailaddr) {
            free(part->emailaddr);
        }
        free(part);
    }

}

void clear_email_sender(emailsession_t *sess) {

    if (!sess) {
        return;
    }
    if (sess->sender.emailaddr) {
        free(sess->sender.emailaddr);
        sess->sender.emailaddr = NULL;
    }
}

static void free_email_session(openli_email_worker_t *state,
        emailsession_t *sess) {
    uint32_t i;
    Word_t rc;

    if (!sess) {
        return;
    }

    JSLFA(rc, sess->ccs_sent);
    JSLFA(rc, sess->iris_sent);

    clear_email_sender(sess);
    clear_email_participant_list(sess);

    if (sess->timeout_ev) {
        sync_epoll_t *ev, *found;
        ev = (sync_epoll_t *)sess->timeout_ev;
        HASH_FIND(hh, state->timeouts, &(ev->fd), sizeof(int), found);
        if (found) {
            HASH_DELETE(hh, state->timeouts, found);
        }
        close(ev->fd);
        free(ev);

    }

    if (sess->held_captured) {
        for (i = 0; i < sess->held_captured_size; i++) {
            if (sess->held_captured[i]) {
                free_captured_email(sess->held_captured[i]);
            }
        }

        free(sess->held_captured);
    }

    if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP) {
        free_smtp_session_state(sess, sess->proto_state);
    }

    if (sess->protocol == OPENLI_EMAIL_TYPE_IMAP) {
        free_imap_session_state(sess, sess->proto_state);
    }

    if (sess->protocol == OPENLI_EMAIL_TYPE_POP3) {
        free_pop3_session_state(sess, sess->proto_state);
    }

    if (sess->serveraddr) {
        free(sess->serveraddr);
    }
    if (sess->clientaddr) {
        free(sess->clientaddr);
    }
    if (sess->session_id) {
        free(sess->session_id);
    }
    if (sess->ingest_target_id) {
        free(sess->ingest_target_id);
    }
    if (sess->key) {
        free(sess->key);
    }
    free(sess);

}

static void update_email_session_timeout(openli_email_worker_t *state,
        emailsession_t *sess) {
    sync_epoll_t *timerev, *syncev;
    struct itimerspec its;

    if (sess->timeout_ev) {
        timerev = (sync_epoll_t *)(sess->timeout_ev);

        HASH_FIND(hh, state->timeouts, &(timerev->fd), sizeof(int), syncev);
        if (syncev) {
            HASH_DELETE(hh, state->timeouts, syncev);
        }
        close(timerev->fd);
    } else {
        timerev = (sync_epoll_t *) calloc(1, sizeof(sync_epoll_t));
    }

    pthread_rwlock_rdlock(state->glob_config_mutex);
    if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP) {
        its.it_value.tv_sec = state->timeout_thresholds->smtp * 60;
    } else if (sess->protocol == OPENLI_EMAIL_TYPE_POP3) {
        its.it_value.tv_sec = state->timeout_thresholds->pop3 * 60;
    } else if (sess->protocol == OPENLI_EMAIL_TYPE_IMAP) {
        its.it_value.tv_sec = state->timeout_thresholds->imap * 60;
    } else {
        its.it_value.tv_sec = 600;
    }
    pthread_rwlock_unlock(state->glob_config_mutex);

    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    sess->timeout_ev = (void *)timerev;
    timerev->fdtype = 0;
    timerev->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(timerev->fd, 0, &its, NULL);

    timerev->ptr = sess;
    HASH_ADD_KEYPTR(hh, state->timeouts, &(timerev->fd), sizeof(int), timerev);

}

void free_captured_email(openli_email_captured_t *cap) {

    if (cap == NULL) {
        return;
    }

    if (cap->session_id) {
        free(cap->session_id);
    }

    if (cap->target_id) {
        free(cap->target_id);
    }

    if (cap->remote_ip) {
        free(cap->remote_ip);
    }

    if (cap->remote_port) {
        free(cap->remote_port);
    }

    if (cap->host_ip) {
        free(cap->host_ip);
    }

    if (cap->host_port) {
        free(cap->host_port);
    }

    if (cap->datasource) {
        free(cap->datasource);
    }

    if (cap->content && cap->own_content) {
        free(cap->content);
    }

    free(cap);
}

static void start_email_intercept(openli_email_worker_t *state,
        emailintercept_t *em, int addtargets) {

    openli_export_recv_t *expmsg;
    email_target_t *tgt, *tmp;

    if (state->tracker_threads <= 1) {
        em->common.seqtrackerid = 0;
    } else {
        em->common.seqtrackerid = hash_liid(em->common.liid) % state->tracker_threads;
    }

    HASH_ADD_KEYPTR(hh_liid, state->allintercepts, em->common.liid,
            em->common.liid_len, em);

    if (addtargets) {
        HASH_ITER(hh, em->targets, tgt, tmp) {
            if (add_intercept_to_email_user_intercept_list(
                    &(state->alltargets), em, tgt) < 0) {
                logger(LOG_INFO, "OpenLI: error while adding all email targets for intercept %s", em->common.liid);
                break;
            }
        }
    }

    if (state->emailid == 0) {
        expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
        expmsg->data.cept.liid = strdup(em->common.liid);
        expmsg->data.cept.authcc = strdup(em->common.authcc);
        expmsg->data.cept.delivcc = strdup(em->common.delivcc);
        expmsg->data.cept.seqtrackerid = em->common.seqtrackerid;
        expmsg->data.cept.encryptmethod = em->common.encrypt;
        if (em->common.encryptkey) {
            expmsg->data.cept.encryptkey = strdup(em->common.encryptkey);
        } else {
            expmsg->data.cept.encryptkey = NULL;
        }

        publish_openli_msg(state->zmq_pubsocks[em->common.seqtrackerid],
                expmsg);
    }
    em->awaitingconfirm = 0;
}

static int update_modified_email_intercept(openli_email_worker_t *state,
        emailintercept_t *found, emailintercept_t *decode) {
    openli_export_recv_t *expmsg;
    int encodingchanged = 0, changed = 0;

    found->delivercompressed = decode->delivercompressed;

    encodingchanged = update_modified_intercept_common(&(found->common),
            &(decode->common), OPENLI_INTERCEPT_TYPE_EMAIL, &changed);

    if (encodingchanged < 0) {
        free_single_emailintercept(decode);
        return -1;
    }

    if (encodingchanged) {
        expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_CHANGED;
        expmsg->data.cept.liid = strdup(found->common.liid);
        expmsg->data.cept.authcc = strdup(found->common.authcc);
        expmsg->data.cept.delivcc = strdup(found->common.delivcc);
        expmsg->data.cept.seqtrackerid = found->common.seqtrackerid;
        expmsg->data.cept.encryptmethod = found->common.encrypt;
        if (found->common.encryptkey) {
            expmsg->data.cept.encryptkey = strdup(found->common.encryptkey);
        } else {
            expmsg->data.cept.encryptkey = NULL;
        }

        publish_openli_msg(state->zmq_pubsocks[found->common.seqtrackerid],
                expmsg);
    }
    free_single_emailintercept(decode);
    return 0;
}

static void remove_email_intercept(openli_email_worker_t *state,
        emailintercept_t *em, int removetargets) {

    openli_export_recv_t *expmsg;
    int i;
    email_target_t *tgt, *tmp;

    /* Either this intercept has been explicitly withdrawn, in which case
     * we need to also purge any target addresses for it, OR the
     * intercept has been reannounced so we're going to "update" it. For an
     * update, we want to keep all existing targets active, but be prepared
     * to drop any that are not subsequently confirmed by the provisioner.
     */
    HASH_ITER(hh, em->targets, tgt, tmp) {
        if (removetargets) {
            if (remove_intercept_from_email_user_intercept_list(
                    &(state->alltargets), em, tgt) < 0) {
                logger(LOG_INFO, "OpenLI: error while removing all email targets for intercept %s", em->common.liid);
                break;
            }
        } else {
            /* Flag this target as needing confirmation */
            tgt->awaitingconfirm = 1;
        }
    }

    HASH_DELETE(hh_liid, state->allintercepts, em);

    if (state->emailid == 0 && removetargets != 0) {
        expmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
        expmsg->data.cept.liid = strdup(em->common.liid);
        expmsg->data.cept.authcc = strdup(em->common.authcc);
        expmsg->data.cept.delivcc = strdup(em->common.delivcc);
        expmsg->data.cept.seqtrackerid = em->common.seqtrackerid;

        publish_openli_msg(state->zmq_pubsocks[em->common.seqtrackerid],
                expmsg);

        for (i = 0; i < state->fwd_threads; i++) {

            expmsg = (openli_export_recv_t *)calloc(1,
                    sizeof(openli_export_recv_t));
            expmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
            expmsg->data.cept.liid = strdup(em->common.liid);
            expmsg->data.cept.authcc = strdup(em->common.authcc);
            expmsg->data.cept.delivcc = strdup(em->common.delivcc);
            expmsg->data.cept.seqtrackerid = em->common.seqtrackerid;

            publish_openli_msg(state->zmq_fwdsocks[i], expmsg);
        }

        pthread_mutex_lock(state->stats_mutex);
        state->stats->emailintercepts_ended_diff ++;
        state->stats->emailintercepts_ended_total ++;
        pthread_mutex_unlock(state->stats_mutex);

        logger(LOG_INFO,
                "OpenLI: removed email intercept %s from email worker threads",
                em->common.liid);
    }

    free_single_emailintercept(em);

}

static int update_default_email_compression(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    uint8_t newval = OPENLI_EMAILINT_DELIVER_COMPRESSED_NOT_SET;

    if (decode_default_email_compression_announcement(provmsg->msgbody,
            provmsg->msglen, &newval) < 0) {
        logger(LOG_INFO, "OpenLI: email worker failed to decode default email compression update message from provisioner");
        return -1;
    }

    if (newval != OPENLI_EMAILINT_DELIVER_COMPRESSED_DEFAULT &&
            newval != OPENLI_EMAILINT_DELIVER_COMPRESSED_NOT_SET) {
        if (state->emailid == 0 && newval != state->default_compress_delivery) {
            char newval_str[256];

            email_decompress_option_as_string(newval, newval_str, 256);
            logger(LOG_INFO, "OpenLI: email workers have changed the default email compression delivery behaviour to '%s'", newval_str);
        }

        state->default_compress_delivery = newval;
    }

    return 0;
}

static int add_new_email_intercept(openli_email_worker_t *state,
        provisioner_msg_t *msg) {

    emailintercept_t *em, *found;
    int ret = 0;

    em = calloc(1, sizeof(emailintercept_t));

    if (decode_emailintercept_start(msg->msgbody, msg->msglen, em) < 0) {
        logger(LOG_INFO, "OpenLI: email worker failed to decode email intercept start message from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->allintercepts, em->common.liid,
            em->common.liid_len, found);

    if (found) {
        email_target_t *tgt, *tmp;
        /* Don't halt any target intercepts just yet -- hopefully a target
         * update is going to follow this...
         */
        HASH_ITER(hh, found->targets, tgt, tmp) {
            tgt->awaitingconfirm = 1;
        }

        update_modified_email_intercept(state, found, em);
        found->awaitingconfirm = 0;
        ret = 1;
        logger(LOG_INFO, "OpenLI: updated email intercept for %s after re-announcement by provisioner", found->common.liid);
    } else {
        start_email_intercept(state, em, 0);
        if (state->emailid == 0) {
            pthread_mutex_lock(state->stats_mutex);
            state->stats->emailintercepts_added_diff ++;
            state->stats->emailintercepts_added_total ++;
            pthread_mutex_unlock(state->stats_mutex);

            logger(LOG_INFO, "OpenLI: added new email intercept for %s to email worker threads", em->common.liid);
        }
    }


    return ret;
}

static int modify_email_intercept(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    emailintercept_t *decode, *found;

    decode = calloc(1, sizeof(emailintercept_t));
    if (decode_emailintercept_modify(provmsg->msgbody, provmsg->msglen,
            decode) < 0) {
        logger(LOG_INFO, "OpenLI: received invalid email intercept modification from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->allintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found) {
        start_email_intercept(state, decode, 0);
        return 0;
    }

    update_modified_email_intercept(state, found, decode);
    return 0;
}

static int halt_email_intercept(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    emailintercept_t *decode, *found;

    decode = calloc(1, sizeof(emailintercept_t));
    if (decode_emailintercept_halt(provmsg->msgbody, provmsg->msglen,
            decode) < 0) {
        logger(LOG_INFO, "OpenLI: received invalid email intercept withdrawal from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->allintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found && state->emailid == 0) {
        logger(LOG_INFO, "OpenLI: tried to halt email intercept %s but this was not in the intercept map?", decode->common.liid);
        free_single_emailintercept(decode);
        return -1;
    }

    remove_email_intercept(state, found, 1);
    free_single_emailintercept(decode);
    return 0;
}

static int process_email_target_withdraw(openli_email_worker_t *state,
        email_target_t *tgt, char *liid) {

    emailintercept_t *found;
    email_target_t *tgtfound;

    HASH_FIND(hh_liid, state->allintercepts, liid, strlen(liid), found);
    if (!found) {
        logger(LOG_INFO, "OpenLI: received email target withdrawal for intercept %s, but this intercept is not active according to email worker thread %d",
                liid, state->emailid);
        return -1;
    }

    if (remove_intercept_from_email_user_intercept_list(&(state->alltargets),
            found, tgt) < 0) {
        logger(LOG_INFO, "OpenLI: email worker thread %d failed to remove email target for intercept %s", state->emailid, liid);
        return -1;
    }

    HASH_FIND(hh, found->targets, tgt->address, strlen(tgt->address), tgtfound);
    if (tgtfound) {
        HASH_DELETE(hh, found->targets, tgtfound);
        free_single_email_target(tgtfound);
    }

    return 0;
}

static int remove_email_target(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    email_target_t *tgt;
    char liid[256];
    int ret;

    tgt = calloc(1, sizeof(email_target_t));

    if (decode_email_target_withdraw(provmsg->msgbody, provmsg->msglen,
            tgt, liid, 256) < 0) {
        logger(LOG_INFO, "OpenLI: email worker %d received invalid email target withdrawal from provisioner", state->emailid);
        return -1;
    }

    ret = process_email_target_withdraw(state, tgt, liid);
    free_single_email_target(tgt);
    return ret;
}

static int add_email_target(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    email_target_t *tgt, *tgtfound;
    emailintercept_t *found;
    char liid[256];
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    unsigned char shaspace[EVP_MAX_MD_SIZE];
    unsigned int sha_len, i;

    tgt = calloc(1, sizeof(email_target_t));
    if (decode_email_target_announcement(provmsg->msgbody, provmsg->msglen,
            tgt, liid, 256) < 0) {
        logger(LOG_INFO, "OpenLI: email worker %d received invalid email target announcement from provisioner", state->emailid);
        return -1;
    }

    if (tgt->address == NULL) {
        logger(LOG_INFO, "OpenLI: email worker %d has a target with no address for liid %s\n", state->emailid, liid);
        return -1;
    }
    if (strlen(tgt->address) > 1023) {
        logger(LOG_INFO, "OpenLI: insanely long email address for %s target\n", liid);
        return -1;
    }

#ifdef HAVE_LIBSSL_11
    ctx = EVP_MD_CTX_new();
#else
    ctx = EVP_MD_CTX_create();
#endif
    md = EVP_sha512();
    EVP_DigestInit_ex(ctx, md, NULL);
    memset(shaspace, 0, EVP_MAX_MD_SIZE);
    EVP_DigestUpdate(ctx, tgt->address, strlen(tgt->address));
    EVP_DigestFinal_ex(ctx, shaspace, &sha_len);

    tgt->sha512 = calloc(sha_len * 2 + 1, sizeof(char));
    for (i = 0; i < sha_len; i++) {
        sprintf(tgt->sha512 + (i * 2), "%02x", shaspace[i]);
    }
#ifdef HAVE_LIBSSL_11
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_destroy(ctx);
#endif

    HASH_FIND(hh_liid, state->allintercepts, liid, strlen(liid), found);
    if (!found) {
        logger(LOG_INFO, "OpenLI: received email target announcement for intercept %s, but this intercept is not active according to email worker thread %d",
        liid, state->emailid);
        return -1;
    }

    if (add_intercept_to_email_user_intercept_list(&(state->alltargets),
            found, tgt) < 0) {
        logger(LOG_INFO, "OpenLI: email worker thread %d failed to add email target for intercept %s", state->emailid, liid);
        return -1;
    }

    HASH_FIND(hh, found->targets, tgt->address, strlen(tgt->address), tgtfound);
    if (!tgtfound) {
        tgt->awaitingconfirm = 0;
        HASH_ADD_KEYPTR(hh, found->targets, tgt->address, strlen(tgt->address),
                tgt);
    } else {
        tgtfound->awaitingconfirm = 0;
        free_single_email_target(tgt);
    }
    return 0;
}

static void flag_all_email_intercepts(openli_email_worker_t *state) {
    emailintercept_t *em, *tmp;
    email_target_t *tgt, *tmp2;

    HASH_ITER(hh_liid, state->allintercepts, em, tmp) {
        em->awaitingconfirm = 1;
        HASH_ITER(hh, em->targets, tgt, tmp2) {
            tgt->awaitingconfirm = 1;
        }
    }
}

static void disable_unconfirmed_email_intercepts(openli_email_worker_t *state)
{
    emailintercept_t *em, *tmp;
    email_target_t *tgt, *tmp2;

    HASH_ITER(hh_liid, state->allintercepts, em, tmp) {
        if (em->awaitingconfirm) {
            remove_email_intercept(state, em, 1);
        } else {
            HASH_ITER(hh, em->targets, tgt, tmp2) {
                if (tgt->awaitingconfirm) {
                    process_email_target_withdraw(state, tgt, em->common.liid);
                }
            }
        }
    }
}

static int handle_provisioner_message(openli_email_worker_t *state,
        openli_export_recv_t *msg) {

    int ret = 0;

    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_START_EMAILINTERCEPT:
            ret = add_new_email_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_EMAILINTERCEPT:
            ret = halt_email_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_EMAILINTERCEPT:
            ret = modify_email_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_ANNOUNCE_EMAIL_TARGET:
            ret = add_email_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_WITHDRAW_EMAIL_TARGET:
            ret = remove_email_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            disable_unconfirmed_email_intercepts(state);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_all_email_intercepts(state);
            break;
        case OPENLI_PROTO_ANNOUNCE_DEFAULT_EMAIL_COMPRESSION:
            ret = update_default_email_compression(state, &(msg->data.provmsg));
            break;
        default:
            logger(LOG_INFO, "OpenLI: email worker thread %d received unexpected message type from provisioner: %u",
                    state->emailid, msg->data.provmsg.msgtype);
            ret = -1;
    }


    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }

    return ret;
}

static int process_sync_thread_message(openli_email_worker_t *state) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(state->zmq_ii_sock, &msg, sizeof(msg),
                ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in email thread %d: %s",
                    state->emailid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_PROVISIONER_MESSAGE) {
            handle_provisioner_message(state, msg);
        }

        /* TODO handle other message types */

        free(msg);
    } while (x > 0);

    return 1;
}

static int find_and_update_active_session(openli_email_worker_t *state,
        openli_email_captured_t *cap) {

    char sesskey[256];
    emailsession_t *sess;
    int r = 0;
    size_t i;

    if (cap->session_id == NULL) {
        logger(LOG_INFO,
                "OpenLI: error creating email session -- session_id is NULL");
        free_captured_email(cap);
        return -1;
    }

    snprintf(sesskey, 256, "%s-%s", email_type_to_string(cap->type),
            cap->session_id);

    HASH_FIND(hh, state->activesessions, sesskey, strlen(sesskey), sess);
    if (!sess) {
        sess = calloc(1, sizeof(emailsession_t));
        init_email_session(sess, cap, sesskey, state);
        HASH_ADD_KEYPTR(hh, state->activesessions, sess->key,
                strlen(sess->key), sess);

    }

    update_email_session_timeout(state, sess);

    if (cap->part_id == 0xFFFFFFFF) {
        cap->part_id = sess->next_expected_captured;
    }

    if (cap->part_id < sess->next_expected_captured) {
        logger(LOG_INFO,
                "OpenLI: warning -- ingested email message for session '%s' has an unexpected PART_ID (%u vs %u), ignoring",
                sesskey, cap->part_id, sess->next_expected_captured);
        free_captured_email(cap);
        return 0;
    }

    if (cap->part_id > sess->held_captured_size + 16) {
        logger(LOG_INFO,
                "OpenLI: warning -- unexpectedly large PART_ID for ingested email session '%s': %u, ignoring",
                sesskey, cap->part_id);
        free_captured_email(cap);
        return 0;
    }

    while (cap->part_id >= sess->held_captured_size) {
        sess->held_captured = realloc(sess->held_captured, (sess->held_captured_size + 16) * sizeof(void *));
        for (i = sess->held_captured_size; i < sess->held_captured_size + 16;
                i++) {
            sess->held_captured[i] = NULL;
        }
        sess->held_captured_size += 16;
    }

    if (sess->held_captured[cap->part_id] != NULL) {
        logger(LOG_INFO,
                "OpenLI: warning -- ingested email message for session '%s' has a duplicated PART_ID of %u, ignoring", sesskey, cap->part_id);
        free_captured_email(cap);
        return 0;
    }

    sess->held_captured[cap->part_id] = cap;

    while (sess->next_expected_captured < sess->held_captured_size &&
            sess->held_captured[sess->next_expected_captured] != NULL) {

        cap = sess->held_captured[sess->next_expected_captured];

        if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP) {
            r = update_smtp_session_by_ingestion(state, sess, cap);
        } else if (sess->protocol == OPENLI_EMAIL_TYPE_IMAP) {
            r = update_imap_session_by_ingestion(state, sess, cap);
        } else if (sess->protocol == OPENLI_EMAIL_TYPE_POP3) {
            r = update_pop3_session_by_ingestion(state, sess, cap);
        }

        if (r < 0) {
            logger(LOG_INFO,
                    "OpenLI: error updating %s session '%s' -- removing session...",
                    email_type_to_string(cap->type), sess->key);

            HASH_DELETE(hh, state->activesessions, sess);
            free_email_session(state, sess);
            return r;
        } else if (r == 1) {
            HASH_DELETE(hh, state->activesessions, sess);
            free_email_session(state, sess);
            return r;
        }
        free_captured_email(cap);
        sess->held_captured[sess->next_expected_captured] = NULL;
        sess->next_expected_captured ++;
    }

    return 0;
}

static int process_received_packet(openli_email_worker_t *state) {
    openli_state_update_t recvd;
    int rc, x;
    openli_email_captured_t *cap = NULL;

    do {
        rc = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving email packet in email thread %d: %s", state->emailid, strerror(errno));
            return -1;
        }

        if ((x = convert_packet_to_email_captured(state, recvd.data.pkt,
                recvd.type, &cap)) < 0) {
            logger(LOG_INFO, "OpenLI: unable to derive email session ID from received packet in email thread %d", state->emailid);
            free_captured_email(cap);
            return -1;
        } else if (x == 0) {
            /* packet was a fragment and we need more fragments to complete
             * the application payload.
             */
             trace_destroy_packet(recvd.data.pkt);
             continue;
        }

        if (cap->content != NULL) {
            find_and_update_active_session(state, cap);
        } else {
            free_captured_email(cap);
        }

        trace_destroy_packet(recvd.data.pkt);
    } while (rc > 0);

    return 0;
}

static int process_ingested_capture(openli_email_worker_t *state) {
    openli_email_captured_t *cap = NULL;
    int x;

    do {
        x = zmq_recv(state->zmq_ingest_recvsock, &cap, sizeof(cap),
                ZMQ_DONTWAIT);

        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving ingested email contents in email thread %d: %s",
                    state->emailid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }
        if (cap == NULL || cap->session_id == NULL) {
            free_captured_email(cap);
            break;
        }
        find_and_update_active_session(state, cap);

    } while (x > 0);

    return 1;
}

static void email_worker_main(openli_email_worker_t *state) {

    emailsession_t **expired = NULL;
    int x;
    int topoll_req;
    sync_epoll_t *ev, *tmp;

    logger(LOG_INFO, "OpenLI: starting email processing thread %d",
            state->emailid);

    /* TODO add other consumer sockets to topoll */

    while (1) {
        topoll_req = 3 + HASH_CNT(hh, state->timeouts);

        if (topoll_req > state->topoll_size) {
            if (state->topoll) {
                free(state->topoll);
            }
            if (expired) {
                free(expired);
            }
            state->topoll = calloc(topoll_req, sizeof(zmq_pollitem_t));
            state->topoll_size = topoll_req;
            expired = calloc(topoll_req, sizeof(emailsession_t *));
        }

        state->topoll[0].socket = state->zmq_ii_sock;
        state->topoll[0].events = ZMQ_POLLIN;

        state->topoll[1].socket = state->zmq_ingest_recvsock;
        state->topoll[1].events = ZMQ_POLLIN;

        state->topoll[2].socket = state->zmq_colthread_recvsock;
        state->topoll[2].events = ZMQ_POLLIN;

        x = 3;
        HASH_ITER(hh, state->timeouts, ev, tmp) {
            state->topoll[x].socket = NULL;
            state->topoll[x].fd = ev->fd;
            state->topoll[x].events = ZMQ_POLLIN;
            expired[x] = (emailsession_t *)(ev->ptr);
            x++;
        }

        if ((x = zmq_poll(state->topoll, topoll_req, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO, "OpenLI: error while polling in email processor %d: %s", state->emailid, strerror(errno));
            return;
        }

        if (x == 0) {
            continue;
        }

        if (state->topoll[0].revents & ZMQ_POLLIN) {
            /* message from the sync thread */
            x = process_sync_thread_message(state);
            if (x < 0) {
                break;
            }
            state->topoll[0].revents = 0;
        }

        if (state->topoll[1].revents & ZMQ_POLLIN) {
            /* message from the email ingesting thread */
            x = process_ingested_capture(state);
            if (x < 0) {
                break;
            }
            state->topoll[1].revents = 0;
        }

        if (state->topoll[2].revents & ZMQ_POLLIN) {
            /* captured packet from a collector thread */
            x = process_received_packet(state);
            if (x < 0) {
                break;
            }
            state->topoll[2].revents = 0;
        }

        for (x = 3; x < topoll_req; x++) {
            emailsession_t *sessfound;

            if (state->topoll[x].revents & ZMQ_POLLIN) {
                HASH_FIND(hh, state->activesessions, expired[x]->key,
                        strlen(expired[x]->key), sessfound);
                if (sessfound) {
                    HASH_DELETE(hh, state->activesessions, sessfound);
                }
                free_email_session(state, expired[x]);
            }
        }
    }
    if (expired) {
        free(expired);
    }
}

static void free_all_email_sessions(openli_email_worker_t *state) {

    emailsession_t *sess, *tmp;

    HASH_ITER(hh, state->activesessions, sess, tmp) {
        HASH_DELETE(hh, state->activesessions, sess);
        free_email_session(state, sess);
    }

}

void *start_email_worker_thread(void *arg) {

    openli_email_worker_t *state = (openli_email_worker_t *)arg;
    int x, zero = 0;
    char sockname[256];
    sync_epoll_t *syncev, *tmp;
    openli_state_update_t recvd;

    state->alltargets.addresses = NULL;
    state->alltargets.targets = NULL;
    state->zmq_pubsocks = calloc(state->tracker_threads, sizeof(void *));
    state->zmq_fwdsocks = calloc(state->fwd_threads, sizeof(void *));

    init_zmq_socket_array(state->zmq_pubsocks, state->tracker_threads,
            "inproc://openlipub", state->zmq_ctxt);

    init_zmq_socket_array(state->zmq_fwdsocks, state->fwd_threads,
            "inproc://openliforwardercontrol_sync", state->zmq_ctxt);

    state->zmq_ii_sock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openliemailcontrol_sync-%d",
            state->emailid);
    if (zmq_bind(state->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: email processing thread %d failed to bind to II zmq: %s", state->emailid, strerror(errno));
        goto haltemailworker;
    }

     if (zmq_setsockopt(state->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
         logger(LOG_INFO, "OpenLI: email processing thread %d failed to configure II zmq: %s", state->emailid, strerror(errno));
         goto haltemailworker;
     }

    state->zmq_ingest_recvsock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openliemailworker-ingest%d",
            state->emailid);

    if (zmq_bind(state->zmq_ingest_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: email processing thread %d failed to bind to ingesting zmq: %s", state->emailid, strerror(errno));
        goto haltemailworker;
    }

    if (zmq_setsockopt(state->zmq_ingest_recvsock, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
         logger(LOG_INFO, "OpenLI: email processing thread %d failed to configure ingesting zmq: %s", state->emailid, strerror(errno));
         goto haltemailworker;
    }

    state->zmq_colthread_recvsock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openliemailworker-colrecv%d",
            state->emailid);

    if (zmq_bind(state->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: email processing thread %d failed to bind to colthread zmq: %s", state->emailid, strerror(errno));
        goto haltemailworker;
    }

    if (zmq_setsockopt(state->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
         logger(LOG_INFO, "OpenLI: email processing thread %d failed to configure colthread zmq: %s", state->emailid, strerror(errno));
         goto haltemailworker;
    }

    state->fragreass = create_new_ipfrag_reassembler();
    email_worker_main(state);

    do {
        /* drain remaining email captures and free them */
        x = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltemailworker:
    logger(LOG_INFO, "OpenLI: halting email processing thread %d",
            state->emailid);
    /* free all state for intercepts and active sessions */
    clear_email_user_intercept_list(&(state->alltargets));
    free_all_emailintercepts(&(state->allintercepts));
    free_all_email_sessions(state);

    /* close all ZMQs */
    zmq_close(state->zmq_ii_sock);

    if (state->topoll) {
        free(state->topoll);
    }

    zmq_close(state->zmq_ingest_recvsock);
    zmq_close(state->zmq_colthread_recvsock);

    clear_zmq_socket_array(state->zmq_pubsocks, state->tracker_threads);
    clear_zmq_socket_array(state->zmq_fwdsocks, state->fwd_threads);

    /* All timeouts should be freed when we release the active sessions,
     * but just in case there are any left floating around...
     */
    HASH_ITER(hh, state->timeouts, syncev, tmp) {
        HASH_DELETE(hh, state->timeouts, syncev);
        free(syncev);
    }
    if (state->fragreass) {
        destroy_ipfrag_reassembler(state->fragreass);
    }
    pthread_exit(NULL);
}

/** Utility functions for the protocol parsers
 *
 *  ==========================================
 */

void mask_plainauth_creds(char *mailbox, char *reencoded, int buflen) {
    char input[2048];
    char *ptr;
    base64_encodestate e;
    int spaces, toencode, cnt;

    /* reencode authtoken with replaced username and password */
    base64_init_encodestate(&e);
    snprintf(input, 2048, "%s XXX XXX", mailbox);
    toencode = strlen(input);
    ptr = input;
    spaces = 0;

    while(spaces < 2) {
        if (*ptr == '\0') {
            break;
        }

        if (*ptr == ' ') {
            *ptr = '\0';
            spaces ++;
        }
        ptr ++;
    }

    /* TODO try not to walk off the end of reencoded -- very unlikely, given
     * that we have 2048 bytes of space but you never know...
     */
    ptr = reencoded;
    cnt = base64_encode_block(input, toencode, ptr, &e);

    ptr += cnt;
    cnt = base64_encode_blockend(ptr, &e);

    ptr += cnt;
    /* libb64 likes to add a newline to the end of its encodings, so make
     * sure we strip it if one is present.
     */
    if (*(ptr - 1) == '\n') {
        ptr--;
    }

    *ptr = '\r'; ptr++;
    *ptr = '\n'; ptr++;
    *ptr = '\0'; ptr++;
}

int get_email_authentication_type(char *authmsg, const char *sesskey,
        openli_email_auth_type_t *at_code, uint8_t is_imap) {

    char *saveptr;
    char *tag = NULL;
    char *comm = NULL;
    char *authtype = NULL;
    char *lineend = NULL;
    char *next = NULL;
    int moveahead = 0;

    lineend = strstr(authmsg, "\r\n");
    if (lineend == NULL) {
        return 0;
    }

    if (is_imap) {
        tag = strtok_r(authmsg, " ", &saveptr);
        if (!tag) {
            logger(LOG_INFO, "OpenLI: unable to derive tag from Email AUTHENTICATE command");
            return -1;
        }
        next = NULL;
    } else {
        next = authmsg;
    }

    comm = strtok_r(next, " ", &saveptr);
    if (!comm) {
        logger(LOG_INFO, "OpenLI: unable to derive command from Email AUTHENTICATE command");
        return -1;
    }

    authtype = strtok_r(NULL,  " \r\n", &saveptr);

    if (!authtype) {
        logger(LOG_INFO, "OpenLI: unable to derive authentication type from Email AUTHENTICATE command");
        return -1;
    }

    if (strcasecmp(authtype, "PLAIN") == 0) {
        *at_code = OPENLI_EMAIL_AUTH_PLAIN;
        moveahead = (5 + (authtype - authmsg));

        if (lineend == authtype + 5) {
            moveahead += 2;
        } else {
            moveahead += 1;
        }
    } else if (strcasecmp(authtype, "LOGIN") == 0) {
        *at_code = OPENLI_EMAIL_AUTH_LOGIN;
        moveahead = (5 + (authtype - authmsg));

        if (lineend == authtype + 5) {
            moveahead += 2;
        } else {
            moveahead += 1;
        }
    } else if (strcasecmp(authtype, "GSSAPI") == 0) {
        *at_code = OPENLI_EMAIL_AUTH_GSSAPI;
        moveahead = (6 + (authtype - authmsg));

        if (lineend == authtype + 6) {
            moveahead += 2;
        } else {
            moveahead += 1;
        }

    } else {
        logger(LOG_INFO, "OpenLI: unsupported Email authentication type '%s' -- will not be able to derive mailbox owner for session %s",
                authtype, sesskey);
        return -1;
    }

    return moveahead;
}

email_address_set_t *is_address_interceptable(
        openli_email_worker_t *state, const char *emailaddr) {

    email_address_set_t *active = NULL;
    if (emailaddr == NULL) {
        return active;
    }

    HASH_FIND(hh_addr, state->alltargets.addresses, emailaddr,
            strlen(emailaddr), active);
    return active;
}

email_target_set_t *is_targetid_interceptable(
        openli_email_worker_t *state, const char *targetid) {

    email_target_set_t *active = NULL;
    if (targetid == NULL) {
        return active;
    }
    HASH_FIND(hh_sha, state->alltargets.targets, targetid, strlen(targetid),
            active);
    if (active) {
        return active;
    }

    HASH_FIND(hh_plain, state->alltargets.targets, targetid, strlen(targetid),
            active);
    return active;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

