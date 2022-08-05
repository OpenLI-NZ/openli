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

#include "util.h"
#include "logger.h"
#include "collector_base.h"
#include "collector_publish.h"
#include "email_worker.h"
#include "netcomms.h"
#include "intercept.h"

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

    if (cap->content) {
        free(cap->content);
    }

    free(cap);
}

static void start_email_intercept(openli_email_worker_t *state,
        emailintercept_t *em, int addtargets) {

    openli_export_recv_t *expmsg;

    /* TODO
     *
     * add timer event for intercept endtime, if required
     * add targets to alltargets, if requested
     */

    if (state->tracker_threads <= 1) {
        em->common.seqtrackerid = 0;
    } else {
        em->common.seqtrackerid = hash_liid(em->common.liid) % state->tracker_threads;
    }

    HASH_ADD_KEYPTR(hh_liid, state->allintercepts, em->common.liid,
            em->common.liid_len, em);

    if (state->emailid == 0) {
        expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
        expmsg->data.cept.liid = strdup(em->common.liid);
        expmsg->data.cept.authcc = strdup(em->common.authcc);
        expmsg->data.cept.delivcc = strdup(em->common.delivcc);
        expmsg->data.cept.seqtrackerid = em->common.seqtrackerid;

        publish_openli_msg(state->zmq_pubsocks[em->common.seqtrackerid],
                expmsg);
    }
}

static void remove_email_intercept(openli_email_worker_t *state,
        emailintercept_t *em, int removetargets) {

    openli_export_recv_t *expmsg;
    int i;

    /* TODO
     *
     * remove from alltargets, if requested
     * remove intercept endtime timer
     */

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
        /* We're going to replace "found" with our new intercept, but keep
         * the same targets (for now at least)
         */
        em->targets = found->targets;
        found->targets = NULL;

        /* Don't halt any target intercepts just yet -- hopefully a target
         * update is going to follow this...
         */
        remove_email_intercept(state, found, 0);
        ret = 1;
    } else if (state->emailid == 0) {
        pthread_mutex_lock(state->stats_mutex);
        state->stats->emailintercepts_added_diff ++;
        state->stats->emailintercepts_added_total ++;
        pthread_mutex_unlock(state->stats_mutex);

        logger(LOG_INFO, "OpenLI: added new email intercept for %s to email worker threads", em->common.liid);
    }

    start_email_intercept(state, em, 0);

    return ret;
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
            break;
        case OPENLI_PROTO_ANNOUNCE_EMAIL_TARGET:
            break;
        case OPENLI_PROTO_WITHDRAW_EMAIL_TARGET:
            break;
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            break;
        case OPENLI_PROTO_DISCONNECT:
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

        if (cap == NULL) {
            break;
        }

        free_captured_email(cap);
    } while (x > 0);

    return 1;
}

static void email_worker_main(openli_email_worker_t *state) {

    zmq_pollitem_t topoll[3];
    int x;

    logger(LOG_INFO, "OpenLI: starting email processing thread %d",
            state->emailid);

    topoll[0].socket = state->zmq_ii_sock;
    topoll[0].events = ZMQ_POLLIN;

    topoll[1].socket = state->zmq_ingest_recvsock;
    topoll[1].events = ZMQ_POLLIN;

    /* TODO add other consumer sockets to topoll */

    while (1) {
        /* TODO replace 2 with 3 when we add the other ZMQ sockets */
        if ((x = zmq_poll(topoll, 2, 10000)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO, "OpenLI: error while polling in email processor %d: %s", state->emailid, strerror(errno));
            return;
        }

        if (x == 0) {
            continue;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            /* message from the sync thread */
            x = process_sync_thread_message(state);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            /* message from the email ingesting thread */
            x = process_ingested_capture(state);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }
    }
}

static inline void clear_zmqsocks(void **zmq_socks, int sockcount) {
    int i, zero = 0;
    if (zmq_socks == NULL) {
        return;
    }

    for (i = 0; i < sockcount; i++) {
        if (zmq_socks[i] == NULL) {
            continue;
        }
        zmq_setsockopt(zmq_socks[i], ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(zmq_socks[i]);
    }
    free(zmq_socks);
}

static inline int init_zmqsocks(void **zmq_socks, int sockcount,
        const char *basename, void *zmq_ctxt) {

    int i, zero = 0;
    char sockname[256];
    int ret = 0;

    for (i = 0; i < sockcount; i++) {
        zmq_socks[i] = zmq_socket(zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 256, "%s-%d", basename, i);
        if (zmq_connect(zmq_socks[i], sockname) < 0) {
            ret = -1;
            logger(LOG_INFO,
                    "OpenLI: email worker failed to bind to publishing zmq %s: %s",
                    sockname, strerror(errno));

            zmq_close(zmq_socks[i]);
            zmq_socks[i] = NULL;
        }
    }
    return ret;
}

void *start_email_worker_thread(void *arg) {

    openli_email_worker_t *state = (openli_email_worker_t *)arg;
    int x, zero = 0;
    char sockname[256];

    state->zmq_pubsocks = calloc(state->tracker_threads, sizeof(void *));
    state->zmq_fwdsocks = calloc(state->fwd_threads, sizeof(void *));

    init_zmqsocks(state->zmq_pubsocks, state->tracker_threads,
            "inproc://openlipub", state->zmq_ctxt);

    init_zmqsocks(state->zmq_fwdsocks, state->fwd_threads,
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

     /* TODO set up ZMQs for consuming email captures and publishing
      * encoding jobs */

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

    email_worker_main(state);

    do {
        /* TODO drain remaining email captures and free them */
        x = 0;

    } while (x > 0);

haltemailworker:
    logger(LOG_INFO, "OpenLI: halting email processing thread %d",
            state->emailid);
    /* TODO free all state for intercepts and active sessions */
    free_all_emailintercepts(&(state->allintercepts));

    zmq_close(state->zmq_ii_sock);

    /* TODO close all other ZMQs */


    zmq_close(state->zmq_ingest_recvsock);

    clear_zmqsocks(state->zmq_pubsocks, state->tracker_threads);
    clear_zmqsocks(state->zmq_fwdsocks, state->fwd_threads);

    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

