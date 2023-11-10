/*
 *
 * Copyright (c) 2018-2023 Searchlight New Zealand Ltd.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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

#include "netcomms.h"
#include "intercept.h"
#include "collector.h"
#include "sms_worker.h"
#include "util.h"
#include "logger.h"

#include <sys/timerfd.h>
#include <libtrace.h>

static void init_sms_voip_intercept(openli_sms_worker_t *state,
        voipintercept_t *vint) {

    if (state->tracker_threads <= 1) {
        vint->common.seqtrackerid = 0;
    } else {
        vint->common.seqtrackerid = hash_liid(vint->common.liid) %
            state->tracker_threads;
    }

    HASH_ADD_KEYPTR(hh_liid, state->voipintercepts, vint->common.liid,
            vint->common.liid_len, vint);

    /* Don't need to tell the seqtracker about this intercept because
     * hopefully the VOIP sync thread will handle that...
     */
    vint->awaitingconfirm = 0;

}

static int update_modified_sms_voip_intercept(openli_sms_worker_t *state,
        voipintercept_t *found, voipintercept_t *decode) {

    int r = 0;

    if (update_modified_intercept_common(&(found->common),
            &(decode->common), OPENLI_INTERCEPT_TYPE_VOIP) < 0) {
        r = -1;
    }

    printf("DEVDEBUG: SMS worker has updated VINT %s\n", found->common.liid);
    free_single_voipintercept(decode);
    return r;

}

static void remove_sms_voip_intercept(openli_sms_worker_t *state,
        voipintercept_t *vint) {

    /* Really simple, because we don't maintain a map of
     * SIP identities to VoIP intercepts -- SIP identities
     * are complex (wildcards, realms being optional, etc) so
     * it's not something that we can be optimise with a
     * lookup table, unlike RADIUS usernames or email addresses.
     */
    HASH_DELETE(hh_liid, state->voipintercepts, vint);
    printf("DEVDEBUG: SMS worker has removed VINT %s\n", vint->common.liid);
    free_single_voipintercept(vint);
}

static int halt_sms_voip_intercept(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *decode, *found;
    decode = calloc(1, sizeof(voipintercept_t));

    if (decode_voipintercept_halt(provmsg->msgbody, provmsg->msglen,
            decode) < 0) {
        logger(LOG_INFO,
                "OpenLI: SMS worker received invalid VoIP intercept withdrawal");
        return -1;
    }

    HASH_FIND(hh_liid, state->voipintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found && state->workerid == 0) {
        logger(LOG_INFO,
                "OpenLI: tried to halt VoIP intercept %s within SMS worker but it was not in the intercept map?",
                decode->common.liid);
        free_single_voipintercept(decode);
        return -1;
    }
    remove_sms_voip_intercept(state, found);
    free_single_voipintercept(decode);
    return 0;
}

static int modify_sms_voip_intercept(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *vint, *found;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_modify(provmsg->msgbody, provmsg->msglen,
            vint) < 0) {
        logger(LOG_INFO, "OpenLI: SMS worker failed to decode VoIP intercept modify message from provisioner");
        return -1;
    }
    HASH_FIND(hh_liid, state->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);
    if (!found) {
        init_sms_voip_intercept(state, vint);
    } else {
        update_modified_sms_voip_intercept(state, found, vint);
    }
    return 0;
}

static int add_new_sms_voip_intercept(openli_sms_worker_t *state,
        provisioner_msg_t *msg) {

    voipintercept_t *vint, *found;
    int ret = 0;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_start(msg->msgbody, msg->msglen, vint) < 0) {
        logger(LOG_INFO, "OpenLI: SMS worker failed to decode VoIP intercept start message from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);

    if (found) {
        openli_sip_identity_t *tgt;
        libtrace_list_node_t *n;

        /* We already know about this intercept, but don't overwrite
         * anything just yet because hopefully our (updated) targets
         * will be announced to us shortly.
         */
        n = found->targets->head;
        while (n) {
            tgt = *((openli_sip_identity_t **)(n->data));
            tgt->awaitingconfirm = 1;
            n = n->next;
        }
        update_modified_sms_voip_intercept(state, found, vint);
        found->awaitingconfirm = 0;
        ret = 0;
    } else {
        init_sms_voip_intercept(state, vint);
        ret = 1;
    }
    return ret;
}

static inline voipintercept_t *lookup_sip_target_intercept(
        openli_sms_worker_t *state, provisioner_msg_t *provmsg,
        openli_sip_identity_t *sipid) {

    voipintercept_t *found = NULL;
    char liidspace[1024];
    if (decode_sip_target_announcement(provmsg->msgbody,
            provmsg->msglen, sipid, liidspace, 1024) < 0) {
        logger(LOG_INFO,
                "OpenLI: SMS worker thread %d received invalid SIP target",
                state->workerid);
        return NULL;
    }

    HASH_FIND(hh_liid, state->voipintercepts, liidspace, strlen(liidspace),
            found);
    if (!found) {
        logger(LOG_INFO,
                "OpenLI: SMS worker thread %d received SIP target for unknown VoIP LIID %s.",
                liidspace);
    }
    return found;
}

static int add_sms_sip_target(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;

    found = lookup_sip_target_intercept(state, provmsg, &sipid);
    if (!found) {
        return -1;
    }
    add_new_sip_target_to_list(found, &sipid);
    return 0;
}

static int remove_sms_sip_target(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;
    int ret = 0;

    found = lookup_sip_target_intercept(state, provmsg, &sipid);
    if (!found) {
        ret = -1;
    } else {
        disable_sip_target_from_list(found, &sipid);
    }
    if (sipid.username) {
        free(sipid.username);
    }
    if (sipid.realm) {
        free(sipid.realm);
    }
    return 0;
}

static int sms_worker_process_packet(openli_sms_worker_t *state) {

    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving packet in SMS worker thread %d: %s",
                    state->workerid, strerror(errno));
            return -1;
        }

        /* TODO
         *
         * is it a "MESSAGE" ?
         *   is it TO or FROM an intercept target?
         *      is it a new call-ID or an existing one?
         *         new: create "session"
         *         existing: grab CIN etc. from existing session
         *      create an IRI from this packet
         *
         * else: does the call ID match a known intercept session?
         *      create an IRI from this packet
         *
         * if intercepted, update timestamp of last session activity
         */

         trace_destroy_packet(recvd.data.pkt);
    } while (rc > 0);
    return 0;
}

static int sms_worker_handle_provisioner_message(openli_sms_worker_t *state,
        openli_export_recv_t *msg) {

    int ret = 0;
    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_START_VOIPINTERCEPT:
            ret = add_new_sms_voip_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_VOIPINTERCEPT:
            ret = halt_sms_voip_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_VOIPINTERCEPT:
            ret = modify_sms_voip_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_ANNOUNCE_SIP_TARGET:
            ret = add_sms_sip_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_WITHDRAW_SIP_TARGET:
            ret = remove_sms_sip_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            /* No additional per-intercept or per-target behaviour is
             * required?
             */
            disable_unconfirmed_voip_intercepts(&(state->voipintercepts),
                    NULL, NULL, NULL, NULL);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_voip_intercepts_as_unconfirmed(&(state->voipintercepts));
            break;
        default:
            logger(LOG_INFO, "OpenLI: SMS worker thread %d received unexpected message type from provisioner: %u",
                    state->workerid, msg->data.provmsg.msgtype);
            ret = -1;
    }

    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }

    return ret;
}


static int sms_worker_process_sync_thread_message(openli_sms_worker_t *state) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(state->zmq_ii_sock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in SMS thread %d: %s",
                    state->workerid, strerror(errno));
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
            if (sms_worker_handle_provisioner_message(state, msg) < 0) {
                free(msg);
                return -1;
            }
        }

        free(msg);
    } while (x > 0);

    return 1;

}

static void sms_worker_main(openli_sms_worker_t *state) {
    zmq_pollitem_t *topoll;
    sync_epoll_t purgetimer;
    struct itimerspec its;
    int x;

    logger(LOG_INFO, "OpenLI: starting SMS worker thread %d", state->workerid);

    topoll = calloc(3, sizeof(zmq_pollitem_t));

    its.it_value.tv_sec = 60;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    while (1) {
        topoll[0].socket = state->zmq_ii_sock;
        topoll[0].events = ZMQ_POLLIN;

        topoll[1].socket = state->zmq_colthread_recvsock;
        topoll[1].events = ZMQ_POLLIN;

        topoll[2].socket = NULL;
        topoll[2].fd = purgetimer.fd;
        topoll[2].events = ZMQ_POLLIN;

        if ((x = zmq_poll(topoll, 3, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO,
                    "OpenLI: error while polling in SMS worker thread %d: %s",
                    state->workerid, strerror(errno));
            break;
        }

        if (x == 0) {
            continue;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            /* message from the sync thread */
            x = sms_worker_process_sync_thread_message(state);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            /* a packet passed on from a collector thread */
            x = sms_worker_process_packet(state);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }

        if (topoll[2].revents & ZMQ_POLLIN) {
            /* expiry check is due for all known call-ids */
            logger(LOG_INFO, "DEVDEBUG: checking for expired SMS call IDs");
            topoll[2].revents = 0;

            purgetimer.fdtype = 0;
            purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(purgetimer.fd, 0, &its, NULL);

            topoll[2].fd = purgetimer.fd;
        }
    }

    free(topoll);
}

void *start_sms_worker_thread(void *arg) {
    openli_sms_worker_t *state = (openli_sms_worker_t *)arg;
    char sockname[256];
    int zero = 0, x;
    openli_state_update_t recvd;

    state->zmq_pubsocks = calloc(state->tracker_threads, sizeof(void *));

    init_zmq_socket_array(state->zmq_pubsocks, state->tracker_threads,
            "inproc://openlipub", state->zmq_ctxt);

    state->zmq_ii_sock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlismscontrol_sync-%d",
            state->workerid);
    if (zmq_bind(state->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to bind to II zmq: %s", state->workerid, strerror(errno));
        goto haltsmsworker;
    }

    if (zmq_setsockopt(state->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to configure II zmq: %s", state->workerid, strerror(errno));
        goto haltsmsworker;
    }

    state->zmq_colthread_recvsock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlismsworker-colrecv%d",
            state->workerid);

    if (zmq_bind(state->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to bind to colthread zmq: %s", state->workerid, strerror(errno));
        goto haltsmsworker;
    }

    if (zmq_setsockopt(state->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
         logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to configure colthread zmq: %s", state->workerid, strerror(errno));
         goto haltsmsworker;
    }


    sms_worker_main(state);

    do {
        /* drain any remaining captured packets in the recv queue */
        x = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltsmsworker:
    logger(LOG_INFO, "OpenLI: halting SMS processing thread %d",
            state->workerid);

    zmq_close(state->zmq_ii_sock);
    zmq_close(state->zmq_colthread_recvsock);

    free_all_voipintercepts(&(state->voipintercepts));
    clear_zmq_socket_array(state->zmq_pubsocks, state->tracker_threads);

    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
