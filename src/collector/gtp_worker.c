/*
 *
 * Copyright (c) 2024 Searchlight New Zealand Ltd.
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
#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <libtrace.h>
#include <sys/timerfd.h>

#include "gtp_worker.h"
#include "collector.h"
#include "logger.h"
#include "util.h"
#include "intercept.h"
#include "netcomms.h"

static void remove_gtp_intercept(openli_gtp_worker_t *worker,
        ipintercept_t *ipint) {

    /* The sync thread should tell the collector threads that the intercept
     * is over, so we don't need to "withdraw" any IP sessions that we've
     * announced.
     */

    logger(LOG_INFO, "DEVDEBUG: removing intercept %s from GTP worker %d",
            ipint->common.liid, worker->workerid);
    remove_intercept_from_user_intercept_list(&worker->userintercepts, ipint);
    HASH_DELETE(hh_liid, worker->ipintercepts, ipint);
    free_single_ipintercept(ipint);
}

static void disable_unconfirmed_gtp_intercepts(openli_gtp_worker_t *worker) {
    ipintercept_t *ipint, *tmp;

    HASH_ITER(hh_liid, worker->ipintercepts, ipint, tmp) {
        if (ipint->awaitingconfirm) {
            remove_gtp_intercept(worker, ipint);
        }
    }
}

static void flag_gtp_intercepts(ipintercept_t *cepts) {
    ipintercept_t *ipint, *tmp;

    /* Don't worry about statics, because we should not be dealing with
     * them here anyway */
    HASH_ITER(hh_liid, cepts, ipint, tmp) {
        ipint->awaitingconfirm = 1;
    }

}

static void push_existing_ip_sessions(openli_gtp_worker_t *worker,
        ipintercept_t *ipint) {

    /* TODO */
}

static int init_gtp_intercept(openli_gtp_worker_t *worker,
        ipintercept_t *ipint) {

    if (ipint->accesstype != INTERNET_ACCESS_TYPE_MOBILE) {
        /* Only care about "mobile" intercepts */
        free_single_ipintercept(ipint);
        return 0;
    }

    /* Discard any static IPs announced for this intercept, as they are
     * irrelevant for the purposes of this thread.
     */
    logger(LOG_INFO, "DEVDEBUG: adding intercept %s -- %s to GTP worker %d",
            ipint->common.liid, ipint->username, worker->workerid);
    free_all_staticipranges(&(ipint->statics));
    ipint->statics = NULL;

    if (worker->tracker_threads <= 1) {
        ipint->common.seqtrackerid = 0;
    } else {
        ipint->common.seqtrackerid = hash_liid(ipint->common.liid) %
                worker->tracker_threads;
    }

    add_intercept_to_user_intercept_list(&worker->userintercepts, ipint);
    HASH_ADD_KEYPTR(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, ipint);
    ipint->awaitingconfirm = 0;
}

static void update_modified_gtp_intercept(openli_gtp_worker_t *worker,
        ipintercept_t *found, ipintercept_t *ipint) {

    int r = 0, changed = 0;

    logger(LOG_INFO, "DEVDEBUG: updating intercept %s -- %s on GTP worker %d",
            found->common.liid, found->username, worker->workerid);
    if (ipint->accesstype != INTERNET_ACCESS_TYPE_MOBILE) {
        /* Intercept has changed to be NOT mobile, so just remove it */
        logger(LOG_INFO, "DEVDEBUG: GTP worker %d -- %s is no longer mobile",
                worker->workerid, found->common.liid);
        remove_intercept_from_user_intercept_list(&worker->userintercepts,
                found);
        HASH_DELETE(hh_liid, worker->ipintercepts, found);
        free_single_ipintercept(ipint);
        free_single_ipintercept(found);
        return;
    }

    if (update_modified_intercept_common(&(found->common), &(ipint->common),
            OPENLI_INTERCEPT_TYPE_IP, &changed) < 0) {
        r = -1;
    } else {
        if (strcmp(ipint->username, found->username) != 0 ||
                ipint->mobileident != found->mobileident) {
            logger(LOG_INFO, "DEVDEBUG: GTP worker %d -- %s has new username '%s'",
                    worker->workerid, found->common.liid, ipint->username);
            remove_intercept_from_user_intercept_list(&worker->userintercepts,
                    found);
            free(found->username);
            found->username = ipint->username;
            found->username_len = ipint->username_len;
            found->mobileident = ipint->mobileident;
            ipint->username = NULL;
            add_intercept_to_user_intercept_list(&worker->userintercepts,
                    found);

            push_existing_ip_sessions(worker, found);
        }
        found->awaitingconfirm = 0;
    }
    free_single_ipintercept(ipint);
}

static int add_new_gtp_intercept(openli_gtp_worker_t *worker,
        provisioner_msg_t *msg) {

    ipintercept_t *ipint, *found;
    int ret = 0;

    ipint = calloc(1, sizeof(ipintercept_t));
    if (decode_ipintercept_start(msg->msgbody, msg->msglen, ipint) < 0) {
        logger(LOG_INFO, "OpenLI: GTP worker %d failed to decode mobile IP intercept start message from provisioner", worker->workerid);
        return -1;
    }

    HASH_FIND(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, found);

    if (found) {
        update_modified_gtp_intercept(worker, found, ipint);
        found->awaitingconfirm = 0;
        ret = 0;
    } else {
        ret = init_gtp_intercept(worker, ipint);
    }
    return ret;
}

static int modify_gtp_intercept(openli_gtp_worker_t *worker,
        provisioner_msg_t *msg) {
    ipintercept_t *ipint, *found;

    ipint = calloc(1, sizeof(ipintercept_t));
    if (decode_ipintercept_modify(msg->msgbody, msg->msglen, ipint) < 0) {
        logger(LOG_INFO, "OpenLI: GTP worker %d failed to decode mobile IP intercept modify message from provisioner", worker->workerid);
        return -1;
    }

    HASH_FIND(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, found);
    if (!found) {
        return init_gtp_intercept(worker, ipint);
    } else {
        update_modified_gtp_intercept(worker, found, ipint);
    }
    return 0;
}

static int halt_gtp_intercept(openli_gtp_worker_t *worker,
        provisioner_msg_t *msg) {
    ipintercept_t *ipint, *found;

    ipint = calloc(1, sizeof(ipintercept_t));
    if (decode_ipintercept_halt(msg->msgbody, msg->msglen, ipint) < 0) {
        logger(LOG_INFO, "OpenLI: GTP worker %d failed to decode mobile IP intercept halt message from provisioner", worker->workerid);
        return -1;
    }

    HASH_FIND(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, found);
    if (found) {
        remove_gtp_intercept(worker, found);
    }
    free_single_ipintercept(ipint);
    return 0;
}

static int gtp_worker_handle_provisioner_message(openli_gtp_worker_t *worker,
        openli_export_recv_t *msg) {

    int ret = 0;
    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            disable_unconfirmed_gtp_intercepts(worker);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_gtp_intercepts(worker->ipintercepts);
            break;
        case OPENLI_PROTO_START_IPINTERCEPT:
            ret = add_new_gtp_intercept(worker, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_IPINTERCEPT:
            ret = halt_gtp_intercept(worker, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_IPINTERCEPT:
            ret = modify_gtp_intercept(worker, &(msg->data.provmsg));
            break;
        default:
            logger(LOG_INFO, "OpenLI: GTP worker thread %d received unexpected message type from provisioner: %u",
                    worker->workerid, msg->data.provmsg.msgtype);
            ret = -1;
    }

    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }
    return ret;
}

static int gtp_worker_process_sync_thread_message(openli_gtp_worker_t *worker) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(worker->zmq_ii_sock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in GTP thread %d: %s",
                    worker->workerid, strerror(errno));
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
            if (gtp_worker_handle_provisioner_message(worker, msg) < 0) {
                free(msg);
                return -1;
            }
        }

        free(msg);
    } while (x > 0);

    return 1;
}

static void process_gtp_u_packet(openli_gtp_worker_t *worker,
        uint8_t *payload, uint32_t plen, uint32_t teid) {


}

static void process_gtp_c_packet(openli_gtp_worker_t *worker,
        libtrace_packet_t *packet) {


}

static void process_gtp_packet(openli_gtp_worker_t *worker,
        libtrace_packet_t *packet) {
    access_plugin_t *p = worker->gtpplugin;
    uint8_t *payload;
    uint32_t plen;
    uint8_t proto;
    uint32_t rem;
    void *transport;
    uint8_t msgtype;
    uint32_t teid;

    if (packet == NULL) {
        return;
    }

    transport = trace_get_transport(packet, &proto, &rem);
    if (transport == NULL || rem == 0) {
        return;
    }

    plen = trace_get_payload_length(packet);
    if (proto != TRACE_IPPROTO_UDP) {
        /* should be UDP only */
        return;
    }
    payload = (uint8_t *)trace_get_payload_from_udp((libtrace_udp_t *)transport,
            &rem);
    if (rem < plen) {
        plen = rem;
    }

    if (((*payload) & 0xe8) == 0x48) {
        /* GTPv2 */
        gtpv2_header_teid_t *v2hdr = (gtpv2_header_teid_t *)payload;

        if (plen <= sizeof(gtpv2_header_teid_t)) {
            return;
        }

        msgtype = v2hdr->msgtype;
        teid = v2hdr->teid;
        payload += sizeof(gtpv2_header_teid_t);
        plen -= sizeof(gtpv2_header_teid_t);

    } else if (((*payload) & 0xe0) == 0x20) {
        /* GTPv1 */
        gtpv1_header_t *v1hdr = (gtpv1_header_t *)payload;

        if (plen <= sizeof(gtpv1_header_t)) {
            return;
        }

        msgtype = v1hdr->msgtype;
        teid = v1hdr->teid;
        payload += sizeof(gtpv1_header_t);
        plen -= sizeof(gtpv1_header_t);

    } else {
        return;
    }

    if (msgtype == 0xff) {
        /* This is GTP-U */
        process_gtp_u_packet(worker, payload, plen, teid);
    } else {
        /* This is GTP-C */
        process_gtp_c_packet(worker, packet);
    }
}

static int gtp_worker_process_packet(openli_gtp_worker_t *worker) {
    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(worker->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving packet in SMS worker thread %d: %s",
                    worker->workerid, strerror(errno));
            return -1;
        }

        if (recvd.type != OPENLI_UPDATE_GTP) {
            logger(LOG_INFO,
                    "OpenLI: GTP worker thread %d received unexpected update type %u",
                    worker->workerid, recvd.type);
            break;
        }

        /* TODO insert packet processing code here! */
        process_gtp_packet(worker, recvd.data.pkt);

        if (recvd.data.pkt) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (rc > 0);

    return 0;
}

static void gtp_worker_main(openli_gtp_worker_t *worker) {

    zmq_pollitem_t *topoll;
    sync_epoll_t purgetimer;
    struct itimerspec its;
    struct timeval tv;
    int x;

    logger(LOG_INFO, "OpenLI: starting GTP worker thread %d",
            worker->workerid);

    topoll = calloc(3, sizeof(zmq_pollitem_t));

    its.it_value.tv_sec = 60;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    while (1) {
        topoll[0].socket = worker->zmq_ii_sock;
        topoll[0].events = ZMQ_POLLIN;

        topoll[1].socket = worker->zmq_colthread_recvsock;
        topoll[1].events = ZMQ_POLLIN;

        topoll[2].socket = NULL;
        topoll[2].fd = purgetimer.fd;
        topoll[2].events = ZMQ_POLLIN;

        if ((x = zmq_poll(topoll, 3, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO,
                    "OpenLI: error while polling in GTP worker thread %d: %s",
                    worker->workerid, strerror(errno));
            break;
        }

        if (x == 0) {
            continue;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            x = gtp_worker_process_sync_thread_message(worker);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            x = gtp_worker_process_packet(worker);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }

        if (topoll[2].revents & ZMQ_POLLIN) {
            topoll[2].revents = 0;

            /* TODO purge "inactive" sessions */

            purgetimer.fdtype = 0;
            purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(purgetimer.fd, 0, &its, NULL);

            topoll[2].fd = purgetimer.fd;
        }
    }

    free(topoll);
}

void *gtp_thread_begin(void *arg) {
    openli_gtp_worker_t *worker = (openli_gtp_worker_t *)arg;
    char sockname[256];
    int zero = 0, x;
    openli_state_update_t recvd;

    worker->zmq_pubsocks = calloc(worker->tracker_threads, sizeof(void *));
    init_zmq_socket_array(worker->zmq_pubsocks, worker->tracker_threads,
            "inproc://openlipub", worker->zmq_ctxt);

    worker->zmq_ii_sock = zmq_socket(worker->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openligtpcontrol_sync-%d",
            worker->workerid);

    if (zmq_bind(worker->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to bind to II zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    if (zmq_setsockopt(worker->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to configure II zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    worker->zmq_colthread_recvsock = zmq_socket(worker->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openligtpworker-colrecv%d",
            worker->workerid);

    if (zmq_bind(worker->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to bind to colthread zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    if (zmq_setsockopt(worker->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
           sizeof(zero)) != 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to configure colthread zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    gtp_worker_main(worker);

    do {
        x = zmq_recv(worker->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltgtpworker:
    logger(LOG_INFO, "OpenLI: halting GTP processing thread %d",
            worker->workerid);

    zmq_close(worker->zmq_ii_sock);
    zmq_close(worker->zmq_colthread_recvsock);
    free_all_users(worker->allusers);
    clear_user_intercept_list(worker->userintercepts);
    free_all_ipintercepts(&(worker->ipintercepts));
    clear_zmq_socket_array(worker->zmq_pubsocks, worker->tracker_threads);

    if (worker->gtpplugin) {
        destroy_access_plugin(worker->gtpplugin);
        free(worker->gtpplugin);
    }

    pthread_exit(NULL);
}

int start_gtp_worker_thread(openli_gtp_worker_t *worker, int id,
        void *globarg) {
    collector_global_t *glob = (collector_global_t *)globarg;
    char name[1024];

    snprintf(name, 1024, "gtpworker-%d", id);

    pthread_mutex_init(&(worker->col_queue_mutex), NULL);

    worker->zmq_ctxt = glob->zmq_ctxt;
    worker->workerid = id;
    worker->stats_mutex = &(glob->stats_mutex);
    worker->stats = &(glob->stats);
    worker->shared = &(glob->sharedinfo);
    worker->zmq_ii_sock = NULL;
    worker->zmq_pubsocks = NULL;
    worker->zmq_colthread_recvsock = NULL;
    worker->collector_queues = NULL;
    worker->tracker_threads = glob->seqtracker_threads;
    worker->ipintercepts = NULL;
    worker->allusers = NULL;
    worker->userintercepts = NULL;
    worker->gtpplugin = init_access_plugin(ACCESS_GTP);

    pthread_create(&(worker->threadid), NULL, gtp_thread_begin,
            (void *)worker);
    pthread_setname_np(worker->threadid, name);

    return 1;
}

