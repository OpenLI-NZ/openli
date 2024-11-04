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

#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timerfd.h>
#include <math.h>
#include <libtrace.h>

#include "logger.h"
#include "util.h"
#include "sip_worker.h"
#include "collector.h"
#include "collector_publish.h"
#include "ipmmiri.h"
#include "intercept.h"
#include "location.h"


int init_sip_worker_thread(openli_sip_worker_t *sipworker,
        collector_global_t *glob, size_t workerid) {

    char name[1024];

    snprintf(name, 1024, "sipworker-%zu", workerid);

    sipworker->workerid = workerid;
    sipworker->worker_threadname = strdup(name);
    sipworker->zmq_ctxt = glob->zmq_ctxt;
    sipworker->stats_mutex = &(glob->stats_mutex);
    sipworker->stats = &(glob->stats);
    sipworker->shared = &(glob->sharedinfo);
    sipworker->shared_mutex = &(glob->config_mutex);
    sipworker->zmq_ii_sock = NULL;
    sipworker->zmq_pubsocks = NULL;
    sipworker->zmq_fwdsocks = NULL;
    sipworker->zmq_colthread_recvsock = NULL;
    sipworker->tracker_threads = glob->seqtracker_threads;
    sipworker->forwarding_threads = glob->forwarding_threads;
    sipworker->voipintercepts = NULL;
    sipworker->sipparser = NULL;
    sipworker->knowncallids = NULL;
    sipworker->ignore_sdpo_matches = glob->ignore_sdpo_matches;

    sipworker->debug.sipdebugfile_base = strdup(glob->sipdebugfile);
    sipworker->debug.sipdebugout = NULL;
    sipworker->debug.sipdebugupdate = NULL;
    sipworker->debug.log_bad_instruct = 1;
    sipworker->debug.log_bad_sip = 1;
    sipworker->timeouts = NULL;

    return 0;
}

static void destroy_sip_worker_thread(openli_sip_worker_t *sipworker) {
    sync_epoll_t *syncev, *tmp;

    if (sipworker->sipparser) {
        release_sip_parser(sipworker->sipparser);
    }

    free_voip_cinmap(sipworker->knowncallids);
    HASH_ITER(hh, sipworker->timeouts, syncev, tmp) {
        HASH_DELETE(hh, sipworker->timeouts, syncev);
    }

    if (sipworker->voipintercepts) {
        free_all_voipintercepts(&(sipworker->voipintercepts));
    }

    if (sipworker->worker_threadname) {
        free(sipworker->worker_threadname);
    }


    if (sipworker->debug.sipdebugupdate) {
        trace_destroy_output(sipworker->debug.sipdebugupdate);
    }

    if (sipworker->debug.sipdebugout) {
        trace_destroy_output(sipworker->debug.sipdebugout);
    }

    if (sipworker->debug.sipdebugfile_base) {
        free(sipworker->debug.sipdebugfile_base);
    }

    if (sipworker->zmq_colthread_recvsock) {
        zmq_close(sipworker->zmq_colthread_recvsock);
    }

    if (sipworker->zmq_ii_sock) {
        zmq_close(sipworker->zmq_ii_sock);
    }

    clear_zmq_socket_array(sipworker->zmq_pubsocks, sipworker->tracker_threads);
    clear_zmq_socket_array(sipworker->zmq_fwdsocks,
            sipworker->forwarding_threads);
}

static int setup_zmq_sockets(openli_sip_worker_t *sipworker) {
    int i, zero = 0;
    char sockname[256];

    sipworker->zmq_pubsocks = calloc(sipworker->tracker_threads,
            sizeof(void *));
    sipworker->zmq_fwdsocks = calloc(sipworker->forwarding_threads,
            sizeof(void *));

    init_zmq_socket_array(sipworker->zmq_pubsocks, sipworker->tracker_threads,
            "inproc://openlipub", sipworker->zmq_ctxt);
    init_zmq_socket_array(sipworker->zmq_fwdsocks,
            sipworker->forwarding_threads,
            "inproc://openliforwardercontrol_sync", sipworker->zmq_ctxt);

    sipworker->zmq_ii_sock = zmq_socket(sipworker->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlisipcontrol_sync-%d",
            sipworker->workerid);
    if (zmq_bind(sipworker->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to bind to II ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }

    if (zmq_setsockopt(sipworker->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to configure II ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }

    sipworker->zmq_colthread_recvsock = zmq_socket(sipworker->zmq_ctxt,
            ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlisipworker_colrecv-%d",
            sipworker->workerid);
    if (zmq_bind(sipworker->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to bind to packet ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }

    if (zmq_setsockopt(sipworker->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to configure packet ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }
    return 0;
}

static size_t setup_pollset(openli_sip_worker_t *sipworker,
        zmq_pollitem_t **topoll, size_t *topoll_size, int timerfd,
        struct rtpstreaminf ***expiring) {

    size_t topoll_req, i;
    sync_epoll_t *syncev, *tmp;

    topoll_req = 3 + HASH_CNT(hh, sipworker->timeouts);
    if (topoll_req > *topoll_size) {
        free(*topoll);
        free(*expiring);
        *topoll = calloc(topoll_req + 32, sizeof(zmq_pollitem_t));
        *expiring = calloc(topoll_req + 32,
                sizeof(struct rtpstreaminf *));
        *topoll_size = topoll_req + 32;
    }

    (*topoll)[0].socket = sipworker->zmq_ii_sock;
    (*topoll)[0].events = ZMQ_POLLIN;

    (*topoll)[1].socket = sipworker->zmq_colthread_recvsock;
    (*topoll)[1].events = ZMQ_POLLIN;

    (*topoll)[2].socket = NULL;
    (*topoll)[2].fd = timerfd;
    (*topoll)[2].events = ZMQ_POLLIN;

    i = 3;
    HASH_ITER(hh, sipworker->timeouts, syncev, tmp) {
        (*topoll)[i].socket = NULL;
        (*topoll)[i].fd = syncev->fd;
        (*topoll)[i].events = ZMQ_POLLIN;
        (*expiring)[i] = (struct rtpstreaminf *)(syncev->ptr);
        i++;
    }

    return i;
}

static void sip_worker_main(openli_sip_worker_t *sipworker) {

    sync_epoll_t purgetimer;
    zmq_pollitem_t *topoll;
    size_t topoll_size, topoll_cnt;
    struct itimerspec its;
    struct timeval tv;
    struct rtpstreaminf **expiringstreams;

    topoll = calloc(128, sizeof(zmq_pollitem_t));
    expiringstreams = calloc(128, sizeof(struct rtpstreaminf *));
    topoll_size = 128;

    its.it_value.tv_sec = 60;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    while (1) {
        topoll_cnt = setup_zmq_sockets(sipworker, &topoll, &topoll_size,
                purgetimer.fd, &expiringstreams);

        if (topoll_cnt < 1) {
            break;
        }
        rc = zmq_poll(topoll, topoll_cnt, 50);
        if (rc < 0) {
            logger(LOG_INFO,
                    "OpenLI: error in zmq_poll in SIP worker %d: %s",
                    sipworker->workerid, strerror(errno));
            break;
        }

        /* TODO */
        /* halt RTP streams for calls that have been over long enough --
         * topoll[3 .. N]
         */

        /* handle any messages from the sync thread -- topoll[0] */

        /* process SIP packets receiving from the packet processing threads --
         * topoll[1]
         */

        /* purge any SMS-only sessions that have been idle for a while --
         * topoll[2] timer
         */
    }
}

void *start_sip_worker_thread(void *arg) {
    openli_sip_worker_t *sipworker = (openli_sip_worker_t *)arg;
    int x;
    openli_state_update_t recvd;

    if (setup_zmq_sockets(sipworker) < 0) {
        goto haltsipworker;
    }

    sip_worker_main(sipworker);

    do {
        /* drain any remaining captured packets in the receive queue */
        x = zmq_recv(sipworker->zmq_colthread_recvsock, &recvd,
                sizeof(recvd), ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltsipworker:
    logger(LOG_INFO, "OpenLI: halting SIP processing thread %d",
            sipworker->workerid);
    destroy_sip_worker_thread(sipworker);
    pthread_exit(NULL);
}
