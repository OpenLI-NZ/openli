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

#ifndef OPENLI_COLLECTOR_SIP_WORKER_H_
#define OPENLI_COLLECTOR_SIP_WORKER_H_

#include <libtrace.h>

#include "intercept.h"
#include "sipparsing.h"
#include "util.h"
#include "collector_util.h"
#include "collector_base.h"

#define SMS_SESSION_EXPIRY 180

typedef struct sip_debug_settings {
    char *sipdebugfile_base;
    libtrace_out_t *sipdebugout;
    libtrace_out_t *sipdebugupdate;

    uint8_t log_bad_sip;
} sip_debug_settings_t;

typedef struct openli_sip_worker {
    /* The global zeromq context for the entire program */
    void *zmq_ctxt;

    /* The name of this worker thread */
    const char *worker_threadname;

    /* A sequential identifier for this SIP worker thread */
    int workerid;

    /* Mutex to protect the collector stats from races */
    pthread_mutex_t *stats_mutex;

    /* Collector statistics (e.g. CC and IRI counters since starting) */
    collector_stats_t *stats;

    /* Shared global-level configuration for this collector instance */
    collector_identity_t *shared;

    /* RW mutex to protect the shared config against race conditions */
    pthread_rwlock_t *shared_mutex;

    /* Hash map of send_syncq_t instances that are used to push interceptable
     * RTP streams back to the collector threads */
    void *collector_queues;

    /* Mutex to protect the collector_queues map */
    pthread_mutex_t col_queue_mutex;

    /* ZMQ for receiving instructions from sync thread */
    void *zmq_ii_sock;
    /* ZMQs for publishing to seqtracker threads */
    void **zmq_pubsocks;
    /* ZMQ for receiving from collector threads */
    void *zmq_colthread_recvsock;
    /* ZMQ for sending messages to forwarding threads */
    void **zmq_fwdsocks;

    /* Number of sequence tracker threads operated by this collector */
    int tracker_threads;

    /* Number of forwarding threads operated by this collector */
    int forwarding_threads;

    /* The pthread ID for this SIP worker thread */
    pthread_t threadid;

    /* Set of all the VoIP intercepts announced to this collector */
    voipintercept_t *voipintercepts;

    /* SIP Parser instance for this thread */
    openli_sip_parser_t *sipparser;

    /* Mapping of SIP call IDs to a list of intercepts that require that
     * SIP session to be intercepted
     */
    voipcinmap_t *knowncallids;

    /* Flag that indicates whether we should avoid treating calls with
     * matching SDP-O fields as separate legs of the same call, regardless
     * of their call ID
     */
    uint8_t ignore_sdpo_matches;

    /* State for managing the pcaps where we will write bogus SIP messages
     * if requested by the user
     */
    sip_debug_settings_t debug;

    /* The set of timer events that will fire to indicate that the timewait
     * for a completed SIP session has expired, and therefore we can remove
     * the state for that session.
     */
    sync_epoll_t *timeouts;

} openli_sip_worker_t;

void *start_sip_worker_thread(void *arg);

#endif
