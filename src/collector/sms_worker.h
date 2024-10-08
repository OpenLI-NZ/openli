/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

#ifndef OPENLI_SMS_WORKER_H_
#define OPENLI_SMS_WORKER_H_

#include "intercept.h"
#include "collector_base.h"
#include "collector_util.h"
#include "sipparsing.h"

typedef struct voip_intercept_ref {
    char *liid;
    voipintercept_t *vint;
    UT_hash_handle hh;
} voip_intercept_ref_t;

typedef struct callid_intercept {
    const char *callid;
    int64_t cin;
    time_t last_observed;

    voip_intercept_ref_t *intlist;
    UT_hash_handle hh;
} callid_intercepts_t;


typedef struct openli_sms_worker {
    /* The global zeromq context for the entire program */
    void *zmq_ctxt;

    /* A sequential identifier for this SMS worker thread */
    int workerid;

    /* Mutex to protect the collector stats from races */
    pthread_mutex_t *stats_mutex;

    /* Collector statistics (e.g. CC and IRI counters since starting) */
    collector_stats_t *stats;

    /* Shared global-level configuration for this collector instance */
    collector_identity_t *shared;

    /* RW mutex to protect the shared config against race conditions */
    pthread_rwlock_t *shared_mutex;

    /* ZMQ for receiving instructions from sync thread */
    void *zmq_ii_sock;
    /* ZMQs for publishing to seqtracker threads */
    void **zmq_pubsocks;
    /* ZMQ for receiving from collector threads */
    void *zmq_colthread_recvsock;

    /* Number of sequence tracker threads operated by this collector */
    int tracker_threads;

    /* The pthread ID for this SMS worker thread */
    pthread_t threadid;

    /* Set of all the VoIP intercepts announced to this collector */
    voipintercept_t *voipintercepts;

    /* SIP Parser instance for processing SMS over SIP traffic */
    openli_sip_parser_t *sipparser;

    /* Mapping of SMS "SIP call IDs" to a list of intercepts that require
     * those SMS sessions to be intercepted.
     */
    callid_intercepts_t *known_callids;
} openli_sms_worker_t;

void *start_sms_worker_thread(void *arg);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
