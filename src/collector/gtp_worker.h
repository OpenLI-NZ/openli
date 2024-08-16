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

#ifndef OPENLI_GTP_WORKER_H_
#define OPENLI_GTP_WORKER_H_

#include "gtp.h"
#include "intercept.h"
#include "collector_base.h"
#include "collector_util.h"
#include "internetaccess.h"

typedef struct openli_gtp_worker {
    /* The global zeromq context for the entire program */
    void *zmq_ctxt;

    /* A sequential identifier for this worker thread */
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

    /* Hash map of send_syncq_t instances that are used to push interceptable
     * IP addresses back to the collector threads */
    void *collector_queues;

    /* Mutex to protect the collector_queues map */
    pthread_mutex_t col_queue_mutex;

    /* Number of sequence tracker threads operated by this collector */
    int tracker_threads;

    /* The pthread ID for this worker thread */
    pthread_t threadid;

    /* Set of all mobile IP data intercepts announced to this collector */
    ipintercept_t *ipintercepts;

    /* Set of all "users" (i.e. MSISDNs, IMSIs, IMEIs) with active GTP
     * sessions */
    internet_user_t *allusers;

    /* Set of all data TEIDs for active intercepts */
    teid_to_session_t *all_data_teids;

    /* Map of user identities -> active intercepts */
    user_intercept_list_t *userintercepts;

    /* Instance of the GTP session state processing plugin used to
     * track sessions observed in GTP-C traffic
     */
    access_plugin_t *gtpplugin;

    /* Free list of ETSILI generic IEs that have been used for encoding
     * fields in previous ETSI records by this thread instance.
     */
    etsili_generic_freelist_t *freegenerics;

} openli_gtp_worker_t;

int start_gtp_worker_thread(openli_gtp_worker_t *worker, int id,
        void *globarg);

#endif
