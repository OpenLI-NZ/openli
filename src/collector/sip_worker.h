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
#include "export_buffer.h"
#include "sip_worker_redirection.h"

#define SMS_SESSION_EXPIRY 180

typedef struct sip_debug_settings {
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
    collector_sip_config_t *shared;

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

    /* ZMQ for receiving SIP messages from other SIP worker threads */
    void *zmq_redirect_insock;

    /* ZMQ for sending SIP messages to other SIP worker threads */
    void **zmq_redirect_outsocks;

    /* Number of SIP worker threads operated by this collector */
    int sipworker_threads;

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

    /* State for managing the pcaps where we will write bogus SIP messages
     * if requested by the user
     */
    sip_debug_settings_t debug;

    /* The set of timer events that will fire to indicate that the timewait
     * for a completed SIP session has expired, and therefore we can remove
     * the state for that session.
     */
    sync_epoll_t *timeouts;

    /* Shared state used to track how many worker threads have halted */
    halt_info_t *haltinfo;

    /* Local state for SIP call-ids that are either being redirected, or
     * have been redirected by other worker threads.
     */
    sip_worker_redirect_t redir_data;

    /* The timestamp when this thread was started */
    time_t started;

} openli_sip_worker_t;

void *start_sip_worker_thread(void *arg);
void create_sip_ipmmiri(openli_sip_worker_t *sipworker,
        voipintercept_t *vint, openli_export_recv_t *irimsg,
        etsili_iri_type_t iritype, int64_t cin, openli_location_t *loc,
        int loc_count, libtrace_packet_t **pkts, int pkt_cnt);
int sipworker_update_sip_state(openli_sip_worker_t *sipworker,
        libtrace_packet_t **pkts,
        int pkt_cnt, openli_export_recv_t *irimsg);
int mask_sms_message_content(uint8_t *sipstart, uint16_t siplen);
int sip_worker_announce_rtp_streams(openli_sip_worker_t *sipworker,
        rtpstreaminf_t *rtp);
void sip_worker_conclude_sip_call(openli_sip_worker_t *sipworker,
        rtpstreaminf_t *thisrtp);

int lookup_sip_callid(openli_sip_worker_t *sipworker, char *callid);

int redirect_sip_worker_packets(openli_sip_worker_t *sipworker,
        char *callid, libtrace_packet_t **pkts, int pkt_cnt);
void clear_redirection_map(Pvoid_t *map);
void destroy_redirected_message(redirected_sip_message_t *msg);
int handle_sip_redirection_reject(openli_sip_worker_t *sipworker,
        char *callid, uint8_t rejector);
int handle_sip_redirection_over(openli_sip_worker_t *sipworker,
        char *callid);
int handle_sip_redirection_claim(openli_sip_worker_t *sipworker,
        char *callid, uint8_t claimer);
int handle_sip_redirection_packet(openli_sip_worker_t *sipworker,
        redirected_sip_message_t *msg);
int handle_sip_redirection_purge(openli_sip_worker_t *sipworker,
        char *callid);
int conclude_redirected_sip_call(openli_sip_worker_t *sipworker, char *callid);
void purge_redirected_sip_calls(openli_sip_worker_t *sipworker);

#endif
