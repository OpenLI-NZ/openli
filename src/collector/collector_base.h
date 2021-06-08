/*
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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

#ifndef OPENLI_COLLECTOR_BASE_H_
#define OPENLI_COLLECTOR_BASE_H_

#include "config.h"
#include <pthread.h>
#include <libwandder_etsili.h>
#include <libwandder.h>
#include <zmq.h>
#include <Judy.h>
#include <amqp.h>

#include "export_shared.h"
#include "etsili_core.h"
#include "collector_publish.h"
#include "export_buffer.h"
#include "openli_tls.h"

typedef struct export_dest {
    int failmsg;
    int fd;
    int awaitingconfirm;
    int halted;
    int pollindex;
    uint32_t mediatorid;
    char *ipstr;
    char *portstr;
    export_buffer_t buffer;
    uint8_t logallowed;

    SSL *ssl;
    int waitingforhandshake;
    int ssllasterror;

    amqp_bytes_t rmq_queueid;

    UT_hash_handle hh_fd;
    UT_hash_handle hh_medid;
} export_dest_t;

typedef struct collector_stats {
    uint64_t packets_accepted;
    uint64_t packets_dropped;
    uint64_t packets_intercepted;
    uint64_t packets_sync_ip;
    uint64_t packets_sync_voip;
    uint64_t ipcc_created;
    uint64_t ipiri_created;
    uint64_t mobiri_created;
    uint64_t ipmmcc_created;
    uint64_t ipmmiri_created;
    uint64_t bad_sip_packets;
    uint64_t bad_ip_session_packets;

    uint64_t ipintercepts_added_diff;
    uint64_t ipintercepts_added_total;
    uint64_t voipintercepts_added_diff;
    uint64_t voipintercepts_added_total;
    uint64_t ipintercepts_ended_diff;
    uint64_t ipintercepts_ended_total;
    uint64_t voipintercepts_ended_diff;
    uint64_t voipintercepts_ended_total;

    uint64_t ipsessions_added_diff;
    uint64_t ipsessions_added_total;
    uint64_t voipsessions_added_diff;
    uint64_t voipsessions_added_total;
    uint64_t ipsessions_ended_diff;
    uint64_t ipsessions_ended_total;
    uint64_t voipsessions_ended_diff;
    uint64_t voipsessions_ended_total;

} collector_stats_t;

typedef struct sync_thread_global {

    pthread_t threadid;
    pthread_mutex_t mutex;
    void *collector_queues;
    void *epollevs;
    int epoll_fd;
    int total_col_threads;

    pthread_mutex_t *stats_mutex;
    collector_stats_t *stats;

} sync_thread_global_t;

enum {
    OPENLI_UPCOMING_INTERCEPT_EVENT_START,
    OPENLI_UPCOMING_INTERCEPT_EVENT_END
};

struct upcoming_intercept_event {
    uint8_t event_type;
    void *intercept;
    char *liid;
    UT_hash_handle hh;
};

typedef struct upcoming_intercept_time {
    uint64_t timestamp;
    struct upcoming_intercept_event *events;
} upcoming_intercept_time_t;

typedef struct collector_identity {
    char *operatorid;
    char *networkelemid;
    char *intpointid;
    char *provisionerip;
    char *provisionerport;

    int operatorid_len;
    int networkelemid_len;
    int intpointid_len;

} collector_identity_t;

typedef struct old_intercept removed_intercept_t;

struct old_intercept {
    void *preencoded;
    void *ber_top;
    uint32_t haltedat;
    removed_intercept_t *next;
};

enum {
    OPENLI_ENCODING_DER,
    OPENLI_ENCODING_BER
};

typedef struct seqtracker_thread_data {
    void *zmq_ctxt;
    pthread_t threadid;
    int trackerid;
    collector_identity_t *colident;

    void *zmq_pushjobsock;
    void *zmq_recvpublished;

    exporter_intercept_state_t *intercepts;
    removed_intercept_t *removedints;
    uint8_t encoding_method;
#if HAVE_BER_ENCODING
    wandder_encoder_ber_t *enc_ber;
#endif

} seqtracker_thread_data_t;

typedef struct intercept_reorderer {

    char *liid;
    char *key;
    uint32_t expectedseqno;
    Pvoid_t pending;

} int_reorderer_t;

typedef struct forwarding_thread_data {
    void *zmq_ctxt;
    pthread_t threadid;
    int forwardid;
    int encoders;
    int colthreads;

    void *zmq_ctrlsock;
    void *zmq_pullressock;

    uint8_t *forcesend;
    zmq_pollitem_t *topoll;
    int pollsize;
    int nextpoll;
    int awaitingconfirm;

    int conntimerfd;
    int flagtimerfd;
    uint8_t forcesend_rmq;

    Pvoid_t destinations_by_fd;
    Pvoid_t destinations_by_id;

    Pvoid_t intreorderer_cc;
    Pvoid_t intreorderer_iri;

    SSL_CTX *ctx;
    pthread_mutex_t sslmutex;

    amqp_connection_state_t ampq_conn;
    amqp_socket_t *ampq_sock;
    openli_RMQ_config_t RMQ_conf;

} forwarding_thread_data_t;

typedef struct encoder_state {
    void *zmq_ctxt;
    void **zmq_recvjobs;
    void **zmq_pushresults;
    void *zmq_control;
    zmq_pollitem_t *topoll;

    pthread_t threadid;
    int workerid;
    collector_identity_t *shared;
    wandder_encoder_t *encoder;
    etsili_generic_freelist_t *freegenerics;

    int seqtrackers;
    int forwarders;
    uint8_t halted;
} openli_encoder_t;

typedef struct encoder_job {
    wandder_encode_job_t *preencoded;
#ifdef HAVE_BER_ENCODING
    wandder_etsili_top_t *top;
    wandder_etsili_child_t *child;
#endif
    uint32_t seqno;
    char *cinstr;
    openli_export_recv_t *origreq;
    char *liid;
} PACKED openli_encoding_job_t;

void destroy_encoder_worker(openli_encoder_t *enc);
void *run_encoder_worker(void *encstate);

void *start_seqtracker_thread(void *data);
void clean_seqtracker(seqtracker_thread_data_t *seqdata);

void *start_forwarding_thread(void *data);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
