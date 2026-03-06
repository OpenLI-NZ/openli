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

#ifndef OPENLI_COLLECTOR_BASE_H_
#define OPENLI_COLLECTOR_BASE_H_

#include "config.h"
#include <pthread.h>
#include <libwandder_etsili.h>
#include <libwandder.h>
#include <zmq.h>
#include <Judy.h>

#ifdef RMQC_HEADER_SUBDIR
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/tcp_socket.h>
#else
#include <amqp.h>
#include <amqp_tcp_socket.h>
#endif

#include <uthash.h>
#include <libtrace.h>
#include <openssl/evp.h>
#include <signal.h>

#include "export_shared.h"
#include "etsili_core.h"
#include "collector_publish.h"
#include "export_buffer.h"
#include "openli_tls.h"
#include "etsiencoding/etsiencoding.h"
#include "yaml_modifier.h"
#include "openli_epoll.h"

#define MAX_ENCODED_RESULT_BATCH 10

extern volatile sig_atomic_t collector_halt;

typedef struct sync_epoll {
    uint8_t fdtype;
    int fd;
    void *ptr;
    libtrace_thread_t *parent;
    UT_hash_handle hh;
} sync_epoll_t;

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
    uint8_t rmq_declared;

    UT_hash_handle hh_fd;
    UT_hash_handle hh_medid;
} export_dest_t;

typedef struct collector_stats {
    uint64_t packets_accepted;
    uint64_t packets_dropped;
    uint64_t packets_intercepted;
    uint64_t packets_sync_ip;
    uint64_t packets_sync_voip;
    uint64_t packets_sync_email;
    uint64_t packets_gtp;
    uint64_t packets_sms;
    uint64_t ipcc_created;
    uint64_t ipiri_created;
    uint64_t mobiri_created;
    uint64_t ipmmcc_created;
    uint64_t ipmmiri_created;
    uint64_t emailcc_created;
    uint64_t emailiri_created;
    uint64_t bad_sip_packets;
    uint64_t bad_ip_session_packets;

    uint64_t ipintercepts_added_diff;
    uint64_t ipintercepts_added_total;
    uint64_t voipintercepts_added_diff;
    uint64_t voipintercepts_added_total;
    uint64_t emailintercepts_added_diff;
    uint64_t emailintercepts_added_total;
    uint64_t ipintercepts_ended_diff;
    uint64_t ipintercepts_ended_total;
    uint64_t voipintercepts_ended_diff;
    uint64_t voipintercepts_ended_total;
    uint64_t emailintercepts_ended_diff;
    uint64_t emailintercepts_ended_total;

    uint64_t ipsessions_added_diff;
    uint64_t ipsessions_added_total;
    uint64_t voipsessions_added_diff;
    uint64_t voipsessions_added_total;
    uint64_t emailsessions_added_diff;
    uint64_t emailsessions_added_total;
    uint64_t ipsessions_ended_diff;
    uint64_t ipsessions_ended_total;
    uint64_t voipsessions_ended_diff;
    uint64_t voipsessions_ended_total;
    uint64_t emailsessions_ended_diff;
    uint64_t emailsessions_ended_total;

} collector_stats_t;

typedef struct colsync_udp_sink {

    char *key;
    char *listenaddr;
    char *listenport;
    char *identifier;

    char *sourcehost;
    char *sourceport;

    char *attached_liid;
    pthread_t tid;

    void *zmq_control;

    uint8_t direction;
    uint8_t encapfmt;
    uint32_t cin;

    uint8_t running;
    UT_hash_handle hh;
} colsync_udp_sink_t;

typedef struct sync_thread_global {

    pthread_t threadid;
    pthread_mutex_t mutex;
    void *collector_queues;
    void *epollevs;
    int epoll_fd;
    int total_col_threads;

    colsync_udp_sink_t *udpsinks;

    pthread_mutex_t *stats_mutex;
    collector_stats_t *stats;

    pthread_mutex_t *configupdate_mutex;
    openli_yaml_config_pending_updates_t configupdates;

    /* ZMQ context for the entire collector process */
    void *zmq_ctxt;
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
    time_t timestamp;
    struct upcoming_intercept_event *events;
} upcoming_intercept_time_t;

typedef struct collector_identity {
    uuid_t uuid;

    char *jsonconfig;

    char *operatorid;
    char *networkelemid;
    char *intpointid;
    char *provisionerip;
    char *provisionerport;

    int operatorid_len;
    int networkelemid_len;
    int intpointid_len;

    /* If not set, encryption for intercepts that have a dedicated key
     * will keep track of their byteCounter in the encoding thread itself.
     * This is faster as long as the LIID is going to be observed at a single
     * collector only, which should be true in almost all cases.
     */
    uint8_t always_request_encrypt_bytecounter;
    uint8_t cisco_noradius;

    EVP_PKEY *digestsigningkey;
} collector_identity_t;

typedef struct collector_sip_configuration {
    uint8_t trust_sip_from;
    uint8_t disable_sip_redirect;
    /* Flag that indicates whether we should avoid treating calls with
     * matching SDP-O fields as separate legs of the same call, regardless
     * of their call ID
     */
    uint8_t ignore_sdpo_matches;
    char *sipdebugfile;

} collector_sip_config_t;

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
    pthread_rwlock_t *colident_mutex;

    size_t encoders;
    void **zmq_pushjobsocks;
    void *zmq_recvpublished;

    exporter_intercept_state_t *intercepts;
    removed_intercept_t *removedints;
    uint8_t encoding_method;
    halt_info_t *haltinfo;
    size_t rr_next_encoder_assign;

} seqtracker_thread_data_t;

typedef struct intercept_reorderer {

    char *liid;
    char *key;
    uint32_t expectedseqno;
    Pvoid_t pending;
    Pvoid_t pending_first_segflags;
    Pvoid_t pending_last_segflags;
    time_t flagged_over;

} int_reorderer_t;

typedef struct forwarding_thread_data {
    void *zmq_ctxt;
    pthread_t threadid;
    int forwardid;
    int encoders;
    int encoders_over;

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
    uint8_t ampq_blocked;
    openli_RMQ_config_t RMQ_conf;
    halt_info_t *haltinfo;

    uint8_t logged_rmq_connect_failure;

} forwarding_thread_data_t;

typedef struct agency_digest_config agency_digest_config_t;

typedef struct digest_map_key {
    uint64_t key_cin;
    const char *keystring;

    UT_hash_handle hh;
} digest_map_key_t;

struct agency_digest_config {
    char *agencyid;
    liagency_digest_config_t *config;
    uint8_t disabled;
    UT_hash_handle hh;
};

typedef struct liid_to_agency {
    char *liid;
    char *agencyid;

    UT_hash_handle hh;
} liid_to_agency_mapping_t;

typedef struct shared_agency_digest_config {
    agency_digest_config_t *map;
} shared_agency_digest_config_t;

typedef struct shared_liid_to_agency_mapping {
    liid_to_agency_mapping_t *map;
} shared_liid_to_agency_mapping_t;

typedef struct encoder_liid_state {
    char *liid_key;
    char *authcc;
    uint8_t no_agency_map_warning;
    time_t last_agency_check;
    liagency_digest_config_t digest_config;
    uint8_t digest_config_disabled;
    digest_map_key_t *digest_cin_keys;

    encrypt_encode_state_t encrypt_cc;
    encrypt_encode_state_t encrypt_iri;

    size_t fwd_index;

    UT_hash_handle hh;
} encoder_liid_state_t;

typedef struct integrity_check_state integrity_check_state_t;

struct integrity_check_state {

    char *key;
    char *liid_key;
    char *authcc;
    char *cinstr;
    openli_liid_format_t liid_format;
    uint32_t cin;
    openli_proto_msgtype_t msgtype;

    uint32_t destmediator;

    liagency_digest_config_t *agency;

    openli_epoll_ev_t *hash_timer;
    openli_epoll_ev_t *sign_timer;

    uint32_t pdus_since_last_hashrec;
    uint32_t hashes_since_last_signrec;

    EVP_MD_CTX *hash_ctx;
    EVP_MD_CTX *signature_ctx;

    int64_t *hashed_seqnos;
    size_t seqno_array_size;
    size_t seqno_next_index;

    int64_t *signing_seqnos;
    size_t signing_seqno_array_size;
    size_t signing_seqno_next_index;

    int64_t self_seqno_hash;
    int64_t self_seqno_sign;

    payload_encryption_method_t encryptmethod;
    uint8_t *encryptkey;
    size_t encryptkey_len;

    uint8_t awaiting_final_signature;
    UT_hash_handle hh;
};

typedef struct encoder_state {
    void *zmq_ctxt;
    void **zmq_recvjob;
    void **zmq_pushresults;
    void *zmq_control;

    int control_pipe[2];

    pthread_t threadid;
    int workerid;
    collector_identity_t *shared;
    pthread_rwlock_t *shared_mutex;
    wandder_encoder_t *encoder;
    wandder_etsispec_t *etsidecoder;
    etsili_generic_freelist_t *freegenerics;

    Pvoid_t saved_intercept_templates;
    Pvoid_t saved_global_templates;

    openli_encoded_result_t **result_array;
    size_t *result_batch;

    /** The set of LEAs that have been announced by the provisioner, and
     *  their corresponding configuration for calculating integrity checks
     */
    shared_agency_digest_config_t *digest_config;
    pthread_rwlock_t *digest_config_mutex;

    shared_liid_to_agency_mapping_t *liid_agencies;
    pthread_rwlock_t *liid_agency_mutex;

    /** Per LIID state required for integrity check generation and
     *  encryption.
     */
    encoder_liid_state_t *known_liids;

    /** The "integrity check" state for all observed "LIID + CIN + HI" streams
     *  going to agencies that require integrity check messages to be
     *  provided.
     */
    integrity_check_state_t *integrity_state;

    EVP_CIPHER_CTX *evp_ctx;

    int epoll_fd;
    openli_epoll_ev_t *zmq_job_ev;
    openli_epoll_ev_t *zmq_control_ev;
    int yield_fd;
    openli_epoll_ev_t *zmq_yield_ev;

    int seqtrackers;
    int forwarders;
    uint8_t halted;
} openli_encoder_t;

void destroy_encoder_worker(openli_encoder_t *enc);
void *run_encoder_worker(void *encstate);

void *start_seqtracker_thread(void *data);
void clean_seqtracker(seqtracker_thread_data_t *seqdata);

void *start_forwarding_thread(void *data);

void *start_udp_sink_worker(void *arg);
void destroy_colsync_udp_sink(colsync_udp_sink_t *sink);

void free_encoded_result(openli_encoded_result_t *res);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
