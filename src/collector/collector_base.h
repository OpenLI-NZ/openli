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

#include <pthread.h>
#include <libwandder_etsili.h>
#include <libwandder.h>
#include <zmq.h>
#include <Judy.h>

#include "export_shared.h"
#include "etsili_core.h"
#include "collector_publish.h"
#include "export_buffer.h"

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

    UT_hash_handle hh_fd;
    UT_hash_handle hh_medid;
} export_dest_t;

typedef struct sync_thread_global {

    pthread_t threadid;
    pthread_mutex_t mutex;
    void *collector_queues;
    void *epollevs;
    int epoll_fd;

} sync_thread_global_t;

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
    uint32_t haltedat;
    removed_intercept_t *next;
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

} seqtracker_thread_data_t;

typedef struct stored_result {
    openli_encoded_result_t res;
    UT_hash_handle hh;
} stored_result_t;

typedef struct intercept_reorderer {

    char *liid;
    char *key;
    uint32_t expectedseqno;
    stored_result_t *pending;

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

    Pvoid_t destinations_by_fd;
    Pvoid_t destinations_by_id;

    Pvoid_t intreorderer_cc;
    Pvoid_t intreorderer_iri;

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
