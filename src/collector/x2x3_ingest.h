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

#ifndef OPENLI_X2X3_INGEST_H_
#define OPENLI_X2X3_INGEST_H_

#include <uthash.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "collector_util.h"

typedef struct x_input_client {
    SSL *ssl;
    int fd;

    uint8_t *buffer;
    size_t buffer_size;
    size_t bufread;
    size_t bufwrite;
} x_input_client_t;

typedef struct x_input_sync {
    void *zmq_socket;
    char *identifier;

    UT_hash_handle hh;
} x_input_sync_t;

typedef struct x_input {

    uint8_t running;
    pthread_t threadid;

    char *identifier;
    char *listenaddr;
    char *listenport;

    SSL_CTX *ssl_ctx;
    uint8_t reset_listener;
    pthread_mutex_t sslmutex;

    int listener_fd;
    x_input_client_t *clients;
    size_t client_count;
    size_t client_array_size;
    size_t dead_clients;

    void *zmq_ctxt;

    void *zmq_ctrlsock;
    void **zmq_fwdsocks;

    /* TODO we need ZMQs that allow us to pass on packets to the
     * various worker threads based on the payload format in the X2/X3
     * PDU header
     *
     *  - sync (for RADIUS)
     *  - gtp workers (GTP-U) 
     *  - sip workers (for SIP) 
     *  - col processing threads (for IP / RTP / Ethernet)
     *
     * XXX GTP-C is not a payload format? I guess that comes as EPSIRIContent.
     */


    int forwarding_threads;

    ipintercept_t *ipintercepts;
    voipintercept_t *voipintercepts;

    /* Shared state used to track when X2/X3 threads have halted */
    halt_info_t *haltinfo;

    UT_hash_handle hh;

} x_input_t;

void destroy_x_input(x_input_t *xinp);
void *start_x2x3_ingest_thread(void *param);

#endif
