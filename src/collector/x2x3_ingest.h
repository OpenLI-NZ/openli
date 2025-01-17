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

#include "collector_util.h"

typedef struct x_input_sync {
    void *zmq_socket;
    char *identifier;

    UT_hash_handle hh;
} x_input_sync_t;

typedef struct x_input {

    char *identifier;
    char *listenaddr;
    char *listenport;

    char *certfile;
    uint8_t running;

    pthread_t threadid;

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

    UT_hash_handle hh;

} x_input_t;

void destroy_x_input(x_input_t *xinp);

#endif
