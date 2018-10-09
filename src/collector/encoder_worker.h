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

#ifndef OPENLI_ENCODER_WORKER_H_
#define OPENLI_ENCODER_WORKER_H_

#include <time.h>
#include <pthread.h>
#include <libwandder.h>

#include "collector_publish.h"
#include "collector.h"
#include "netcomms.h"
#include "etsili_core.h"
#include "export_shared.h"

typedef struct encoder_state {
    void *zmq_ctxt;
    void *zmq_recvjob;
    void *zmq_pushresult;
    void *zmq_control;

    pthread_t threadid;
    int workerid;
    shared_global_info_t *shared;
	wandder_encoder_t *encoder;
    etsili_generic_t *freegenerics;
} openli_encoder_t;

typedef struct encoder_job {
    exporter_intercept_state_t *intstate;
    uint8_t type;
    uint32_t seqno;
    uint32_t destid;
    struct timeval ts;
    wandder_encoded_result_t *toreturn;
    union {
        openli_ipcc_job_t ipcc;
        openli_ipmmcc_job_t ipmmcc;
        openli_ipmmiri_job_t ipmmiri;
        openli_ipiri_job_t ipiri;
    } data;
} PACKED openli_encoding_job_t;

typedef struct encoder_result {
    exporter_intercept_state_t *intstate;

    ii_header_t header;
    wandder_encoded_result_t *msgbody;
    uint8_t *ipcontents;
    uint32_t ipclen;
    uint32_t seqno;
    uint32_t destid;
} PACKED openli_encoded_result_t;

void destroy_encoder_worker(openli_encoder_t *enc);
void *run_encoder_worker(void *encstate);

#endif


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
