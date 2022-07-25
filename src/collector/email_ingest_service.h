/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#ifndef OPENLI_EMAIL_INGEST_SERVICE_H_
#define OPENLI_EMAIL_INGEST_SERVICE_H_

#include <stdlib.h>
#include <microhttpd.h>

#include "email_worker.h"

typedef struct openli_email_ingest_config {
    uint8_t enabled;
    uint8_t authrequired;
    uint8_t tlsrequired;
    uint32_t maxclients;

    char *listenport;
    char *listenaddr;

} openli_email_ingest_config_t;

typedef struct email_ingest_state {
    struct MHD_Daemon *daemon;
    openli_email_ingest_config_t *config;
    int email_worker_count;

    void *zmq_ctxt;
    void **zmq_publishers;

} email_ingestor_state_t;

typedef struct email_connection {
    struct MHD_PostProcessor *postproc;
    const char *answerstring;
    int answercode;
    email_ingestor_state_t *parentstate;

    openli_email_captured_t *thismsg;
} email_connection_t;

void stop_email_mhd_daemon(email_ingestor_state_t *state);
struct MHD_Daemon *start_email_mhd_daemon(openli_email_ingest_config_t *config,
        int sockfd, email_ingestor_state_t *state);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
