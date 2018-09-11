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

#ifndef OPENLI_COLLECTOR_EXPORT_H_
#define OPENLI_COLLECTOR_EXPORT_H_

#include <libwandder.h>
#include <sys/epoll.h>

#include "collector.h"
#include "export_buffer.h"
#include "netcomms.h"
#include "internetaccess.h"
#include "collector_publish.h"

typedef struct export_dest {
    int failmsg;
    int fd;
    int awaitingconfirm;
    int halted;
    openli_mediator_t details;
    export_buffer_t buffer;
} export_dest_t;

typedef struct exporter_intercept_msg {
    char *liid;
    int liid_len;
    char *authcc;
    int authcc_len;
    char *delivcc;
    int delivcc_len;
} exporter_intercept_msg_t;

typedef struct cin_seqno {
    uint32_t cin;
    uint32_t cc_seqno;
    uint32_t iri_seqno;
    UT_hash_handle hh;
} cin_seqno_t;

typedef struct intercept_state {
    exporter_intercept_msg_t *details;
    cin_seqno_t *cinsequencing;
    UT_hash_handle hh;
} exporter_intercept_state_t;


typedef struct colexp_data {

    export_thread_data_t *glob;
    libtrace_list_t *dests;     // if dests gets large, replace with map?
    exporter_intercept_state_t *intercepts;
    wandder_encoder_t *encoder;
    etsili_generic_t *freegenerics;

    uint8_t flagged;
    int failed_conns;
    int flagtimerfd;

    void *zmq_subsock;
    int count;

} collector_export_t;

collector_export_t *init_exporter(export_thread_data_t *glob);
int connect_export_targets(collector_export_t *exp);
void destroy_exporter(collector_export_t *exp);
int exporter_thread_main(collector_export_t *exp);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
