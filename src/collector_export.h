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

#include <sys/epoll.h>
#include "collector.h"
#include "export_buffer.h"
#include "mediator.h"

typedef struct colexp_data {

    collector_global_t *glob;
    libtrace_list_t *dests;     // if dests gets large, replace with map?

    int failed_conns;

} collector_export_t;

typedef struct export_dest {
    int failmsg;
    int fd;
    int awaitingconfirm;
    int halted;
    openli_mediator_t details;
    export_buffer_t buffer;
} export_dest_t;

enum {
    OPENLI_EXPORT_ETSIREC = 1,
    OPENLI_EXPORT_PACKET_FIN = 2,
    OPENLI_EXPORT_MEDIATOR = 3,
    OPENLI_EXPORT_FLAG_MEDIATORS = 4,
    OPENLI_EXPORT_INIT_MEDIATORS_OVER = 5,
};

typedef struct openli_export_recv {
    uint8_t type;
    union {
        openli_exportmsg_t toexport;
        openli_mediator_t med;
        libtrace_packet_t *packet;
    } data;
} PACKED openli_export_recv_t;


collector_export_t *init_exporter(collector_global_t *glob);
int connect_export_targets(collector_export_t *exp);
void destroy_exporter(collector_export_t *exp);
int exporter_thread_main(collector_export_t *exp);
void register_export_queue(collector_global_t *glob,
        libtrace_message_queue_t *q);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
