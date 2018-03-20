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

#ifndef OPENLI_COLLECTOR_SYNC_H_
#define OPENLI_COLLECTOR_SYNC_H_

#include <sys/epoll.h>

#include <libtrace/linked_list.h>
#include <uthash.h>
#include "collector.h"
#include "netcomms.h"
#include "intercept.h"

enum {
    SYNC_EVENT_PROC_QUEUE,
    SYNC_EVENT_PROVISIONER
};

typedef struct sync_epoll {
    uint8_t fdtype;
    int fd;
    libtrace_message_queue_t *msgq;
} sync_epoll_t;

typedef struct colsync_data {

    collector_global_t *glob;

    libtrace_list_t *ipintercepts;
    voipintercept_t *voipintercepts;
    voipintercept_t *voipintercepts_by_uri;
    int instruct_fd;
    uint8_t instruct_fail;
    sync_epoll_t *ii_ev;

    net_buffer_t *outgoing;
    net_buffer_t *incoming;

    libtrace_message_queue_t exportq;
    openli_sip_parser_t *sipparser;

} collector_sync_t;

collector_sync_t *init_sync_data(collector_global_t *glob);
void clean_sync_data(collector_sync_t *sync);
int sync_connect_provisioner(collector_sync_t *sync);
int sync_thread_main(collector_sync_t *sync);
void register_sync_queues(collector_global_t *glob,
        libtrace_message_queue_t *recvq, libtrace_message_queue_t *sendq);

void halt_processing_threads(collector_global_t *glob);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
