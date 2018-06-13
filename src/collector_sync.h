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

#include <libwandder.h>
#include <libtrace/linked_list.h>
#include <uthash.h>
#include "collector.h"
#include "netcomms.h"
#include "intercept.h"
#include "internetaccess.h"
#include "coreserver.h"
#include "sipparsing.h"

typedef struct colsync_data {

    support_thread_global_t *glob;
    shared_global_info_t *info;

    internet_user_t *allusers;
    ipintercept_t *ipintercepts;
    user_intercept_list_t *userintercepts;

    coreserver_t *coreservers;

    int instruct_fd;
    uint8_t instruct_fail;
    sync_epoll_t *ii_ev;

    net_buffer_t *outgoing;
    net_buffer_t *incoming;

    libtrace_message_queue_t *intersyncq;
    libtrace_message_queue_t exportq;
    wandder_encoder_t *encoder;

    access_plugin_t *radiusplugin;
    etsili_generic_t *freegenerics;

} collector_sync_t;

collector_sync_t *init_sync_data(collector_global_t *glob);
void clean_sync_data(collector_sync_t *sync);
void sync_disconnect_provisioner(collector_sync_t *sync);
int sync_connect_provisioner(collector_sync_t *sync);
int sync_thread_main(collector_sync_t *sync);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
