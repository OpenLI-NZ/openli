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

#ifndef OPENLI_COLLECTOR_SYNC_VOIP_H_
#define OPENLI_COLLECTOR_SYNC_VOIP_H_

#include <libtrace.h>
#include <libtrace/message_queue.h>

#include "intercept.h"
#include "collector.h"
#include "sipparsing.h"
#include "util.h"

typedef struct collector_sync_voip_data {

    sync_thread_global_t *glob;
    collector_identity_t *info;

    int pubsockcount;
    void **zmq_pubsocks;

    voipintercept_t *voipintercepts;
    voipcinmap_t *knowncallids;

    libtrace_message_queue_t *intersyncq;
    sync_epoll_t intersync_ev;

    openli_sip_parser_t *sipparser;

    char *sipdebugfile;
    libtrace_out_t *sipdebugout;
    libtrace_out_t *sipdebugupdate;

    uint8_t log_bad_instruct;
    uint8_t log_bad_sip;

} collector_sync_voip_t;

collector_sync_voip_t *init_voip_sync_data(collector_global_t *glob);
void clean_sync_voip_data(collector_sync_voip_t *sync);
int sync_voip_thread_main(collector_sync_voip_t *sync);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
