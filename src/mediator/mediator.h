/*
 *
 * Copyright (c) 2018-2020 The University of Waikato, Hamilton, New Zealand.
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

#ifndef OPENLI_MEDIATOR_H_
#define OPENLI_MEDIATOR_H_

#include <Judy.h>
#include <libwandder.h>
#include <libwandder_etsili.h>
#include <uthash.h>
#include "netcomms.h"
#include "export_buffer.h"
#include "util.h"
#include "openli_tls.h"
#include "med_epoll.h"
#include "pcapthread.h"
#include "liidmapping.h"
#include "mediator_prov.h"
#include "mediator_coll.h"

typedef struct med_state {
    uint32_t mediatorid;
    char *conffile;
    char *mediatorname;
    char *operatorid;
    char *listenaddr;
    char *listenport;
    uint8_t etsitls;

    char *pcapdirectory;

    handover_state_t handover_state;
    liid_map_t liidmap;

    int epoll_fd;
    med_epoll_ev_t *listenerev;
    med_epoll_ev_t *signalev;
    med_epoll_ev_t *timerev;
    med_epoll_ev_t *pcaptimerev;

    mediator_prov_t provisioner;
    mediator_collector_t collectors;

    uint32_t pcaprotatefreq;
    pthread_t pcapthread;
    libtrace_message_queue_t pcapqueue;
    wandder_etsispec_t *etsidecoder;
    openli_ssl_config_t sslconf;

} mediator_state_t;

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
