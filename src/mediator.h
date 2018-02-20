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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#ifndef OPENLI_MEDIATOR_H_
#define OPENLI_MEDIATOR_H_

#include "netcomms.h"

typedef struct med_epoll_ev {
    int fdtype;
    int fd;
    void *state;
} med_epoll_ev_t;

enum {
    MED_EPOLL_COLL_CONN,
    MED_EPOLL_PROVISIONER,
    MED_EPOLL_LEA,
    MED_EPOLL_COLLECTOR,
    MED_EPOLL_KA_TIMER,
    MED_EPOLL_KA_RESPONSE_TIMER,
    MED_EPOLL_SIGNAL,
    MED_EPOLL_SIGCHECK_TIMER,
};

typedef struct mediator_collector {
    med_epoll_ev_t *colev;
    net_buffer_t *incoming;
    int disabled;
} mediator_collector_t;

typedef struct mediator_provisioner {
    med_epoll_ev_t *provev;
    int sentinfo;
    net_buffer_t *outgoing;
    net_buffer_t *incoming;
} mediator_prov_t;

typedef struct med_state {
    uint32_t mediatorid;
    char *conffile;
    char *mediatorname;
    char *listenaddr;
    char *listenport;

    char *provaddr;
    char *provport;

    libtrace_list_t *collectors;

    int epoll_fd;
    med_epoll_ev_t *listenerev;
    med_epoll_ev_t *signalev;
    med_epoll_ev_t *timerev;

    mediator_prov_t provisioner;

} mediator_state_t;

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
