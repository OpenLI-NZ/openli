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

#ifndef OPENLI_PROVISIONER_H_
#define OPENLI_PROVISIONER_H_

#include <libtrace/linked_list.h>
#include <uthash.h>
#include "netcomms.h"

typedef struct prov_epoll_ev {
    int fdtype;
    int fd;
    void *state;
} prov_epoll_ev_t;

enum {
    PROV_EPOLL_COLL_CONN,
    PROV_EPOLL_MEDIATE_CONN,
    PROV_EPOLL_UPDATE_CONN,
    PROV_EPOLL_UPDATE,
    PROV_EPOLL_MEDIATOR,
    PROV_EPOLL_COLLECTOR,
    PROV_EPOLL_MAIN_TIMER,
    PROV_EPOLL_FD_TIMER,
    PROV_EPOLL_SIGNAL,
};

typedef struct update_state {
    char *recvbuf;
    char *readptr;
    char *writeptr;
    uint32_t alloced;

    int16_t tocome;
} provision_update_t;

typedef struct liid_hash {
    char *agency;
    char *liid;
    UT_hash_handle hh;
} liid_hash_t;

typedef struct prov_agency {
    liagency_t *ag;
    uint8_t announcereq;
    UT_hash_handle hh;
} prov_agency_t;

typedef struct disabled_client {
    char *ipaddr;
    UT_hash_handle hh;
} prov_disabled_client_t;

/* Describes a collector that is being served by the provisioner */
typedef struct prov_collector {

    prov_epoll_ev_t *commev;
    prov_epoll_ev_t *authev;

    UT_hash_handle hh;
} prov_collector_t;

typedef struct prov_mediator {

    int fd;     /* the socket for communication with the mediator */
    openli_mediator_t *details;
    prov_epoll_ev_t *commev;
    prov_epoll_ev_t *authev;

} prov_mediator_t;

typedef struct prov_state {

    char *conffile;
    char *listenaddr;
    char *listenport;
    char *mediateaddr;
    char *mediateport;
    char *pushaddr;
    char *pushport;

    int epoll_fd;
    libtrace_list_t *mediators;
    prov_collector_t *collectors;
    coreserver_t *radiusservers;
    coreserver_t *sipservers;

    prov_disabled_client_t *badmediators;
    prov_disabled_client_t *badcollectors;

    voipintercept_t *voipintercepts;
    ipintercept_t *ipintercepts;

    prov_epoll_ev_t *clientfd;
    prov_epoll_ev_t *updatefd;
    prov_epoll_ev_t *mediatorfd;
    prov_epoll_ev_t *timerfd;
    prov_epoll_ev_t *signalfd;

    prov_agency_t *leas;
    liid_hash_t *liid_map;

    int ignorertpcomfort;
    /*
    int activeupdatefd;
    int updatetimerfd;

    provision_update_t upstate;
    */

} provision_state_t;

typedef struct prov_sock_state {
    char *ipaddr;
    uint8_t log_allowed;
    net_buffer_t *incoming;
    net_buffer_t *outgoing;
    uint8_t trusted;
    uint8_t halted;
    int mainfd;
    int authfd;
    int clientrole;

} prov_sock_state_t;

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
