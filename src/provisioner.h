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

#ifndef OPENLI_PROVISIONER_H_
#define OPENLI_PROVISIONER_H_

#include <libtrace/linked_list.h>


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
    PROV_EPOLL_MEDIATOR_RECV,
    PROV_EPOLL_MEDIATOR_SEND,
    PROV_EPOLL_COLL_SEND,
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

typedef struct prov_state {

    char *conffile;
    char *listenaddr;
    char *listenport;
    char *mediateaddr;
    char *mediateport;
    char *pushaddr;
    char *pushport;

    int epoll_fd;
    libtrace_list_t *ipintercepts;
    libtrace_list_t *mediators;
    libtrace_list_t *collectors;
    libtrace_list_t *leas;

    prov_epoll_ev_t *clientfd;
    prov_epoll_ev_t *updatefd;
    prov_epoll_ev_t *mediatorfd;
    prov_epoll_ev_t *timerfd;
    prov_epoll_ev_t *signalfd;

    /*
    int activeupdatefd;
    int updatetimerfd;

    provision_update_t upstate;
    */

} provision_state_t;

/* Describes a collector that is being served by the provisioner */
typedef struct prov_collector {

    int fd;     /* The socket for communicating over */
    prov_epoll_ev_t *sendev;

    /* TODO consider a receive event for messages from the collector,
     * e.g. warnings about dropped packets, filling buffers etc.
     */

} prov_collector_t;

typedef struct prov_mediator {

    int fd;     /* the socket for communication with the mediator */
    uint32_t destid;    /* the unique ID for this mediator */
    prov_epoll_ev_t *sendev;
    prov_epoll_ev_t *recvev;

} prov_mediator_t;

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
