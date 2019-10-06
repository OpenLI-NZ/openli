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
#include "util.h"
#include "openli_tls.h"

typedef struct prov_client prov_client_t;

/** Represents an event that has been added to the epoll event set */
typedef struct prov_epoll_ev {
    /** The event type -- one of the PROV_EPOLL_* values listed below */
    int fdtype;

    /** The file descriptor that is being polled by epoll */
    int fd;

    /** A reference to the client that the fd belongs to (only appropriate
     *  for some event types).
     */
    prov_client_t *client;
} prov_epoll_ev_t;


/** Types of sockets that may trigger an epoll event */
enum {
    /** An incoming connection from a collector */
    PROV_EPOLL_COLL_CONN,
    /** An incoming connection from a mediator */
    PROV_EPOLL_MEDIATE_CONN,
    /** An incoming connection from an updater */
    PROV_EPOLL_UPDATE_CONN,

    /** Communication either to or from an updater */
    PROV_EPOLL_UPDATE,
    /** Communication either to or from a mediator */
    PROV_EPOLL_MEDIATOR,
    /** Communication either to or from a collector */
    PROV_EPOLL_COLLECTOR,

    /** Internal tick timer, used to trigger checks for halting or config
     *  reloads. */
    PROV_EPOLL_MAIN_TIMER,

    /** Authentication timeout for a client has expired */
    PROV_EPOLL_FD_TIMER,

    /** A signal has been received */
    PROV_EPOLL_SIGNAL,

    /** A pending SSL handshake from a mediator has progressed */
    PROV_EPOLL_MEDIATOR_HANDSHAKE,
    /** A pending SSL handshake from a collector has progressed */
    PROV_EPOLL_COLLECTOR_HANDSHAKE,

    /** Idle timeout for a client has expired */
    PROV_EPOLL_FD_IDLETIMER,
};

typedef struct update_state {
    char *recvbuf;
    char *readptr;
    char *writeptr;
    uint32_t alloced;

    int16_t tocome;
} provision_update_t;

/** A LIID->agency mapping, used to ensure mediators route the intercept
 *  traffic to the correct LEA.
 */
typedef struct liid_hash {
    /** The identifier for the agency */
    char *agency;
    /** The LIID for the intercept */
    char *liid;

    UT_hash_handle hh;
} liid_hash_t;

/** An LEA that this provisioner knows about */
typedef struct prov_agency {
    /** The agency details */
    liagency_t *ag;

    /** A flag indicating whether the agency needs to be re-announced to
     *  all mediators (i.e. after a config change) */
    uint8_t announcereq;

    UT_hash_handle hh;
} prov_agency_t;

typedef struct prov_sock_state prov_sock_state_t;

/** State for a client (either collector or mediator) that has connected
 *  to the provisioner.
 */
struct prov_client {

    /** Epoll event for the main communication socket */
    prov_epoll_ev_t *commev;

    /** Epoll event for the authentication timer */
    prov_epoll_ev_t *authev;

    /** Epoll event for the idle timer */
    prov_epoll_ev_t *idletimer;

    /** Socket state for the main communication socket */
    prov_sock_state_t *state;

    /** SSL handle for the communication socket, if using TLS */
    SSL *ssl;

    /** Flag to indicate whether our last SSL handshake failed */
    uint8_t lastsslerror;

    /** Flag to indicate whether our last connection failed for a non-SSL
     *  reason */
    uint8_t lastothererror;
};

/* Describes a collector that is being served by the provisioner */
typedef struct prov_collector {
    /** Unique identifier for the collector (using the IP address for now) */
    char *identifier;

    /** Common "client" state */
    prov_client_t client;

    UT_hash_handle hh;
} prov_collector_t;

/* Describes a mediator that is being served by the provisioner */
typedef struct prov_mediator {

    /** Unique identifier for the mediator (using the IP address for now) */
    char *identifier;
    /** Common "client" state */
    prov_client_t client;

    /** The IP address and port that the mediator is listening on for
     *  connections from collectors */
    openli_mediator_t *details;

    UT_hash_handle hh;
} prov_mediator_t;

/** Global state for the provisioner instance */
typedef struct prov_state {

    /** Path to the configuration file */
    char *conffile;

    /** The IP address to listen on for incoming collector connections */
    char *listenaddr;
    /** The port to listen on for incoming collector connections */
    char *listenport;
    /** The IP address to listen on for incoming mediator connections */
    char *mediateaddr;
    /** The port to listen on for incoming mediator connections */
    char *mediateport;
    /** The IP address to listen on for incoming updater connections */
    char *pushaddr;
    /** The port to listen on for incoming updater connections */
    char *pushport;

    /** The file descriptor that is used for polling using epoll */
    int epoll_fd;

    /** The set of mediators that we are managing */
    prov_mediator_t *mediators;

    /** The set of collectors that we are managing */
    prov_collector_t *collectors;

    /** The set of known RADIUS servers that will be provided to collectors */
    coreserver_t *radiusservers;
    /** The set of known SIP servers that will be provided to collectors */
    coreserver_t *sipservers;

    /** The set of VOIP intercepts that we are currently running */
    voipintercept_t *voipintercepts;
    /** The set of IP intercepts that we are currently running */
    ipintercept_t *ipintercepts;

    /** Epoll event for the collector connection socket */
    prov_epoll_ev_t *clientfd;
    /** Epoll event for the updater connection socket */
    prov_epoll_ev_t *updatefd;
    /** Epoll event for the mediator connection socket */
    prov_epoll_ev_t *mediatorfd;
    /** Epoll event for the "check if halted" timer */
    prov_epoll_ev_t *timerfd;
    /** Epoll event for the incoming signal socket */
    prov_epoll_ev_t *signalfd;

    /** The set of LEAs that are potential intercept recipients */
    prov_agency_t *leas;

    /** A map of LIIDs to their destination LEAs */
    liid_hash_t *liid_map;

    /** A flag indicating whether collectors should ignore RTP comfort noise
     *  packets when intercepting voice traffic.
     */
    int ignorertpcomfort;

    /** The SSL configuration, including the SSL context pointer */
    openli_ssl_config_t sslconf;

} provision_state_t;

/** Socket state information for a single client */
struct prov_sock_state {
    /** The IP address of the client, used for identification purposes */
    char *ipaddr;

    /** A flag indicating whether we should log errors that occur when
     *  communicating with this client.
     */
    uint8_t log_allowed;

    /** Buffer for storing messages that have been received from the client */
    net_buffer_t *incoming;
    /** Buffer for storing messages that are to be sent to the client */
    net_buffer_t *outgoing;

    /** Set to 1 if the client has authenticated, 0 otherwise */
    uint8_t trusted;

    /** Set to 1 if the client has been disconnected, 0 otherwise */
    uint8_t halted;

    /** The type of client, e.g. either collector or mediator */
    int clientrole;

};

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
