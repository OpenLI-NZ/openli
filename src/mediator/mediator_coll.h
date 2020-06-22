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

#ifndef OPENLI_MEDIATOR_COLL_H_
#define OPENLI_MEDIATOR_COLL_H_

#include <uthash.h>
#include <libtrace/linked_list.h>
#include "med_epoll.h"
#include "netcomms.h"

/** Describes a collector which has been temporarily disabled, e.g. due to
 *  a connection breaking down.
 */
typedef struct disabled_collector {
    /** The IP address that the collector connected from */
    char *ipaddr;
    UT_hash_handle hh;
} disabled_collector_t;

/** State associated with a single collector connection */
typedef struct single_coll_state {

    /** The IP address that the collector has connected from */
    char *ipaddr;

    /** The buffer used to store ETSI records received from the collector */
    net_buffer_t *incoming;

    /** A flag indicating whether error logging is disabled for this
     *  collector.
     */
    int disabled_log;

    /** The SSL socker for this collector connection */
    SSL *ssl;
} single_coll_state_t;

/** An instance of an active collector */
typedef struct active_collector {
    /** The epoll event for the collector connection socket */
    med_epoll_ev_t *colev;

    /** The SSL socket for this collector connection, if required */
    SSL *ssl;
} active_collector_t;

/** Structure for storing global state for all collectors managed by a
 *  mediator instance.
 */
typedef struct mediator_collector_glob_state {
    /* The error code for the most recent SSL error when accepting a collector
     * connection.
     */
    int lastsslerror;

    /** Points to the flag that indicates whether collector connections are
     *  using TLS.
     */
    uint8_t *usingtls;

    /** The global epoll fd for this mediator instance. */
    int epoll_fd;

    /** The list of currently active collector connections. */
    libtrace_list_t *collectors;

    /** A map containing all collectors that are currently disconnected. */
    disabled_collector_t *disabledcols;

    /** The SSL configuration for this mediator instance. */
    openli_ssl_config_t *sslconf;
} mediator_collector_t;

/** Initialises the state for the collectors managed by a mediator.
 *
 *  @param medcol       The global state for the collectors that is to be
 *                      initialised.
 *  @param usetls       A pointer to the global flag that indicates whether
 *                      new collector connections must use TLS.
 *  @param sslconf      A pointer to the SSL configuration for this mediator.
 */
void init_med_collector_state(mediator_collector_t *medcol, uint8_t *usetls,
        openli_ssl_config_t *sslconf);

/** Destroys the state for the collectors managed by mediator, including
 *  dropping any remaining collector connections.
 *
 *  @param medcol       The global state for the collectors that is to be
 *                      destroyed.
 */
void destroy_med_collector_state(mediator_collector_t *medcol);

/** Accepts a connection from a collector and prepares to receive encoded
 *  ETSI records from that collector.
 *
 *  @param medcol        The global state for the collectors seen by this
 *                       mediator.
 *  @param listenfd      The file descriptor that the connection attempt
 *                       was seen on.
 *
 *  @return -1 if an error occurs, otherwise the file descriptor for the
 *          collector connection.
 */
int mediator_accept_collector(mediator_collector_t *medcol, int listenfd);

/** Attempts to complete an ongoing TLS handshake with a collector.
 *
 *  @param medcol       The global state for the collectors seen by the mediator
 *  @param mev          The epoll event for the collector socket
 *
 *  @return -1 if an error occurs, 0 if the handshake is not yet complete,
 *          1 if the handshake has now completed.
 */
int continue_collector_handshake(mediator_collector_t *medcol,
        med_epoll_ev_t *mev);

/** Drops the connection to a collector and moves the collector to the
 *  disabled collector list.
 *
 *  @param medcol       The global state for collectors seen by the mediator
 *  @param colev        The epoll event for this collection connection
 *  @param disablelog   A flag that indicates whether we should log about
 *                      this incident
 */
void drop_collector(mediator_collector_t *medcol,
        med_epoll_ev_t *colev, int disablelog);

/** Drops *all* currently connected collectors.
 *
 *  @param medcol    The set of collectors for this mediator
 */
void drop_all_collectors(mediator_collector_t *medcol);

/** Re-enables log messages for a collector that has re-connected.
 *
 *  @param medcol       The global state for collectors seen by this mediator
 *  @param cs           The collector that has re-connected
 *
 */
void reenable_collector_logging(mediator_collector_t *medcol,
        single_coll_state_t *cs);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
