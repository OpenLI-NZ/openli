/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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
#include "coll_recv_thread.h"
#include "lea_send_thread.h"

/** Global state variables for a mediator instance */
typedef struct med_state {

    /** A unique identifier for the mediator, provided via config */
    uint32_t mediatorid;

    /** Path to the mediator config file */
    char *conffile;

    /** The operator ID string (to be inserted into keep-alive messages) */
    char *operatorid;

    /** The five character operator ID string (used for HI2
     *  Network-Identifiers) */
    char *shortoperatorid;

    /** The IP address to listen on for incoming collector connections */
    char *listenaddr;

    /** The port to listen on for incoming collector connections
     *  (as a string) */
    char *listenport;

    /** A flag indicating whether collector connections should use TLS to
     *  encrypt exported records.
     */
    uint8_t etsitls;

    /** Directory in which any pcap files should be written */
    char *pcapdirectory;

    /** Template used for naming pcap files */
    char *pcaptemplate;

    /** Compression level to use when writing pcap files */
    uint8_t pcapcompress;

    /** The global epoll file descriptor for this mediator */
    int epoll_fd;

    /** The epoll event for the socket listening for collectors */
    med_epoll_ev_t *listenerev;

    /** The epoll event for the socket watching for signals */
    med_epoll_ev_t *signalev;

    /** The epoll event for the epoll loop timer */
    med_epoll_ev_t *timerev;

    /** The epoll event for the collector receiver cleanup timer */
    med_epoll_ev_t *col_clean_timerev;

    /** State for managing the connection back to the provisioner */
    mediator_prov_t provisioner;

    /** The collector receive threads that have been spawned */
    mediator_collector_t collector_threads;

    /** The integrity check configuration for all known agencies */
    agency_digest_config_t *saved_agencies;

    /** The LEA send threads that have been spawned */
    mediator_lea_t agency_threads;

    /** The frequency to rotate the pcap files (in minutes) */
    uint32_t pcaprotatefreq;

    /** The SSL configuration for the mediator */
    openli_ssl_config_t sslconf;

    /** The RabbitMQ configuration for the mediator */
    openli_RMQ_config_t RMQ_conf;

} mediator_state_t;

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
