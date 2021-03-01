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
#include <amqp.h>
#include "netcomms.h"
#include "export_buffer.h"
#include "util.h"
#include "openli_tls.h"
#include "med_epoll.h"
#include "pcapthread.h"
#include "liidmapping.h"
#include "mediator_prov.h"
#include "mediator_coll.h"

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

    /** State for managing all connected handovers */
    handover_state_t handover_state;

    /** A map of LIIDs to their corresponding agencies */
    liid_map_t liidmap;

    /** The global epoll file descriptor for this mediator */
    int epoll_fd;

    /** The epoll event for the socket listening for collectors */
    med_epoll_ev_t *listenerev;

    /** The epoll event for the socket watching for signals */
    med_epoll_ev_t *signalev;

    /** The epoll event for the epoll loop timer */
    med_epoll_ev_t *timerev;

    /** The epoll event for the pcap file rotation timer */
    med_epoll_ev_t *pcaptimerev;

    /** The epoll event for the RabbitMQ heartbeat check timer */
    med_epoll_ev_t *RMQtimerev;

    /** State for managing the connection back to the provisioner */
    mediator_prov_t provisioner;

    /** State for managing the connections from collectors */
    mediator_collector_t collectors;

    /** The frequency to rotate the pcap files (in minutes) */
    uint32_t pcaprotatefreq;

    /** The pthread ID for the pcap file writing thread */
    pthread_t pcapthread;

    /** The queue for pushing packets to the pcap file writing thread */
    libtrace_message_queue_t pcapqueue;

    /** The SSL configuration for the mediator */
    openli_ssl_config_t sslconf;
    openli_RMQ_config_t RMQ_conf;

} mediator_state_t;

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
