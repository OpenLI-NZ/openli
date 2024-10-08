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

#ifndef OPENLI_MEDIATOR_COLL_RECV_THREAD_H
#define OPENLI_MEDIATOR_COLL_RECV_THREAD_H

#include <amqp.h>
#include <libtrace/message_queue.h>
#include "netcomms.h"
#include "openli_tls.h"
#include "med_epoll.h"

/** This file defines public types and methods for interactive with a
 *  "collector receive" thread for the OpenLI mediator.
 *  Each OpenLI collector that reports to a mediator will be handled using
 *  a separate instance of one of these threads.
 *
 *  The core functionality of a collector receive thread is to:
 *    - receive LI records from the collector via either a RMQ queue hosted
 *      on the collector OR a TCP socket
 *    - insert each received record into the appropriate internal RMQ queue,
 *      named after the LIID that the record was intercepted for and the
 *      record type (e.g. IRI or CC).
 *
 */


/** Types of messages that can be sent from the main mediator thread to a
 *  collector receive thread.
 */
enum {
    /** Collector has reconnected on a different file descriptor */
    MED_COLL_MESSAGE_RECONNECT,

    /** Collector has disconnected, but thread needs to remain active
     *  (message unused in current implementation).
     */
    MED_COLL_MESSAGE_DISCONNECT,

    /** Mediator is exiting, please terminate the collector thread. */
    MED_COLL_MESSAGE_HALT,

    /** Global shared configuration has changed, update local copy of this
     *  config.
     */
    MED_COLL_MESSAGE_RELOAD
};


/** Structure defining a message that may be sent from the main mediator
 *  thread to a collector receive thread.
 */
typedef struct col_thread_msg {
    /** The message type -- see enum above for possible values */
    int type;

    /** A message argument -- the type and meaning will depend on the message
     *  type.
     */
    uint64_t arg;
} col_thread_msg_t;

/** Structure for keeping track of the LIIDs that a collector receive thread
 *  has seen
 */
typedef struct col_known_liid {
    /** The LIID itself, as a string */
    char *liid;

    /** The length of the LIID string */
    int liidlen;

    /** Timestamp when this LIID was last seen */
    uint64_t lastseen;

    /** Flag indicating whether we have declared an RMQ for publishing
     *  raw IP to the pcap thread.
     */
    uint8_t declared_raw_rmq;

    /** Flag indicating whether we have declared the RMQs for publishing
     *  IRIs and CCs internally
     */
    uint8_t declared_int_rmq;

    const char *queuenames[3];

    UT_hash_handle hh;
} col_known_liid_t;

/** Collector thread configuration that is shared across all collector
 *  receive threads.
 */
typedef struct mediator_collector_config {
    /** The SSL configuration for this mediator instance. */
    openli_ssl_config_t *sslconf;

    /** The RabbitMQ configuration for this mediator instance */
    openli_RMQ_config_t *rmqconf;

    /** The ID of the mediator instance */
    uint32_t parent_mediatorid;

    /** A mutex to protect against race conditions when reading this config */
    pthread_mutex_t mutex;

    /** Boolean flag indicating whether collector connections are using TLS */
    uint8_t usingtls;
} mediator_collector_config_t;


/** State associated with a single collector connection */
typedef struct single_coll_receiver coll_recv_t;

struct single_coll_receiver {

    /** ID of the thread that this connection is running in */
    pthread_t tid;

    /** The particular forwarding thread on the collector that is
     *  connected via this receiver thread.
     */
    int forwarder_id;

    /** The RabbitMQ queue name for this receiving thread (if using RMQ) */
    char *rmq_queuename;

    /** The IP address that the collector has connected from */
    char *ipaddr;

    /** The length of the IP address string */
    int iplen;

    /** The file descriptor for the connection with the collector */
    int col_fd;

    /** The most recent SSL connection error, if there has been one */
    int lastsslerror;

    /** Flag indicating if the collector thread should be inactive */
    int was_dropped;

    /** The frequency at which the thread needs to attempt a read from any
     *  RMQ consumers to allow heartbeats to be handled.
     */
    int rmq_hb_freq;

    /** Flag indicating whether the collector receive thread should be
     *  consuming from RMQ (as opposed to reading from a TCP socket)
     */
    int rmqenabled;

    /** Password to access the local RMQ instance where received records
     *  are published to so that LEA threads can read them when ready/
     */
    char *internalpass;

    /** Flag indicating whether the TCP socket to the collector should be
     *  encrypted with TLS or not
     */
    uint8_t using_tls;

    /** A mediator epoll event for reading from a TCP connection to the
     *  collector.
     */
    med_epoll_ev_t *colev;

    /** A mediator epoll event for reading from RabbitMQ */
    med_epoll_ev_t *rmq_colev;

    /** The AMQP connection state for the connection to the collector RMQ */
    amqp_connection_state_t amqp_state;

    /** The AMQP connection state for the connection to our local RMQ */
    amqp_connection_state_t amqp_producer_state;

    /** The socket for sending records onto the local RMQ instance */
    amqp_socket_t *amqp_producer_sock;

    /** The buffer used to store ETSI records received from the collector via
     *  a network connection */
    net_buffer_t *incoming;

    /** The buffer used to store ETSI records received from the collector via
     *  RabbitMQ */
    net_buffer_t *incoming_rmq;

    /** A flag indicating whether error logging is disabled for this
     *  collector.
     */
    int disabled_log;

    /** The SSL socket for this collector connection, if not using RMQ */
    SSL *ssl;

    /** The set of LIIDs that we have seen */
    col_known_liid_t *known_liids;

    /** A pointer to the shared global config for collector receive threads
     *  (owned by the main mediator thread)
     */
    mediator_collector_config_t *parentconfig;

    /** The message queue on which this thread will receive instructions
     *  from the main mediator thread.
     */
    libtrace_message_queue_t in_main;

    /** Flag that indicates whether RMQ has told us that it is "connection
     *  blocked, i.e. no longer able to accept published messages
     */
    uint8_t rmq_blocked;

    /** Number of received records that we have been unable to publish
     *  to the internal RMQ
     */
    uint64_t dropped_recs;

    /** Pointer to the next receive thread for this collector, i.e. in
     *  cases where the collector has multiple forwarding threads */
    coll_recv_t *next;

    /** Pointer to the first receive thread in the list for this collector */
    coll_recv_t *head;
    /** Pointer to the last receive thread in the list for this collector */
    coll_recv_t *tail;

    UT_hash_handle hh;

};

/** Structure that tracks the set of existing collector receive threads
 *  and their shared configuration.
 */
typedef struct mediator_collectors {
    /** A hashmap containing the set of collector receive threads */
    coll_recv_t *threads;

    /** Shared configuration for all collector receive threads */
    mediator_collector_config_t config;

} mediator_collector_t;

/** Initialises the shared configuration for the collectors managed by a
 *  mediator.
 *
 *  @param medcol       The global state for the collectors that is to be
 *                      initialised.
 *  @param usetls       The value of the global flag that indicates whether
 *                      new collector connections must use TLS.
 *  @param sslconf      A pointer to the SSL configuration for this mediator.
 *  @param rmqconf      A pointer to the RabbitMQ configuration for this
 *                      mediator.
 *  @param mediatorid   The ID number of the mediator
 */
void init_med_collector_config(mediator_collector_config_t *config,
        uint8_t usetls, openli_ssl_config_t *sslconf,
        openli_RMQ_config_t *rmqconf, uint32_t mediatorid);

/** Locks the shared collector configuration for exclusive use.
 *
 *
 *  @param config       The global config to be locked
 */
void lock_med_collector_config(mediator_collector_config_t *config);

/** Unlocks the shared collector configuration from exclusive use.
 *
 *
 *  @param config       The global config to be unlocked
 */
void unlock_med_collector_config(mediator_collector_config_t *config);

/** Updates the shared configuration for the collectors managed by a
 *  mediator.
 *
 *  @param config       The global config for the collectors that is to be
 *                      updated.
 *  @param usetls       The value of the global flag that indicates whether
 *                      new collector connections must use TLS.
 *  @param mediatorid   The ID number of the mediator
 */
void update_med_collector_config(mediator_collector_config_t *config,
        uint8_t usetls, uint32_t mediatorid);

/** Frees any resources allocated to the shared collector configuration.
 *
 *
 *  @param config       The global config to be destroyed
 */
void destroy_med_collector_config(mediator_collector_config_t *config);

/** Accepts a connection from a collector and spawns a new collector
 *  receive thread for that collector.
 *
 *  @param medcol       The shared config for all collector receive threads
 *  @param listenfd     The listening file descriptor that the connection
 *                      arrived on
 *
 *  @return -1 if an error occurs, otherwise returns the file descriptor
 *          for the newly accepted connection.
 */
int mediator_accept_collector_connection(mediator_collector_t *medcol,
        int listenfd);

/** Halts all collector receive threads and waits for the threads to
 *  terminate.
 *
 *  @param medcol       The shared state for all collector receive threads
 */
void mediator_disconnect_all_collectors(mediator_collector_t *medcol);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
