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

#ifndef OPENLI_MEDIATOR_RMQ_H_
#define OPENLI_MEDIATOR_RMQ_H_

#include "config.h"

#ifdef RMQC_HEADER_SUBDIR
#include <rabbitmq-c/tcp_socket.h>
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/ssl_socket.h>
#else
#include <amqp_tcp_socket.h>
#include <amqp.h>
#include <amqp_ssl_socket.h>
#endif

#include "coll_recv_thread.h"
#include "lea_send_thread.h"

/** Creates a connection to the internal RMQ instance for the purposes of
 *  writing intercept records received from a collector
 *
 *  Intended to be called by collector receive threads to establish their RMQ
 *  connection session.
 *
 *  @param col              The state for the collector receive thread that
 *                          is calling this function
 *
 *  @return NULL if the connection fails, otherwise the newly created
 *          connection object.
 */
amqp_connection_state_t join_mediator_RMQ_as_producer(coll_recv_t *col);

/** Connect to the RMQ instance that is running on an OpenLI collector.
 *
 *  This connection would be used by a collector receive thread to
 *  consume intercept records from its corresponding collector
 *  (assuming that the collector is exporting via RMQ, of course).
 *
 *  @param col          The state for the collector receive thread that
 *                      is requesting the connection to the collector RMQ
 *
 *  @return NULL if the connection fails, otherwise the newly created
 *          connection object
 */
amqp_connection_state_t join_collector_RMQ(coll_recv_t *col);

/** Creates a connection to the internal RMQ instance for the purposes of
 *  consuming intercept records for intercepts headed for a particular agency.
 *
 *  Intended to be called by LEA send threads to establish their RMQ
 *  connection session.
 *
 *  @param agencyid         The ID of the agency that this connection is for.
 *  @param logfailure       Flag indicating whether to write a log message if
 *                          an error occurs. Set to zero to avoid log spam
 *                          if the connection attempt repeatedly fails.
 *  @param password         The password to use to authenticate with RMQ.
 *
 *  @return NULL if the connection fails, otherwise the newly created
 *          connection object.
 */
amqp_connection_state_t join_mediator_RMQ_as_consumer(char *agencyid,
        int logfailure, char *password);

/** Declares the IRI queue for a given LIID and registers it with an
 *  RMQ connection for consumption.
 *
 *  @param state            The RMQ connection to register the queue on
 *  @param liid             The LIID of the intercept to register
 *
 *  @return -1 if the queue declaration fails, -2 if the registration
 *          fails, 0 if either parameter is bad, 1 if everything was
 *          successful
 */
int register_mediator_iri_RMQ_consumer(amqp_connection_state_t state,
        char *liid);

/** Stop consuming IRI messages for a given LIID
 *
 *  @param state            The RMQ connection to stop consuming on
 *  @param liid             The LIID to stop consuming IRI records for
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int deregister_mediator_iri_RMQ_consumer(amqp_connection_state_t state,
        char *liid);

/** Declares the CC queue for a given LIID and registers it with an
 *  RMQ connection for consumption.
 *
 *  @param state            The RMQ connection to register the queue on
 *  @param liid             The LIID of the intercept to register
 *
 *  @return -1 if the queue declaration fails, -2 if the registration
 *          fails, 0 if either parameter is bad, 1 if everything was
 *          successful
 */
int register_mediator_cc_RMQ_consumer(amqp_connection_state_t state,
        char *liid);

/** Stop consuming CC messages for a given LIID
 *
 *  @param state            The RMQ connection to stop consuming on
 *  @param liid             The LIID to stop consuming CC records for
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int deregister_mediator_cc_RMQ_consumer(amqp_connection_state_t state,
        char *liid);

/** Declares the raw IP packet queue for a given LIID and registers it with an
 *  RMQ connection for consumption.
 *
 *  @param state            The RMQ connection to register the queue on
 *  @param liid             The LIID of the intercept to register
 *
 *  @return -1 if the queue declaration fails, -2 if the registration
 *          fails, 0 if either parameter is bad, 1 if everything was
 *          successful
 */
int register_mediator_rawip_RMQ_consumer(amqp_connection_state_t state,
        char *liid);

/** Stop consuming raw IP packets for a given LIID
 *
 *  @param state            The RMQ connection to stop consuming on
 *  @param liid             The LIID to stop consuming raw IP packets for
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */

int deregister_mediator_rawip_RMQ_consumer(amqp_connection_state_t state,
        char *liid);

/** Declares the CC and IRI queues in RabbitMQ for a particular LIID
 *
 *  If the queues are already declared, this should be a no-op.
 *
 *  @param state        The RMQ connection to use to declare the queues
 *  @param liid         The LIID to declare queues for
 *  @param is_blocked   [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int declare_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        char *liid, uint8_t *is_blocked);

/** Declares the Raw IP queue in RabbitMQ for a particular LIID
 *
 *  Only required for LIIDs that are being written to pcap files.
 *
 *  @param state        The RMQ connection to use to declare the queue
 *  @param liid         The LIID to declare a raw IP queue for
 *  @param is_blocked   [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int declare_mediator_rawip_RMQ_queue(amqp_connection_state_t state,
        char *liid, uint8_t *is_blocked);


void remove_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        char *liid);
void remove_mediator_rawip_RMQ_queue(amqp_connection_state_t state,
        char *liid);

/** Publishes an encoded CC onto a mediator RMQ queue.
 *
 *  @param state            The RMQ connection to use to publish the message
 *  @param msg              A pointer to the start of the encoded CC
 *  @param msglen           The length of the encoded CC, in bytes
 *  @param liid             The LIID that the message belongs to
 *  @param queuename        THe name of the queue to publish to
 *  @param is_blocked       [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return 0 if an error occurs, 1 if the message is published successfully
 */
int publish_iri_on_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        uint8_t *msg, uint16_t msglen, char *liid, const char *queuename,
        uint8_t *is_blocked);

/** Publishes an encoded CC onto a mediator RMQ queue.
 *
 *  @param state            The RMQ connection to use to publish the message
 *  @param msg              A pointer to the start of the encoded CC
 *  @param msglen           The length of the encoded CC, in bytes
 *  @param liid             The LIID that the message belongs to
 *  @param queuename        THe name of the queue to publish to
 *  @param is_blocked       [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return 0 if an error occurs, 1 if the message is published successfully
 */
int publish_cc_on_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        uint8_t *msg, uint16_t msglen, char *liid, const char *queuename,
        uint8_t *is_blocked);

/** Publishes an encoded CC onto a mediator RMQ queue.
 *
 *  @param state            The RMQ connection to use to publish the message
 *  @param msg              A pointer to the start of the encoded CC
 *  @param msglen           The length of the encoded CC, in bytes
 *  @param liid             The LIID that the message belongs to
 *  @param queuename        THe name of the queue to publish to
 *  @param is_blocked       [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return 0 if an error occurs, 1 if the message is published successfully
 */
int publish_rawip_on_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        uint8_t *msg, uint16_t msglen, char *liid, const char *queuename,
        uint8_t *is_blocked);

/** Consumes CC records using an RMQ connection, writing them into the
 *  provided export buffer.
 *
 *  Note that only CCs for LIIDs that are registered with this connection
 *  will be consumed.
 *
 *  @param state            The RMQ connection to consume CCs from
 *  @param buf              The export buffer to write the CCs into
 *  @param maxread          The maximum number of CCs to read before
 *                          returning from this function
 *  @param last_deliv       The delivery tag of the most recent consumed
 *                          message (updated by this function)
 *
 *  @return -1 if an error occurs, -2 if the RMQ connection has timed out
 *          due to a heartbeat failure, 0 if no CCs were consumed, or
 *          1 if at least one CC was consumed successfully.
 */
int consume_mediator_cc_messages(amqp_connection_state_t state,
        export_buffer_t *buf, int maxread, uint64_t *last_deliv);

/** Consumes IRI records using an RMQ connection, writing them into the
 *  provided export buffer.
 *
 *  Note that only IRIs for LIIDs that are registered with this connection
 *  will be consumed.
 *
 *  @param state            The RMQ connection to consume IRIs from
 *  @param buf              The export buffer to write the IRIs into
 *  @param maxread          The maximum number of IRIs to read before
 *                          returning from this function
 *  @param last_deliv       The delivery tag of the most recent consumed
 *                          message (updated by this function)
 *
 *  @return -1 if an error occurs, -2 if the RMQ connection has timed out
 *          due to a heartbeat failure, 0 if no IRIs were consumed, or
 *          1 if at least one IRI was consumed successfully.
 */
int consume_mediator_iri_messages(amqp_connection_state_t state,
        export_buffer_t *buf, int maxread, uint64_t *last_deliv);

/** Consumes raw IP packets using an RMQ connection, writing them into the
 *  provided export buffer.
 *
 *  Note that only raw IP packets for LIIDs that are registered with this
 *  connection will be consumed.
 *
 *  @param state            The RMQ connection to consume packets from
 *  @param buf              The export buffer to write the packets into
 *  @param maxread          The maximum number of packets to read before
 *                          returning from this function
 *  @param last_deliv       The delivery tag of the most recent consumed
 *                          message (updated by this function)
 *
 *  @return -1 if an error occurs, -2 if the RMQ connection has timed out
 *          due to a heartbeat failure, 0 if no packets were consumed, or
 *          1 if at least one packet was consumed successfully.
 */
int consume_mediator_rawip_messages(amqp_connection_state_t state,
        export_buffer_t *buf, int maxread, uint64_t *last_deliv);

/** Acknowledges IRI messages for an RMQ connection, up to the provided
 *  delivery tag number.
 *
 *  @param state            The RMQ connection to acknowledge messages on
 *  @param deliv_tag        The delivery tag to acknowledge
 *
 *  @return AMQP_STATUS_OK if the acknowledgement was successful, otherwise
 *          will return the corresponding AMQP error code
 */
int ack_mediator_iri_messages(amqp_connection_state_t state,
        uint64_t deliv_tag);

/** Acknowledges CC messages for an RMQ connection, up to the provided
 *  delivery tag number.
 *
 *  @param state            The RMQ connection to acknowledge messages on
 *  @param deliv_tag        The delivery tag to acknowledge
 *
 *  @return AMQP_STATUS_OK if the acknowledgement was successful, otherwise
 *          will return the corresponding AMQP error code
 */
int ack_mediator_cc_messages(amqp_connection_state_t state,
        uint64_t deliv_tag);

/** Acknowledges raw IP messages for an RMQ connection, up to the provided
 *  delivery tag number.
 *
 *  @param state            The RMQ connection to acknowledge messages on
 *  @param deliv_tag        The delivery tag to acknowledge
 *
 *  @return AMQP_STATUS_OK if the acknowledgement was successful, otherwise
 *          will return the corresponding AMQP error code
 */
int ack_mediator_rawip_messages(amqp_connection_state_t state,
        uint64_t deliv_tag);

/** Indicates whether the IRI queue for a given LIID is empty or not.
 *
 *  @param state            The RMQ connection to use to undertake the check
 *  @param liid             The LIID whose IRI queue needs to be checked
 *
 *  @return -1 if an error occurs, 0 if the queue is not empty or the
 *          parameters are invalid, 1 if the queue is empty.
 */
int check_empty_mediator_iri_RMQ(amqp_connection_state_t state, char *liid);

/** Indicates whether the CC queue for a given LIID is empty or not.
 *
 *  @param state            The RMQ connection to use to undertake the check
 *  @param liid             The LIID whose CC queue needs to be checked
 *
 *  @return -1 if an error occurs, 0 if the queue is not empty or the
 *          parameters are invalid, 1 if the queue is empty.
 */
int check_empty_mediator_cc_RMQ(amqp_connection_state_t state, char *liid);

/** Indicates whether the raw IP packet queue for a given LIID is empty or not.
 *
 *  @param state            The RMQ connection to use to undertake the check
 *  @param liid             The LIID whose raw IP queue needs to be checked
 *
 *  @return -1 if an error occurs, 0 if the queue is not empty or the
 *          parameters are invalid, 1 if the queue is empty.
 */
int check_empty_mediator_rawip_RMQ(amqp_connection_state_t state, char *liid);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
