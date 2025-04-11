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

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include "mediator_rmq.h"
#include <unistd.h>
#include "logger.h"
#include "coll_recv_thread.h"

/** This file implements the interactions between various elements of the
 *  OpenLI mediator (e.g. LEA send threads, collector receive threads) and
 *  the RabbitMQ API.
 */

/** Declares a RabbitMQ queue on a specified channel
 *
 *  @param state        The RMQ connection to use to declare the queue
 *  @param queueid      The name to assign to the queue
 *  @param channel      The channel to declare the queue on
 *
 *  @return -1 if an error occurs, 0 if the queue cannot be declared right
 *  now, 1 if the queue was declared successfully.
 */
static int declare_RMQ_queue(amqp_connection_state_t state,
        char *queueid, int channel) {

    amqp_bytes_t rmq_queueid;

#if 0
    amqp_table_t queueargs;
    amqp_table_entry_t entries[2];

    entries[0].key = amqp_cstring_bytes("x-queue-type");
    entries[0].value.kind = AMQP_FIELD_KIND_UTF8;
    entries[0].value.value.bytes = amqp_cstring_bytes("stream");

    entries[1].key = amqp_cstring_bytes("x-max-length-bytes");
    entries[1].value.kind = AMQP_FIELD_KIND_U64;
    entries[1].value.value.u64 = 20000000000;       // 20 GB max size
    queueargs.num_entries = 2;
    queueargs.entries = entries;
#endif

    rmq_queueid.len = strlen(queueid);
    rmq_queueid.bytes = (void *)queueid;

    amqp_queue_declare(state, channel, rmq_queueid, 0, 1, 0, 0,
            amqp_empty_table);
    if (amqp_get_rpc_reply(state).reply_type != AMQP_RESPONSE_NORMAL) {
        logger(LOG_INFO, "OpenLI Mediator: unable to declare RMQ queue for %s on channel %d: %u", queueid, channel, amqp_get_rpc_reply(state).reply_type);
        return -1;
    }

    return 1;
}

/** Checks if a particular RabbitMQ queue is empty (i.e. contains zero
 *  unconsumed messages).
 *
 *  @param state        The RMQ connection to use to access the queue
 *  @param queueid      The name of the queue to check
 *  @param channel      The channel that the queue exists on
 *
 *  @return -1 if an error occurs, 0 if the queue is not empty, 1 if the queue
 *          is empty.
 */
static int is_RMQ_queue_empty(amqp_connection_state_t state, char *queueid,
        int channel) {

    amqp_bytes_t rmq_queueid;
    amqp_table_t queueargs;
    amqp_queue_declare_ok_t *r;

    queueargs.num_entries = 0;
    queueargs.entries = NULL;

    rmq_queueid.len = strlen(queueid);
    rmq_queueid.bytes = (void *)queueid;

    r = amqp_queue_declare(state, channel, rmq_queueid, 0, 1, 0, 0, queueargs);
    if (amqp_get_rpc_reply(state).reply_type != AMQP_RESPONSE_NORMAL) {
        logger(LOG_INFO, "OpenLI Mediator: unable to declare passive RMQ queue for %s on channel %d: %u", queueid, channel, amqp_get_rpc_reply(state).reply_type);
        return -1;
    }

    /* TODO this is wrong! message_count doesn't include pre-fetched
     * messages so is often 0 when there are still unacked messages :(
     *
     * Need a way to get the number that rabbitmqctl reports for the
     * queue -- I don't think rabbitmq-c provides a useful API for this.
     */
    printf("queueid %s -- message count %u\n", queueid, r->message_count);
    if (r->message_count == 0) {
        return 1;
    }

    return 0;
}

/** Registers a RabbitMQ queue for consumption by an existing connection
 *
 *  @param state            The RMQ connection to register the queue on
 *  @param queueid          The name of the queue to consume from
 *  @param channel          The channel that the queue should be on
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int register_RMQ_consumer(amqp_connection_state_t state,
        char *queueid, int channel) {

    amqp_bytes_t rmq_queueid;

    rmq_queueid.len = strlen(queueid);
    rmq_queueid.bytes = (void *)queueid;

    amqp_basic_consume(state, channel, rmq_queueid, amqp_cstring_bytes(queueid),
            0, 0, 0, amqp_empty_table);

    if (amqp_get_rpc_reply(state).reply_type != AMQP_RESPONSE_NORMAL ) {
        return -1;
    }

    return 0;
}

static int update_mediator_rmq_connection_block_status(
        amqp_connection_state_t state, uint8_t *is_blocked) {

    /* copy of code from export_buffer.c, but with different log
     * messages when things go awry
     */
    amqp_frame_t frame;
    struct timeval tv;
    int x, ret;

    tv.tv_sec = tv.tv_usec = 0;
    x = amqp_simple_wait_frame_noblock(state, &frame, &tv);

    if (x != AMQP_STATUS_OK && x != AMQP_STATUS_TIMEOUT) {
        logger(LOG_INFO,
                "OpenLI mediator: unable to check status of an internal RMQ publishing socket");
        return -1;
    }

    if (*is_blocked) {
        ret = 0;
    } else {
        ret = 1;
    }

    if (x == AMQP_STATUS_TIMEOUT) {
        return ret;
    }

    if (AMQP_FRAME_METHOD == frame.frame_type) {
        switch(frame.payload.method.id) {
            case AMQP_CONNECTION_BLOCKED_METHOD:
                if ((*is_blocked) == 0) {
                    logger(LOG_INFO,
                            "OpenLI mediator: RMQ is unable to handle any more published ETSI records!");
                    logger(LOG_INFO,
                            "OpenLI mediator: this is a SERIOUS problem -- received ETSI records are going to be dropped!");
                }
                *is_blocked = 1;
                ret = 0;
                break;
            case AMQP_CONNECTION_UNBLOCKED_METHOD:
                if ((*is_blocked) == 1) {
                    logger(LOG_INFO,
                            "OpenLI mediator: RMQ has become unblocked and will resume publishing ETSI records.");
                    ret = 0;
                } else {
                    ret = 1;
                }
                *is_blocked = 0;
                break;
            case AMQP_CONNECTION_CLOSE_METHOD:
                logger(LOG_INFO,
                        "OpenLI mediator: 'close' exception occurred on an internal RMQ connection -- must restart connection");
                return -1;
            case AMQP_CHANNEL_CLOSE_METHOD:
                logger(LOG_INFO,
                        "OpenLI mediator: channel exception occurred on an internal RMQ connection -- must reset connection");
                return -1;
        }
    }
    return ret;
}

/** Disables consumption from a RabbitMQ queue by an existing connection
 *
 *  @param state            The RMQ connection to disassociate the queue from
 *  @param queueid          The name of the queue to disable
 *  @param channel          The channel that the queue should be on
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int cancel_RMQ_consumer(amqp_connection_state_t state,
        char *queueid, int channel) {

    if (state == NULL) {
        return 0;
    }

    amqp_basic_cancel(state, channel, amqp_cstring_bytes(queueid));
    if (amqp_get_rpc_reply(state).reply_type != AMQP_RESPONSE_NORMAL) {
        return -1;
    }
    return 0;
}

/** Declares the CC and IRI queues in RabbitMQ for a particular LIID
 *
 *  If the queues are already declared, this should be a no-op.
 *
 *  @param state        The RMQ connection to use to declare the queues
 *  @param liid         The LIID to declare queues for
 *  @param liidlen      The length of the LIID (in bytes)
 *
 *  @return -1 if an error occurs, 0 if the queue cannot be declared right
 *  now, 1 if the queue was declared successfully.
 */
int declare_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        char *liid, uint8_t *is_blocked) {

    char cc_queuename[1024];
    char iri_queuename[1024];

    /*
    if (update_mediator_rmq_connection_block_status(state, is_blocked) < 0) {
        return -1;
    }
    */
    if (*is_blocked) {
        return 0;
    }
    snprintf(cc_queuename, 1024, "%s-%s", liid, "cc");
    snprintf(iri_queuename, 1024, "%s-%s", liid, "iri");

    if (declare_RMQ_queue(state, iri_queuename, 2) < 0) {
        return -1;
    }
    return declare_RMQ_queue(state, cc_queuename, 3);
}

/** Declares the Raw IP queue in RabbitMQ for a particular LIID
 *
 *  Only required for LIIDs that are being written to pcap files.
 *
 *  @param state        The RMQ connection to use to declare the queue
 *  @param liid         The LIID to declare a raw IP queue for
 *  @param liidlen      The length of the LIID (in bytes)
 *
 *  @return -1 if an error occurs, 0 if the queue cannot be declared right
 *  now, 1 if the queue was declared successfully.
 */
int declare_mediator_rawip_RMQ_queue(amqp_connection_state_t state,
        char *liid, uint8_t *is_blocked) {

    char queuename[1024];
    /*
    if (update_mediator_rmq_connection_block_status(state, is_blocked) < 0) {
        return -1;
    }
    */
    if (*is_blocked == 0) {
        snprintf(queuename, 1024, "%s-rawip", liid);
        return declare_RMQ_queue(state, queuename, 4);
    }
    return 0;
}

/** Publishes a message onto a mediator RMQ queue.
 *
 *  A message can be an encoded CC, an encoded IRI, or a raw IP packet body.
 *
 *  @param state            The RMQ connection to use to publish the message
 *  @param msg              A pointer to the start of the messsage content
 *  @param msglen           The length of the message content, in bytes
 *  @param liid             The LIID that the message belongs to
 *  @param channel          The channel to publish the message to
 *  @param queuename        THe name of the queue to publish to
 *  @param expiry           The TTL of the message in seconds -- if set to 0,
 *                          the message will not be expired by RMQ
 *  @param is_blocked       [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return 0 if an error occurs, 1 if the message is published successfully
 */
static int produce_mediator_RMQ(amqp_connection_state_t state,
        uint8_t *msg, uint16_t msglen, char *liid, int channel,
        const char *queuename, uint32_t expiry, uint8_t *is_blocked) {
    amqp_bytes_t message_bytes;
    amqp_basic_properties_t props;
    int pub_ret;
    char expirystr[1024];

    message_bytes.len = msglen;
    message_bytes.bytes = msg;

    props._flags = AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.delivery_mode = 2;        /* persistent mode */

    if (expiry != 0) {
        snprintf(expirystr, 1024, "%u", expiry * 1000);
        props.expiration = amqp_cstring_bytes(expirystr);
    }

    if (update_mediator_rmq_connection_block_status(state, is_blocked) < 0) {
        return -1;
    }

    if ((*is_blocked) == 0) {
        pub_ret = amqp_basic_publish(state, channel, amqp_cstring_bytes(""),
                amqp_cstring_bytes(queuename), 0, 0, &props, message_bytes);
        if (pub_ret != 0) {
            logger(LOG_INFO, "OpenLI Mediator: error publishing to internal RMQ for LIID %s: %d", liid, pub_ret);
            return -1;
        }
    } else {
        return 0;
    }

    return 1;
}

/** Publishes a raw IP packet onto a mediator RMQ queue.
 *
 *  @param state            The RMQ connection to use to publish the message
 *  @param msg              A pointer to the start of the packet body
 *  @param msglen           The length of the packet body, in bytes
 *  @param liid             The LIID that the message belongs to
 *  @param queuename        THe name of the queue to publish to
 *  @param is_blocked       [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return 0 if an error occurs, 1 if the message is published successfully
 */
int publish_rawip_on_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        uint8_t *msg, uint16_t msglen, char *liid, const char *queuename,
        uint8_t *is_blocked) {
    return produce_mediator_RMQ(state, msg, msglen, liid, 4, queuename, 0,
            is_blocked);
}

/** Publishes an encoded IRI onto a mediator RMQ queue.
 *
 *  @param state            The RMQ connection to use to publish the message
 *  @param msg              A pointer to the start of the encoded IRI
 *  @param msglen           The length of the encoded IRI, in bytes
 *  @param liid             The LIID that the message belongs to
 *  @param queuename        THe name of the queue to publish to
 *  @param is_blocked       [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return 0 if an error occurs, 1 if the message is published successfully
 */
int publish_iri_on_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        uint8_t *msg, uint16_t msglen, char *liid, const char *queuename,
        uint8_t *is_blocked) {

    return produce_mediator_RMQ(state, msg, msglen, liid, 2, queuename, 0,
            is_blocked);
}

/** Publishes an encoded CC onto a mediator RMQ queue.
 *
 *  @param state            The RMQ connection to use to publish the message
 *  @param msg              A pointer to the start of the encoded CC
 *  @param msglen           The length of the encoded CC, in bytes
 *  @param liid             The LIID that the message belongs to
 *  @param queuename        The name of the queue to publish to
 *  @param is_blocked       [in|out] Is the RMQ broker accepting publishes?
 *
 *  @return 0 if an error occurs, 1 if the message is published successfully
 */
int publish_cc_on_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        uint8_t *msg, uint16_t msglen, char *liid, const char *queuename,
        uint8_t *is_blocked) {

    return produce_mediator_RMQ(state, msg, msglen, liid, 3, queuename, 0,
            is_blocked);
}

void remove_mediator_liid_RMQ_queue(amqp_connection_state_t state,
        char *liid) {
    int err = 0;
    amqp_queue_delete_ok_t *reply;
    char queuename[1024];

    snprintf(queuename, 1024, "%s-iri", liid);

    reply = amqp_queue_delete(state, 2, amqp_cstring_bytes(queuename), 0, 0);
    if (reply == NULL) {
        err = 1;
    }

    snprintf(queuename, 1024, "%s-cc", liid);
    reply = amqp_queue_delete(state, 3, amqp_cstring_bytes(queuename), 0, 0);
    if (reply == NULL) {
        err = 1;
    }

    if (err) {
        /* I guess this is bad, not sure what to do though... */
        logger(LOG_ERR, "Error while deleting internal RMQ for LIID %s",
                liid);
    }

}

void remove_mediator_rawip_RMQ_queue(amqp_connection_state_t state,
        char *liid) {

    amqp_queue_delete_ok_t *reply;
    char queuename[1024];

    snprintf(queuename, 1024, "%s-rawip", liid);
    reply = amqp_queue_delete(state, 4, amqp_cstring_bytes(queuename), 0, 0);
    if (reply == NULL) {
        logger(LOG_ERR, "Error while deleting internal rawip RMQ for LIID %s",
                liid);
    }
}

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
        int logfailure, char *password) {

    amqp_connection_state_t state;
    amqp_socket_t *amqp_sock;

    state = amqp_new_connection();
    amqp_sock = amqp_tcp_socket_new(state);

    if (amqp_socket_open(amqp_sock, "localhost", 5672)) {
        if (logfailure) {
            logger(LOG_INFO, "OpenLI Mediator: unable to open amqp consumer socket for internal RMQ in agency thread %s", agencyid);
        }
        goto consfailed;
    }

    /* Hard-coded username and vhost */
    if ((amqp_login(state, "OpenLI-med", 0, 131072, 0,
                AMQP_SASL_METHOD_PLAIN, "openli.nz", password))
            .reply_type != AMQP_RESPONSE_NORMAL) {
        if (logfailure) {
            logger(LOG_ERR, "OpenLI Mediator: failed to log into RMQ broker using plain auth in agency thread %s", agencyid);
        }
        goto consfailed;
    }

    /* TODO replace with loop */
    amqp_channel_open(state, 2);
    if ((amqp_get_rpc_reply(state).reply_type) != AMQP_RESPONSE_NORMAL) {
        if (logfailure) {
            logger(LOG_ERR, "OpenLI Mediator: failed to open RMQ channel 2 in agency thread %s", agencyid);
        }
        goto consfailed;
    }

    amqp_channel_open(state, 3);
    if ((amqp_get_rpc_reply(state).reply_type) != AMQP_RESPONSE_NORMAL) {
        if (logfailure) {
            logger(LOG_ERR, "OpenLI Mediator: failed to open RMQ channel 3 in agency thread %s", agencyid);
        }
        goto consfailed;
    }

    amqp_channel_open(state, 4);
    if ((amqp_get_rpc_reply(state).reply_type) != AMQP_RESPONSE_NORMAL) {
        if (logfailure) {
            logger(LOG_ERR, "OpenLI Mediator: failed to open RMQ channel 4 in agency thread %s", agencyid);
        }
        goto consfailed;
    }

    return state;

consfailed:
    if (state) {
        amqp_destroy_connection(state);
    }
    return NULL;
}

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
amqp_connection_state_t join_mediator_RMQ_as_producer(coll_recv_t *col) {

    amqp_table_entry_t login_properties[1];
    amqp_table_t login_properties_table;

    amqp_table_entry_t client_capabilities[1];
    amqp_table_t client_capabilities_table;

    if (col->amqp_producer_state) {
        return col->amqp_producer_state;
    }

    if (col->internalpass == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: collector thread for %s cannot log into RMQ broker because no suitable password has been configured.", col->ipaddr);
        goto prodfailed;
    }

    col->amqp_producer_state = amqp_new_connection();
    col->amqp_producer_sock = amqp_tcp_socket_new(col->amqp_producer_state);

    if (amqp_socket_open(col->amqp_producer_sock, "localhost", 5672)) {
        if (col->disabled_log == 0) {
            logger(LOG_INFO, "OpenLI Mediator: collector thread for %s could not open amqp producer socket", col->ipaddr);
        }
        goto prodfailed;
    }

    client_capabilities[0].key = amqp_cstring_bytes("connection.blocked");
    client_capabilities[0].value.kind = AMQP_FIELD_KIND_BOOLEAN;
    client_capabilities[0].value.value.boolean = 1;

    client_capabilities_table.entries = client_capabilities;
    client_capabilities_table.num_entries = 1;

    login_properties[0].key = amqp_cstring_bytes("capabilities");
    login_properties[0].value.kind = AMQP_FIELD_KIND_TABLE;
    login_properties[0].value.value.table = client_capabilities_table;

    login_properties_table.entries = login_properties;
    login_properties_table.num_entries = 1;

    /* Hard-coded username and password -- not ideal, but the RMQ instance
     * should only be accessible via localhost.
     */
    if ((amqp_login_with_properties(col->amqp_producer_state, "OpenLI-med", 0,
                131072, 0, &login_properties_table,
                AMQP_SASL_METHOD_PLAIN, "openli.nz", col->internalpass))
            .reply_type != AMQP_RESPONSE_NORMAL) {
        if (col->disabled_log == 0) {
            logger(LOG_ERR, "OpenLI Mediator: failed to log into RMQ broker using plain auth in collector thread %s", col->ipaddr);
        }
        goto prodfailed;
    }

    /* TODO replace with loop */
    /* TODO some of this stuff could be moved into a separate inline
     * function that is called by both the producer and consumer functions
     */
    amqp_channel_open(col->amqp_producer_state, 2);
    if ((amqp_get_rpc_reply(col->amqp_producer_state).reply_type) !=
            AMQP_RESPONSE_NORMAL) {
        if (col->disabled_log == 0) {
            logger(LOG_ERR, "OpenLI Mediator: failed to open RMQ channel 2 in collector thread for %s", col->ipaddr);
        }
        goto prodfailed;
    }

    amqp_channel_open(col->amqp_producer_state, 3);
    if ((amqp_get_rpc_reply(col->amqp_producer_state).reply_type) !=
            AMQP_RESPONSE_NORMAL) {
        if (col->disabled_log == 0) {
            logger(LOG_ERR, "OpenLI Mediator: failed to open RMQ channel 3 in collector thread for %s", col->ipaddr);
        }
        goto prodfailed;
    }

    amqp_channel_open(col->amqp_producer_state, 4);
    if ((amqp_get_rpc_reply(col->amqp_producer_state).reply_type) !=
            AMQP_RESPONSE_NORMAL) {
        if (col->disabled_log == 0) {
            logger(LOG_ERR, "OpenLI Mediator: failed to open RMQ channel 4 in collector thread for %s", col->ipaddr);
        }
        goto prodfailed;
    }

    logger(LOG_INFO, "OpenLI Mediator: collector thread for %s has connected to local RMQ instance", col->ipaddr);

    return col->amqp_producer_state;

prodfailed:
    if (col->amqp_producer_state) {
        amqp_destroy_connection(col->amqp_producer_state);
        col->amqp_producer_state = NULL;
    }
    return NULL;
}

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
amqp_connection_state_t join_collector_RMQ(coll_recv_t *col) {

    char stringspace[32];
    struct timeval tv;
    int status;
    amqp_connection_state_t amqp_state;
    amqp_socket_t *amqp_sock = NULL;
    mediator_collector_config_t *conf = col->parentconfig;
    uint16_t useport;
    uint32_t medid;

    /* Try to connect to RMQ service at col->ipaddr and join the appropiate
     * queue (which should be named after our mediator ID)
     */
    amqp_set_initialize_ssl_library(0);
    amqp_state = amqp_new_connection();

    lock_med_collector_config(conf);    /* LOCK SHARED CONFIGURATION */

    medid = conf->parent_mediatorid;

    //If no port is supplied use default
    if (conf->rmqconf->port == 0) {
        if (conf->rmqconf->SSLenabled) {
            useport = 5671;
        } else {
            useport = 5672;
        }
    } else {
        useport = conf->rmqconf->port;
    }

    tv.tv_usec = 0;
    tv.tv_sec = 1;

    if (conf->rmqconf->SSLenabled && conf->sslconf->cacertfile &&
            conf->sslconf->certfile && conf->sslconf->keyfile) {
        /* SSL connection is required */
        amqp_sock = amqp_ssl_socket_new(amqp_state);
        if (!amqp_sock) {
            if (!col->disabled_log) {
                logger(LOG_INFO, "OpenLI Mediator: RMQ failed to create new SSL socket");
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }

        amqp_ssl_socket_set_verify_peer(amqp_sock, 0);
        amqp_ssl_socket_set_verify_hostname(amqp_sock, 0);

        if (amqp_ssl_socket_set_cacert(amqp_sock, conf->sslconf->cacertfile)
                != AMQP_STATUS_OK) {
            if (!col->disabled_log) {
                logger(LOG_INFO, "OpenLI Mediator: RMQ failed to load cacert");
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }

        if (amqp_ssl_socket_set_key(amqp_sock, conf->sslconf->certfile,
                conf->sslconf->keyfile) != AMQP_STATUS_OK ) {
            if (!col->disabled_log) {
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ failed to load SSL cert/key");
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }

        if (!col->disabled_log) {
            logger(LOG_INFO,
                    "OpenLI Mediator: attempting to connect to RMQ using SSL on %s:%u",
                    col->ipaddr, useport);
        }

        if ((status = amqp_socket_open_noblock(amqp_sock,
                    (const char *)col->ipaddr,
                    useport, &tv))){
            if (!col->disabled_log) {
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ failed to open AMQP socket: %d",
                        status);
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }
        if ( (amqp_login(amqp_state, "OpenLI", 0, 131072,
                conf->rmqconf->heartbeatFreq,
                AMQP_SASL_METHOD_EXTERNAL, "EXTERNAL")
                ).reply_type != AMQP_RESPONSE_NORMAL ) {
            if (!col->disabled_log) {
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ failed to login using EXTERNAL auth");
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }
    } else if (conf->rmqconf->name && conf->rmqconf->pass) {
        //start up socket with non SSL auth
        amqp_sock = amqp_tcp_socket_new(amqp_state);

        if (!amqp_sock) {
            if (!col->disabled_log) {
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ error opening new TCP socket");
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }

        if (!col->disabled_log) {
            logger(LOG_INFO, "OpenLI Mediator: attempting to connect to RMQ using PLAIN auth at %s:%u", col->ipaddr, useport);
        }

        if (amqp_socket_open_noblock(amqp_sock, (const char *)col->ipaddr,
                useport, &tv)){
            if (!col->disabled_log) {
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ failed to open AMQP socket");
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }

        if (amqp_login(amqp_state, "OpenLI", 0, 131072,
                conf->rmqconf->heartbeatFreq, AMQP_SASL_METHOD_PLAIN,
                conf->rmqconf->name,
                conf->rmqconf->pass).reply_type != AMQP_RESPONSE_NORMAL) {
            if (!col->disabled_log) {
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ failed to login using PLAIN auth");
            }
            amqp_destroy_connection(amqp_state);
            unlock_med_collector_config(conf);
            return NULL;
        }
    } else {
        if (!col->disabled_log) {
            logger(LOG_INFO,
                    "OpenLI Mediator: no valid RMQ login was provided");
        }
        amqp_destroy_connection(amqp_state);
        unlock_med_collector_config(conf);
        return NULL;
    }

    unlock_med_collector_config(conf);  /* UNLOCK SHARED CONFIGURATION */

    /* Use channel 1 for exchanging intercept records */
    amqp_channel_open(amqp_state, 1);

    if ( (amqp_get_rpc_reply(amqp_state).reply_type) != AMQP_RESPONSE_NORMAL ) {
        if (!col->disabled_log) {
            logger(LOG_ERR, "OpenLI Mediator: RMQ failed to open channel");
        }
        amqp_destroy_connection(amqp_state);
        return NULL;
    }

    /* Make sure we have a declared instance of the queue for this mediator */
    snprintf(stringspace, sizeof(stringspace), "ID%d-%d", medid,
            col->forwarder_id);
    if (declare_RMQ_queue(amqp_state, stringspace, 1) < 0) {
        if (!col->disabled_log) {
            logger(LOG_INFO, "OpenLI Mediator: RMQ failed to declare queue %s on collector %s", stringspace, col->ipaddr);
        }
        amqp_destroy_connection(amqp_state);
        return NULL;
    }


    /* Add the queue to our list of consumable queues for this connection */
    if (register_RMQ_consumer(amqp_state, stringspace, 1) < 0) {
        if (!col->disabled_log) {
            logger(LOG_INFO,
                    "OpenLI Mediator: RMQ failed to register consumer");
        }
        amqp_destroy_connection(amqp_state);
        return NULL;
    } else if (!col->disabled_log) {
        logger(LOG_INFO, "OpenLI Mediator: RMQ Registered consumer %s",
            stringspace);
    }

    return amqp_state;
}


/** Stop consuming IRI messages for a given LIID
 *
 *  @param state            The RMQ connection to stop consuming on
 *  @param liid             The LIID to stop consuming IRI records for
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int deregister_mediator_iri_RMQ_consumer(amqp_connection_state_t state,
        char *liid) {

    char iri_queuename[1024];
    snprintf(iri_queuename, 1024, "%s-%s", liid, "iri");

    return cancel_RMQ_consumer(state, iri_queuename, 2);
}

/** Stop consuming CC messages for a given LIID
 *
 *  @param state            The RMQ connection to stop consuming on
 *  @param liid             The LIID to stop consuming CC records for
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int deregister_mediator_cc_RMQ_consumer(amqp_connection_state_t state,
        char *liid) {

    char cc_queuename[1024];
    snprintf(cc_queuename, 1024, "%s-%s", liid, "cc");

    return cancel_RMQ_consumer(state, cc_queuename, 3);
}

/** Stop consuming raw IP packets for a given LIID
 *
 *  @param state            The RMQ connection to stop consuming on
 *  @param liid             The LIID to stop consuming raw IP packets for
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int deregister_mediator_rawip_RMQ_consumer(amqp_connection_state_t state,
        char *liid) {

    char cc_queuename[1024];
    snprintf(cc_queuename, 1024, "%s-%s", liid, "rawip");

    return cancel_RMQ_consumer(state, cc_queuename, 4);
}

/** Consume (and potentially act upon) a non-standard frame seen by an
 *  RMQ consuming connection.
 *
 *  Such frames usually indicate that the connection is in an error state or
 *  communicate some information from the server back to the consumer.
 *
 *  @param state            The RMQ connection with a pending non-standard
 *                          message.
 *
 *  @return -1 if the connection has failed and needs to be reset, 0 otherwise.
 */
static int consume_other_frame(amqp_connection_state_t state) {
    amqp_frame_t frame;
    amqp_rpc_reply_t ret;

    if (AMQP_STATUS_OK != amqp_simple_wait_frame(state, &frame)) {
        return 0;
    }

    if (AMQP_FRAME_METHOD == frame.frame_type) {
        switch (frame.payload.method.id) {
            case AMQP_BASIC_ACK_METHOD:
                /* if we've turned publisher confirms on, and we've published a
                 * message here is a message being confirmed.
                 */
                return 0;
            case AMQP_BASIC_RETURN_METHOD:
                /* if a published message couldn't be routed and the mandatory
                 * flag was set this is what would be returned. The message then
                 * needs to be read.
                 */
                {
                    amqp_message_t message;
                    ret = amqp_read_message(state, frame.channel, &message, 0);
                    if (AMQP_RESPONSE_NORMAL != ret.reply_type) {
                        return -1;
                    }
                    amqp_destroy_message(&message);
                }
                return 0;

            case AMQP_CHANNEL_CLOSE_METHOD:
                /* a channel.close method happens when a channel exception
                 * occurs, this can happen by publishing to an exchange that
                 * doesn't exist for example.
                 *
                 * In this case you would need to open another channel,
                 * redeclare any queues that were declared auto-delete, and
                 * restart any consumers that were attached to the previous
                 * channel.
                 */
                return -1;

            case AMQP_CONNECTION_CLOSE_METHOD:
                /* a connection.close method happens when a connection exception
                 * occurs, this can happen by trying to use a channel that isn't
                 * open for example.
                 *
                 * In this case the whole connection must be restarted.
                 */
                return -1;

            default:
                return -1;
        }
    }
    /* If we get here, something really weird is going on -- usually this
     * means we've consumed the "method" portion of a message (i.e. the
     * first frame) without subsequently reading the header and body that
     * follow the method.
     *
     * Best way to resolve this is to reset the RMQ connection and try
     * again, hopefully without doing a partial message read next time.
     *
     * Note: this often happens if you mess around with
     * amqp_simple_wait_frame_noblock(), so don't do that unless you know
     * what you are doing.
     */

    return -1;
}

#define MAX_CONSUMER_REJECTIONS 10

/** Consumes messages from an internal RMQ connection and writes them into
 *  an export buffer.
 *
 *  @param state            The RMQ connection to consume messages from
 *  @param buf              The export buffer to write the messages into
 *  @param maxread          The maximum number of messages to read before
 *                          returning from this function
 *  @param channel          The channel to consume from
 *  @param last_deliv       The delivery tag of the most recent consumed
 *                          message (updated by this function)
 *  @param prependlength    Flag to indicate whether the message length
 *                          should be written into the export buffer ahead
 *                          of writing the message itself
 *
 *  @return -1 if an error occurs, -2 if the RMQ connection has timed out
 *          due to a heartbeat failure, 0 if no messages were consumed, or
 *          1 if at least one message was consumed successfully.
 */
static int consume_mediator_liid_messages(amqp_connection_state_t state,
        export_buffer_t *buf, int maxread, int channel, uint64_t *last_deliv,
        uint8_t prependlength) {

    int msgread = 0;
    int rejects = 0;
    struct timeval tv;
    uint32_t len;
    amqp_envelope_t envelope;
    amqp_rpc_reply_t ret;

    tv.tv_sec = 0;
    tv.tv_usec = 2500;

    if (state == NULL) {
        usleep(10000);
        return 0;
    }

    amqp_maybe_release_buffers(state);
    while (msgread < maxread) {
        /* Let the connection free any unused internal state / buffers */

        /* Grab the next message */
        ret = amqp_consume_message(state, &envelope, &tv, 0);
        if (ret.reply_type != AMQP_RESPONSE_NORMAL) {
            if (ret.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
                    ret.library_error == AMQP_STATUS_TIMEOUT) {
                /* No messages available */
                //usleep(10000);
                return (msgread > 0);
            }

            if (ret.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
                    ret.library_error == AMQP_STATUS_HEARTBEAT_TIMEOUT) {
                /* Connection has timed out because we didn't respond to
                 * a heartbeat in time?
                 */
                return -2;
            }

            if (ret.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
                    ret.library_error == AMQP_STATUS_UNEXPECTED_STATE) {
                /* Non-standard frame, probably an error or internal RMQ
                 * message.
                 */
                if (consume_other_frame(state) < 0) {
                    return -1;
                }
            } else {
                return -1;
            }
            amqp_destroy_envelope(&envelope);
            continue;
        }

        if (envelope.channel == 0) {
            /* Probably a heartbeat or some other internal admin message */
            amqp_destroy_envelope(&envelope);
            continue;
        }

        if (envelope.channel != channel) {
            /* Message has an unexpected channel, reject it. If we
             * have to reject too many messages, break out of the consuming
             * loop
             */
            if (amqp_basic_reject(state, envelope.channel,
                    envelope.delivery_tag, true) != 0) {
                return -1;
            }
            amqp_destroy_envelope(&envelope);
            rejects += 1;
            if (rejects >= MAX_CONSUMER_REJECTIONS) {
                return (msgread > 0);
            }
            continue;
        }

        msgread += 1;

        /* Raw IP messages need to be prepended with their length as we have
         * no other reliable indicator of their length in the message
         * itself.
         */
        if (prependlength) {
            len = envelope.message.body.len;
            if (append_etsipdu_to_buffer(buf, (uint8_t *)(&len),
                    sizeof(len), 0) == 0) {
                logger(LOG_INFO, "OpenLI Mediator: unable to enqueue ETSI PDU length into export buffer");
                return -1;
            }
        }

        if (append_etsipdu_to_buffer(buf, envelope.message.body.bytes,
                envelope.message.body.len, 0) == 0) {
            logger(LOG_INFO, "OpenLI Mediator: unable to enqueue ETSI PDU into export buffer");
            return -1;
        }

        *last_deliv = envelope.delivery_tag;
        amqp_destroy_envelope(&envelope);
    }

    return 1;
}

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
        export_buffer_t *buf, int maxread, uint64_t *last_deliv) {

    return consume_mediator_liid_messages(state, buf, maxread, 2, last_deliv,
            0);
}

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
        export_buffer_t *buf, int maxread, uint64_t *last_deliv) {

    return consume_mediator_liid_messages(state, buf, maxread, 3, last_deliv,
            0);
}

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
        export_buffer_t *buf, int maxread, uint64_t *last_deliv) {

    return consume_mediator_liid_messages(state, buf, maxread, 4, last_deliv,
            1);
}

/** Acknowledges messages for an RMQ connection, up to the provided
 *  delivery tag number.
 *
 *  @param state            The RMQ connection to acknowledge messages on
 *  @param deliv_tag        The delivery tag to acknowledge
 *  @param channel          The channel to apply the acknowledgement to
 *
 *  @return AMQP_STATUS_OK if the acknowledgement was successful, otherwise
 *          will return the corresponding AMQP error code
 */
static inline int ack_mediator_liid_messages(amqp_connection_state_t state,
        uint64_t deliv_tag, int channel) {

    int x;

    if (state == NULL) {
        return 0;
    }

    if ((x = amqp_basic_ack(state, channel, deliv_tag, 1)) != 0) {
        return x;
    }
    return 0;
}

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
        uint64_t deliv_tag) {
    return ack_mediator_liid_messages(state, deliv_tag, 2);
}

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
        uint64_t deliv_tag) {
    return ack_mediator_liid_messages(state, deliv_tag, 3);
}

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
        uint64_t deliv_tag) {
    return ack_mediator_liid_messages(state, deliv_tag, 4);
}

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
        char *liid) {

    char iri_queuename[1024];

    if (state == NULL || liid == NULL) {
        return 0;
    }
    snprintf(iri_queuename, 1024, "%s-%s", liid, "iri");

    if (declare_RMQ_queue(state, iri_queuename, 2) < 0) {
        return -1;
    }

    if (register_RMQ_consumer(state, iri_queuename, 2) < 0) {
        return -2;
    }

    return 1;

}

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
        char *liid) {

    char cc_queuename[1024];

    if (state == NULL || liid == NULL) {
        return 0;
    }
    snprintf(cc_queuename, 1024, "%s-%s", liid, "cc");

    if (declare_RMQ_queue(state, cc_queuename, 3) < 0) {
        return -1;
    }

    if (register_RMQ_consumer(state, cc_queuename, 3) < 0) {
        return -2;
    }

    return 1;

}

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
        char *liid) {

    char raw_queuename[1024];

    if (state == NULL || liid == NULL) {
        return 0;
    }
    snprintf(raw_queuename, 1024, "%s-%s", liid, "rawip");

    if (declare_RMQ_queue(state, raw_queuename, 4) < 0) {
        return -1;
    }

    if (register_RMQ_consumer(state, raw_queuename, 4) < 0) {
        return -2;
    }

    return 1;

}

/** Indicates whether the IRI queue for a given LIID is empty or not.
 *
 *  @param state            The RMQ connection to use to undertake the check
 *  @param liid             The LIID whose IRI queue needs to be checked
 *
 *  @return -1 if an error occurs, 0 if the queue is not empty or the
 *          parameters are invalid, 1 if the queue is empty.
 */
int check_empty_mediator_iri_RMQ(amqp_connection_state_t state, char *liid) {

    char iri_queuename[1024];

    if (state == NULL || liid == NULL) {
        return 0;
    }
    snprintf(iri_queuename, 1024, "%s-%s", liid, "iri");

    return is_RMQ_queue_empty(state, iri_queuename, 2);
}

/** Indicates whether the CC queue for a given LIID is empty or not.
 *
 *  @param state            The RMQ connection to use to undertake the check
 *  @param liid             The LIID whose CC queue needs to be checked
 *
 *  @return -1 if an error occurs, 0 if the queue is not empty or the
 *          parameters are invalid, 1 if the queue is empty.
 */
int check_empty_mediator_cc_RMQ(amqp_connection_state_t state, char *liid) {

    char cc_queuename[1024];

    if (state == NULL || liid == NULL) {
        return 0;
    }
    snprintf(cc_queuename, 1024, "%s-%s", liid, "cc");

    return is_RMQ_queue_empty(state, cc_queuename, 3);
}

/** Indicates whether the raw IP packet queue for a given LIID is empty or not.
 *
 *  @param state            The RMQ connection to use to undertake the check
 *  @param liid             The LIID whose raw IP queue needs to be checked
 *
 *  @return -1 if an error occurs, 0 if the queue is not empty or the
 *          parameters are invalid, 1 if the queue is empty.
 */
int check_empty_mediator_rawip_RMQ(amqp_connection_state_t state, char *liid) {

    char raw_queuename[1024];

    if (state == NULL || liid == NULL) {
        return 0;
    }
    snprintf(raw_queuename, 1024, "%s-%s", liid, "rawip");

    return is_RMQ_queue_empty(state, raw_queuename, 4);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
