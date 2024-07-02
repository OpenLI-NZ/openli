/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#include <unistd.h>
#include <assert.h>

#include "netcomms.h"
#include "util.h"
#include "logger.h"
#include "coll_recv_thread.h"
#include "lea_send_thread.h"
#include "mediator_rmq.h"
#include "med_epoll.h"

/** This file implements a "collector receive" thread for the OpenLI mediator.
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

/** Maximum amount of data (in bytes) to receive from a collector before
 *  returning to the main epoll loop
 */
#define MAX_COLL_RECV (10 * 1024 * 1024)

/** Period of inactivity before we decide to remove our internal state for
 *  an LIID queue declared on the local RabbitMQ instance -- if we see the
 *  LIID again after removal, we'll just re-declare the queue.
 *
 *  Note: the queue will NOT be deleted from RabbitMQ until the "x-expires"
 *  threshold for inactivity is reached. This is set when the queue is
 *  declared -- 30 mins is the original default I've set.
 */
#define LIID_QUEUE_EXPIRY_THRESH (10 * 60)

/** Initialises the shared configuration for the collectors managed by a
 *  mediator.
 *
 *  @param config       The global config for the collectors that is to be
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
        openli_RMQ_config_t *rmqconf, uint32_t mediatorid) {

    config->usingtls = usetls;
    config->sslconf = sslconf;
    config->rmqconf = rmqconf;
    config->parent_mediatorid = mediatorid;

    pthread_mutex_init(&(config->mutex), NULL);
}

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
        uint8_t usetls, uint32_t mediatorid) {

    pthread_mutex_lock(&(config->mutex));

    config->usingtls = usetls;
    config->parent_mediatorid = mediatorid;

    pthread_mutex_unlock(&(config->mutex));
}

/** Frees any resources allocated to the shared collector configuration.
 *
 *
 *  @param config       The global config to be destroyed
 */
void destroy_med_collector_config(mediator_collector_config_t *config) {
    pthread_mutex_destroy(&(config->mutex));
}

/** Grabs the mutex for the shared collector configuration to prevent
 *  any other threads from modifying it while we're reading it.
 *
 *  @param config       The global config to be locked
 */
void lock_med_collector_config(mediator_collector_config_t *config) {
    pthread_mutex_lock(&(config->mutex));
}

/** Releases the mutex for the shared collector configuration.
 *
 *  @param config       The global config to be unlocked
 */
void unlock_med_collector_config(mediator_collector_config_t *config) {
    pthread_mutex_unlock(&(config->mutex));
}

/** Removes any local state for LIIDs which our collector has not sent
 *  any data for recently.
 *
 *  @param col      The state object for this collector receive thread
 */
static void remove_expired_liid_queues(coll_recv_t *col) {
    col_known_liid_t *known, *tmp;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    HASH_ITER(hh, col->known_liids, known, tmp) {
        if (tv.tv_sec - known->lastseen < LIID_QUEUE_EXPIRY_THRESH) {
            /* Not expired yet, so redeclare the queue to keep rabbitmq
             * from deleting it accidentally */
            if (declare_mediator_liid_RMQ_queue(col->amqp_producer_state,
                    known->liid, known->liidlen,
                    &(col->rmq_blocked)) > 0) {
                known->declared_int_rmq = 1;
            }
            continue;
        }

        if (known->liid) {
            free(known->liid);
        }
        if (known->queuenames[0]) {
            free((void *)known->queuenames[0]);
        }
        if (known->queuenames[1]) {
            free((void *)known->queuenames[1]);
        }
        if (known->queuenames[2]) {
            free((void *)known->queuenames[2]);
        }
        HASH_DELETE(hh, col->known_liids, known);
        free(known);
    }
}

static void destroy_rmq_colev(coll_recv_t *col) {

    if (col->incoming_rmq) {
        destroy_net_buffer(col->incoming_rmq, col->amqp_state);
    }
    if (col->amqp_state) {
        amqp_destroy_connection(col->amqp_state);
    }
    remove_mediator_fdevent(col->rmq_colev);
    col->rmq_colev = NULL;
    col->amqp_state = NULL;
    col->incoming_rmq = NULL;
}

/** Perform the necessary setup to establish a TLS connection with the
 *  OpenLI collector that we are responsible for.
 *
 *  @param col      The state object for this collector receive thread
 *
 *  @return -1 if an error occurs, MED_EPOLL_COLLECTOR_HANDSHAKE if the
 *          connection is established but TLS handshake is incomplete,
 *          MED_EPOLL_COLLECTOR if the connection is established and the
 *          TLS handshake has completed.
 */
static int start_collector_ssl(coll_recv_t *col) {

    int r;

    lock_med_collector_config(col->parentconfig);
    r = listen_ssl_socket(col->parentconfig->sslconf, &col->ssl, col->col_fd);
    unlock_med_collector_config(col->parentconfig);

    if (r == OPENLI_SSL_CONNECT_FAILED) {
        close(col->col_fd);
        col->col_fd = -1;
        SSL_free(col->ssl);
        col->ssl = NULL;

        if (r != col->lastsslerror) {
            logger(LOG_INFO,
                    "OpenLI Mediator: SSL handshake failed for collector %s",
                    col->ipaddr);
        }

        col->lastsslerror = r;
        return -1;
    }

    col->using_tls = 1;
    if (r == OPENLI_SSL_CONNECT_WAITING) {
        return MED_EPOLL_COLLECTOR_HANDSHAKE;
    }
    col->lastsslerror = 0;
    return MED_EPOLL_COLLECTOR;
}

/** Connects to the RMQ queue for this mediator on the collector and
 *  (if successful) creates an epoll read event for the underlying TCP
 *  socket for the RMQ connection.
 *
 *  @param col          The state object for this collector receive thread
 *  @param epoll_fd     The epoll file descriptor to add the read event to
 *
 *  @return NULL if the RMQ connection cannot established or added to the
 *          epoll event list, otherwise returns a pointer to the mediator
 *          epoll event structure that was successfully created by this
 *          function.
 */
static med_epoll_ev_t *prepare_collector_receive_rmq(coll_recv_t *col,
        int epoll_fd) {

    med_epoll_ev_t *rmqev = NULL;
    int rmq_sock = -1;

    /* method defined in mediator_rmq.c -- establishes the RMQ connection */
    amqp_connection_state_t amqp_state = join_collector_RMQ(col);

    if (!amqp_state) {
        if (!col->disabled_log) {
            logger(LOG_INFO, "OpenLI Mediator: error while connecting to RMQ for collector %s", col->ipaddr);
        }
        col->disabled_log = 1;
        return NULL;
    }

    /* Get the file descriptor from the RMQ connection so we can listen to
     * it via epoll.
     */
    rmq_sock = amqp_get_sockfd(amqp_state);
    if (rmq_sock < 0) {
        if (!col->disabled_log) {
            logger(LOG_INFO, "OpenLI Mediator: bad socket returned by RMQ for collector %s", col->ipaddr);
        }
        col->disabled_log = 1;
        return NULL;
    }

    col->amqp_state = amqp_state;
    /* Create a net buffer for receiving data from the RMQ socket */
    col->incoming_rmq = create_net_buffer(NETBUF_RECV, 0, NULL);

    /* Create an epoll event and add it to our epoll FD set */
    rmqev = create_mediator_fdevent(epoll_fd, col, MED_EPOLL_COL_RMQ, rmq_sock,
            EPOLLIN | EPOLLRDHUP);
    if (rmqev == NULL) {
        if (!col->disabled_log) {
            logger(LOG_INFO,
                    "OpenLI Mediator: unable to add RMQ fd for collector %s to epoll: %s",
                    col->ipaddr, strerror(errno));
        }
        col->disabled_log = 1;
        close(rmq_sock);
        return NULL;
    }

    if (col->disabled_log == 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: joined RMQ on collector %s successfully",
                col->ipaddr);
    }
    return rmqev;
}

/** Creates an epoll read event for an existing TCP socket that is
 *  connected to the OpenLI collector forwarding thread.
 *
 *  @param col          The state object for this collector receive thread
 *  @param epoll_fd     The epoll file descriptor to add the read event to
 *
 *  @return NULL if the socket cannot be added to the
 *          epoll event list, otherwise returns a pointer to the mediator
 *          epoll event structure that was successfully created by this
 *          function.
 */
static med_epoll_ev_t *prepare_collector_receive_fd(coll_recv_t *col,
        int epoll_fd) {

    med_epoll_ev_t *colev = NULL;
    int fdtype;

    /* If we are supposed to be using TLS, establish a TLS session */
    if (col->parentconfig->usingtls) {
        fdtype = start_collector_ssl(col);
    } else {
        /* Otherwise, we can use the existing socket as is */
        fdtype = MED_EPOLL_COLLECTOR;
        col->using_tls = 0;
    }

    /* Create an epoll event and add it to our epoll FD set */
    colev = create_mediator_fdevent(epoll_fd, col, fdtype, col->col_fd,
            EPOLLIN | EPOLLRDHUP);
    if (colev == NULL && col->disabled_log == 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: unable to add collector fd to epoll: %s",
                strerror(errno));
        col->disabled_log = 1;
        close(col->col_fd);
        col->col_fd = -1;
        return NULL;
    }

    /* Create a net buffer for receiving data from the TCP socket */
    if (col->incoming) {
        destroy_net_buffer(col->incoming, NULL);
    }
    col->incoming = create_net_buffer(NETBUF_RECV, col->col_fd,
            col->ssl);

    if (col->disabled_log == 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: accepted connection from collector %s.",
                col->ipaddr);
    }
    return colev;
}

/** Completes a partially-established TLS handshake on the TCP socket that
 *  connects this thread to the collector.
 *
 *  @param col          The state object for this collector receive thread
 *  @param mev          The mediator epoll event for the TCP socket
 *
 *  @return -1 if an error occurs, 0 if the handshake remains incomplete, 1
 *          if the handshake is now complete
 */
static int continue_collector_handshake(coll_recv_t *col, med_epoll_ev_t *mev) {

    int ret = SSL_accept(col->ssl);

    if (ret <= 0) {
        ret = SSL_get_error(col->ssl, ret);
        if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) {
            /* Not fatal -- can keep trying */
            return 0;
        } else {
            logger(LOG_INFO, "OpenLI Mediator: Pending SSL handshake for collector %s failed", col->ipaddr);
            return -1;
        }
    }
    logger(LOG_INFO, "OpenLI Mediator: Pending SSL handshake for collector %s completed", col->ipaddr);
    col->lastsslerror = 0;
    mev->fdtype = MED_EPOLL_COLLECTOR;

    /* If we're meant to be reading records from RMQ, then we are now
     * ready to set that event up too.
     */
    if (col->rmqenabled && col->rmq_colev == NULL) {
        col->rmq_colev = prepare_collector_receive_rmq(col, mev->epoll_fd);
    }
    return 1;
}

static void increment_col_drop_counter(coll_recv_t *col) {

    col->dropped_recs ++;
    if (col->dropped_recs == 10 || col->dropped_recs % 1000 == 0) {
        logger(LOG_INFO,
                "OpenLI mediator: dropped %lu records from collector %s so far",
                col->dropped_recs, col->ipaddr);
    }
}

/** Processes an intercept record received from a collector and inserts
 *  it into the appropriate mediator-internal LIID queue.
 *
 *  @param col      The state object for this collector receive thread
 *  @param msgbody  A pointer to the start of the received record
 *  @param msglen   The length of the received record, in bytes
 *  @param msgtype  The record type (e.g. CC, IRI, etc).
 *
 *  @return 1 if the record is processed successfully, 0 if an error
 *          occurs.
 */
static int process_received_data(coll_recv_t *col, uint8_t *msgbody,
        uint16_t msglen, openli_proto_msgtype_t msgtype) {

    unsigned char liidstr[65536];
    uint16_t liidlen;
    col_known_liid_t *found;
    struct timeval tv;
    int r;

    /* The queue that this record must be published to is derived from
     * the LIID for the record and the record type
     */
    extract_liid_from_exported_msg(msgbody, msglen, liidstr, 65536, &liidlen);

    if (liidlen > 2) {
        liidlen -= 2;
    } else {
        return 0;
    }

    if (col->disabled_log) {
        col->disabled_log = 0;
    }

    HASH_FIND(hh, col->known_liids, liidstr, liidlen, found);
    if (!found) {
        char qname[1024];
        /* This is an LIID that we haven't seen before (or recently), so
         * make sure we have a set of internal mediator RMQ queues for it.
         */
        found = (col_known_liid_t *)calloc(1, sizeof(col_known_liid_t));
        found->liid = strdup((const char *)liidstr);
        found->liidlen = strlen(found->liid);
        found->lastseen = 0;
        found->declared_raw_rmq = 0;
        found->declared_int_rmq = 0;

        snprintf(qname, 1024, "%s-iri", found->liid);
        found->queuenames[0] = strdup(qname);
        snprintf(qname, 1024, "%s-cc", found->liid);
        found->queuenames[1] = strdup(qname);
        snprintf(qname, 1024, "%s-rawip", found->liid);
        found->queuenames[2] = strdup(qname);

        HASH_ADD_KEYPTR(hh, col->known_liids, found->liid, found->liidlen,
                found);
        logger(LOG_INFO, "OpenLI Mediator: LIID %s has been seen coming from collector %s", found->liid, col->ipaddr);

    }

    if (found->declared_int_rmq == 0) {
        /* declare amqp queue for this LIID */
        r = declare_mediator_liid_RMQ_queue(col->amqp_producer_state,
                    found->liid, found->liidlen, &(col->rmq_blocked));
        if (r < 0) {
            logger(LOG_INFO, "OpenLI Mediator: failed to create internal RMQ queues for LIID %s in collector thread %s", found->liid, col->ipaddr);
            return -1;
        }
        if (r > 0) {
            found->declared_int_rmq = 1;
        }
    }

    gettimeofday(&tv, NULL);
    found->lastseen = tv.tv_sec;

    /* Hand off to publishing methods defined in mediator_rmq.c */
    if (msgtype == OPENLI_PROTO_ETSI_CC) {
        if (found->declared_int_rmq) {
            r = publish_cc_on_mediator_liid_RMQ_queue(col->amqp_producer_state,
                    msgbody + (liidlen + 2), msglen - (liidlen + 2),
                    found->liid, found->queuenames[1], &(col->rmq_blocked));
            if (r <= 0) {
                increment_col_drop_counter(col);
            }
            if (r < 0) {
                amqp_destroy_connection(col->amqp_producer_state);
                col->amqp_producer_state = NULL;
            }
        } else {
            increment_col_drop_counter(col);
            r = 0;
        }
        return r;
    }

    if (msgtype == OPENLI_PROTO_ETSI_IRI) {
        if (found->declared_int_rmq) {
            r = publish_iri_on_mediator_liid_RMQ_queue(
                    col->amqp_producer_state,
                    msgbody + (liidlen + 2), msglen - (liidlen + 2),
                    found->liid, found->queuenames[0], &(col->rmq_blocked));
            if (r <= 0) {
                increment_col_drop_counter(col);
            }
            if (r < 0) {
                amqp_destroy_connection(col->amqp_producer_state);
                col->amqp_producer_state = NULL;
            }
        } else {
            increment_col_drop_counter(col);
            r = 0;
        }
        return r;
    }

    if (msgtype == OPENLI_PROTO_RAWIP_SYNC ||
            msgtype == OPENLI_PROTO_RAWIP_CC ||
            msgtype == OPENLI_PROTO_RAWIP_IRI) {

        /* declare a queue for raw IP */
        if (!found->declared_raw_rmq) {
            r = declare_mediator_rawip_RMQ_queue(col->amqp_producer_state,
                    found->liid, found->liidlen, &(col->rmq_blocked));
            if (r < 0) {
                return -1;
            } else if (r > 0) {
                found->declared_raw_rmq = 1;
            }
        }
        /* publish to raw IP queue */
        if (found->declared_raw_rmq) {
            r = publish_rawip_on_mediator_liid_RMQ_queue(
                    col->amqp_producer_state, msgbody, msglen, found->liid,
                    found->queuenames[2], &(col->rmq_blocked));
            if (r <= 0) {
                increment_col_drop_counter(col);
            }
            if (r < 0) {
                amqp_destroy_connection(col->amqp_producer_state);
                col->amqp_producer_state = NULL;
            }
        } else {
            increment_col_drop_counter(col);
            r = 0;
        }
        return r;
    }

    return 1;
}

/** Reads and processes a message from the collector that this thread
 *  is responsible for.
 *
 *  @param col      The state object for this collector receive thread
 *  @param mev      The epoll event for the connection to the collector
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
static int receive_collector(coll_recv_t *col, med_epoll_ev_t *mev) {

    uint8_t *msgbody = NULL;
    uint16_t msglen = 0;
    uint64_t internalid;
    int total_recvd = 0;
    openli_proto_msgtype_t msgtype;

    /* An epoll read event fired for our collector connection, so there
     * should be at least one message for us to read.
     */
    do {
        /* Read the next available message -- see netcomms.c for the
         * implementation of these methods */
        if (mev->fdtype == MED_EPOLL_COL_RMQ) {
            msgtype = receive_RMQ_buffer(col->incoming_rmq, col->amqp_state,
                    &msgbody, &msglen, &internalid);
        } else {
            msgtype = receive_net_buffer(col->incoming, &msgbody,
                        &msglen, &internalid);
        }

        if (msgtype < 0) {
            if (col->disabled_log == 0) {
                nb_log_receive_error(msgtype);
                logger(LOG_INFO, "OpenLI Mediator: error receiving message from collector %s.", col->ipaddr);
            }
            return -1;
        }

        total_recvd += msglen;
        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                if (col->disabled_log == 0) {
                    logger(LOG_INFO, "OpenLI Mediator: received disconnect message from collector %s", col->ipaddr);
                }
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
            case OPENLI_PROTO_HEARTBEAT:
                /* Heartbeats are periodically sent to ensure that RMQ doesn't
                 * kill our connection for being too idle -- they don't
                 * serve any actual messaging purpose so we can just read them
                 * and discard them.
                 */
                break;
            case OPENLI_PROTO_RAWIP_SYNC:
            case OPENLI_PROTO_RAWIP_CC:
            case OPENLI_PROTO_RAWIP_IRI:
            case OPENLI_PROTO_ETSI_CC:
            case OPENLI_PROTO_ETSI_IRI:
                /* Intercept record -- process it appropriately */
                if (process_received_data(col, msgbody, msglen, msgtype) < 0) {
                    return -1;
                }
                break;
            default:
                /* Unexpected message type, probably OK to just ignore... */
                break;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE && total_recvd < MAX_COLL_RECV);

    /* We use a cap of MAX_COLL_RECV bytes per receive method call so that
     * we can periodically go back and check for "halt" messages etc. even
     * when the receive socket is getting hammered.
     */

    return 0;

}

/** Handler method for any file descriptors or timers that are reported as
 *  "ready" by epoll.
 *
 * @param col       The state object for this collector receive thread
 * @param ev        The generic epoll event for the fd or timer that is ready
 *
 * @return -1 if an error occurs, 0 otherwise.
 */
static int collector_thread_epoll_event(coll_recv_t *col,
        struct epoll_event *ev) {

    med_epoll_ev_t *mev = (med_epoll_ev_t *)(ev->data.ptr);
    int ret = 0;

    switch(mev->fdtype) {
        case MED_EPOLL_SIGCHECK_TIMER:
            /* Time to check for control messages -- fires once per second */
            if (ev->events & EPOLLIN) {
                ret = 1;
            } else {
                logger(LOG_INFO,
                        "OpenLI Mediator: main epoll timer has failed in collector thread for %s",
                        col->ipaddr);
                ret = -1;
            }
            break;
        case MED_EPOLL_QUEUE_EXPIRE_TIMER:
            /* Time to purge any state for inactive LIIDs */
            halt_mediator_timer(mev);

            remove_expired_liid_queues(col);

            if (start_mediator_timer(mev, 120) < 0) {
                logger(LOG_INFO, "OpenLI Mediator: unable to reset queue expiry timer in collector thread for %s: %s", col->ipaddr, strerror(errno));
                ret =  -1;
            } else {
                ret = 1;
            }
            break;

        case MED_EPOLL_COLLECTOR_HANDSHAKE:
            /* A socket with an incomplete SSL handshake is active -- try
             * to complete the handshake.
             */
            ret = continue_collector_handshake(col, mev);
            if (ret == -1) {
                return -1;
            }
            break;
        case MED_EPOLL_COLLECTOR:
        case MED_EPOLL_COL_RMQ:
            /* Data is readable from our collector socket / RMQ */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                ret = receive_collector(col, mev);
            }
            break;
        default:
            logger(LOG_INFO,
                    "OpenLI Mediator: invalid epoll event type %d seen in collector thread for %s", mev->fdtype, col->ipaddr);
            ret = -1;

    }
    return ret;
}

/** Destroys the state for a collector receive thread and frees any
 *  allocated memory.
 *
 *  @param col      The state object for this collector receive thread
 */
static void cleanup_collector_thread(coll_recv_t *col) {
    col_known_liid_t *known, *tmp;

    if (col->colev) {
        remove_mediator_fdevent(col->colev);
    }
    if (col->incoming) {
        destroy_net_buffer(col->incoming, NULL);
    }
    if (col->amqp_producer_state) {
        amqp_destroy_connection(col->amqp_producer_state);
    }

    destroy_rmq_colev(col);
    if (col->ssl) {
        SSL_free(col->ssl);
    }

    if (col->internalpass) {
        free(col->internalpass);
    }
    HASH_ITER(hh, col->known_liids, known, tmp) {
        if (known->liid) {
            free(known->liid);
        }
        if (known->queuenames[0]) {
            free((void *)known->queuenames[0]);
        }
        if (known->queuenames[1]) {
            free((void *)known->queuenames[1]);
        }
        if (known->queuenames[2]) {
            free((void *)known->queuenames[2]);
        }
        HASH_DELETE(hh, col->known_liids, known);
        free(known);
    }

    if (col->ipaddr) {
        logger(LOG_INFO, "OpenLI mediator: exiting collector thread for %s",
                col->ipaddr);
        logger(LOG_INFO,
                "OpenLI mediator: dropped %lu records from collector %s",
                col->dropped_recs, col->ipaddr);

        free(col->ipaddr);
    }

}

/** pthread_create() callback to start a collector receive thread
 *
 *  @param params       The state object for this collector receive thread (as
 *                      a void pointer)
 *
 *  @return NULL when the thread exits
 */
static void *start_collector_thread(void *params) {

    coll_recv_t *col = (coll_recv_t *)params;
    int is_halted = 0, i;
    col_thread_msg_t msg;
    int epoll_fd = -1, timerexpired, nfds;
    med_epoll_ev_t *timerev, *queuecheck = NULL;
    struct epoll_event evs[64];

    if (col->ipaddr == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: started collector thread for NULL collector IP??");
        pthread_exit(NULL);
    }

    /* Save frequently read fields from parent config so we don't have to
     * lock it frequently for reading. We'll get a RELOAD message when
     * we need to check if these values may have changed.
     */
    lock_med_collector_config(col->parentconfig);
    if (col->parentconfig->rmqconf) {
        col->rmq_hb_freq = col->parentconfig->rmqconf->heartbeatFreq;
        col->rmqenabled = col->parentconfig->rmqconf->enabled;
        col->internalpass = strdup(col->parentconfig->rmqconf->internalpass);
    }
    unlock_med_collector_config(col->parentconfig);

    epoll_fd = epoll_create1(0);

    timerev = col->colev = col->rmq_colev = NULL;
    col->incoming = NULL;

    logger(LOG_INFO, "OpenLI Mediator: starting collector thread for %s",
            col->ipaddr);

    /* timerev is used to regularly break from epoll_wait() so we can check
     * for incoming messages on our control socket.
     */
    timerev = create_mediator_timer(epoll_fd, NULL, MED_EPOLL_SIGCHECK_TIMER, 0);
    if (timerev == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: failed to create main loop timer in collector thread for %s", col->ipaddr);
        goto threadexit;
    }

    queuecheck = create_mediator_timer(epoll_fd, NULL,
            MED_EPOLL_QUEUE_EXPIRE_TIMER, 60);

    while (!is_halted) {

        /* Check for messages on the control socket */
        if (libtrace_message_queue_try_get(&(col->in_main), (void *)&msg) !=
                LIBTRACE_MQ_FAILED) {

            if (msg.type == MED_COLL_MESSAGE_HALT) {
                /* Parent thread has told us to exit asap */
                is_halted = 1;
                continue;
            }

            if (msg.type == MED_COLL_MESSAGE_RELOAD) {
                /* Parent thread has reloaded the shared configuration, so
                 * we need to update our local copies of these values.
                 */
                lock_med_collector_config(col->parentconfig);

                /* Stop using RMQ if it has been disabled */
                if (col->parentconfig->rmqconf->enabled == 0 &&
                        col->rmqenabled == 1) {
                    destroy_rmq_colev(col);
                }

                /* TODO handle change in mediator ID ? */

                if (strcmp(col->internalpass,
                        col->parentconfig->rmqconf->internalpass) != 0) {

                    if (col->internalpass) {
                        free(col->internalpass);
                    }
                    if (col->parentconfig->rmqconf->internalpass) {
                        col->internalpass =
                            strdup(col->parentconfig->rmqconf->internalpass);
                    }
                    /* Need to reconnect to RMQ */
                    destroy_rmq_colev(col);
                }

                /* If our FD socket has changed TLS status, we should
                 * disconnect the current session and reconnect using
                 * the new TLS status.
                 */
                if (col->using_tls != col->parentconfig->usingtls) {
                    if (col->colev) {
                        remove_mediator_fdevent(col->colev);
                        col->colev = NULL;
                    }
                }

                /* re-save rmqconf->heartbeat */
                col->rmq_hb_freq = col->parentconfig->rmqconf->heartbeatFreq;
                col->rmqenabled = col->parentconfig->rmqconf->enabled;

                unlock_med_collector_config(col->parentconfig);

            }

            if (msg.type == MED_COLL_MESSAGE_DISCONNECT) {
                /* A configuration change means that we need to disconnect
                 * from the collector.
                 */
                if (col->colev) {
                    remove_mediator_fdevent(col->colev);
                    col->colev = NULL;
                }
                if (col->rmq_colev) {
                    destroy_rmq_colev(col);
                }
                /* Disable logging until the collector starts working
                 * properly again to avoid spamming connection failure
                 * messages if the collector is down for a long time.
                 */
                col->was_dropped = 1;
                col->disabled_log = 1;
            }

            if (msg.type == MED_COLL_MESSAGE_RECONNECT) {
                /* A collector has reconnected, so we need to shift our
                 * epoll events to the new socket.
                 */
                if (col->colev) {
                    remove_mediator_fdevent(col->colev);
                    col->colev = NULL;
                }
                if (col->rmq_colev) {
                    destroy_rmq_colev(col);
                }
                col->col_fd = (int)msg.arg;
                col->was_dropped = 0;
            }

        }

        if (col->was_dropped) {
            usleep(100000);
            continue;
        }

        /* Prepare our local RMQ state for emitting records for the LEA
         * threads to consume.
         */
        if (col->amqp_producer_state == NULL) {
            if (join_mediator_RMQ_as_producer(col) == NULL) {
                col->disabled_log = 1;
                continue;
            }
        }

        /* If we don't have epoll events for this collector AND the
         * collector is actually connected to us, then make some
         * epoll events for both the plain socket and RMQ (if enabled).
         */
        if (col->colev == NULL && col->col_fd != -1) {
            col->colev = prepare_collector_receive_fd(col, epoll_fd);
        }

        if (col->colev && col->colev->fdtype == MED_EPOLL_COLLECTOR &&
                col->rmqenabled && col->rmq_colev == NULL) {
            col->rmq_colev = prepare_collector_receive_rmq(col, epoll_fd);
        }

        /* Start our timer to break out and check for control messages once
         * per second.
         */
        if (start_mediator_timer(timerev, 1) < 0) {
            logger(LOG_INFO, "OpenLI Mediator: failed to add timer to epoll in collector thread for %s", col->ipaddr);
            break;
        }

        timerexpired = 0;
        while (!timerexpired && !is_halted) {
            /* See if there is any activity on any of our timers or fds */
            nfds = epoll_wait(epoll_fd, evs, 64, -1);
            if (nfds < 0) {
                if (errno == EINTR) {
                    continue;
                }
                logger(LOG_INFO, "OpenLI Mediator: error while waiting for epoll events in collector thread for %s: %s", col->ipaddr, strerror(errno));
                is_halted = true;
                continue;
            }

            for (i = 0; i < nfds; i++) {
                timerexpired = collector_thread_epoll_event(col, &(evs[i]));
                if (timerexpired == -1) {
                    /* We're in an error state -- disable this thread for now */
                    if (col->colev) {
                        remove_mediator_fdevent(col->colev);
                        col->colev = NULL;
                    }
                    if (col->rmq_colev) {
                        destroy_rmq_colev(col);
                    }
                    if (col->disabled_log == 0) {
                        logger(LOG_INFO, "OpenLI Mediator: collector thread for %s is now inactive", col->ipaddr);
                    }
                    col->was_dropped = 1;
                    col->disabled_log = 1;
                    break;
                }
            }
        }
        /* If we get here, the message timer expired -- loop around and
         * check for new messages.
         */
        halt_mediator_timer(timerev);
    }

threadexit:

    destroy_mediator_timer(queuecheck);
    destroy_mediator_timer(timerev);
    cleanup_collector_thread(col);

    close(epoll_fd);
    pthread_exit(NULL);

}

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
        int listenfd) {
    int newfd = -1;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    coll_recv_t *newcol = NULL;
    mediator_collector_config_t *config = &(medcol->config);

    /* Standard socket connection accept code... */
    newfd = accept(listenfd, (struct sockaddr *)&saddr, &socklen);
    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
                0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_INFO, "OpenLI Mediator: getnameinfo error in mediator: %s.",
                strerror(errno));
    }

    if (newfd < 0) {
        return newfd;
    }

    HASH_FIND(hh, medcol->threads, strbuf, strlen(strbuf), newcol);

    if (newcol == NULL) {
        /* Never seen a connection from this collector before, so spawn
         * a new receive thread for it.
         */
        newcol = (coll_recv_t *)calloc(1, sizeof(coll_recv_t));
        newcol->parentconfig = config;

        newcol->ipaddr = strdup(strbuf);
        newcol->iplen = strlen(strbuf);
        newcol->col_fd = newfd;
        newcol->rmq_blocked = 0;

        HASH_ADD_KEYPTR(hh, medcol->threads, newcol->ipaddr, newcol->iplen,
                newcol);

        libtrace_message_queue_init(&(newcol->in_main),
                sizeof(col_thread_msg_t));
        pthread_create(&(newcol->tid), NULL, start_collector_thread, newcol);
    } else {
        /* We've already got a thread for this collector (?), so swap over to
         * using the new file descriptor as the old one is probably dead
         */
        col_thread_msg_t reconn_msg;
        reconn_msg.type = MED_COLL_MESSAGE_RECONNECT;
        reconn_msg.arg = newfd;
        libtrace_message_queue_put(&(newcol->in_main), &reconn_msg);
    }

    return newfd;
}

/** Halts all collector receive threads and waits for the threads to
 *  terminate.
 *
 *  @param medcol       The shared state for all collector receive threads
 */
void mediator_disconnect_all_collectors(mediator_collector_t *medcol) {

    coll_recv_t *col, *tmp;

    /* Send a halt message to all known threads, then use pthread_join() to
     * block until each thread exits.
     */
    HASH_ITER(hh, medcol->threads, col, tmp) {
        col_thread_msg_t end_msg;
        end_msg.type = MED_COLL_MESSAGE_HALT;
        end_msg.arg = 0;
        libtrace_message_queue_put(&(col->in_main), &end_msg);

        pthread_join(col->tid, NULL);
        libtrace_message_queue_destroy(&(col->in_main));
        HASH_DELETE(hh, medcol->threads, col);
        free(col);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
