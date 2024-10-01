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

#ifndef OPENLI_MEDIATOR_HANDOVER_H_
#define OPENLI_MEDIATOR_HANDOVER_H_

#include <libtrace/simple_circular_buffer.h>
#include <libwandder.h>
#include <libwandder_etsili.h>
#include <amqp.h>

#include "export_buffer.h"
#include "med_epoll.h"
#include "liidmapping.h"

/** Possible handover types */
enum {
    /** HI2 -- used for transmiting IRIs and other "meta" messages */
    HANDOVER_HI2 = 2,

    /** HI3 -- used for transmitting CCs */
    HANDOVER_HI3 = 3,

    /** Raw IP -- OpenLI-specific handover for writing raw IP packets to
     *  pcap files on disk
     */
    HANDOVER_RAWIP = 4,
};

/** State that needs to be retained for each mediator handover */
typedef struct per_handover_state {
    /** A buffer for storing data queued for sending over the handover */
    export_buffer_t buf;

    /** A buffer for storing data received over the handover
     * (e.g. keepalives)
     */
    libtrace_scb_t *incoming;
    uint32_t katimer_setsec;
    wandder_encoded_result_t *pending_ka;
    int64_t lastkaseq;
    wandder_encoder_t *encoder;
    wandder_etsispec_t *decoder;
    uint32_t kafreq;
    uint32_t kawait;
    pthread_mutex_t ho_mutex;
    uint64_t next_rmq_ack;
    uint8_t valid_rmq_ack;
} per_handover_state_t;

typedef struct handover {
    char *ipstr;
    char *portstr;
    int handover_type;
    amqp_connection_state_t rmq_consumer;
    int amqp_log_failure;
    uint8_t rmq_registered;
    med_epoll_ev_t *outev;
    med_epoll_ev_t *aliveev;
    med_epoll_ev_t *aliverespev;
    per_handover_state_t *ho_state;
    uint8_t disconnect_msg;
} handover_t;

typedef struct mediator_agency {
    char *agencyid;
    char *agencycc;
    int awaitingconfirm;
    int disabled;
    int disabled_msg;
    handover_t *hi2;
    handover_t *hi3;
} mediator_agency_t;

/** Destroys the state for a particular agency entity, including its
 *  corresponding handovers
 *
 *  @param ag       The agency to be destroyed.
 */
void destroy_agency(mediator_agency_t *ag);

/** Sends a buffer of ETSI records out via a handover.
 *
 *  @param ho              The handover to send the records over
 *  @param maxsend         The maximum amount of data to send (in bytes)
 *
 *  @return -1 is an error occurs, 0 otherwise.
 */
int xmit_handover_records(handover_t *ho, uint32_t maxsend);

/** Sends any pending keep-alive message out via a handover.
 *
 *  @param ho              The handover to send the keep-alive over
 *
 *  @return -1 is an error occurs, 0 otherwise.
 */
int xmit_handover_keepalive(handover_t *ho);

/** React to a handover's failure to respond to a keep alive before the
 *  response timer expired.
 *
 *  @param ho              The handover that failed to reply to a KA message
 *
 */
void trigger_handover_ka_failure(handover_t *ho);

/** Creates and sends a keep-alive message over a handover
 *
 *  @param ho           The handover that needs to send a keep alive
 *  @param mediator_id  The ID of this mediator (to be included in the KA msg)
 *  @param operator_id  The operator ID string (to be included in the KA msg)
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
int trigger_handover_keepalive(handover_t *ho, uint32_t mediator_id,
        char *operator_id, char *agency_cc);

/** Disconnects a single mediator handover connection to an LEA.
 *
 *  Typically triggered when an LEA is withdrawn, becomes unresponsive,
 *  or fails a keep-alive test.
 *
 *  @param ho       The handover that is being disconnected.
 */
void disconnect_handover(handover_t *ho);

/** Receives and actions a message sent to the mediator over a handover
 *  (typically a keep alive response).
 *
 *  @param ho              The handover to receive the message on
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int receive_handover(handover_t *ho);

/* Creates a new instance of a handover.
 *
 * @param epoll_fd      The global epoll fd for the mediator.
 * @param ipstr         The IP address of the handover recipient (as a string).
 * @param portstr       The port that the handover recipient is listening on
 *                      (as a string).
 * @param handover_type Either HANDOVER_HI2 or HANDOVER_HI3, to indicate which
 *                      type of handover this is.
 * @param kafreq        The frequency to send keep alive requests (in seconds).
 * @param kawait        The time to wait before assuming a keep alive has
 *                      failed (in seconds).
 *
 * @return a pointer to a new handover instance, or NULL if an error occurs.
 */
handover_t *create_new_handover(int epoll_fd, char *ipstr, char *portstr,
        int handover_type, uint32_t kafreq, uint32_t kawait);

/** Establish an agency handover connection
 *
 *  The resulting socket will be added to the provided epoll event set as
 *  available for reading and writing.
 *
 *  This method also starts the keepalive timer for the handover, if
 *  keepalives are required.
 *
 *  @param ho           The handover object that is to be connected
 *  @param epoll_fd     The epoll fd to add handover events to
 *  @param ho_id        The unique ID number for this handover
 *
 *  @return -1 if the connection fails, 0 otherwise.
 */
int connect_mediator_handover(handover_t *ho, int epoll_fd, uint32_t ho_id);

/** Releases all memory associated with a single handover object.
 *
 *  @param ho       The handover object that is being destroyed
 */
void free_handover(handover_t *ho);

/** Creates an RMQ connection for consumption and registers it with
 *  the IRI or CC queues for each LIID that is to be exported via this
 *  handover.
 *
 *  @param ho       The handover to be registered with RMQ
 *  @param liidmap  The set of known LIIDs associated with this handover
 *  @param agencyid The name of the agency that this handover belongs to
 *  @param password The password to use to authenticate with RMQ
 *
 *  @return -1 if an error occurs during registration, 1 if all LIIDs
 *          are successfully registered.
 */
int register_handover_RMQ_all(handover_t *ho, liid_map_t *liidmap,
        char *agencyid, char *password);

/** Resets the RMQ state for a given handover.
 *
 *  This is typically used when an error occurs with the RMQ consumer for
 *  a handover, which will then force the handover to re-register its
 *  connection to the RMQ service.
 *
 *  @param ho       The handover to reset RMQ state for
 */
void reset_handover_rmq(handover_t *ho);

/** Checks if a handover's RMQ connection is still alive and error-free. If
 *  not, destroy the connection and reset it to NULL
 *
 *  @param ho       The handover which needs its RMQ connection checked.
 *  @param agencyid The name of the agency that the handover belongs to (for
 *                  logging purposes).
 *
 *  @return -1 if the RMQ connection was destroyed, 0 otherwise
 */
int check_handover_rmq_status(handover_t *ho, char *agencyid);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
