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

#ifndef OPENLI_MEDIATOR_HANDOVER_H_
#define OPENLI_MEDIATOR_HANDOVER_H_

#include <libtrace/simple_circular_buffer.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "export_buffer.h"
#include "med_epoll.h"

enum {
    HANDOVER_HI2 = 2,
    HANDOVER_HI3 = 3,
};

typedef struct per_handover_state {
    export_buffer_t buf;
    libtrace_scb_t *incoming;
    int outenabled;
    uint32_t katimer_setsec;
    wandder_encoded_result_t *pending_ka;
    int64_t lastkaseq;
    wandder_encoder_t *encoder;
    wandder_etsispec_t *decoder;
    uint32_t kafreq;
    uint32_t kawait;
    pthread_mutex_t ho_mutex;
} per_handover_state_t;

typedef struct handover {
    char *ipstr;
    char *portstr;
    int handover_type;
    med_epoll_ev_t *outev;
    med_epoll_ev_t *aliveev;
    med_epoll_ev_t *aliverespev;
    per_handover_state_t *ho_state;
    uint8_t disconnect_msg;
} handover_t;

typedef struct handover_state {
    uint16_t next_handover_id;
    int epoll_fd;
    libtrace_list_t *agencies;
    pthread_mutex_t *agency_mutex;
    int halt_flag;
    pthread_t connectthread;
} handover_state_t;

typedef struct mediator_agency {
    char *agencyid;
    int awaitingconfirm;
    int disabled;
    int disabled_msg;
    handover_t *hi2;
    handover_t *hi3;
} mediator_agency_t;

/** Send some buffered ETSI records out via a handover.
 *
 *  If there is a keep alive message pending for this handover, that will
 *  be sent before sending any buffered records.
 *
 *  @param mev              The epoll event for the handover
 *
 *  @return -1 is an error occurs, 0 otherwise.
 */
int xmit_handover(med_epoll_ev_t *mev);

/** Disconnects a single mediator handover connection to an LEA.
 *
 *  Typically triggered when an LEA is withdrawn, becomes unresponsive,
 *  or fails a keep-alive test.
 *
 *  @param ho       The handover that is being disconnected.
 */
void disconnect_handover(handover_t *ho);

/** Disconnects and drops all known agencies
 *
 *  @param state        The global handover state for this mediator.
 */
void drop_all_agencies(handover_state_t *state);

/** Attempt to connect all handovers for all known agencies
 *
 *  @param state        The global handover state for this mediator
 */
void connect_agencies(handover_state_t *state);

/** Adds an agency to the known agency list.
 *
 *  If an agency with the same ID already exists, we update its handovers
 *  to match the details we just received.
 *
 *  If the agency was awaiting confirmation after a lost provisioner
 *  connection, it will be marked as confirmed.
 *
 *  @param state            The global handover state for the mediator
 *  @param agencyid         The agency to add to the list.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int enable_agency(handover_state_t *state, liagency_t *lea);

/** Disables a specific agency.
 *
 *  A disabled agency will have its handovers disconnected and they
 *  will not be reconnected until the provisioner announces the agency
 *  is valid again.
 *
 *  @param state            The global handover state for the mediator
 *  @param agencyid         The ID of the agency to be disabled, as a string.
 */
void withdraw_agency(handover_state_t *state, char *agencyid);

/** Modify a handover's epoll event to check if writing is possible.
 *
 *  If an error occurs, the handover will be disconnected.
 *
 *  @param ho               The handover to modify
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int enable_handover_writing(handover_t *ho);

/** Modify a handover's epoll event to NOT check if writing is possible.
 *
 *  If an error occurs, the handover will be disconnected.
 *
 *  @param ho               The handover to modify
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int disable_handover_writing(handover_t *ho);

/** Restarts the keep alive timer for a handover
 *
 *  @param ho           The handover to restart the keep alive timer for
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
int restart_handover_keepalive(handover_t *ho);

/** Receives and actions a message sent to the mediator over a handover
 *  (typically a keep alive response).
 *
 *  @param mev              The epoll event for the handover
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int receive_handover(med_epoll_ev_t *mev);

/** Finds an agency that matches a given ID in the agency list
 *
 *  @param state        The global handover state for the mediator
 *  @param id           A string containing the agency ID to search for
 *
 *  @return a pointer to the agency with the given ID, or NULL if no such
 *          agency is found.
 */
mediator_agency_t *lookup_agency(handover_state_t *state, char *id);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
