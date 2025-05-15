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

#ifndef OPENLI_MEDIATOR_LEA_SEND_THREAD_H
#define OPENLI_MEDIATOR_LEA_SEND_THREAD_H

#include <amqp.h>
#include <libtrace/message_queue.h>
#include "netcomms.h"
#include "openli_tls.h"
#include "med_epoll.h"
#include "handover.h"
#include "agency.h"
#include "liidmapping.h"


/** The code in this source file defines types and methods used by an
 *  "LEA send" thread for the OpenLI mediator.
 *  Each agency that is configured with the OpenLI provisioner will be
 *  handled using a separate instance of one of these threads.
 *
 *  The core functionality of an LEA send thread is to:
 *    - establish the handovers to the agency for both HI2 and HI3.
 *    - consume any IRIs or CCs for LIIDs that belong to the agency from
 *      their respective internal RMQ queue, placing them in an export
 *      buffer for the corresponding handover.
 *    - send data from the export buffer over the handover socket, when the
 *      LEA end is able to receive data.
 *    - send periodic keepalives on each handover, as required.
 */



/** Types of messages that can be sent to an LEA send thread by the main
 *  mediator thread
 */
enum {

    /** Disconnect and then re-connect the handovers for this agency */
    MED_LEA_MESSAGE_RECONNECT,

    /** Disconnect the handovers for this agency until further notice */
    MED_LEA_MESSAGE_DISCONNECT,

    /** Stop the thread for this agency as soon as possible */
    MED_LEA_MESSAGE_HALT,

    /** The configuration for the agency has changed, update accordingly */
    MED_LEA_MESSAGE_UPDATE_AGENCY,

    /** Disassociate an LIID with this agency */
    MED_LEA_MESSAGE_REMOVE_LIID,

    /** Announcement that an LIID has been associated with an agency */
    MED_LEA_MESSAGE_ADD_LIID,

    /** Shared configuration for the LEA send threads has changed, update
     *  local version accordingly
     */
    MED_LEA_MESSAGE_RELOAD_CONFIG,

    /** An HI1 notification message needs to be sent to this agency */
    MED_LEA_MESSAGE_SEND_HI1_NOTIFICATION,

    /** The provisioner has disconnected, so start a shutdown timer for this
     *  agency thread.
     */
    MED_LEA_MESSAGE_SHUTDOWN_TIMER,
};

/** Message structure for the LEA send threads */
typedef struct lea_thread_msg {
    /** The message type, defined by the enum above */
    int type;
    /** Additional data/context for the message -- actual type will vary
     *  depending on the message type.
     */
    void *data;

    uint64_t data_uint;
} lea_thread_msg_t;

/** Shared configuration for the LEA send threads -- all config values
 *  are derived from the mediator configuration file
 */
typedef struct mediator_lea_config {
    /** Pointer to the RMQ configuration for the mediator */
    openli_RMQ_config_t *rmqconf;

    /** The mediator ID number */
    uint32_t mediatorid;

    /** The operator ID for the mediator */
    char *operatorid;

    /** The abbreviated operator ID for the mediator */
    char *shortoperatorid;

    /** The compression level to use when writing pcap files */
    uint8_t pcap_compress_level;
    /** The template to use when deriving filenames for pcap files */
    char *pcap_outtemplate;
    /** The directory to write pcap files into */
    char *pcap_dir;
    /** The frequency (in minutes) to rotate pcap files */
    uint32_t pcap_rotate_frequency;

    /** A mutex to protect the shared config from race conditions */
    pthread_mutex_t mutex;
} mediator_lea_config_t;

/** The local per-thread state for an LEA send thread */
typedef struct lea_thread_state {
    /** The pthread id number for the thread */
    pthread_t tid;

    /** The ID number for HI2 for this agency (HI3 is this number + 1) */
    uint32_t handover_id;

    /** The epoll file descriptor */
    int epoll_fd;

    /** The agency state instance describing the agency and its handovers */
    mediator_agency_t agency;

    /** The full agency configuration as announced by the provisioner */
    liagency_t *lea;

    /** The set of LIIDs that are associated with the agency */
    liid_map_t active_liids;

    /** The mediator ID number */
    uint32_t mediator_id;

    /** The operator ID for this mediator */
    char *operator_id;
    /** The abbreviated operator ID for this mediator */
    char *short_operator_id;

    /** The compression level to use when writing pcap files */
    uint8_t pcap_compress_level;
    /** The template to use when deriving filenames for pcap files */
    char *pcap_outtemplate;
    /** The directory to write pcap files into */
    char *pcap_dir;
    /** The frequency (in minutes) to rotate pcap files */
    uint32_t pcap_rotate_frequency;

    /** The queue for messages from the main mediator thread */
    libtrace_message_queue_t in_main;

    /** The shared configuration for all LEA threads */
    mediator_lea_config_t *parentconfig;

    /** The password to use to authenticate against the internal RMQ vhost */
    char *internalrmqpass;
    /** The frequency at which this thread should perform RMQ maintenance
     *  tasks (in seconds)
     */
    int rmq_hb_freq;

    /** The ID string for this agency */
    char *agencyid;

    /** Mediator epoll event for the shutdown timer */
    med_epoll_ev_t *shutdown_wait;
    /** Mediator epoll event for the message queue checking timer */
    med_epoll_ev_t *timerev;
    /** Mediator epoll event for the RMQ maintenance timer */
    med_epoll_ev_t *rmqhb;
    /** Mediator epoll event for a timer to remove unconfirmed LIID mappings */
    med_epoll_ev_t *cleanse_liids;

    UT_hash_handle hh;

} lea_thread_state_t;

/** Structure to keep track of all LEA send threads within the main mediator
 *  thread.
 */
typedef struct mediator_leas {
    /** The set of active LEA send threads */
    lea_thread_state_t *threads;
    /** The shared configuration for the LEA send threads */
    mediator_lea_config_t config;
    /** The ID number to assign to the next newly created LEA handover */
    uint32_t next_handover_id;
} mediator_lea_t;

/** Functions called from the main mediator thread to start / manage LEA
 *  send threads.
 */

/** Initialises and starts a new LEA send thread
 *
 *  @param medleas          The set of LEA threads for this mediator.
 *  @param lea              The definition of the agency that the newly
 *                          created thread will be sending records to.
 *
 *  @return -1 if an error occurs, 1 if successful
 */
int mediator_start_agency_thread(mediator_lea_t *medleas, liagency_t *lea);

/** Sends an UPDATE AGENCY message to an LEA send thread.
 *
 *  @param thread           The state object for the LEA send thread that is
 *                          to receive the update agency message.
 *  @param lea              The updated definition of the agency that the
 *                          recipient thread corresponds to.
 *
 *  @return 0 always
 */
int mediator_update_agency_thread(lea_thread_state_t *thread, liagency_t *lea);

/** Halts an LEA send thread.
 *
 *  @param medleas          The set of LEA threads for this mediator.
 *  @param agencyid         The ID of the agency whose LEA send thread is to
 *                          be halted.
 */
void mediator_halt_agency_thread(mediator_lea_t *medleas, char *agencyid);

/** Halts the LEA send threads for ALL agencies
 *
 *  @param medleas          The set of LEA threads for this mediator.
 */
void mediator_disconnect_all_leas(mediator_lea_t *medleas);

/** Initialises the shared configuration for the LEA send threads
 *
 *  @param config           The shared configuration instance to be initialised
 *  @param rmqconf          The RMQ configuration for the mediator
 *  @param mediatorid       The ID number assigned to this mediator
 *  @param operatorid       The operator ID configured for this mediator
 *  @param shortopid        The short operator ID configured for this mediator
 *  @param pcapdir          The directory to write pcap files into
 *  @param pcaptemplate     The template to use when naming pcap files
 *  @param pcapcompress     The compression level to use when writing pcap files
 *  @param pcaprotate       The frequency to rotate pcap files, in minutes
 *
 */
void init_med_agency_config(mediator_lea_config_t *config,
        openli_RMQ_config_t *rmqconf, uint32_t mediatorid, char *operatorid,
        char *shortopid, char *pcapdir, char *pcaptemplate,
        uint8_t pcapcompress, uint32_t pcaprotate);

/** Updates the shared configuration for the LEA send threads with new values
 *
 *  @param config           The shared configuration instance to be updated
 *  @param mediatorid       The ID number assigned to this mediator
 *  @param operatorid       The operator ID configured for this mediator
 *  @param shortopid        The short operator ID configured for this mediator
 *  @param pcapdir          The directory to write pcap files into
 *  @param pcaptemplate     The template to use when naming pcap files
 *  @param pcapcompress     The compression level to use when writing pcap files
 *  @param pcaprotate       The frequency to rotate pcap files, in minutes
 *
 */
void update_med_agency_config(mediator_lea_config_t *config,
        uint32_t mediatorid, char *operatorid,
        char *shortopid, char *pcapdir, char *pcaptemplate,
        uint8_t pcapcompress, uint32_t pcaprotate);

/** Destroys the shared configuration for the LEA send threads.
 *
 *  @param config       The shared configuration instance to be destroyed
 */
void destroy_med_agency_config(mediator_lea_config_t *config);

/** Functions used by both LEA send threads and pcap threads */

/** Handle any outstanding heartbeats for this thread's RMQ connections and
 *  tidy up any unused RMQ internal queues.
 *
 *  Should be called periodically using a epoll timer event.
 *
 *  @param state        The state object for this LEA send thread
 *  @param mev          The mediator epoll timer event that fired to trigger
 *                      this function being called
 *
 *  @return 0 if the triggering timer is unable to be reset, 1 otherwise.
 */
int agency_thread_action_rmqcheck_timer(lea_thread_state_t *state,
        med_epoll_ev_t *mev);

/** Loops over the set of known LIIDs and withdraws any that have not been
 *  confirmed by the provisioner since it last (re-)connected.
 *
 *  Should be called via a epoll timer event set for some amount of time
 *  after a provisioner has re-connected to the main mediator thread.
 *
 *  @param state        The state object for this LEA send thread
 *
 *  @return 0 always
 */
int agency_thread_action_cease_liid_timer(lea_thread_state_t *state);

/** Updates local copies of configuration variables to match the shared
 *  version of the configuration managed by the main mediator thread.
 *
 *  @param state        The state object for the LEA send thread
 *  @return 1 if the RMQ internal password has changed (so all RMQ
 *          local connections should be restarted, 0 otherwise.

 */
int read_parent_config(lea_thread_state_t *state);

/** Declares and initialises the mediator epoll timer events that are
 *  used by an LEA send thread (or a pcap writer thread).
 *
 *  @param state        The state object for the LEA send thread
 *
 *  @return -1 if an error occurs, 1 otherwise
 */
int create_agency_thread_timers(lea_thread_state_t *state);

/** Tidy up the state object for an LEA send thread, freeing all allocated
 *  memory and closing any open sockets.
 *
 *  @param state        The state object for the LEA send thread
 */
void destroy_agency_thread_state(lea_thread_state_t *state);

/** Disables an LIID for an LEA send thread.
 *
 *  @param state        The state object for the LEA send thread
 *  @param liid         The LIID to disable
 *
 *  @return 1 if successful, 0 if the LIID was not in this thread's LIID set.
 */
int purge_lea_liid_mapping(lea_thread_state_t *state, char *liid);

/** Adds an LIID to the LIID set for an LEA send thread.
 *
 *  Also registers the corresponding RMQ internal queues with the agency
 *  handovers so records for that LIID will be consumed by this thread.
 *
 *  @param state        The state object for the LEA send thread
 *  @param liid         The LIID to associate with this agency
 *
 *  @return 1 if successful, 0 if the LIID was already in this thread's LIID
 *          set, -1 if an error occurs.
 */
int insert_lea_liid_mapping(lea_thread_state_t *state, char *liid);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
