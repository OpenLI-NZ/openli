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

#ifndef OPENLI_MEDIATOR_PCAPTHREAD_H_
#define OPENLI_MEDIATOR_PCAPTHREAD_H_

#include <libtrace.h>
#include <libtrace/message_queue.h>
#include <libwandder_etsili.h>
#include <uthash.h>

#include "lea_send_thread.h"
#include "export_buffer.h"

/** State for a particular intercept that is being written to pcap files */
typedef struct active_pcap_output {
    /** The LIID for the intercept that is being written as pcap */
    char *liid;

    /** The libtrace output file handle for the output file */
    libtrace_out_t *out;

    /** The number of packets written to the open file so far */
    int pktwritten;

    UT_hash_handle hh;
} active_pcap_output_t;

/** Pcap-specific state for the pcap thread */
typedef struct pcap_thread_state {

    /** The queue which this thread will receive messages from the mediator */
    libtrace_message_queue_t *inqueue;

    /** A dummy libtrace instance, required for packet instance creation */
    libtrace_t *dummypcap;

    /** A libtrace packet used to convert raw IP blobs into a usable packet */
    libtrace_packet_t *packet;

    /** A map of open pcap outputs, one per LIID */
    active_pcap_output_t *active;

    /** A flag that indicates whether we have logged an error due to there
     *  being no valid directory configured to write pcaps into
     */
    int dirwarned;

    /** A libwandder decoder for converting ETSI-encoded packets into pcap
     *  formatted packets.
     */
    wandder_etsispec_t *decoder;

    /** A dedicated handover instance used for receiving raw IP packets over
     *  RabbitMQ
     */
    handover_t *rawip_handover;

} pcap_thread_state_t;

/** Creates and starts the pcap output thread for an OpenLI mediator.
 *
 *  The pcap thread is treated as another LEA send thread by the mediator,
 *  so it will be added to the set of LEA send threads maintained by the
 *  main mediator thread.
 *
 *  @param medleas          The list of LEA send threads for the mediator
 *
 *  @return 1 always.
 */
int mediator_start_pcap_thread(mediator_lea_t *medleas);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
