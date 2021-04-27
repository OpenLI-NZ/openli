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

#ifndef OPENLI_MEDIATOR_PCAPTHREAD_H_
#define OPENLI_MEDIATOR_PCAPTHREAD_H_

#include <libtrace.h>
#include <libtrace/message_queue.h>
#include <libwandder_etsili.h>
#include <uthash.h>

/** State for a particular pcap output file */
typedef struct active_pcap_output {
    /** The LIID for the intercept that is being written to this file */
    char *liid;

    /** The libtrace output file handle for the output file */
    libtrace_out_t *out;

    /** The number of packets written to this file so far */
    int pktwritten;

    UT_hash_handle hh;
} active_pcap_output_t;

/** State for the pcap thread */
typedef struct pcap_thread_state {

    /** The queue which this thread will receive messages from the mediator */
    libtrace_message_queue_t *inqueue;

    /** A libtrace packet used to convert raw IP blobs into a usable packet */
    libtrace_packet_t *packet;

    /** A map of open pcap outputs, one per LIID */
    active_pcap_output_t *active;

    /** The directory where pcap file are to be written into */
    char *dir;

    /** The template that is used to name the pcap files */
    char *outtemplate;

    /** The compression level to use when writing pcap files */
    uint8_t compresslevel;

    /** A flag that indicates whether we have logged an error due to there
     *  being no valid directory configured to write pcaps into
     */
    int dirwarned;

    /** A libwandder decoder for converting ETSI-encoded packets into pcap
     *  formatted packets.
     */
    wandder_etsispec_t *decoder;

} pcap_thread_state_t;

/** Simple wrapper structure for a message sent to the pcap thread */
typedef struct mediator_pcap_message {

    /** The message type (see enum below for possible values) */
    uint8_t msgtype;

    /** Pointer to the message body (e.g. the packet to be written) */
    uint8_t *msgbody;

    /** Length of the msgbody, in bytes */
    uint16_t msglen;
} mediator_pcap_msg_t;

/** Types of messages that can be sent to a pcap thread */
enum {
    /** Changes the directory where pcap files are written into */
    PCAP_MESSAGE_CHANGE_DIR,

    /** Tells the pcap thread to exit */
    PCAP_MESSAGE_HALT,

    /** Message contains an encoded ETSI record to be written as pcap */
    PCAP_MESSAGE_PACKET,

    /** Tells the pcap thread to flush any buffered output to disk */
    PCAP_MESSAGE_FLUSH,

    /** Triggers a rotation of all active pcap files */
    PCAP_MESSAGE_ROTATE,

    /** Message contains a raw IP packet to be written as pcap */
    PCAP_MESSAGE_RAWIP,

    /** Changes the template used to name pcap files */
    PCAP_MESSAGE_CHANGE_TEMPLATE,

    /** Changes the compression level used when writing pcap files */
    PCAP_MESSAGE_CHANGE_COMPRESS,

    /** Removes an LIID from the set of active pcap outputs */
    PCAP_MESSAGE_DISABLE_LIID,
};


/** Starts the pcap file writing thread, which will listen on a queue for
 *  messages containing packets that will be written to pcap output files
 *  (as opposed to being emitted via an ETSI handover).
 *
 *  @param params       A pointer to the libtrace message queue that the
 *                      packets for pcap export will be sent to by the main
 *                      thread.
 */
void *start_pcap_thread(void *params);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
