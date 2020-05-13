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

typedef struct active_pcap_output {
    char *liid;
    libtrace_out_t *out;
    int pktwritten;

    UT_hash_handle hh;
} active_pcap_output_t;

typedef struct pcap_thread_state {

    libtrace_message_queue_t *inqueue;
    libtrace_packet_t *packet;
    active_pcap_output_t *active;
    char *dir;
    int dirwarned;
    wandder_etsispec_t *decoder;

} pcap_thread_state_t;

typedef struct mediator_pcap_message {
    uint8_t msgtype;
    uint8_t *msgbody;
    uint16_t msglen;
} mediator_pcap_msg_t;

enum {
    PCAP_MESSAGE_CHANGE_DIR,
    PCAP_MESSAGE_HALT,
    PCAP_MESSAGE_PACKET,
    PCAP_MESSAGE_FLUSH,
    PCAP_MESSAGE_ROTATE,
    PCAP_MESSAGE_RAWIP,
};


void *start_pcap_thread(void *params);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
