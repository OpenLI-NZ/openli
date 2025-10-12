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

#ifndef OPENLI_COLLECTOR_BUFFER_H_
#define OPENLI_COLLECTOR_BUFFER_H_

#include "config.h"
#include <libwandder.h>
#include <libwandder_etsili.h>
#include <Judy.h>
#include "netcomms.h"
#include "collector/collector_publish.h"

typedef struct pcap_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t wirelen;
} PACKED openli_pcap_header_t;

typedef struct encoder_result {
    ii_header_t header;
    wandder_encoded_result_t *msgbody;
    uint8_t *ipcontents;
    uint32_t ipclen;
    uint32_t seqno;
    uint32_t destid;
    char *liid;
    char *cinstr;
    uint8_t encodedby;
    openli_export_recv_t *origreq;
} PACKED openli_encoded_result_t;


typedef struct export_buffer {
    uint8_t *bufhead;
    uint8_t *buftail;
    uint64_t alloced;

    /* all data prior to this offset can be considered "successfully written" */
    uint32_t deadfront;

    /* offset pointing to the first record that has not been sent */
    uint32_t writeoffset;

    /* offset pointing to where a previous partial write ended */
    uint32_t partialfront;

    /* number of bytes remaining to be written following a previous partial
     * write */
    uint32_t partialrem;

    uint64_t nextwarn;

    /* number of subsequent bytes that must be sent before data in the buffer
     * can be considered "sent"
     */
    uint32_t deadwindow;

    Pvoid_t record_offsets;
    uint32_t since_last_saved_offset;
} export_buffer_t;


void init_export_buffer(export_buffer_t *buf);
void reset_export_buffer(export_buffer_t *buf);
void release_export_buffer(export_buffer_t *buf);
uint64_t get_buffered_amount(export_buffer_t *buf);
uint64_t append_message_to_buffer(export_buffer_t *buf,
        openli_encoded_result_t *msg, uint32_t beensent);
uint64_t append_heartbeat_to_buffer(export_buffer_t *buf);
uint64_t append_etsipdu_to_buffer(export_buffer_t *buf,
        uint8_t *pdustart, uint32_t pdulen, uint32_t beensent);
int transmit_buffered_records(export_buffer_t *buf, int fd,
        uint64_t bytelimit, SSL *ssl);
int transmit_buffered_records_RMQ(export_buffer_t *buf, 
        amqp_connection_state_t amqp_state, amqp_channel_t channel, 
        amqp_bytes_t exchange, amqp_bytes_t routing_key,
        uint64_t bytelimit, uint8_t *is_blocked);
int check_rmq_connection_block_status(amqp_connection_state_t amqp_state,
        uint8_t *is_blocked);
int transmit_heartbeat(int fd, SSL *ssl);
int advance_export_buffer_head(export_buffer_t *buf, uint64_t amount);
uint8_t *get_buffered_head(export_buffer_t *buf, uint64_t *rem);
void set_export_buffer_ack_window(export_buffer_t *buf, uint32_t window);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
