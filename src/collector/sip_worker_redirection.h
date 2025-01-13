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

#ifndef OPENLI_COLLECTOR_SIP_WORKER_REDIRECT_H_
#define OPENLI_COLLECTOR_SIP_WORKER_REDIRECT_H_

#include <Judy.h>
#include <libtrace.h>

enum {
    REDIRECTED_SIP_PACKET = 1,
    REDIRECTED_SIP_CLAIM = 2,
    REDIRECTED_SIP_REJECTED = 3,
    REDIRECTED_SIP_OVER = 4,
};

typedef struct sip_worker_redirect {
    Pvoid_t redirections;
    Pvoid_t recvd_redirections;
} sip_worker_redirect_t;

typedef struct redirected_sip_message {
    uint8_t message_type;
    char *callid;
    uint32_t pkt_cnt;
    libtrace_packet_t **packets;
} redirected_sip_message_t;

typedef struct saved_redirection {
    char *callid;
    uint64_t redir_mask;
    uint8_t receive_status;
} sip_saved_redirection_t;

#endif
