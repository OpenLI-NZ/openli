/*
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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

#ifndef OPENLI_COLLECTOR_SYNC_VOIP_H_
#define OPENLI_COLLECTOR_SYNC_VOIP_H_

#include <libtrace.h>

#include "intercept.h"
#include "collector_sync.h"
#include "util.h"

void push_all_active_voipstreams(libtrace_message_queue_t *q,
        voipintercept_t *vint);
void push_voipintercept_halt_to_threads(collector_sync_t *sync,
        voipintercept_t *vint);

int update_sip_state(collector_sync_t *sync, libtrace_packet_t *pkt);

int new_voipintercept(collector_sync_t *sync, uint8_t *intmsg, uint16_t msglen);
int halt_voipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen);
void touch_all_voipintercepts(voipintercept_t *vints);

int withdraw_voip_sip_target(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen);
int new_voip_sip_target(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
