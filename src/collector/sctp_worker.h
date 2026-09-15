/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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

#ifndef OPENLI_SCTP_WORKER_H
#define OPENLI_SCTP_WORKER_H

#include "intercept.h"
#include "collector_base.h"

void start_sctp_worker_thread(openli_sctp_worker_t *sctp, int workerid,
        void *globalstate);

uint8_t *parse_m2pa_header_for_sccp(uint8_t *m2pa, uint16_t len,
        uint16_t *sccp_len, uint32_t *opc, uint32_t *dpc);
uint8_t *parse_m3ua_header_for_sccp(uint8_t *m3ua, uint16_t len,
        uint16_t *sccp_len, uint32_t *opc, uint32_t *dpc);

#endif
