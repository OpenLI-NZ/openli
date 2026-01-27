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
#ifndef OPENLI_ALUSHIM_PARSER_H_
#define OPENLI_ALUSHIM_PARSER_H_

#include <libtrace.h>
#include "collector.h"
#include "coreserver.h"
#include "intercept.h"

uint8_t *decode_alushim_from_udp_payload(uint8_t *payload, uint32_t plen,
        uint32_t *cin, uint8_t *dir, uint32_t *shimintid, uint32_t *bodylen,
        uint8_t l3_only);
int check_alu_intercept(colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        coreserver_t *alusources, vendmirror_intercept_list_t *aluints);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

