/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

#ifndef OPENLI_COLLECTOR_UTIL_H_
#define OPENLI_COLLECTOR_UTIL_H_

#include "export_buffer.h"

int init_zmq_socket_array(void **zmq_socks, int sockcount,
        const char *basename, void *zmq_ctxt);
void clear_zmq_socket_array(void **zmq_socks, int sockcount);
int send_halt_message_to_zmq_socket_array(void **zmq_socks, int sockcount,
		halt_info_t *haltinfo);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
