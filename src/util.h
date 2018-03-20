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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#ifndef OPENLI_UTIL_H_
#define OPENLI_UTIL_H_

#include <sys/epoll.h>

int connect_socket(char *ipstr, char *portstr, uint8_t isretry);
int epoll_add_timer(int epoll_fd, uint32_t secs, void *ptr);
int create_listener(char *addr, char *port, char *name);

uint32_t hashlittle( const void *key, size_t length, uint32_t initval);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

