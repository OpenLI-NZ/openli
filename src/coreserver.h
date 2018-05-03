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

#ifndef OPENLI_CORESERVER_H_
#define OPENLI_CORESERVER_H_

/* Header file for communicating descriptions of the machines hosting
 * core services (e.g. SIP and RADIUS) between components.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <uthash.h>

enum {
    OPENLI_CORE_SERVER_UNKNOWN,
    OPENLI_CORE_SERVER_RADIUS,
    OPENLI_CORE_SERVER_DHCP,
    OPENLI_CORE_SERVER_SIP,
};

typedef struct coreserver {
    char *serverkey;
    uint8_t servertype;
    char *ipstr;
    char *portstr;
    struct addrinfo *info;
    uint8_t awaitingconfirm;

    UT_hash_handle hh;
} coreserver_t;

void free_single_coreserver(coreserver_t *cs);
char *construct_coreserver_key(coreserver_t *cs);
void free_coreserver_list(coreserver_t *servlist);
const char *coreserver_type_to_string(uint8_t cstype);
coreserver_t *deep_copy_coreserver(coreserver_t *cs);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
