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

#ifndef OPENLI_INTERCEPT_H_
#define OPENLI_INTERCEPT_H_

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libtrace/linked_list.h>

typedef struct ipintercept {
    uint64_t internalid;
    char *liid;
    char *authcc;
    char *delivcc;
    uint64_t cin;

    int liid_len;
    int authcc_len;
    int delivcc_len;
    int username_len;

    int ai_family;
    struct sockaddr_storage *ipaddr;
    char *username;

    uint64_t nextseqno;
    uint32_t destid;
    char *targetagency;
    uint8_t active;
} ipintercept_t;

void free_all_intercepts(libtrace_list_t *interceptlist);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
