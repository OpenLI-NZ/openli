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

#define OPENLI_II_MAGIC 0x5c4c6c5c

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libtrace/linked_list.h>

/*
enum {
    OPENLI_II_IPINTERCEPT = 1,
    OPENLI_II_HALT_IPINTERCEPT = 2,
};

typedef struct ii_header {
    uint32_t magic;
    uint16_t bodylen;
    uint16_t intercepttype;
    uint64_t internalid;
} ii_header_t;

enum {
    OPENLI_IPII_FIELD_LIID,
    OPENLI_IPII_FIELD_AUTHCC,
    OPENLI_IPII_FIELD_DELIVCC,
    OPENLI_IPII_FIELD_TARGET,
    OPENLI_IPII_FIELD_DESTID
};
*/

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

struct dest_details {
    char *ipstr;
    char *portstr;
    uint32_t destid;
};

void free_all_intercepts(libtrace_list_t *interceptlist);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
