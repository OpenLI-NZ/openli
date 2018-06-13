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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <libtrace/linked_list.h>
#include "coreserver.h"
#include "logger.h"

const char *coreserver_type_to_string(uint8_t cstype) {
    switch(cstype) {
        case OPENLI_CORE_SERVER_RADIUS:
            return "RADIUS";
        case OPENLI_CORE_SERVER_DHCP:
            return "DHCP";
        case OPENLI_CORE_SERVER_SIP:
            return "SIP";
        case OPENLI_CORE_SERVER_ALUMIRROR:
            return "ALU-Mirror";
    }
    return "Unknown";
}

static struct addrinfo *populate_addrinfo(char *ipstr, char *portstr,
        int socktype) {
    struct addrinfo hints, *res;
    int s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_PASSIVE;

    s = getaddrinfo(ipstr, portstr, &hints, &res);
    if (s != 0) {
        logger(LOG_DAEMON,
                "OpenLI: error calling getaddrinfo on %s:%s: %s",
                ipstr, portstr, gai_strerror(s));
        return NULL;
    }

    return res;
}

int coreserver_match(coreserver_t *cs, struct sockaddr_storage *sa,
        uint16_t port) {

    struct sockaddr_in *in, *csin;
    struct sockaddr_in6 *in6, *csin6;

    /* XXX for now, all supported server types are UDP so no need to
     * set socktype to be anything other than SOCK_DGRAM */

    /* TCP SIP?? TODO */
    if (cs->info == NULL) {
        cs->info = populate_addrinfo(cs->ipstr, cs->portstr, SOCK_DGRAM);
    }

    if (!cs->info) {
        return -1;
    }

    if (sa->ss_family != cs->info->ai_family) {
        return 0;
    }

    if (sa->ss_family == AF_INET) {
        in = (struct sockaddr_in *)sa;
        csin = (struct sockaddr_in *)(cs->info->ai_addr);

        if (port != ntohs(csin->sin_port)) {
            return 0;
        }

        if (memcmp(&(in->sin_addr), &(csin->sin_addr), sizeof(struct in_addr))
                != 0) {
            return 0;
        }

        return 1;
    }

    if (sa->ss_family == AF_INET6) {
        in6 = (struct sockaddr_in6 *)sa;
        csin6 = (struct sockaddr_in6 *)(cs->info->ai_addr);

        if (port != ntohs(csin6->sin6_port)) {
            return 0;
        }

        if (memcmp(&(in6->sin6_addr), &(csin6->sin6_addr),
                sizeof(struct in6_addr)) != 0) {
            return 0;
        }

        return 1;
    }

    /* Unsupported family */
    return 0;
}

coreserver_t *deep_copy_coreserver(coreserver_t *cs) {
    coreserver_t *cscopy;

    cscopy = (coreserver_t *)malloc(sizeof(coreserver_t));
    cscopy->serverkey = strdup(cs->serverkey);
    cscopy->ipstr = strdup(cs->ipstr);
    if (cs->portstr) {
        cscopy->portstr = strdup(cs->portstr);
    } else {
        cscopy->portstr = NULL;
    }
    cscopy->servertype = cs->servertype;
    cscopy->info = NULL;
    cscopy->awaitingconfirm = 0;
    return cscopy;
}

void free_single_coreserver(coreserver_t *cs) {
    if (cs->ipstr) {
        free(cs->ipstr);
    }
    if (cs->portstr) {
        free(cs->portstr);
    }
    if (cs->info) {
        freeaddrinfo(cs->info);
    }
    if (cs->serverkey) {
        free(cs->serverkey);
    }
    free(cs);
}

char *construct_coreserver_key(coreserver_t *cs) {
    char keyspace[256];
    if (cs->ipstr == NULL) {
        return NULL;
    }

    if (cs->portstr == NULL) {
        snprintf(keyspace, 256, "%s-default", cs->ipstr);
    } else {
        snprintf(keyspace, 256, "%s-%s", cs->ipstr, cs->portstr);
    }
    cs->serverkey = strdup(keyspace);
    return cs->serverkey;
}


void free_coreserver_list(coreserver_t *cslist) {
    coreserver_t *cs, *tmp;

    HASH_ITER(hh, cslist, cs, tmp) {
        HASH_DELETE(hh, cslist, cs);
        free_single_coreserver(cs);
    }

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
