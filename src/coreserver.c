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
