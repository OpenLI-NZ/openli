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
#include "util.h"

const char *coreserver_type_to_string(uint8_t cstype) {
    switch(cstype) {
        case OPENLI_CORE_SERVER_RADIUS:
            return "RADIUS";
        case OPENLI_CORE_SERVER_DHCP:
            return "DHCP";
        case OPENLI_CORE_SERVER_SIP:
            return "SIP";
        case OPENLI_CORE_SERVER_SMTP:
            return "SMTP";
        case OPENLI_CORE_SERVER_IMAP:
            return "IMAP";
        case OPENLI_CORE_SERVER_POP3:
            return "POP3";
        case OPENLI_CORE_SERVER_GTP:
            return "GTP";
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
    cscopy->portswapped = cs->portswapped;
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
        snprintf(keyspace, 256, "%s-default-%s", cs->ipstr,
                coreserver_type_to_string(cs->servertype));
    } else {
        snprintf(keyspace, 256, "%s-%s-%s", cs->ipstr, cs->portstr,
                coreserver_type_to_string(cs->servertype));
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

coreserver_t *match_packet_to_coreserver(coreserver_t *serverlist,
        packet_info_t *pinfo) {

    coreserver_t *cs, *tmp;

	if (pinfo->destport == 0) {
		return NULL;
	}

	HASH_ITER(hh, serverlist, cs, tmp) {
        if (cs->info == NULL) {
            cs->info = populate_addrinfo(cs->ipstr, cs->portstr, SOCK_DGRAM);
            if (!cs->info) {
                logger(LOG_INFO,
                        "Removing %s:%s from %s core server list due to getaddrinfo error",
                        cs->ipstr, cs->portstr,
                        coreserver_type_to_string(cs->servertype));
                HASH_DELETE(hh, serverlist, cs);
                continue;
            }
            if (cs->info->ai_family == AF_INET) {
                cs->portswapped = ntohs(CS_TO_V4(cs)->sin_port);
            } else if (cs->info->ai_family == AF_INET6) {
                cs->portswapped = ntohs(CS_TO_V6(cs)->sin6_port);
            }
        }

        if (cs->info->ai_family == AF_INET) {
            struct sockaddr_in *sa;
            sa = (struct sockaddr_in *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V4(cs, sa, pinfo->destport)) {
                return cs;
            }
        } else if (cs->info->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6;
            sa6 = (struct sockaddr_in6 *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V6(cs, sa6, pinfo->destport)) {
				return cs;
            }
        }
	}

	return NULL;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
