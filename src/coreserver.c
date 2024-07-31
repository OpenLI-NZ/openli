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
#include <errno.h>
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
    if (cs->lower_portstr) {
        cscopy->lower_portstr = strdup(cs->lower_portstr);
    } else {
        cscopy->lower_portstr = NULL;
    }
    if (cs->upper_portstr) {
        cscopy->upper_portstr = strdup(cs->upper_portstr);
    } else {
        cscopy->upper_portstr = NULL;
    }
    cscopy->servertype = cs->servertype;
    cscopy->info = NULL;
    cscopy->lower_portnumeric = cs->lower_portnumeric;
    cscopy->upper_portnumeric = cs->upper_portnumeric;
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
    if (cs->lower_portstr) {
        free(cs->lower_portstr);
    }
    if (cs->upper_portstr) {
        free(cs->upper_portstr);
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

    if (cs->lower_portstr || cs->upper_portstr) {
        snprintf(keyspace, 256, "%s-%s-%s-%s", cs->ipstr,
                cs->lower_portstr ? cs->lower_portstr : "1",
                cs->upper_portstr ? cs->upper_portstr : "65535",
                coreserver_type_to_string(cs->servertype));
    } else if (cs->portstr) {
        snprintf(keyspace, 256, "%s-%s-%s-%s", cs->ipstr, cs->portstr,
                cs->portstr, coreserver_type_to_string(cs->servertype));
    } else {
        snprintf(keyspace, 256, "%s-1-65535-%s", cs->ipstr,
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

static inline int portstr_to_numericport(const char *portstr, uint16_t *res) {

    uint16_t port16;
    uint64_t toul;

    errno = 0;
    toul = strtoul(portstr, NULL, 10);
    if (errno) {
        logger(LOG_INFO,
                "OpenLI: unable to convert '%s' to a valid port number: %s",
                portstr, strerror(errno));
        return -1;
    }

    if (toul > 65535) {
        logger(LOG_INFO,
                "OpenLI: invalid port number '%lu' -- must be 65535 or below",
                toul);
        return -1;
    }

    /* Don't actually need to swap because already in host byte order... */
    port16 = (uint16_t)toul;
    *res = port16;
    return 0;
}

int prepare_coreserver(coreserver_t *cs) {

    cs->info = populate_addrinfo(cs->ipstr, NULL, SOCK_DGRAM);
    if (!cs->info) {
        logger(LOG_INFO,
                "Removing %s from core server list due to getaddrinfo error",
                cs->serverkey);
        return -1;
    }

    if (cs->lower_portstr && cs->upper_portstr) {
        if (portstr_to_numericport(cs->lower_portstr,
                    &(cs->lower_portnumeric)) < 0) {
            return -1;
        }
        if (portstr_to_numericport(cs->upper_portstr,
                    &(cs->upper_portnumeric)) < 0) {
            return -1;
        }
    } else if (cs->lower_portstr) {
        if (portstr_to_numericport(cs->lower_portstr,
                    &(cs->lower_portnumeric)) < 0) {
            return -1;
        }
        if (portstr_to_numericport("65535",
                    &(cs->upper_portnumeric)) < 0) {
            return -1;
        }
    } else if (cs->upper_portstr) {
        if (portstr_to_numericport("1",
                    &(cs->lower_portnumeric)) < 0) {
            return -1;
        }
        if (portstr_to_numericport(cs->upper_portstr,
                    &(cs->upper_portnumeric)) < 0) {
            return -1;
        }
    } else if (cs->portstr) {
        if (portstr_to_numericport(cs->portstr,
                    &(cs->lower_portnumeric)) < 0) {
            return -1;
        }
        if (portstr_to_numericport(cs->portstr,
                    &(cs->upper_portnumeric)) < 0) {
            return -1;
        }
    } else {
        logger(LOG_INFO,
                "Removing %s from core server list due to missing port information",
                cs->serverkey);
        return -1;
    }

    if (cs->lower_portnumeric > cs->upper_portnumeric) {
        logger(LOG_INFO,
                "Invalid port range: %s : %s - %s  (check the ordering!)\n",
                cs->ipstr, cs->lower_portstr, cs->upper_portstr);
        return -1;
    }

    return 0;
}

coreserver_t *match_packet_to_coreserver(coreserver_t *serverlist,
        packet_info_t *pinfo, uint8_t just_dest) {

    coreserver_t *cs, *tmp;

	if (pinfo->destport == 0) {
		return NULL;
	}
    if (pinfo->srcport == 0 && just_dest == 0) {
        return NULL;
    }

	HASH_ITER(hh, serverlist, cs, tmp) {
        if (cs->info == NULL) {
            if (prepare_coreserver(cs) < 0) {
                HASH_DELETE(hh, serverlist, cs);
                continue;
            }
        }

        if (cs->info->ai_family == AF_INET) {
            struct sockaddr_in *sa;
            sa = (struct sockaddr_in *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V4(cs, sa, pinfo->destport)) {
                return cs;
            }
            if (!just_dest) {
                sa = (struct sockaddr_in *)(&(pinfo->srcip));
                if (CORESERVER_MATCH_V4(cs, sa, pinfo->srcport)) {
                    return cs;
                }
            }
        } else if (cs->info->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6;
            sa6 = (struct sockaddr_in6 *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V6(cs, sa6, pinfo->destport)) {
				return cs;
            }
            if (!just_dest) {
                sa6 = (struct sockaddr_in6 *)(&(pinfo->srcip));
                if (CORESERVER_MATCH_V6(cs, sa6, pinfo->srcport)) {
                    return cs;
                }
            }
        }
	}

	return NULL;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
