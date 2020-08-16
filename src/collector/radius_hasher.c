/*
 *
 * Copyright (c) 2018-2020 The University of Waikato, Hamilton, New Zealand.
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

#include "radius_hasher.h"

#include <libtrace/libtrace_radius.h>
#include <libtrace/hash_toeplitz.h>
#include <Judy.h>

void hash_radius_init_config(hash_radius_conf_t *conf,
                                       bool bidirectional) {
    conf->jarray = (Pvoid_t) NULL;

    /* secondary hasher */
    if (bidirectional)
        toeplitz_create_bikey(conf->toeplitz.key);
    else
        toeplitz_create_unikey(conf->toeplitz.key);

    toeplitz_hash_expand_key(&conf->toeplitz);
    conf->toeplitz.hash_ipv4 = 1;
    conf->toeplitz.hash_ipv6 = 1;
    conf->toeplitz.hash_tcp_ipv4 = 1;
    conf->toeplitz.x_hash_udp_ipv4 = 1;
    conf->toeplitz.hash_tcp_ipv6 = 1;
    conf->toeplitz.x_hash_udp_ipv6 = 1;
}

void hash_radius_cleanup(hash_radius_conf_t *conf) {

    Pvoid_t *Pip;
    Word_t Pip_index;

    Pvoid_t *Pport;
    Word_t Pport_index;

    Word_t word;

    /* free each IP jarray */
    Pip_index = 0;
    JLN(Pip, conf->jarray, Pip_index);
    while (Pip != NULL) {

        /* free each port jarray */
        Pport_index = 0;
        JLN(Pport, *Pip, Pport_index);
        while (Pport != NULL) {
            JLFA(word, *Pport);
            JLN(Pport, *Pip, Pport_index);

        }

        JLFA(word, *Pip);
        JLN(Pip, conf->jarray, Pip_index);
    }

    /* free the main jarray */
    JLFA(word, conf->jarray);
}

static uint32_t hash_djb(const char *str, uint8_t len) {

    /* djb hashing algorithm */
    unsigned long hash = 5381;
    for (int i = 0; i < len; str++, i++) {
        hash = ((hash << 5) + hash) + (*str);
    }

    return hash;
}

static uint8_t state_get_queue(Pvoid_t *jarray,
                               uint32_t ip,
                               uint16_t port,
                               uint8_t id) {
    PWord_t Pip;
    PWord_t Pport;
    PWord_t Pid;

    /* find the ip */
    JLG(Pip, *jarray, ip);
    if (Pip == NULL) {
        return 1;
    }

    /* find the port */
    JLG(Pport, *Pip, port);
    if (Pport == NULL) {
        return 1;
    }

    /* find the identifier */
    JLG(Pid, *Pport, id);
    if (Pid == NULL) {
        return 1;
    }

    /* return the stored queue */
    return (uint8_t)*Pid;

}

static void state_update(Pvoid_t *jarray,
                         uint32_t ip,
                         uint16_t port,
                         uint8_t id,
                         uint8_t queue) {

    Pvoid_t *Pip;
    Pvoid_t *PPort;
    Word_t *Pid;

    /* find the jarray for the ip */
    JLG(Pip, *jarray, ip);
    if (Pip == NULL) {
        /* ip not in jarray, create jarray for this ip */
        JLI(Pip, *jarray, ip);
        if (*Pip == 0) {
            *Pip = (Pvoid_t) NULL;
        }
    }

    /* find the jarray for the port */
    JLG(PPort, *Pip, port);
    if (PPort == NULL) {
        /* port not in jarray, create jarray for this port */
        JLI(PPort, *Pip, port);
        if (*PPort == 0) {
            *PPort = (Pvoid_t) NULL;
        }
    }

    /* find the value for this identifier */
    JLG(Pid, *PPort, id);
    if (Pid == NULL) {
        /* identifier not found, add the identifier */
        JLI(Pid, *PPort, id);
        if (*Pid == 0) {
            /* store the queue */
            *Pid = (Word_t)queue;
        }
    } else {
        /* identifier was found, update queue */
        *Pid = (Word_t)queue;
    }

}

static uint32_t ip_to_hash(struct sockaddr_storage *ip) {

    /* if we get a IPv6 address hash it down to a ip4 sized hash */
    switch (ip->ss_family) {
        case AF_INET:
            return ((struct sockaddr_in *)ip)->sin_addr.s_addr;
        case AF_INET6:
            return hash_djb((const char *)&((struct sockaddr_in6 *)ip)->sin6_addr.s6_addr[0],
                    16);
        default:
            return UINT32_MAX;
    }

}

uint64_t hash_radius_packet(const libtrace_packet_t *packet, void *arg) {

    libtrace_radius_t *radius;
    hash_radius_conf_t *conf = (hash_radius_conf_t *)arg;
    uint16_t port;
    uint8_t queue;
    uint8_t namelen = 0;
    char *username = NULL;
    struct sockaddr_storage ip;
    uint32_t ip_hash;
    uint32_t radrem = 0;

    radius = trace_get_radius((libtrace_packet_t *)packet, &radrem);
    if (radius != NULL) {
        /* use the source port for requests and destination for responses. */
        switch (radius->code) {
            case LIBTRACE_RADIUS_ACCESS_REQUEST:
            case LIBTRACE_RADIUS_ACCOUNTING_REQUEST:
            case LIBTRACE_RADIUS_DISCONNECT_REQUEST:
            case LIBTRACE_RADIUS_COA_REQUEST:
                port = trace_get_source_port(packet);
                username = trace_get_radius_username(radius, radrem, &namelen);

                trace_get_source_address(packet, (struct sockaddr *)&ip);
                ip_hash = ip_to_hash(&ip);

                /* RFC2865 says all requests SHOULD have a username.
                 * In the odd case that we do not have one just set the queue to 1.
                 */
                if (username) {
                    /* modulo result down so we dont need to store such
                     * a large number. This is important when we are not using
                     * a Judy array.
                     */
                    queue = hash_djb(username, namelen) % UINT8_MAX;
                } else {
                    queue = 1;
                }
                state_update(&conf->jarray,
                             ip_hash,
                             port,
                             radius->identifier,
                             queue);

                return queue;
            case LIBTRACE_RADIUS_ACCESS_ACCEPT:
            case LIBTRACE_RADIUS_ACCESS_REJECT:
            case LIBTRACE_RADIUS_ACCOUNTING_RESPONSE:
            case LIBTRACE_RADIUS_DISCONNECT_ACK:
            case LIBTRACE_RADIUS_DISCONNECT_NAK:
            case LIBTRACE_RADIUS_COA_ACK:
            case LIBTRACE_RADIUS_COA_NAK:
                port = trace_get_destination_port(packet);

		        trace_get_destination_address(packet, (struct sockaddr *)&ip);
                ip_hash = ip_to_hash(&ip);

                /* pull the queue from the state information */
                queue = state_get_queue(&conf->jarray,
                                       ip_hash,
                                       port,
                                       radius->identifier);
                return queue;
            default:
                break;
        }
    }

    /* fallback to toeplitz hasher */;
    return toeplitz_hash_packet(packet, &conf->toeplitz);
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
