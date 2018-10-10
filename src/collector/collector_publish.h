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

#ifndef OPENLI_COLLECTOR_PUBLISH_H_
#define OPENLI_COLLECTOR_PUBLISH_H_

#include <libtrace.h>
#include <zmq.h>

#include "netcomms.h"
#include "etsili_core.h"
#include "intercept.h"

enum {
    OPENLI_EXPORT_HALT_WORKER = 1,
    OPENLI_EXPORT_PACKET_FIN = 2,
    OPENLI_EXPORT_MEDIATOR = 3,
    OPENLI_EXPORT_FLAG_MEDIATORS = 4,
    OPENLI_EXPORT_DROP_ALL_MEDIATORS = 6,
    OPENLI_EXPORT_DROP_SINGLE_MEDIATOR = 7,
    OPENLI_EXPORT_IPCC = 8,
    OPENLI_EXPORT_IPMMCC = 9,
    OPENLI_EXPORT_IPIRI = 10,
    OPENLI_EXPORT_IPMMIRI = 11,
    OPENLI_EXPORT_INTERCEPT_DETAILS = 12,
    OPENLI_EXPORT_INTERCEPT_OVER = 13,

};

typedef struct openli_ipcc_job_header {
    uint8_t type;
    uint32_t destid;
    uint32_t cin;
    uint8_t dir;
    uint32_t tvsec;
    uint32_t tvusec;
    uint16_t liid_len;
    uint16_t ipc_len;
} PACKED openli_ipcc_job_header_t;

typedef struct openli_ipmmcc_job {
    char *liid;
    libtrace_packet_t *packet;
    uint32_t cin;
    uint8_t dir;
} PACKED openli_ipmmcc_job_t;

typedef struct openli_ipcc_job {
    char *liid;
    uint8_t *ipcontent;
    uint32_t ipclen;
    uint32_t ipcalloc;
    uint16_t liidalloc;
    uint32_t cin;
    uint8_t dir;
} PACKED openli_ipcc_job_t;

typedef struct openli_ipmmiri_job {
    char *liid;
    libtrace_packet_t *packet;
    uint32_t cin;
    etsili_iri_type_t iritype;
    uint8_t ipmmiri_style;
    char *content;
    uint16_t contentlen;
    uint8_t ipsrc[16];
    uint8_t ipdest[16];
    int ipfamily;
} PACKED openli_ipmmiri_job_t;

typedef struct openli_ipiri_job {
    char *liid;
    //access_plugin_t *plugin;
    //void *plugin_data;

    uint32_t cin;
    char *username;
    struct sockaddr_storage assignedip;
    int ipfamily;
    struct timeval sessionstartts;
    internet_access_method_t access_tech;
    uint8_t special;
    uint8_t ipassignmentmethod;
    uint8_t assignedip_prefixbits;
} PACKED openli_ipiri_job_t;

enum {
    OPENLI_IPIRI_STANDARD,
    OPENLI_IPIRI_ENDWHILEACTIVE,
    OPENLI_IPIRI_STARTWHILEACTIVE,
    OPENLI_IPIRI_SILENTLOGOFF,
};

enum {
    OPENLI_IPIRI_IPMETHOD_STATIC,
    OPENLI_IPIRI_IPMETHOD_DYNAMIC,
    OPENLI_IPIRI_IPMETHOD_UNKNOWN,
};

typedef struct published_intercept_msg {
    char *liid;
    char *authcc;
    char *delivcc;
} published_intercept_msg_t;

typedef struct openli_export_recv openli_export_recv_t;
typedef struct openli_exportmsg_freelist openli_exportmsg_freelist_t;

struct openli_export_recv {
    uint8_t type;
    uint32_t destid;
    struct timeval ts;
    union {
        openli_mediator_t med;
        libtrace_packet_t *packet;
        published_intercept_msg_t cept;
        openli_ipcc_job_t ipcc;
        openli_ipmmcc_job_t ipmmcc;
        openli_ipmmiri_job_t ipmmiri;
        openli_ipiri_job_t ipiri;
    } data;
    openli_export_recv_t *nextfree;
    openli_exportmsg_freelist_t *owner;
} PACKED;

struct openli_exportmsg_freelist {
    pthread_mutex_t mutex;
    openli_export_recv_t *available;
    uint32_t created;
    uint32_t freed;
    uint32_t recycled;
};

int publish_openli_msg(void *pubsock, openli_export_recv_t *msg);
void free_published_message(openli_export_recv_t *msg);
void release_published_message(openli_export_recv_t *msg);

openli_export_recv_t *create_ipcc_job(openli_exportmsg_freelist_t *flist,
        uint32_t cin, char *liid, uint32_t destid, libtrace_packet_t *pkt,
        uint8_t dir);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
