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

#ifndef OPENLI_COLLECTOR_EXPORT_H_
#define OPENLI_COLLECTOR_EXPORT_H_

#include <libwandder.h>
#include <sys/epoll.h>

#include "collector.h"
#include "export_buffer.h"
#include "netcomms.h"
#include "internetaccess.h"

typedef struct export_dest {
    int failmsg;
    int fd;
    int awaitingconfirm;
    int halted;
    openli_mediator_t details;
    export_buffer_t buffer;
} export_dest_t;

typedef struct exporter_epoll {
    uint8_t type;
    union {
        libtrace_message_queue_t *q;
        export_dest_t *dest;
    } data;
} exporter_epoll_t;

typedef struct exporter_intercept_msg {
    char *liid;
    int liid_len;
    char *authcc;
    int authcc_len;
    char *delivcc;
    int delivcc_len;
} exporter_intercept_msg_t;

typedef struct cin_seqno {
    uint32_t cin;
    uint32_t cc_seqno;
    uint32_t iri_seqno;
    UT_hash_handle hh;
} cin_seqno_t;

typedef struct intercept_state {
    exporter_intercept_msg_t *details;
    cin_seqno_t *cinsequencing;
    UT_hash_handle hh;
} exporter_intercept_state_t;


typedef struct colexp_data {

    support_thread_global_t *glob;
    libtrace_list_t *dests;     // if dests gets large, replace with map?
    exporter_intercept_state_t *intercepts;
    wandder_encoder_t *encoder;
    etsili_generic_t *freegenerics;

    uint8_t flagged;
    int failed_conns;
    exporter_epoll_t *flag_timer_ev;
    int flagtimerfd;

} collector_export_t;

enum {
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

typedef struct openli_ipmmcc_job {
    char *liid;
    libtrace_packet_t *packet;
    uint32_t cin;
    uint8_t dir;
    shared_global_info_t *colinfo;
} openli_ipmmcc_job_t;

typedef struct openli_ipcc_job {
    char *liid;
    libtrace_packet_t *packet;
    uint32_t cin;
    uint8_t dir;
    shared_global_info_t *colinfo;
} openli_ipcc_job_t;

typedef struct openli_ipmmiri_job {
    char *liid;
    libtrace_packet_t *packet;
    uint32_t cin;
    etsili_iri_type_t iritype;
    uint8_t ipmmiri_style;
    shared_global_info_t *colinfo;
    char *content;
    uint16_t contentlen;
    uint8_t ipsrc[16];
    uint8_t ipdest[16];
    int ipfamily;
} openli_ipmmiri_job_t;

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

typedef struct openli_ipiri_job {
    char *liid;
    access_plugin_t *plugin;
    void *plugin_data;

    uint32_t cin;
    char *username;
    struct sockaddr_storage assignedip;
    int ipfamily;
    struct timeval sessionstartts;
    internet_access_method_t access_tech;
    shared_global_info_t *colinfo;
    uint8_t special;
    uint8_t ipassignmentmethod;
    uint8_t assignedip_prefixbits;
} openli_ipiri_job_t;


typedef struct openli_export_recv {
    uint8_t type;
    uint32_t destid;
    struct timeval ts;
    union {
        openli_mediator_t med;
        libtrace_packet_t *packet;
        exporter_intercept_msg_t *cept;
        openli_ipcc_job_t ipcc;
        openli_ipmmcc_job_t ipmmcc;
        openli_ipmmiri_job_t ipmmiri;
        openli_ipiri_job_t ipiri;
    } data;
} PACKED openli_export_recv_t;


collector_export_t *init_exporter(support_thread_global_t *glob);
int connect_export_targets(collector_export_t *exp);
void destroy_exporter(collector_export_t *exp);
int exporter_thread_main(collector_export_t *exp);
void register_export_queues(support_thread_global_t *glob,
        export_queue_set_t *qset);

export_queue_set_t *create_export_queue_set(int numqueues);
void free_export_queue_set(export_queue_set_t *qset);
void export_queue_put_all(export_queue_set_t *qset, openli_export_recv_t *msg);
int export_queue_put_by_liid(export_queue_set_t *qset,
        openli_export_recv_t *msg, char *liid);
int export_queue_put_by_queueid(export_queue_set_t *qset,
        openli_export_recv_t *msg, int queueid);



#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
