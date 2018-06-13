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

#ifndef OPENLI_COLLECTOR_H_
#define OPENLI_COLLECTOR_H_

#include <pthread.h>
#include <inttypes.h>
#include <libtrace.h>
#include <libtrace/message_queue.h>
#include <libtrace/linked_list.h>
#include <uthash.h>
#include <libwandder.h>

#include "coreserver.h"
#include "intercept.h"
#include "etsili_core.h"

enum {
    OPENLI_PUSH_IPINTERCEPT = 1,
    OPENLI_PUSH_HALT_IPINTERCEPT = 2,
    OPENLI_PUSH_IPMMINTERCEPT = 3,
    OPENLI_PUSH_HALT_IPMMINTERCEPT = 4,
    OPENLI_PUSH_CORESERVER = 7,
    OPENLI_PUSH_REMOVE_CORESERVER = 8,
    OPENLI_PUSH_ALUINTERCEPT = 9,
    OPENLI_PUSH_HALT_ALUINTERCEPT = 10,
};

enum {
    OPENLI_UPDATE_HELLO = 0,
    OPENLI_UPDATE_RADIUS = 1,
    OPENLI_UPDATE_DHCP = 2,
    OPENLI_UPDATE_SIP = 3
};

typedef struct openli_intersync_msg {
    uint8_t msgtype;
    uint8_t *msgbody;
    uint16_t msglen;
} PACKED openli_intersync_msg_t;

typedef struct openli_state_msg {

    uint8_t type;
    union {
        libtrace_message_queue_t *replyq;
        libtrace_packet_t *pkt;
    } data;

} PACKED openli_state_update_t;

typedef struct openli_ii_msg {

    uint8_t type;
    union {
        ipsession_t *ipsess;
        rtpstreaminf_t *ipmmint;
        aluintercept_t *aluint;
        char *rtpstreamkey;
        coreserver_t *coreserver;
    } data;

} PACKED openli_pushed_t;

typedef struct colinput {
    char *uri;
    int threadcount;
    libtrace_t *trace;
    libtrace_callback_set_t *pktcbs;

    uint8_t running;
    UT_hash_handle hh;
} colinput_t;

typedef struct ipv4_target {
    uint32_t address;
    ipsession_t *intercepts;

    UT_hash_handle hh;
} ipv4_target_t;

typedef struct ipv6_target {
    uint8_t address[16];
    ipsession_t *intercepts;

    UT_hash_handle hh;
} ipv6_target_t;

enum {
    SYNC_EVENT_PROC_QUEUE,
    SYNC_EVENT_PROVISIONER,
    SYNC_EVENT_SIP_TIMEOUT,
    SYNC_EVENT_INTERSYNC,
};


typedef struct sync_epoll {
    uint8_t fdtype;
    int fd;
    void *ptr;
    libtrace_thread_t *parent;
    UT_hash_handle hh;
} sync_epoll_t;

typedef struct sync_sendq {
    libtrace_message_queue_t *q;
    libtrace_thread_t *parent;
    UT_hash_handle hh;
} sync_sendq_t;


typedef struct colthread_local {

    /* Message queue for pushing updates to sync IP thread */
    libtrace_message_queue_t tosyncq_ip;

    /* Message queue for receiving IP intercept instructions from sync thread */
    libtrace_message_queue_t fromsyncq_ip;

    /* Message queue for pushing updates to sync VOIP thread */
    libtrace_message_queue_t tosyncq_voip;

    /* Message queue for receiving VOIP intercept instructions from sync
       thread */
    libtrace_message_queue_t fromsyncq_voip;


    /* Current intercepts */
    ipv6_target_t *activeipv6intercepts;
    ipv4_target_t *activeipv4intercepts;

    rtpstreaminf_t *activertpintercepts;
    aluintercept_t *activealuintercepts;

    /* Message queue for exporting LI records */
    libtrace_message_queue_t exportq;

    /* Known RADIUS servers, i.e. if we see traffic to or from these
     * servers, we assume it is RADIUS.
     */
    coreserver_t *radiusservers;

    /* Known SIP servers, i.e. if we see traffic to or from these
     * servers, we assume it is SIP.
     */
    coreserver_t *sipservers;

    wandder_encoder_t *encoder;
    char *inputidentifier;

} colthread_local_t;

typedef struct shared_global_info {
    char *operatorid;
    char *networkelemid;
    char *intpointid;
    char *provisionerip;
    char *provisionerport;

    int operatorid_len;
    int networkelemid_len;
    int intpointid_len;

} shared_global_info_t;

typedef struct supporting_thread_global {

    pthread_t threadid;
    pthread_mutex_t mutex;
    void *collector_queues;
    void *epollevs;
    int epoll_fd;

} support_thread_global_t;

typedef struct collector_global {

    colinput_t *inputs;

    int totalthreads;
    int queuealloced;

    pthread_rwlock_t config_mutex;

    support_thread_global_t syncip;
    support_thread_global_t syncvoip;
    support_thread_global_t exporter;

    libtrace_message_queue_t intersyncq;

    char *configfile;
    shared_global_info_t sharedinfo;
    libtrace_list_t *expired_inputs;

    coreserver_t *alumirrors;



} collector_global_t;

typedef struct packetinfo {
    int family;
    struct sockaddr_storage srcip;
    struct sockaddr_storage destip;
    uint16_t srcport;
    uint16_t destport;
} packet_info_t;

int register_sync_queues(support_thread_global_t *glob,
        libtrace_message_queue_t *recvq, libtrace_message_queue_t *sendq,
        libtrace_thread_t *parent);
void deregister_sync_queues(support_thread_global_t *glob,
        libtrace_thread_t *t);


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
