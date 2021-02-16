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
#include <zmq.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "util.h"
#include "patricia.h"
#include "coreserver.h"
#include "intercept.h"
#include "etsili_core.h"
#include "reassembler.h"
#include "collector_publish.h"
#include "collector_base.h"
#include "openli_tls.h"
#include "radius_hasher.h"

enum {
    OPENLI_PUSH_IPINTERCEPT = 1,
    OPENLI_PUSH_HALT_IPINTERCEPT = 2,
    OPENLI_PUSH_IPMMINTERCEPT = 3,
    OPENLI_PUSH_HALT_IPMMINTERCEPT = 4,
    OPENLI_PUSH_CORESERVER = 7,
    OPENLI_PUSH_REMOVE_CORESERVER = 8,
    OPENLI_PUSH_VENDMIRROR_INTERCEPT = 9,
    OPENLI_PUSH_HALT_VENDMIRROR_INTERCEPT = 10,
    OPENLI_PUSH_IPRANGE = 11,
    OPENLI_PUSH_REMOVE_IPRANGE = 12,
    OPENLI_PUSH_MODIFY_IPRANGE = 13,
};

enum {
    OPENLI_UPDATE_HELLO = 0,
    OPENLI_UPDATE_RADIUS = 1,
    OPENLI_UPDATE_DHCP = 2,
    OPENLI_UPDATE_SIP = 3,
    OPENLI_UPDATE_GTP = 4,
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
        vendmirror_intercept_t *mirror;
        char *rtpstreamkey;
        coreserver_t *coreserver;
        staticipsession_t *iprange;
    } data;

} PACKED openli_pushed_t;

enum {
    OPENLI_HASHER_BALANCE,
    OPENLI_HASHER_BIDIR,
    OPENLI_HASHER_RADIUS,
};

typedef struct colinput {
    char *uri;
    char *filterstring;
    int threadcount;
    libtrace_t *trace;
    libtrace_filter_t *filter;
    libtrace_callback_set_t *pktcbs;

    uint8_t hasher_apply;
    hash_radius_conf_t hashradconf;
    uint8_t report_drops;
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
    uint8_t prefixlen;
    char *prefixstr;
    ipsession_t *intercepts;

    UT_hash_handle hh;
} ipv6_target_t;

enum {
    SYNC_EVENT_PROC_QUEUE,
    SYNC_EVENT_PROVISIONER,
    SYNC_EVENT_SIP_TIMEOUT,
    SYNC_EVENT_INTERSYNC,
};

typedef struct export_queue_set {

    int numqueues;
    libtrace_message_queue_t *queues;

} export_queue_set_t;


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


typedef struct liid_set {
    char *liid;
    uint32_t cin;
    char *key;
    size_t keylen;
    UT_hash_handle hh;
} liid_set_t;

typedef struct staticip_cacheentry {
    prefix_t prefix;
    patricia_node_t *pnode;
    UT_hash_handle hh;
} static_ipcache_t;

typedef struct colthread_local {

    /* Message queue for pushing updates to sync IP thread */
    void *tosyncq_ip;

    /* Message queue for receiving IP intercept instructions from sync thread */
    libtrace_message_queue_t fromsyncq_ip;

    /* Message queue for pushing updates to sync VOIP thread */
    void *tosyncq_voip;

    /* Message queue for receiving VOIP intercept instructions from sync
       thread */
    libtrace_message_queue_t fromsyncq_voip;


    /* Current intercepts */
    ipv4_target_t *activeipv4intercepts;
    ipv6_target_t *activeipv6intercepts;

    rtpstreaminf_t *activertpintercepts;
    vendmirror_intercept_list_t *activemirrorintercepts;

    staticipsession_t *activestaticintercepts;

    /* Message queue for exporting LI records */
    void **zmq_pubsocks;

    /* Known RADIUS servers, i.e. if we see traffic to or from these
     * servers, we assume it is RADIUS.
     */
    coreserver_t *radiusservers;

    /* Known SIP servers, i.e. if we see traffic to or from these
     * servers, we assume it is SIP.
     */
    coreserver_t *sipservers;

    /* Known GTP servers, i.e. if we see traffic to or from these
     * servers, we assume it is GTP.
     */
    coreserver_t *gtpservers;

    patricia_tree_t *staticv4ranges;
    patricia_tree_t *staticv6ranges;
    patricia_tree_t *dynamicv6ranges;
    static_ipcache_t *staticcache;

    ipfrag_reassembler_t *fragreass;

    uint64_t accepted;
    uint64_t dropped;

} colthread_local_t;

typedef struct collector_global {

    void *zmq_ctxt;
    colinput_t *inputs;

    int total_col_threads;
    int seqtracker_threads;
    int encoding_threads;
    int forwarding_threads;

    void *zmq_forwarder_ctrl;
    void *zmq_encoder_ctrl;

    pthread_rwlock_t config_mutex;

    sync_thread_global_t syncip;
    sync_thread_global_t syncvoip;
    etsili_generic_freelist_t *syncgenericfreelist;

    //support_thread_global_t *exporters;

    seqtracker_thread_data_t *seqtrackers;
    openli_encoder_t *encoders;
    forwarding_thread_data_t *forwarders;
    colthread_local_t *collocals;
    int nextloc;

    libtrace_message_queue_t intersyncq;

    char *configfile;
    collector_identity_t sharedinfo;
    libtrace_list_t *expired_inputs;

    coreserver_t *alumirrors;
    coreserver_t *jmirrors;

    char *sipdebugfile;
    uint8_t ignore_sdpo_matches;

    pthread_t seqproxy_tid;

    uint32_t stat_frequency;
    uint64_t ticks_since_last_stat;
    collector_stats_t stats;
    pthread_mutex_t stats_mutex;

    uint8_t etsitls;

    uint8_t encoding_method;
    openli_ssl_config_t sslconf;
    openli_RMQ_config_t RMQ_conf; 

} collector_global_t;

int register_sync_queues(sync_thread_global_t *glob,
        void *recvq, libtrace_message_queue_t *sendq,
        libtrace_thread_t *parent);
void deregister_sync_queues(sync_thread_global_t *glob,
        libtrace_thread_t *t);


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
