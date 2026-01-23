/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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
#include <uuid/uuid.h>

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
#include "email_ingest_service.h"
#include "email_worker.h"
#include "gtp_worker.h"
#include "sip_worker.h"
#include "sipparsing.h"
#include "x2x3_ingest.h"

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
    OPENLI_PUSH_UPDATE_IPINTERCEPT=14,
    OPENLI_PUSH_UPDATE_VENDMIRROR_INTERCEPT=15,
    OPENLI_PUSH_UPDATE_IPRANGE_INTERCEPT=16,
    OPENLI_PUSH_UPDATE_VOIPINTERCEPT=17,
    OPENLI_PUSH_HUP_RELOAD=18,
};

enum {
    OPENLI_UPDATE_HELLO = 0,
    OPENLI_UPDATE_RADIUS = 1,
    OPENLI_UPDATE_DHCP = 2,
    OPENLI_UPDATE_SIP = 3,
    OPENLI_UPDATE_GTP = 4,
    OPENLI_UPDATE_SMTP = 5,
    OPENLI_UPDATE_IMAP = 6,
    OPENLI_UPDATE_POP3 = 7,
    OPENLI_UPDATE_SMS_SIP = 8,
};

typedef struct openli_sip_content {
    uint8_t *content;
    uint16_t contentlen;
    uint8_t ipsrc[16];
    uint8_t ipdest[16];
    int ipfamily;
    struct timeval timestamp;
} PACKED openli_sip_content_t;

typedef struct openli_state_msg {

    uint8_t type;
    union {
        libtrace_message_queue_t *replyq;
        libtrace_packet_t *pkt;
        openli_sip_content_t sip;
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
    char *coremap;
    int threadcount;
    libtrace_t *trace;
    libtrace_filter_t *filter;
    libtrace_callback_set_t *pktcbs;

    time_t start_at;
    uint8_t no_restart;

    uint8_t hasher_apply;
    hash_radius_conf_t hashradconf;
    uint8_t hashconfigured;
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

    char *localname;

    /* Message queue for pushing updates to sync IP thread */
    void *tosyncq_ip;

    /* Message queue for receiving IP intercept instructions from sync thread */
    libtrace_message_queue_t fromsyncq_ip;

    /* Array of message threads for receiving intercept instructions from
     * the GTP processing threads
     */
    libtrace_message_queue_t *fromgtp_queues;

    /* Array of message threads for receiving intercept instructions from
     * the SIP processing threads
     */
    libtrace_message_queue_t *fromsip_queues;

    /* Number of GTP processing threads that have queues in the above array */
    int gtpq_count;

    /* Number of SIP processing threads that have queues in the above array */
    int sipq_count;

    /* Array of message queues to pass packets to the email worker threads */
    void **email_worker_queues;

    /* Array of message queues to pass packets to the SMS worker threads */
    void **sip_worker_queues;

    /* Array of message queues to pass packets to the GTP worker threads */
    void **gtp_worker_queues;

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

    /* Known SMTP servers, i.e. if we see traffic to or from these
     * servers, we assume it is SMTP.
     */
    coreserver_t *smtpservers;

    /* Known IMAP servers, i.e. if we see traffic to or from these
     * servers, we assume it is IMAP.
     */
    coreserver_t *imapservers;

    /* Known POP3 servers, i.e. if we see traffic to or from these
     * servers, we assume it is POP3.
     */
    coreserver_t *pop3servers;

    coreserver_fast_filter_v4_t *cs_v4_fast_filter;

    patricia_tree_t *staticv4ranges;
    patricia_tree_t *staticv6ranges;
    patricia_tree_t *dynamicv6ranges;
    static_ipcache_t *staticcache;

    ipfrag_reassembler_t *fragreass;

    uint64_t accepted;
    uint64_t dropped;

    time_t startedat;
    uint16_t pkts_since_msg_read;
    uint16_t tick_counter;

    UT_hash_handle hh;

} colthread_local_t;

typedef struct collector_global {

    uuid_t uuid;

    void *zmq_ctxt;
    colinput_t *inputs;

    int total_col_threads;
    int seqtracker_threads;
    int encoding_threads;
    int forwarding_threads;
    int email_threads;
    int gtp_threads;
    int sip_threads;

    void *zmq_encoder_ctrl;

    pthread_rwlock_t config_mutex;

    sync_thread_global_t syncip;
    etsili_generic_freelist_t *syncgenericfreelist;

    //support_thread_global_t *exporters;

    seqtracker_thread_data_t *seqtrackers;
    openli_encoder_t *encoders;
    forwarding_thread_data_t *forwarders;
    openli_email_worker_t *emailworkers;
    openli_gtp_worker_t *gtpworkers;
    openli_sip_worker_t *sipworkers;
    colthread_local_t *collocals;
    int nextloc;

    char *configfile;
    collector_identity_t sharedinfo;
    pthread_rwlock_t sipconfig_mutex;
    collector_sip_config_t sipconfig;
    libtrace_list_t *expired_inputs;

    coreserver_t *alumirrors;
    coreserver_t *jmirrors;
    coreserver_t *ciscomirrors;

    pthread_t seqproxy_tid;

    uint32_t stat_frequency;
    uint64_t ticks_since_last_stat;
    collector_stats_t stats;
    pthread_mutex_t stats_mutex;

    uint8_t etsitls;

    uint8_t encoding_method;
    openli_ssl_config_t sslconf;
    openli_RMQ_config_t RMQ_conf;
    openli_email_ingest_config_t emailconf;

    pthread_rwlock_t email_config_mutex;
    openli_email_timeouts_t email_timeouts;
    uint8_t mask_imap_creds;
    uint8_t mask_pop3_creds;
    char *default_email_domain;
    string_set_t *email_forwarding_headers;
    uint8_t email_ingest_use_targetid;
    int emailsockfd;
    email_ingestor_state_t *email_ingestor;

    x_input_t *x_inputs;
    pthread_rwlock_t x_input_mutex;

} collector_global_t;

// "dirty" flag that is used to signal when the sync thread has received
// updated collector config from the provisioner that needs to be written
// to disk
extern volatile int config_write_required;


int register_sync_queues(sync_thread_global_t *glob,
        void *recvq, libtrace_message_queue_t *sendq,
        libtrace_thread_t *parent);
void deregister_sync_queues(sync_thread_global_t *glob,
        libtrace_thread_t *t);


// implemented in collector.c
int update_coreserver_fast_filter(colthread_local_t *loc, coreserver_t *cs,
        uint8_t ismirror);
void remove_coreserver_fast_filter(colthread_local_t *loc, coreserver_t *cs,
        uint8_t ismirror);

// implemented in configwriter_collector.c
int emit_collector_config(char *configfile, collector_global_t *conf);
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
