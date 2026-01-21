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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>

#include <libtrace_parallel.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "configparser_collector.h"
#include "collector_sync.h"
#include "collector_push_messaging.h"
#include "ipcc.h"
#include "ipmmcc.h"
#include "sipparsing.h"
#include "alushim_parser.h"
#include "jmirror_parser.h"
#include "cisco_parser.h"
#include "util.h"

volatile int collector_halt = 0;
volatile int reload_config = 0;
volatile int config_write_required = 0;

static void cleanup_signal(int signal UNUSED)
{
    collector_halt = 1;
}

static void reload_signal(int signal UNUSED) {
    reload_config = 1;
}

static void usage(char *prog) {

    fprintf(stderr, "Usage: %s -c configfile\n", prog);
}

static void reset_collector_stats(collector_global_t *glob) {

    glob->stats.packets_dropped = 0;
    glob->stats.packets_accepted = 0;
    glob->stats.packets_intercepted = 0;
    glob->stats.packets_sync_ip = 0;
    glob->stats.packets_sync_voip = 0;
    glob->stats.ipcc_created = 0;
    glob->stats.mobiri_created = 0;
    glob->stats.ipiri_created = 0;
    glob->stats.ipmmcc_created = 0;
    glob->stats.ipmmiri_created = 0;
    glob->stats.emailiri_created = 0;
    glob->stats.emailcc_created = 0;
    glob->stats.bad_sip_packets = 0;
    glob->stats.bad_ip_session_packets = 0;

    glob->stats.ipintercepts_added_diff = 0;
    glob->stats.voipintercepts_added_diff = 0;
    glob->stats.emailintercepts_added_diff = 0;
    glob->stats.ipintercepts_ended_diff = 0;
    glob->stats.voipintercepts_ended_diff = 0;
    glob->stats.emailintercepts_ended_diff = 0;
    glob->stats.ipsessions_added_diff = 0;
    glob->stats.voipsessions_added_diff = 0;
    glob->stats.emailsessions_added_diff = 0;
    glob->stats.ipsessions_ended_diff = 0;
    glob->stats.voipsessions_ended_diff = 0;
    glob->stats.emailsessions_ended_diff = 0;
}

static void log_collector_stats(collector_global_t *glob) {
    if (glob->stat_frequency > 1) {
        logger(LOG_INFO,
                "OpenLI: Collector statistics for the last %u minutes:",
                glob->stat_frequency);
    } else {
        logger(LOG_INFO,
                "OpenLI: Collector statistics for the last minute:");
    }
    logger(LOG_INFO, "OpenLI: Packets... captured: %lu    dropped: %lu   intercepted: %lu",
            glob->stats.packets_accepted, glob->stats.packets_dropped,
            glob->stats.packets_intercepted);
    logger(LOG_INFO, "OpenLI: Packets sent to IP sync: %lu",
            glob->stats.packets_sync_ip);
    logger(LOG_INFO, "OpenLI: Packets sent to SIP workers: %lu",
            glob->stats.packets_sync_voip);
    logger(LOG_INFO, "OpenLI: Packets sent to Email workers: %lu",
            glob->stats.packets_sync_email);
    logger(LOG_INFO, "OpenLI: Packets sent to GTP workers: %lu",
            glob->stats.packets_gtp);
    logger(LOG_INFO, "OpenLI: Bad SIP packets: %lu   Bad RADIUS packets: %lu",
            glob->stats.bad_sip_packets, glob->stats.bad_ip_session_packets);
    logger(LOG_INFO, "OpenLI: Records created... IPCCs: %lu  IPIRIs: %lu  MobIRIs: %lu",
            glob->stats.ipcc_created, glob->stats.ipiri_created,
            glob->stats.mobiri_created);
    logger(LOG_INFO, "OpenLI: Records created... IPMMCCs: %lu  IPMMIRIs: %lu",
            glob->stats.ipmmcc_created, glob->stats.ipmmiri_created);
    logger(LOG_INFO, "OpenLI: Records created... EmailCCs: %lu  EmailIRIs: %lu",
            glob->stats.emailcc_created, glob->stats.emailiri_created);

    logger(LOG_INFO, "OpenLI: IP intercepts added: %lu  (all-time: %lu)",
            glob->stats.ipintercepts_added_diff,
            glob->stats.ipintercepts_added_total);
    logger(LOG_INFO, "OpenLI: IP intercepts ended: %lu  (all-time: %lu)",
            glob->stats.ipintercepts_ended_diff,
            glob->stats.ipintercepts_ended_total);

    logger(LOG_INFO, "OpenLI: VOIP intercepts added: %lu  (all-time: %lu)",
            glob->stats.voipintercepts_added_diff,
            glob->stats.voipintercepts_added_total);
    logger(LOG_INFO, "OpenLI: VOIP intercepts ended: %lu  (all-time: %lu)",
            glob->stats.voipintercepts_ended_diff,
            glob->stats.voipintercepts_ended_total);

    logger(LOG_INFO, "OpenLI: Email intercepts added: %lu  (all-time: %lu)",
            glob->stats.emailintercepts_added_diff,
            glob->stats.emailintercepts_added_total);
    logger(LOG_INFO, "OpenLI: Email intercepts ended: %lu  (all-time: %lu)",
            glob->stats.emailintercepts_ended_diff,
            glob->stats.emailintercepts_ended_total);

    logger(LOG_INFO, "OpenLI: IP sessions added: %lu  (all-time: %lu)",
            glob->stats.ipsessions_added_diff,
            glob->stats.ipsessions_added_total);
    logger(LOG_INFO, "OpenLI: IP sessions ended: %lu  (all-time: %lu)",
            glob->stats.ipsessions_ended_diff,
            glob->stats.ipsessions_ended_total);

    logger(LOG_INFO, "OpenLI: VOIP sessions added: %lu  (all-time: %lu)",
            glob->stats.voipsessions_added_diff,
            glob->stats.voipsessions_added_total);
    logger(LOG_INFO, "OpenLI: VOIP sessions ended: %lu  (all-time: %lu)",
            glob->stats.voipsessions_ended_diff,
            glob->stats.voipsessions_ended_total);

    logger(LOG_INFO, "OpenLI: Email sessions added: %lu  (all-time: %lu)",
            glob->stats.emailsessions_added_diff,
            glob->stats.emailsessions_added_total);
    logger(LOG_INFO, "OpenLI: Email sessions ended: %lu  (all-time: %lu)",
            glob->stats.emailsessions_ended_diff,
            glob->stats.emailsessions_ended_total);

    logger(LOG_INFO, "OpenLI: === statistics complete ===");
}

static void free_coreserver_fast_filters(colthread_local_t *loc) {
    coreserver_fast_filter_v4_t *fast, *tmp;

    HASH_ITER(hh, loc->cs_v4_fast_filter, fast, tmp) {
        HASH_DELETE(hh, loc->cs_v4_fast_filter, fast);
        free(fast);
    }

}

static int fast_coreserver_check(colthread_local_t *loc, packet_info_t *pinfo) {
    coreserver_fast_filter_v4_t *fast;

    if (pinfo->family == AF_INET) {
        struct sockaddr_in *sa;
        sa = (struct sockaddr_in *)(&(pinfo->destip));

        HASH_FIND(hh, loc->cs_v4_fast_filter, &(sa->sin_addr.s_addr),
                sizeof(uint32_t), fast);
        if (fast) {
            return 1;
        }
        sa = (struct sockaddr_in *)(&(pinfo->srcip));

        HASH_FIND(hh, loc->cs_v4_fast_filter, &(sa->sin_addr.s_addr),
                sizeof(uint32_t), fast);
        if (fast) {
            return 1;
        }
    }

    return 0;

}

int update_coreserver_fast_filter(colthread_local_t *loc, coreserver_t *cs,
        uint8_t ismirror) {
    coreserver_fast_filter_v4_t *fast;

    if (cs->info == NULL) {
        if (prepare_coreserver(cs) < 0) {
            return -1;
        }
    }
    if (cs->info->ai_family == AF_INET) {
        HASH_FIND(hh, loc->cs_v4_fast_filter,
                &(CS_TO_V4(cs)->sin_addr.s_addr), sizeof(uint32_t), fast);
        if (fast) {
            fast->refcount ++;
            if (ismirror) {
                fast->mirrorrefs ++;
            }
            return 0;
        }
        fast = calloc(1, sizeof(coreserver_fast_filter_v4_t));
        fast->server_ipv4 = CS_TO_V4(cs)->sin_addr.s_addr;
        fast->refcount = 1;
        if (ismirror) {
            fast->mirrorrefs = 1;
        } else {
            fast->mirrorrefs = 0;
        }

        HASH_ADD_KEYPTR(hh, loc->cs_v4_fast_filter, &(fast->server_ipv4),
                sizeof(uint32_t), fast);
    }
    return 0;
}

void remove_coreserver_fast_filter(colthread_local_t *loc, coreserver_t *cs,
        uint8_t ismirror) {
    coreserver_fast_filter_v4_t *fast;

    if (cs->info == NULL) {
        return;
    }

    if (cs->info->ai_family == AF_INET) {
        HASH_FIND(hh, loc->cs_v4_fast_filter,
                &(CS_TO_V4(cs)->sin_addr.s_addr), sizeof(uint32_t), fast);
        if (!fast) {
            /* shouldn't happen? */
            return;
        }

        if (ismirror) {
            fast->mirrorrefs --;
        }
        fast->refcount --;
        if (fast->refcount == 0) {
            HASH_DELETE(hh, loc->cs_v4_fast_filter, fast);
            free(fast);
        }
    }
    return ;
}

static void populate_coreserver_fast_filters_from_global(colthread_local_t *loc,
        collector_global_t *glob) {

    coreserver_t *cs, *tmp;

    HASH_ITER(hh, glob->alumirrors, cs, tmp) {
        if (update_coreserver_fast_filter(loc, cs, 1) < 0) {
            HASH_DELETE(hh, glob->alumirrors, cs);
        }
    }

    HASH_ITER(hh, glob->jmirrors, cs, tmp) {
        if (update_coreserver_fast_filter(loc, cs, 1) < 0) {
            HASH_DELETE(hh, glob->jmirrors, cs);
        }
    }

    HASH_ITER(hh, glob->ciscomirrors, cs, tmp) {
        if (update_coreserver_fast_filter(loc, cs, 1) < 0) {
            HASH_DELETE(hh, glob->ciscomirrors, cs);
        }
    }
}

static void remove_mirrors_from_coreserver_fast_filters(colthread_local_t *loc)
{
    coreserver_fast_filter_v4_t *fast, *tmp;

    HASH_ITER(hh, loc->cs_v4_fast_filter, fast, tmp) {
        if (fast->mirrorrefs > fast->refcount) {
            HASH_DELETE(hh, loc->cs_v4_fast_filter, fast);
            free(fast);
            continue;
        }
        fast->refcount -= fast->mirrorrefs;
        fast->mirrorrefs = 0;

        if (fast->refcount == 0) {
            HASH_DELETE(hh, loc->cs_v4_fast_filter, fast);
            free(fast);
        }
    }

}

static void process_incoming_messages(colthread_local_t *loc,
        openli_pushed_t *syncpush, collector_global_t *glob) {

    if (syncpush->type == OPENLI_PUSH_HUP_RELOAD) {
        remove_mirrors_from_coreserver_fast_filters(loc);
        pthread_rwlock_rdlock(&(glob->config_mutex));
        populate_coreserver_fast_filters_from_global(loc, glob);
        pthread_rwlock_unlock(&(glob->config_mutex));

    }

    if (syncpush->type == OPENLI_PUSH_IPINTERCEPT) {
        handle_push_ipintercept(loc, syncpush->data.ipsess);
    }

    if (syncpush->type == OPENLI_PUSH_HALT_IPINTERCEPT) {
        handle_halt_ipintercept(loc, syncpush->data.ipsess);
    }

    if (syncpush->type == OPENLI_PUSH_IPMMINTERCEPT) {
        handle_push_ipmmintercept(loc, syncpush->data.ipmmint);
    }

    if (syncpush->type == OPENLI_PUSH_HALT_IPMMINTERCEPT) {
        handle_halt_ipmmintercept(loc, syncpush->data.rtpstreamkey);
    }

    if (syncpush->type == OPENLI_PUSH_CORESERVER) {
        handle_push_coreserver(loc, syncpush->data.coreserver);
    }

    if (syncpush->type == OPENLI_PUSH_REMOVE_CORESERVER) {
        handle_remove_coreserver(loc, syncpush->data.coreserver);
    }

    if (syncpush->type == OPENLI_PUSH_VENDMIRROR_INTERCEPT) {
        handle_push_mirror_intercept(loc, syncpush->data.mirror);
    }

    if (syncpush->type == OPENLI_PUSH_HALT_VENDMIRROR_INTERCEPT) {
        handle_halt_mirror_intercept(loc, syncpush->data.mirror);
    }

    if (syncpush->type == OPENLI_PUSH_IPRANGE) {
        handle_iprange(loc, syncpush->data.iprange);
    }

    if (syncpush->type == OPENLI_PUSH_REMOVE_IPRANGE) {
        handle_remove_iprange(loc, syncpush->data.iprange);
    }

    if (syncpush->type == OPENLI_PUSH_MODIFY_IPRANGE) {
        handle_modify_iprange(loc, syncpush->data.iprange);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_VOIPINTERCEPT) {
        handle_change_voip_intercept(loc, syncpush->data.ipmmint);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_IPINTERCEPT) {
        handle_change_ipint_intercept(loc, syncpush->data.ipsess);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_VENDMIRROR_INTERCEPT) {
        handle_change_vendmirror_intercept(loc, syncpush->data.mirror);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_IPRANGE_INTERCEPT) {
        handle_change_iprange_intercept(loc, syncpush->data.iprange);
    }

}

#define PACKETS_PER_READ_THRESH 100

static void check_for_messages(colthread_local_t *loc,
        collector_global_t *glob) {
    openli_pushed_t syncpush;
    int i;

    /* Check for any messages from the sync threads */
    while (libtrace_message_queue_try_get(&(loc->fromsyncq_ip),
            (void *)&syncpush) != LIBTRACE_MQ_FAILED) {

        process_incoming_messages(loc, &syncpush, glob);
    }

    for (i = 0; i < loc->gtpq_count; i++) {
        while (libtrace_message_queue_try_get(&(loc->fromgtp_queues[i]),
                (void *)&syncpush) != LIBTRACE_MQ_FAILED) {

            process_incoming_messages(loc, &syncpush, glob);
        }
    }

    for (i = 0; i < loc->sipq_count; i++) {
        while (libtrace_message_queue_try_get(&(loc->fromsip_queues[i]),
                (void *)&syncpush) != LIBTRACE_MQ_FAILED) {

            process_incoming_messages(loc, &syncpush, glob);
        }
    }
    loc->pkts_since_msg_read = 0;
}

static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, uint64_t tick) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)local;
    libtrace_stat_t *stats;
    struct timeval tv;

    check_for_messages(loc, glob);
    loc->tick_counter ++;
    if (loc->tick_counter < 100) {
        return;
    }
    loc->tick_counter = 0;

    if (trace_get_perpkt_thread_id(t) == 0) {

	gettimeofday(&tv, NULL);
        stats = trace_create_statistics();
        trace_get_statistics(trace, stats);

	if (tv.tv_sec - loc->startedat > 1) {
	    /* ignore drops in the first second -- they probably happened
	     * while our processing threads were starting because of the order
	     * that libtrace does all the tasks necessary to start an input.
	     */
            pthread_mutex_lock(&(glob->stats_mutex));
            glob->stats.packets_dropped += (stats->dropped - loc->dropped);
            glob->stats.packets_accepted += (stats->accepted - loc->accepted);
            pthread_mutex_unlock(&(glob->stats_mutex));

            if (stats->dropped > loc->dropped) {
                logger(LOG_INFO,
                        "%lu dropped %lu packets in last second (accepted %lu)",
                        (tick >> 32),
                        stats->dropped - loc->dropped,
                        stats->accepted - loc->accepted);
            }
	}
        loc->dropped = stats->dropped;

        pthread_rwlock_rdlock(&(glob->config_mutex));
        if (glob->stat_frequency > 0) {
            glob->ticks_since_last_stat ++;

            if (glob->ticks_since_last_stat >= glob->stat_frequency * 60) {
                pthread_mutex_lock(&(glob->stats_mutex));
                log_collector_stats(glob);
                reset_collector_stats(glob);
                pthread_mutex_unlock(&(glob->stats_mutex));
                glob->ticks_since_last_stat = 0;
            }
        }
        pthread_rwlock_unlock(&(glob->config_mutex));
        loc->accepted = stats->accepted;
        free(stats);
    }
}

static void init_collocal(colthread_local_t *loc, collector_global_t *glob) {

    int i, hwm=1000;
    libtrace_message_queue_init(&(loc->fromsyncq_ip),
            sizeof(openli_pushed_t));

    loc->activeipv4intercepts = NULL;
    loc->activeipv6intercepts = NULL;
    loc->activertpintercepts = NULL;
    loc->activemirrorintercepts = NULL;
    loc->activestaticintercepts = NULL;
    loc->radiusservers = NULL;
    loc->gtpservers = NULL;
    loc->sipservers = NULL;
    loc->smtpservers = NULL;
    loc->imapservers = NULL;
    loc->pop3servers = NULL;
    loc->cs_v4_fast_filter = NULL;
    loc->staticv4ranges = New_Patricia(32);
    loc->staticv6ranges = New_Patricia(128);
    loc->dynamicv6ranges = New_Patricia(128);
    loc->staticcache = NULL;
    loc->tosyncq_ip = NULL;

    loc->accepted = 0;
    loc->dropped = 0;
    loc->pkts_since_msg_read = 0;
    loc->tick_counter = 0;


    loc->zmq_pubsocks = calloc(glob->seqtracker_threads, sizeof(void *));
    for (i = 0; i < glob->seqtracker_threads; i++) {
        char pubsockname[128];

        snprintf(pubsockname, 128, "inproc://openlipub-%d", i);
        loc->zmq_pubsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        zmq_setsockopt(loc->zmq_pubsocks[i], ZMQ_SNDHWM, &hwm, sizeof(hwm));
        zmq_connect(loc->zmq_pubsocks[i], pubsockname);
    }

    if (glob->email_threads > 0) {
        loc->email_worker_queues = calloc(glob->email_threads, sizeof(void *));
        for (i = 0; i < glob->email_threads; i++) {
            char pubsockname[128];

            snprintf(pubsockname, 128, "inproc://openliemailworker-colrecv%d",
                    i);
            loc->email_worker_queues[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
            zmq_setsockopt(loc->email_worker_queues[i], ZMQ_SNDHWM, &hwm,
                    sizeof(hwm));
            zmq_connect(loc->email_worker_queues[i], pubsockname);
        }
    } else {
        loc->email_worker_queues = NULL;
    }

    if (glob->sip_threads > 0) {
        loc->sip_worker_queues = calloc(glob->sip_threads, sizeof(void *));
        loc->fromsip_queues = calloc(glob->sip_threads,
                sizeof(libtrace_message_queue_t));

        for (i = 0; i < glob->sip_threads; i++) {
            char pubsockname[128];

            snprintf(pubsockname, 128, "inproc://openlisipworker-colrecv-%d",
                    i);
            loc->sip_worker_queues[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
            zmq_setsockopt(loc->sip_worker_queues[i], ZMQ_SNDHWM, &hwm,
                    sizeof(hwm));
            zmq_connect(loc->sip_worker_queues[i], pubsockname);
            libtrace_message_queue_init(&(loc->fromsip_queues[i]),
                    sizeof(openli_pushed_t));
        }
        loc->sipq_count = glob->sip_threads;
    } else {
        loc->sip_worker_queues = NULL;
        loc->fromsip_queues = NULL;
        loc->sipq_count = 0;
    }

    if (glob->gtp_threads > 0) {
        loc->fromgtp_queues = calloc(glob->gtp_threads,
                sizeof(libtrace_message_queue_t));

        loc->gtp_worker_queues = calloc(glob->gtp_threads, sizeof(void *));
        for (i = 0; i < glob->gtp_threads; i++) {
            char pubsockname[128];

            snprintf(pubsockname, 128, "inproc://openligtpworker-colrecv%d", i);
            loc->gtp_worker_queues[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
            zmq_setsockopt(loc->gtp_worker_queues[i], ZMQ_SNDHWM, &hwm,
                    sizeof(hwm));
            zmq_connect(loc->gtp_worker_queues[i], pubsockname);

            libtrace_message_queue_init(&(loc->fromgtp_queues[i]),
                    sizeof(openli_pushed_t));
        }
        loc->gtpq_count = glob->gtp_threads;
    } else {
        loc->gtpq_count = 0;
        loc->fromgtp_queues = NULL;
        loc->gtp_worker_queues = NULL;
    }

    loc->fragreass = create_new_ipfrag_reassembler();

    loc->tosyncq_ip = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    zmq_setsockopt(loc->tosyncq_ip, ZMQ_SNDHWM, &hwm, sizeof(hwm));
    zmq_connect(loc->tosyncq_ip, "inproc://openli-ipsync");

}

static void *start_processing_thread(libtrace_t *trace,
        libtrace_thread_t *t, void *global) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = NULL;
    int i;
    sync_sendq_t *syncq, *sendq_hash;
    struct timeval tv;
    char locname[1024];

    snprintf(locname, 1024, "%s-%s-%d", trace_get_uri_format(trace),
            trace_get_uri_body(trace), trace_get_perpkt_thread_id(t));

    pthread_rwlock_wrlock(&(glob->config_mutex));
    HASH_FIND(hh, glob->collocals, locname, strlen(locname), loc);
    if (!loc) {
        loc = calloc(1, sizeof(colthread_local_t));
        init_collocal(loc, glob);
        loc->localname = strdup(locname);
        HASH_ADD_KEYPTR(hh, glob->collocals, loc->localname,
                strlen(loc->localname), loc);
    } else {
        init_collocal(loc, glob);
    }

    populate_coreserver_fast_filters_from_global(loc, glob);

    pthread_rwlock_unlock(&(glob->config_mutex));

    register_sync_queues(&(glob->syncip), loc->tosyncq_ip,
			&(loc->fromsyncq_ip), t);

    for (i = 0; i < glob->gtp_threads; i++) {
        syncq = (sync_sendq_t *)malloc(sizeof(sync_sendq_t));
        syncq->q = &(loc->fromgtp_queues[i]);
        syncq->parent = t;

        pthread_mutex_lock(&(glob->gtpworkers[i].col_queue_mutex));

        sendq_hash = (sync_sendq_t *)(glob->gtpworkers[i].collector_queues);
        HASH_ADD_PTR(sendq_hash, parent, syncq);
        glob->gtpworkers[i].collector_queues = (void *)sendq_hash;

        pthread_mutex_unlock(&(glob->gtpworkers[i].col_queue_mutex));
    }

    for (i = 0; i < glob->sip_threads; i++) {
        syncq = (sync_sendq_t *)malloc(sizeof(sync_sendq_t));
        syncq->q = &(loc->fromsip_queues[i]);
        syncq->parent = t;

        pthread_mutex_lock(&(glob->sipworkers[i].col_queue_mutex));

        sendq_hash = (sync_sendq_t *)(glob->sipworkers[i].collector_queues);
        HASH_ADD_PTR(sendq_hash, parent, syncq);
        glob->sipworkers[i].collector_queues = (void *)sendq_hash;

        pthread_mutex_unlock(&(glob->sipworkers[i].col_queue_mutex));
    }
    gettimeofday(&tv, NULL);
    loc->startedat = tv.tv_sec;

    return loc;
}

static void free_staticrange_data(void *data) {
    liid_set_t *all, *iter, *tmp;

    all = (liid_set_t *)data;
    HASH_ITER(hh, all, iter, tmp) {
        HASH_DELETE(hh, all, iter);
        free(iter->liid);
        free(iter->key);
        free(iter);
    }
}

static void free_staticcache(static_ipcache_t *cache) {
    static_ipcache_t *ent, *tmp;

    HASH_ITER(hh, cache, ent, tmp) {
        HASH_DELETE(hh, cache, ent);
        free(ent);
    }
}

static void stop_processing_thread(libtrace_t *trace UNUSED,
        libtrace_thread_t *t, void *global, void *tls) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)tls;
    ipv4_target_t *v4, *tmp;
    ipv6_target_t *v6, *tmp2;
    openli_pushed_t syncpush;
    int zero = 0, i;
    sync_sendq_t *syncq, *sendq_hash;

    while (libtrace_message_queue_try_get(&(loc->fromsyncq_ip),
            (void *)&syncpush) != LIBTRACE_MQ_FAILED) {
        process_incoming_messages(loc, &syncpush, glob);
    }

    deregister_sync_queues(&(glob->syncip), t);

    libtrace_message_queue_destroy(&(loc->fromsyncq_ip));

    for (i = 0; i < glob->seqtracker_threads; i++) {
        zmq_setsockopt(loc->zmq_pubsocks[i], ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(loc->zmq_pubsocks[i]);
    }

    for (i = 0; i < glob->email_threads; i++) {
        zmq_setsockopt(loc->email_worker_queues[i], ZMQ_LINGER, &zero,
                sizeof(zero));
        zmq_close(loc->email_worker_queues[i]);
    }

    for (i = 0; i < glob->gtp_threads; i++) {
        openli_gtp_worker_t *worker;

        worker = &(glob->gtpworkers[i]);

        zmq_setsockopt(loc->gtp_worker_queues[i], ZMQ_LINGER, &zero,
                sizeof(zero));
        zmq_close(loc->gtp_worker_queues[i]);

        while (libtrace_message_queue_try_get(&(loc->fromgtp_queues[i]),
                    (void *)&syncpush) != LIBTRACE_MQ_FAILED) {
            process_incoming_messages(loc, &syncpush, glob);
        }
        pthread_mutex_lock(&(worker->col_queue_mutex));
        sendq_hash = (sync_sendq_t *)(worker->collector_queues);

        HASH_FIND_PTR(sendq_hash, &t, syncq);
        if (syncq) {
            HASH_DELETE(hh, sendq_hash, syncq);
            free(syncq);
            worker->collector_queues = (void *)sendq_hash;
        }
        pthread_mutex_unlock(&(worker->col_queue_mutex));

        libtrace_message_queue_destroy(&(loc->fromgtp_queues[i]));
    }

    for (i = 0; i < glob->sip_threads; i++) {
        openli_sip_worker_t *sipworker;

        sipworker = &(glob->sipworkers[i]);
        zmq_setsockopt(loc->sip_worker_queues[i], ZMQ_LINGER, &zero,
                sizeof(zero));
        zmq_close(loc->sip_worker_queues[i]);
        while (libtrace_message_queue_try_get(&(loc->fromsip_queues[i]),
                    (void *)&syncpush) != LIBTRACE_MQ_FAILED) {
            process_incoming_messages(loc, &syncpush, glob);
        }
        pthread_mutex_lock(&(sipworker->col_queue_mutex));
        sendq_hash = (sync_sendq_t *)(sipworker->collector_queues);

        HASH_FIND_PTR(sendq_hash, &t, syncq);
        if (syncq) {
            HASH_DELETE(hh, sendq_hash, syncq);
            free(syncq);
            sipworker->collector_queues = (void *)sendq_hash;
        }
        pthread_mutex_unlock(&(sipworker->col_queue_mutex));

        libtrace_message_queue_destroy(&(loc->fromsip_queues[i]));
    }

    zmq_setsockopt(loc->tosyncq_ip, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_close(loc->tosyncq_ip);

    if (loc->fromgtp_queues) {
        free(loc->fromgtp_queues);
    }
    if (loc->fromsip_queues) {
        free(loc->fromsip_queues);
    }
    free(loc->zmq_pubsocks);
    if (loc->email_worker_queues) {
        free(loc->email_worker_queues);
    }
    if (loc->gtp_worker_queues) {
        free(loc->gtp_worker_queues);
    }
    if (loc->sip_worker_queues) {
        free(loc->sip_worker_queues);
    }

    HASH_ITER(hh, loc->activeipv4intercepts, v4, tmp) {
        free_all_ipsessions(&(v4->intercepts));
        HASH_DELETE(hh, loc->activeipv4intercepts, v4);
        free(v4);
    }

    HASH_ITER(hh, loc->activeipv6intercepts, v6, tmp2) {
        free_all_ipsessions(&(v6->intercepts));
        HASH_DELETE(hh, loc->activeipv6intercepts, v6);
        free(v6->prefixstr);
        free(v6);
    }


    free_all_staticipsessions(&(loc->activestaticintercepts));
    free_all_rtpstreams(&(loc->activertpintercepts));
    free_all_vendmirror_intercepts(&(loc->activemirrorintercepts));
    free_coreserver_list(loc->radiusservers);
    free_coreserver_list(loc->gtpservers);
    free_coreserver_list(loc->sipservers);
    free_coreserver_list(loc->smtpservers);
    free_coreserver_list(loc->imapservers);
    free_coreserver_list(loc->pop3servers);
    free_coreserver_fast_filters(loc);

    destroy_ipfrag_reassembler(loc->fragreass);

    Destroy_Patricia(loc->staticv4ranges, free_staticrange_data);
    Destroy_Patricia(loc->staticv6ranges, free_staticrange_data);
    Destroy_Patricia(loc->dynamicv6ranges, free_staticrange_data);

    free_staticcache(loc->staticcache);

}

static inline void send_packet_to_sync(libtrace_packet_t *pkt,
        void *q, uint8_t updatetype) {
    openli_state_update_t syncup;
    libtrace_packet_t *copy;

    if (collector_halt) {
        return;
    }

    /* We do this ourselves instead of calling trace_copy_packet() because
     * we don't want to be allocating 64K per copied packet -- we could be
     * doing this a lot and don't want to be wasteful */
    copy = openli_copy_packet(pkt);
    if (copy == NULL) {
        return;
    }

    syncup.type = updatetype;
    syncup.data.pkt = copy;

    //trace_increment_packet_refcount(pkt);
    zmq_send(q, (void *)(&syncup), sizeof(syncup), 0);
}

static void send_packet_to_emailworker(libtrace_packet_t *pkt,
        void **queues, int qcount, uint32_t hashval, uint8_t pkttype) {

    int destind;

    if (qcount == 0) {
        return;
    }
    assert(hashval != 0);
    destind = (hashval - 1) % qcount;
    send_packet_to_sync(pkt, queues[destind], pkttype);
}

static void add_payload_info_from_packet(libtrace_packet_t *pkt,
        packet_info_t *pinfo) {
    void *transport, *payload;
    uint32_t plen;
    uint8_t proto;
    uint32_t rem;

    if (pinfo->trans_proto != 0) {
        /* already looked this up */
        return;
    }

    transport = trace_get_transport(pkt, &proto, &rem);

    if (transport == NULL || rem == 0) {
        pinfo->trans_proto = 255;
        return;
    }

    pinfo->trans_proto = proto;
    plen = trace_get_payload_length(pkt);

    if (proto == TRACE_IPPROTO_UDP) {
        payload = trace_get_payload_from_udp((libtrace_udp_t *)transport,
                &rem);
        if (payload == NULL) {
            return;
        }
    } else if (proto == TRACE_IPPROTO_TCP) {
        payload = trace_get_payload_from_tcp((libtrace_tcp_t *)transport,
                &rem);
        if (payload == NULL) {
            return;
        }
    } else {
        return;
    }

    pinfo->payload_ptr = payload;
    if (plen <= rem) {
        pinfo->payload_len = plen;
    } else {
        pinfo->payload_len = rem;
    }

}

static inline uint8_t check_for_invalid_sip(packet_info_t *pinfo,
        uint16_t fragoff) {

    uint32_t fourbytes;

    /* STUN can be sent by clients to the SIP servers, so try to detect
     * that.
     *
     * Typical examples so far: 20 byte UDP, with payload beginning with
     * 00 01 00 00.
     */
    if (fragoff > 0) {
        return 0;
    }

    if (pinfo->trans_proto != TRACE_IPPROTO_UDP) {
        return 0;
    }

    if (pinfo->payload_len < 20 || pinfo->payload_ptr == NULL) {
        return 0;
    }
    fourbytes = ntohl(*((uint32_t *)pinfo->payload_ptr));

    /* STUN matching borrowed from libprotoident */
    if ((fourbytes & 0xffff) == pinfo->payload_len - 20) {
        if ((fourbytes & 0xffff0000) == 0x00010000) {
            return 1;
        }

        if ((fourbytes & 0xffff0000) == 0x01010000) {
            return 1;
        }

        if ((fourbytes & 0xffff0000) == 0x01110000) {
            return 1;
        }

        if ((fourbytes & 0xffff0000) == 0x00030000) {
            return 1;
        }

        if ((fourbytes & 0xffff0000) == 0x01030000) {
            return 1;
        }

        if ((fourbytes & 0xffff0000) == 0x01130000) {
            return 1;
        }
    }

    return 0;
}

static inline uint32_t is_core_server_packet(
        packet_info_t *pinfo, coreserver_t *servers, uint8_t hashrequired) {

    coreserver_t *found = NULL;
    uint32_t hashval = 0;

    found = match_packet_to_coreserver(servers, pinfo, 0);

    /* Doesn't match any of our known core servers */
    if (found == NULL) {
        return 0;
    }

    /* Not technically an LIID, but we just need a hashed ID for the server
     * entity.
     */
    if (hashrequired) {
        hashval = hash_liid(found->serverkey);
        /* 0 is our value for "not found", so make sure we never use it... */
        if (hashval == 0) {
            hashval = 1;
        }
    } else {
        hashval = 1;
    }

    return hashval;

}

static uint8_t check_if_gtp(packet_info_t *pinfo, libtrace_packet_t *pkt,
        colthread_local_t *loc, collector_global_t *glob) {

    uint32_t fwdto = 0;
    uint8_t msgtype;
    gtpv1_header_t *v1_hdr;
    gtpv2_header_teid_t *v2_hdr;

    if (loc->gtpservers == NULL) {
        return 0;
    }

    if (glob->gtp_threads == 0) {
        return 0;
    }

    if ( !is_core_server_packet(pinfo, loc->gtpservers, 0)) {
        return 0;
    }

    add_payload_info_from_packet(pkt, pinfo);
    if (pinfo->payload_len == 0) {
        return 0;
    }

    if (loc->gtpq_count > 1) {
        /* check GTP version */
        if (((*(pinfo->payload_ptr)) & 0xe8) == 0x48) {
            /* GTPv2 */
            if (pinfo->payload_len < sizeof(gtpv2_header_teid_t)) {
                return 0;
            }
            v2_hdr = (gtpv2_header_teid_t *)pinfo->payload_ptr;
            msgtype = v2_hdr->msgtype;

            /*
            fwdto = hashlittle(&(v2_hdr->teid), sizeof(v2_hdr->teid),
                    312267023) % loc->gtpq_count;
            */

        } else if (((*(pinfo->payload_ptr)) & 0xe0) == 0x20) {
            /* GTPv1 */
            if (pinfo->payload_len < sizeof(gtpv1_header_t)) {
                return 0;
            }

            v1_hdr = (gtpv1_header_t *)pinfo->payload_ptr;
            msgtype = v1_hdr->msgtype;

            /*
            fwdto = hashlittle(&(v1_hdr->teid), sizeof(v1_hdr->teid),
                    312267023) % loc->gtpq_count;
            */

        } else {
            return 0;
        }

        switch(msgtype) {
            case GTPV1_CREATE_PDP_CONTEXT_REQUEST:
            case GTPV1_UPDATE_PDP_CONTEXT_REQUEST:
            case GTPV1_DELETE_PDP_CONTEXT_REQUEST:
            case GTPV2_CREATE_SESSION_REQUEST:
            case GTPV2_DELETE_SESSION_REQUEST:
                fwdto = hashlittle(&(pinfo->srcip),
                        sizeof(struct sockaddr_storage), 312267023) %
                        loc->gtpq_count;
                break;
            case GTPV1_CREATE_PDP_CONTEXT_RESPONSE:
            case GTPV1_UPDATE_PDP_CONTEXT_RESPONSE:
            case GTPV1_DELETE_PDP_CONTEXT_RESPONSE:
            case GTPV2_CREATE_SESSION_RESPONSE:
            case GTPV2_DELETE_SESSION_RESPONSE:
                fwdto = hashlittle(&(pinfo->destip),
                        sizeof(struct sockaddr_storage), 312267023) %
                        loc->gtpq_count;
                break;
            default:
                fwdto = 0;
        }
    }

    send_packet_to_sync(pkt, loc->gtp_worker_queues[fwdto], OPENLI_UPDATE_GTP);

    pthread_mutex_lock(&(glob->stats_mutex));
    glob->stats.packets_gtp ++;
    pthread_mutex_unlock(&(glob->stats_mutex));
    return 1;
}

static libtrace_packet_t *process_packet(libtrace_t *trace,
        libtrace_thread_t *t, void *global, void *tls,
        libtrace_packet_t *pkt) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)tls;
    void *l3;
    uint16_t ethertype;
    uint32_t rem, iprem;
    uint8_t proto;
    int forwarded = 0, ret;
    int ipsynced = 0, voipsynced = 0, emailsynced = 0;
    uint16_t fragoff = 0, offset;
    uint32_t servhash = 0;

    packet_info_t pinfo;

	//check_for_messages(loc, glob);

    //loc->pkts_since_msg_read ++;
    l3 = trace_get_layer3(pkt, &ethertype, &rem);
    if (l3 == NULL || rem == 0) {
        return pkt;
    }

    //trace_increment_packet_refcount(pkt);
    memset(&pinfo, 0, sizeof(pinfo));
    pinfo.tv = trace_get_timeval(pkt);
    iprem = rem;
    if (ethertype == TRACE_ETHERTYPE_IP) {
        uint8_t moreflag;
        ip_reassemble_stream_t *ipstream;
        libtrace_ip_t *ipheader = (libtrace_ip_t *)l3;
        struct sockaddr_in *in4;

        if (rem < ipheader->ip_hl * 4) {
            return pkt;
        }

        in4 = (struct sockaddr_in *)(&(pinfo.srcip));
        in4->sin_addr = ipheader->ip_src;
        in4 = (struct sockaddr_in *)(&(pinfo.destip));
        in4->sin_addr = ipheader->ip_dst;

	offset = ntohs(ipheader->ip_off);
	/* fast check for IP fragmentation */
	if ((offset & 0x2000) || (offset & 0x1FFF)) {
            fragoff = trace_get_fragment_offset(pkt, &moreflag);
            ipstream = get_ipfrag_reassemble_stream(loc->fragreass, pkt);
            if (!ipstream) {
                logger(LOG_INFO, "OpenLI: error trying to reassemble IP fragment in collector.");
                return pkt;
            }

            ret = update_ipfrag_reassemble_stream(ipstream, pkt, fragoff,
                    moreflag);
            if (ret < 0) {
                logger(LOG_INFO, "OpenLI: error while trying to reassemble IP fragment in collector.");
                return pkt;
            }

            if (get_ipfrag_ports(ipstream, &(pinfo.srcport), &(pinfo.destport))
                    < 0) {
                logger(LOG_INFO, "OpenLI: unable to get port numbers from fragmented IP.");
                return pkt;
            }

            if (is_ip_reassembled(ipstream)) {
                remove_ipfrag_reassemble_stream(loc->fragreass, ipstream);
            }
            if (rem <= ipheader->ip_hl * 4) {
                proto = 0;
            } else {
                proto = ipheader->ip_p;
            }

        } else {
            uint8_t *postip = ((uint8_t *)l3) + ipheader->ip_hl * 4;

            pinfo.srcport = ntohs(*((uint16_t *)postip));
            pinfo.destport = ntohs(*((uint16_t *)(postip + 2)));
            proto = ipheader->ip_p;
        }
        pinfo.family = AF_INET;
    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        struct sockaddr_in6 *in6;
        libtrace_ip6_t *ip6header = (libtrace_ip6_t *)l3;
        uint8_t *postip6 = (uint8_t *)(trace_get_payload_from_ip6(ip6header,
                &proto, &rem));

        pinfo.srcport = ntohs(*((uint16_t *)postip6));
        pinfo.destport = ntohs(*((uint16_t *)(postip6 + 2)));
        proto = ip6header->nxt;
        pinfo.family = AF_INET6;

        in6 = (struct sockaddr_in6 *)(&(pinfo.srcip));
        in6->sin6_addr = ip6header->ip_src;
        in6 = (struct sockaddr_in6 *)(&(pinfo.destip));
        in6->sin6_addr = ip6header->ip_dst;
    } else {
        pinfo.srcport = 0;
        pinfo.destport = 0;
        proto = 0;
        pinfo.family = 0;
    }

    if (fast_coreserver_check(loc, &pinfo) == 0) {
        goto skipcoreservers;
    }

    /* All these special packets are UDP, so we can avoid a whole bunch
     * of these checks for TCP traffic */
    if (proto == TRACE_IPPROTO_UDP) {

        /* Is this from one of our ALU mirrors -- if yes, parse + strip it
         * for conversion to an ETSI record */
        if (glob->alumirrors) {
            pthread_rwlock_rdlock(&(glob->config_mutex));
            ret = check_alu_intercept(loc,
                    pkt, &pinfo, glob->alumirrors,
                    loc->activemirrorintercepts);
            pthread_rwlock_unlock(&(glob->config_mutex));
            if (ret > 0) {
                forwarded = 1;
                pthread_mutex_lock(&(glob->stats_mutex));
                glob->stats.ipcc_created += 1;
                pthread_mutex_unlock(&(glob->stats_mutex));
                goto processdone;
            }
            if (ret < 0) {
                goto processdone;
            }
        }

        if (glob->jmirrors) {
            pthread_rwlock_rdlock(&(glob->config_mutex));
            ret = check_jmirror_intercept(loc, pkt, &pinfo, glob->jmirrors,
                    loc->activemirrorintercepts);
            pthread_rwlock_unlock(&(glob->config_mutex));
            if (ret > 0) {
                forwarded = 1;
                pthread_mutex_lock(&(glob->stats_mutex));
                glob->stats.ipcc_created += 1;
                pthread_mutex_unlock(&(glob->stats_mutex));
                goto processdone;
            }
            if (ret < 0) {
                goto processdone;
            }
        }

        if (glob->ciscomirrors) {
            coreserver_t *cs;
            if ((cs = match_packet_to_coreserver(glob->ciscomirrors,
                    &pinfo, 1)) != NULL) {
                if (glob->sharedinfo.cisco_noradius) {
                    pthread_rwlock_rdlock(&(glob->config_mutex));
                    ret = generate_cc_from_cisco(loc, pkt, &pinfo,
                        loc->activemirrorintercepts);
                    pthread_rwlock_unlock(&(glob->config_mutex));
                    if (ret > 0) {
                        forwarded = 1;
                        pthread_mutex_lock(&(glob->stats_mutex));
                        glob->stats.ipcc_created += 1;
                        pthread_mutex_unlock(&(glob->stats_mutex));
                        goto processdone;
                    }
                    if (ret < 0) {
                        goto processdone;
                    }
                } else {
                    /* strip the cisco shim and just treat it like an
                     * ordinary packet -- we'll instead rely on RADIUS
                     * or some other session management protocol to tell
                     * us whether we need to intercept this packet or not.
                     */
                    libtrace_packet_t *stripped;
                    stripped = strip_cisco_mirror_header(pkt);
                    if (stripped) {
                        if (process_packet(trace, t, global, tls,
                                stripped)) {
                            trace_destroy_packet(stripped);
                        }
                    }
                    goto processdone;
                }
            }
        }

        /* Is this a RADIUS packet? -- if yes, create a state update */
        if (loc->radiusservers && is_core_server_packet(&pinfo,
                    loc->radiusservers, 0)) {
            send_packet_to_sync(pkt, loc->tosyncq_ip, OPENLI_UPDATE_RADIUS);
            ipsynced = 1;
            goto processdone;
        }

        check_if_gtp(&pinfo, pkt, loc, glob);

        /* Is this a SIP packet? -- if yes, create a state update */
        if (loc->sipservers && is_core_server_packet(&pinfo,
                    loc->sipservers, 0)) {

            add_payload_info_from_packet(pkt, &pinfo);
            if (!check_for_invalid_sip(&pinfo, fragoff)) {
                int sipthread;
                if (glob->sip_threads > 1) {
                    sipthread = hash_packet_info_fivetuple(&pinfo,
                            glob->sip_threads);
                } else {
                    sipthread = 0;
                }

                send_packet_to_sync(pkt, loc->sip_worker_queues[sipthread],
                        OPENLI_UPDATE_SIP);
                voipsynced = 1;
            }
        }
    } else if (proto == TRACE_IPPROTO_TCP) {
        /* Is this a SIP packet? -- if yes, create a state update */
        if (loc->sipservers && is_core_server_packet(&pinfo,
                    loc->sipservers, 0)) {

            int sipthread;
            if (glob->sip_threads > 1) {
                sipthread = hash_packet_info_fivetuple(&pinfo,
                        glob->sip_threads);
            } else {
                sipthread = 0;
            }
            send_packet_to_sync(pkt, loc->sip_worker_queues[sipthread],
                    OPENLI_UPDATE_SIP);
            voipsynced = 1;
        }

        else if (loc->smtpservers &&
                (servhash = is_core_server_packet(&pinfo,
                    loc->smtpservers, 1))) {
            send_packet_to_emailworker(pkt, loc->email_worker_queues,
                    glob->email_threads, servhash, OPENLI_UPDATE_SMTP);
            emailsynced = 1;

        }

        else if (loc->imapservers &&
                (servhash = is_core_server_packet(&pinfo,
                    loc->imapservers, 1))) {
            send_packet_to_emailworker(pkt, loc->email_worker_queues,
                    glob->email_threads, servhash, OPENLI_UPDATE_IMAP);
            emailsynced = 1;
        }

        else if (loc->pop3servers &&
                (servhash = is_core_server_packet(&pinfo,
                    loc->pop3servers, 1))) {
            send_packet_to_emailworker(pkt, loc->email_worker_queues,
                    glob->email_threads, servhash, OPENLI_UPDATE_POP3);
            emailsynced = 1;
        }
    }

skipcoreservers:
    if (ethertype == TRACE_ETHERTYPE_IP) {
        /* Is this an IP packet? -- if yes, possible IP CC */
        if ((ret = ipv4_comm_contents(pkt, &pinfo, (libtrace_ip_t *)l3, iprem,
                    loc))) {
            forwarded = 1;
            pthread_mutex_lock(&(glob->stats_mutex));
            glob->stats.ipcc_created += ret;
            pthread_mutex_unlock(&(glob->stats_mutex));
        }

        /* Is this an RTP packet? -- if yes, possible IPMM CC */
        if (proto == TRACE_IPPROTO_UDP) {
            if ((ret = ip4mm_comm_contents(pkt, &pinfo, (libtrace_ip_t *)l3,
                        iprem, loc))) {
                forwarded = 1;
                pthread_mutex_lock(&(glob->stats_mutex));
                glob->stats.ipmmcc_created += ret;
                pthread_mutex_unlock(&(glob->stats_mutex));
            }
        }

    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        /* Is this an IP packet? -- if yes, possible IP CC */
        if ((ret = ipv6_comm_contents(pkt, &pinfo, (libtrace_ip6_t *)l3, iprem,
                    loc))) {
            forwarded = 1;
            pthread_mutex_lock(&(glob->stats_mutex));
            glob->stats.ipcc_created += ret;
            pthread_mutex_unlock(&(glob->stats_mutex));
        }

        if (proto == TRACE_IPPROTO_UDP) {
            if ((ret = ip6mm_comm_contents(pkt, &pinfo, (libtrace_ip6_t *)l3,
                        iprem, loc))) {
                forwarded = 1;
                pthread_mutex_lock(&(glob->stats_mutex));
                glob->stats.ipmmcc_created += ret;
                pthread_mutex_unlock(&(glob->stats_mutex));
            }
        }
    }

processdone:
    if (emailsynced) {
        pthread_mutex_lock(&(glob->stats_mutex));
        glob->stats.packets_sync_email ++;
        pthread_mutex_unlock(&(glob->stats_mutex));
    }

    if (ipsynced) {
        pthread_mutex_lock(&(glob->stats_mutex));
        glob->stats.packets_sync_ip ++;
        pthread_mutex_unlock(&(glob->stats_mutex));
    }

    if (voipsynced) {
        pthread_mutex_lock(&(glob->stats_mutex));
        glob->stats.packets_sync_voip ++;
        pthread_mutex_unlock(&(glob->stats_mutex));
    }


    if (forwarded) {
        pthread_mutex_lock(&(glob->stats_mutex));
        glob->stats.packets_intercepted ++;
        pthread_mutex_unlock(&(glob->stats_mutex));
    }

    return pkt;
}

static int start_xinput(collector_global_t *glob, x_input_t *xinp) {

    char name[1024];

    if (xinp->running == 1) {
        return 1;
    }

    snprintf(name, 1024, "x2x3input-%s", xinp->identifier);

    xinp->zmq_ctxt = glob->zmq_ctxt;
    xinp->forwarding_threads = glob->forwarding_threads;
    xinp->tracker_threads = glob->seqtracker_threads;
    xinp->zmq_ctrlsock = NULL;
    xinp->zmq_fwdsocks = NULL;
    xinp->zmq_pubsocks = NULL;
    xinp->haltinfo = NULL;

    xinp->reset_listener = 1;
    xinp->ssl_ctx = glob->sslconf.ctx;
    xinp->ssl_ctx_bad = 0;
    pthread_mutex_init(&(xinp->sslmutex), NULL);

    pthread_create(&(xinp->threadid), NULL,
            start_x2x3_ingest_thread, (void *)xinp);
    pthread_setname_np(xinp->threadid, name);

    logger(LOG_INFO,
            "OpenLI: collector has started X2/X3 ingestor %s.",
            xinp->identifier);
    xinp->running = 1;
    return 1;
}

static int start_input(collector_global_t *glob, colinput_t *inp,
        int todaemon, char *progname) {

    libtrace_info_t *info;
    struct timeval tv;

    if (inp->running == 1) {
        /* Trace is already running */
        if (inp->trace && trace_is_err(inp->trace)) {
            /* We had a problem with this input trace -- make sure we stop
             * it cleanly and attempt to restart it if it is a live source
             */
            libtrace_err_t err = trace_get_err(inp->trace);
            info = trace_get_information(inp->trace);

            logger(LOG_INFO,
                    "OpenLI: halting input %s%s due to an error encountered by libtrace: %s",
                    inp->uri, info->live ? "" : "permanently", err.problem);
            trace_pstop(inp->trace);
            trace_join(inp->trace);
            trace_destroy(inp->trace);
            inp->trace = NULL;

            if (info->live && inp->no_restart == 0) {
                // try to restart live inputs, just in case
                inp->running = 0;
                gettimeofday(&tv, NULL);
                inp->start_at = tv.tv_sec + 60;
            }
        }

        return 1;
    }

    gettimeofday(&tv, NULL);
    if (tv.tv_sec < inp->start_at) {
        return 1;
    }
    if (!inp->pktcbs) {
        inp->pktcbs = trace_create_callback_set();
    }
    trace_set_starting_cb(inp->pktcbs, start_processing_thread);
    trace_set_stopping_cb(inp->pktcbs, stop_processing_thread);
    trace_set_packet_cb(inp->pktcbs, process_packet);

    trace_set_tick_interval_cb(inp->pktcbs, process_tick);

    assert(!inp->trace);
    inp->trace = trace_create(inp->uri);

    /* Stupid DPDK will "steal" our syslog logid, so we need to reset it
     * after we call trace_create() to ensure our logs have the right
     * program name associated with them.
     */

    if (todaemon) {
        open_daemonlog(progname);
    }

    if (trace_is_err(inp->trace)) {
        libtrace_err_t lterr = trace_get_err(inp->trace);
        logger(LOG_INFO, "OpenLI: Failed to create trace for input %s: %s",
                inp->uri, lterr.problem);
        return 0;
    }

    trace_set_perpkt_threads(inp->trace, inp->threadcount);
    hash_radius_init_config(&(inp->hashradconf), 1);
    inp->hashconfigured = 1;

    if (inp->hasher_apply == OPENLI_HASHER_BIDIR) {
        logger(LOG_INFO, "OpenLI: collector is using a bidirectional hasher for input %s", inp->uri);
        trace_set_hasher(inp->trace, HASHER_BIDIRECTIONAL, NULL, NULL);
    } else if (inp->hasher_apply == OPENLI_HASHER_BALANCE) {
        logger(LOG_INFO, "OpenLI: collector is using a balanced hasher for input %s", inp->uri);
        trace_set_hasher(inp->trace, HASHER_BALANCE, NULL, NULL);
    } else if (inp->hasher_apply == OPENLI_HASHER_RADIUS) {
        logger(LOG_INFO, "OpenLI: collector is using a RADIUS-session hasher for input %s", inp->uri);
        trace_set_hasher(inp->trace, HASHER_CUSTOM, hash_radius_packet,
                (void *)&(inp->hashradconf));
    }

    if (inp->coremap) {
	char opt[256];

	snprintf(opt, 256, "coremap=%s", inp->coremap);
	if (trace_set_configuration(inp->trace, opt) < 0) {
	    logger(LOG_INFO, "OpenLI: unable to set coremap (%s) for %s",
			    inp->coremap, inp->uri);
	}
    }

    if (inp->filterstring) {
        inp->filter = trace_create_filter(inp->filterstring);

        if (inp->filter == NULL) {
            logger(LOG_INFO, "OpenLI: unable to create input filter for %s",
                    inp->uri);
        } else {
            if (trace_config(inp->trace, TRACE_OPTION_FILTER, inp->filter) < 0) {
                logger(LOG_INFO, "OpenLI: unable to set input filter for %s",
                        inp->uri);
            }
            logger(LOG_INFO, "OpenLI: applying filter '%s' to input %s",
                    inp->filterstring, inp->uri);
        }

    }

    trace_set_tick_interval(inp->trace, 10);

    if (trace_pstart(inp->trace, glob, inp->pktcbs, NULL) == -1) {
        libtrace_err_t lterr = trace_get_err(inp->trace);
        logger(LOG_INFO, "OpenLI: Failed to start trace for input %s: %s",
                inp->uri, lterr.problem);
        return 0;
    }

    logger(LOG_INFO,
            "OpenLI: collector has started reading packets from %s using %d threads.",
            inp->uri, inp->threadcount);
    inp->running = 1;
    return 1;
}

static void reload_udpsinks(collector_global_t *glob,
        collector_global_t *newstate) {

    colsync_udp_sink_t *oldsink, *newsink, *tmp;

    pthread_mutex_lock(&(glob->syncip.mutex));
    HASH_ITER(hh, glob->syncip.udpsinks, oldsink, tmp) {
        HASH_FIND(hh, newstate->syncip.udpsinks, oldsink->key,
                strlen(oldsink->key), newsink);
        if (newsink) {
            newsink->running = 1;
            oldsink->running = 1;
        } else {
            // this sink has been removed, flag it
            oldsink->running = 0;
        }
    }

    HASH_ITER(hh, newstate->syncip.udpsinks, newsink, tmp) {
        if (newsink->running) {
            continue;
        }
        HASH_DELETE(hh, newstate->syncip.udpsinks, newsink);
        HASH_ADD_KEYPTR(hh, glob->syncip.udpsinks, newsink->key,
                strlen(newsink->key), newsink);
        newsink->running = 1;
        // the sync thread will handle activating the sink if there is
        // already an intercept configured for it

    }

    pthread_mutex_unlock(&(glob->syncip.mutex));
}

static void reload_x2x3_inputs(collector_global_t *glob,
        collector_global_t *newstate, collector_sync_t *sync, int tlschanged) {

    /* TODO same thing as with inputs
     *  - mark the inputs that are in newstate that are also in old
     *  - announce removal of any existing inputs that are not in newstate
     *  - announce any remaining inputs in newstate that were not already
     *    running
     */
    x_input_t *oldinp, *newinp, *tmp;

    HASH_ITER(hh, glob->x_inputs, oldinp, tmp) {
        HASH_FIND(hh, newstate->x_inputs, oldinp->identifier,
                strlen(oldinp->identifier), newinp);
        if (newinp) {
            newinp->running = 1;
            if (tlschanged) {
                pthread_mutex_lock(&(oldinp->sslmutex));
                oldinp->ssl_ctx = glob->sslconf.ctx;
                oldinp->reset_listener = 1;
                pthread_mutex_unlock(&(oldinp->sslmutex));
            }
        } else {
            // this input has been removed
            remove_x2x3_from_sync(sync, oldinp->identifier, oldinp->threadid);
            HASH_DELETE(hh, glob->x_inputs, oldinp);
            if (oldinp->threadid != 0) {
                pthread_join(oldinp->threadid, NULL);
            }
            destroy_x_input(oldinp);

        }

    }

    HASH_ITER(hh, newstate->x_inputs, newinp, tmp) {
        if (newinp->running) {
            continue;
        }
        HASH_DELETE(hh, newstate->x_inputs, newinp);
        HASH_ADD_KEYPTR(hh, glob->x_inputs, newinp->identifier,
                strlen(newinp->identifier), newinp);
        if (add_x2x3_to_sync(sync, newinp->identifier, newinp->listenaddr,
                    newinp->listenport) < 0) {
            logger(LOG_INFO,
                    "OpenLI: failed to register X2-X3 input %s with sync thread",
                    newinp->identifier);
        }
        if (start_xinput(glob, newinp) == 0) {
            logger(LOG_INFO,
                    "OpenLI: failed to start X2-X3 input %s\n",
                    newinp->identifier);
        }
    }


}

static void reload_inputs(collector_global_t *glob,
        collector_global_t *newstate) {

    colinput_t *oldinp, *newinp, *tmp;
    int filterchanged = 0, i, coremapchanged = 0;
    char locname[1024];
    colthread_local_t *loc;

    logger(LOG_INFO,
            "OpenLI: collector is reloading input configuration.");

    glob->total_col_threads = newstate->total_col_threads;
    HASH_ITER(hh, glob->inputs, oldinp, tmp) {
        HASH_FIND(hh, newstate->inputs, oldinp->uri, strlen(oldinp->uri),
                newinp);
        filterchanged = 0;
        if (newinp) {
            if (oldinp->coremap) {
                if (newinp->coremap == NULL) {
                    coremapchanged = 1;
                } else if (strcmp(newinp->coremap, oldinp->coremap) != 0) {
                    coremapchanged = 1;
                }
            } else {
                if (newinp->coremap) {
                    coremapchanged = 1;
                }
            }

            if (oldinp->filterstring) {
                if (newinp->filterstring == NULL) {
                    filterchanged = 1;
                } else if (strcmp(newinp->filterstring,
                        oldinp->filterstring) != 0) {
                    filterchanged = 1;
                }
            } else {
                if (newinp->filterstring) {
                    filterchanged = 1;
                }
            }
        }

        if (!newinp || newinp->threadcount != oldinp->threadcount ||
                newinp->hasher_apply != oldinp->hasher_apply ||
                filterchanged || coremapchanged) {
            /* This input is either no longer wanted at all or has
	     * changed configuration
	     */
            logger(LOG_INFO,
                    "OpenLI collector: stop reading packets from %s",
                    oldinp->uri);
            trace_pstop(oldinp->trace);
            trace_join(oldinp->trace);
            trace_destroy(oldinp->trace);

            for (i = 0; i < oldinp->threadcount; i++) {
                snprintf(locname, 1024, "%s-%s-%d",
                        trace_get_uri_format(oldinp->trace),
                        trace_get_uri_body(oldinp->trace), i);
                HASH_FIND(hh, glob->collocals, locname, strlen(locname),
                        loc);
                if (loc) {
                    HASH_DELETE(hh, glob->collocals, loc);
                    if (loc->localname) {
                        free(loc->localname);
                    }
                    free(loc);
                }
            }


            oldinp->trace = NULL;
            HASH_DELETE(hh, glob->inputs, oldinp);
            libtrace_list_push_back(glob->expired_inputs, &oldinp);
            continue;
        }

        /* Mark this input as being present in the original list */
        newinp->running = 1;
    }

    HASH_ITER(hh, newstate->inputs, newinp, tmp) {
        if (newinp->running) {
            continue;
        }

        /* This input is new, move it into the 'official' input list */
        HASH_DELETE(hh, newstate->inputs, newinp);
        HASH_ADD_KEYPTR(hh, glob->inputs, newinp->uri, strlen(newinp->uri),
                newinp);
    }

}

static void clear_input(colinput_t *input) {

    if (!input) {
        return;
    }
    if (input->trace) {
        trace_destroy(input->trace);
    }
    if (input->pktcbs) {
        trace_destroy_callback_set(input->pktcbs);
    }
    if (input->uri) {
        free(input->uri);
    }
    if (input->filter) {
        trace_destroy_filter(input->filter);
    }
    if (input->filterstring) {
        free(input->filterstring);
    }
    if (input->coremap) {
        free(input->coremap);
    }
    if (input->hashconfigured) {
        hash_radius_cleanup(&(input->hashradconf));
    }
}

static inline void init_sync_thread_data(collector_global_t *glob,
        sync_thread_global_t *sup) {

    sup->threadid = 0;
    sup->zmq_ctxt = glob->zmq_ctxt;
    pthread_mutex_init(&(sup->mutex), NULL);
    sup->collector_queues = NULL;
    sup->epollevs = NULL;
    sup->epoll_fd = epoll_create1(0);
    sup->total_col_threads = glob->total_col_threads;

    sup->stats_mutex = &(glob->stats_mutex);
    sup->stats = &(glob->stats);
}

static inline void free_sync_thread_data(sync_thread_global_t *sup) {
	pthread_mutex_destroy(&(sup->mutex));

	if (sup->epoll_fd != -1) {
		close(sup->epoll_fd);
	}
	if (sup->collector_queues) {
		free(sup->collector_queues);
	}
	if (sup->epollevs) {
        libtrace_list_deinit((libtrace_list_t *)(sup->epollevs));
	}
}

static void destroy_collector_state(collector_global_t *glob) {

    colinput_t *inp;
    int i;
    colthread_local_t *loc, *tmp;

    if (glob->expired_inputs) {
        libtrace_list_node_t *n;
        n = glob->expired_inputs->head;
        while (n) {
            inp = *((colinput_t **)(n->data));
            clear_input(inp);
            free(inp);
            n = n->next;
        }
        libtrace_list_deinit(glob->expired_inputs);
    }

	free_sync_thread_data(&(glob->syncip));

    if (glob->emailworkers) {
        free(glob->emailworkers);
    }

    if (glob->gtpworkers) {
        for (i = 0; i < glob->gtp_threads; i++) {
            pthread_mutex_destroy(&(glob->gtpworkers[i].col_queue_mutex));
        }
        free(glob->gtpworkers);
    }

    if (glob->sipworkers) {
        for (i = 0; i < glob->sip_threads; i++) {
            pthread_mutex_destroy(&(glob->sipworkers[i].col_queue_mutex));
        }
        free(glob->sipworkers);
    }

    if (glob->zmq_encoder_ctrl) {
        zmq_close(glob->zmq_encoder_ctrl);
    }

    if (glob->syncgenericfreelist) {
        free_etsili_generics(glob->syncgenericfreelist);
    }

    if (glob->forwarders) {
        for (i = 0; i < glob->forwarding_threads; i++) {
            zmq_close(glob->forwarders[i].zmq_pullressock);
            pthread_mutex_destroy(&(glob->forwarders[i].sslmutex));
        }
        free(glob->forwarders);
    }

    if (glob->zmq_ctxt) {
        logger(LOG_INFO, "OpenLI: waiting for zeromq context to be destroyed.");
        zmq_ctx_destroy(glob->zmq_ctxt);
    }

    if (glob->seqtrackers) {
        for (i = 0; i < glob->seqtracker_threads; i++) {
            clean_seqtracker(&(glob->seqtrackers[i]));
        }

        free(glob->seqtrackers);
    }

    if (glob->encoders) {
        free(glob->encoders);
    }

    HASH_ITER(hh, glob->collocals, loc, tmp) {
        HASH_DELETE(hh, glob->collocals, loc);
        if (loc->localname) {
            free(loc->localname);
        }
        free(loc);
    }

    pthread_mutex_destroy(&(glob->stats_mutex));
    pthread_rwlock_destroy(&(glob->email_config_mutex));
    pthread_rwlock_destroy(&glob->config_mutex);
    pthread_rwlock_destroy(&glob->sipconfig_mutex);
    free(glob);
}

static void clear_global_config(collector_global_t *glob) {
    colinput_t *inp, *tmp;
    x_input_t *xinp, *xtmp;
    colsync_udp_sink_t *sink, *sinktmp;

    HASH_ITER(hh, glob->inputs, inp, tmp) {
        HASH_DELETE(hh, glob->inputs, inp);
        clear_input(inp);
        free(inp);
    }

    HASH_ITER(hh, glob->syncip.udpsinks, sink, sinktmp) {
        HASH_DELETE(hh, glob->syncip.udpsinks, sink);
        destroy_colsync_udp_sink(sink);
    }

    HASH_ITER(hh, glob->x_inputs, xinp, xtmp) {
        HASH_DELETE(hh, glob->x_inputs, xinp);
        destroy_x_input(xinp);
    };

    if (glob->sipconfig.sipdebugfile) {
        free(glob->sipconfig.sipdebugfile);
    }

    if (glob->default_email_domain) {
        free(glob->default_email_domain);
    }

    if (glob->email_forwarding_headers) {
        purge_string_set(&(glob->email_forwarding_headers));
    }

    if (glob->sharedinfo.operatorid) {
        free(glob->sharedinfo.operatorid);
    }

    if (glob->sharedinfo.networkelemid) {
        free(glob->sharedinfo.networkelemid);
    }

    if (glob->sharedinfo.intpointid) {
        free(glob->sharedinfo.intpointid);
    }

    if (glob->sharedinfo.provisionerip) {
        free(glob->sharedinfo.provisionerip);
    }

    if (glob->sharedinfo.provisionerport) {
        free(glob->sharedinfo.provisionerport);
    }
    if (glob->alumirrors) {
        free_coreserver_list(glob->alumirrors);
    }
    if (glob->jmirrors) {
        free_coreserver_list(glob->jmirrors);
    }
    if (glob->ciscomirrors) {
        free_coreserver_list(glob->ciscomirrors);
    }

    if (glob->RMQ_conf.name) {
        free(glob->RMQ_conf.name);
    }
    if (glob->RMQ_conf.pass) {
        free(glob->RMQ_conf.pass);
    }
    if (glob->RMQ_conf.internalpass) {
        free(glob->RMQ_conf.internalpass);
    }
    if (glob->RMQ_conf.hostname) {
        free(glob->RMQ_conf.hostname);
    }

    free_ssl_config(&(glob->sslconf));

    if (glob->emailconf.listenaddr) {
        free(glob->emailconf.listenaddr);
    }
    if (glob->emailconf.listenport) {
        free(glob->emailconf.listenport);
    }
    if (glob->emailconf.authpassword) {
        free(glob->emailconf.authpassword);
    }
    if (glob->email_ingestor) {
        free(glob->email_ingestor);
    }
}

static inline void push_hello_message(void *atob,
        libtrace_message_queue_t *btoa) {

    openli_state_update_t hello;

    memset(&hello, 0, sizeof(openli_state_update_t));
    hello.type = OPENLI_UPDATE_HELLO;
    hello.data.replyq = btoa;

    zmq_send(atob, (void *)&hello, sizeof(hello), 0);
}

int register_sync_queues(sync_thread_global_t *glob,
        void *recvq, libtrace_message_queue_t *sendq,
        libtrace_thread_t *parent) {

    sync_sendq_t *syncq, *sendq_hash, *found;

    syncq = (sync_sendq_t *)malloc(sizeof(sync_sendq_t));
    syncq->q = sendq;
    syncq->parent = parent;

    pthread_mutex_lock(&(glob->mutex));

    sendq_hash = (sync_sendq_t *)(glob->collector_queues);
    HASH_FIND_PTR(sendq_hash, parent, found);
    if (found) {
        HASH_DEL(sendq_hash, found);
        free(found);
    }
    HASH_ADD_PTR(sendq_hash, parent, syncq);
    glob->collector_queues = (void *)sendq_hash;

    pthread_mutex_unlock(&(glob->mutex));

    push_hello_message(recvq, sendq);
    return 0;
}

void deregister_sync_queues(sync_thread_global_t *glob,
		libtrace_thread_t *t) {

    sync_sendq_t *syncq, *sendq_hash;

    pthread_mutex_lock(&(glob->mutex));
    sendq_hash = (sync_sendq_t *)(glob->collector_queues);

    HASH_FIND_PTR(sendq_hash, &t, syncq);
    /* Caller will free the queue itself */
    if (syncq) {
        HASH_DELETE(hh, sendq_hash, syncq);
        free(syncq);
        glob->collector_queues = (void *)sendq_hash;
    }

    pthread_mutex_unlock(&(glob->mutex));
}


static int prepare_collector_glob(collector_global_t *glob) {

    glob->zmq_ctxt = zmq_ctx_new();

    glob->expired_inputs = libtrace_list_init(sizeof(colinput_t *));

    init_sync_thread_data(glob, &(glob->syncip));

    glob->collocals = NULL;
    glob->syncgenericfreelist = create_etsili_generic_freelist(1);

    glob->zmq_encoder_ctrl = zmq_socket(glob->zmq_ctxt, ZMQ_PUB);
    if (zmq_bind(glob->zmq_encoder_ctrl,
            "inproc://openliencodercontrol") != 0) {
        logger(LOG_INFO, "OpenLI: unable to connect to zmq control socket for encoding threads. Exiting.");
        return -1;
    }

    if (glob->email_ingestor) {
        glob->email_ingestor->email_worker_count = glob->email_threads;
        glob->email_ingestor->zmq_publishers = NULL;
        glob->email_ingestor->zmq_ctxt = glob->zmq_ctxt;
    }

    return 0;
}

static void init_collector_global(collector_global_t *glob) {
    uuid_clear(glob->sharedinfo.uuid);

    glob->zmq_ctxt = NULL;
    glob->inputs = NULL;
    glob->x_inputs = NULL;
    glob->seqtracker_threads = 1;
    glob->forwarding_threads = 1;
    glob->encoding_threads = 2;
    glob->email_threads = 1;
    glob->gtp_threads = 1;
    glob->sip_threads = 1;
    glob->sharedinfo.jsonconfig = NULL;
    glob->sharedinfo.intpointid = NULL;
    glob->sharedinfo.intpointid_len = 0;
    glob->sharedinfo.operatorid = NULL;
    glob->sharedinfo.operatorid_len = 0;
    glob->sharedinfo.networkelemid = NULL;
    glob->sharedinfo.networkelemid_len = 0;
    glob->sharedinfo.cisco_noradius = 0;       // defaults to "expect RADIUS"
    glob->total_col_threads = 0;
    glob->collocals = NULL;
    glob->expired_inputs = NULL;

    glob->configfile = NULL;
    glob->sharedinfo.provisionerip = NULL;
    glob->sharedinfo.provisionerport = NULL;
    glob->sipconfig.disable_sip_redirect = 0;
    glob->alumirrors = NULL;
    glob->jmirrors = NULL;
    glob->ciscomirrors = NULL;
    glob->nextloc = 0;
    glob->syncgenericfreelist = NULL;

    glob->sslconf.certfile = NULL;
    glob->sslconf.keyfile = NULL;
    glob->sslconf.cacertfile = NULL;
    glob->sslconf.logkeyfile = NULL;
    glob->sslconf.ctx = NULL;

    glob->RMQ_conf.name = NULL;
    glob->RMQ_conf.pass = NULL;
    glob->RMQ_conf.internalpass = NULL;
    glob->RMQ_conf.hostname = NULL;
    glob->RMQ_conf.port = 0;
    glob->RMQ_conf.heartbeatFreq = 0;
    glob->RMQ_conf.enabled = 0;

    glob->emailconf.enabled = 255;
    glob->emailconf.authrequired = 0;
    glob->emailconf.tlsrequired = 0;
    glob->emailconf.maxclients = 20;
    glob->emailconf.listenport = NULL;
    glob->emailconf.listenaddr = NULL;
    glob->emailconf.authpassword = NULL;

    glob->etsitls = 1;
    glob->sipconfig.ignore_sdpo_matches = 0;
    glob->sipconfig.sipdebugfile = NULL;
    glob->encoding_method = OPENLI_ENCODING_DER;

    memset(&(glob->stats), 0, sizeof(glob->stats));
    glob->stat_frequency = 0;
    glob->ticks_since_last_stat = 0;

    glob->emailsockfd = -1;
    glob->email_ingestor = NULL;

    /* The rest of syncip gets initialized later, but this is going to
     * populated when we parse the config file.
     */
    glob->syncip.udpsinks = NULL;

    /* TODO add config options to change these values
     *      also make sure changes are actions post config-reload */
    glob->email_timeouts.smtp = 5;
    glob->email_timeouts.pop3 = 10;
    glob->email_timeouts.imap = 30;
    glob->mask_imap_creds = 1;      // defaults to "enabled"
    glob->mask_pop3_creds = 1;      // defaults to "enabled"
    glob->default_email_domain = NULL;
    glob->email_forwarding_headers = NULL;
    glob->email_ingest_use_targetid = 0; // defaults to "disabled"   XXX for now
}

static collector_global_t *parse_global_config(char *configfile) {

    collector_global_t *glob = NULL;
    char *jsonconfig;

    glob = (collector_global_t *)calloc(1, sizeof(collector_global_t));
    init_collector_global(glob);
    glob->configfile = configfile;

    pthread_mutex_init(&(glob->stats_mutex), NULL);
    pthread_rwlock_init(&(glob->email_config_mutex), NULL);

    pthread_rwlock_init(&glob->config_mutex, NULL);
    pthread_rwlock_init(&glob->sipconfig_mutex, NULL);

    if (parse_collector_config(configfile, glob) == -1) {
        clear_global_config(glob);
        return NULL;
    }

    if (uuid_is_null(glob->sharedinfo.uuid)) {
        uuid_generate(glob->sharedinfo.uuid);
        /* rewrite config file to contain new UUID */
        emit_collector_config(configfile, glob);
    }
    jsonconfig = collector_config_to_json(glob);
    pthread_rwlock_wrlock(&glob->config_mutex);
    glob->sharedinfo.jsonconfig = jsonconfig;
    pthread_rwlock_unlock(&glob->config_mutex);

    /* Disable by default, unless the user has configured EITHER:
     *   a) set the enabled flag to true (obviously)
     *   b) provided a listen address or port for the ingestion service
     */
    if (glob->emailconf.listenaddr || glob->emailconf.listenport) {
        if (glob->emailconf.enabled == 255) {
            glob->emailconf.enabled = 1;
        }
    } else {
        if (glob->emailconf.enabled == 255) {
            glob->emailconf.enabled = 0;
        }
    }

    if (glob->emailconf.enabled) {
        glob->email_ingestor = calloc(1, sizeof(email_ingestor_state_t));
        if (glob->emailconf.listenaddr == NULL) {
            glob->emailconf.listenaddr = strdup("0.0.0.0");
        }
        if (glob->emailconf.listenport == NULL) {
            glob->emailconf.listenport = strdup("19999");
        }
        logger(LOG_INFO, "OpenLI: starting email ingestor service on %s:%s -- auth %s, TLS %s",
                glob->emailconf.listenaddr,
                glob->emailconf.listenport,
                glob->emailconf.authrequired ? "required": "disabled",
                glob->emailconf.tlsrequired ? "required": "disabled");

    }

    logger(LOG_DEBUG, "OpenLI: Encoding Method: %s",
        glob->encoding_method == OPENLI_ENCODING_BER ? "BER" : "DER");

    logger(LOG_DEBUG, "OpenLI: ETSI TLS encryption %s",
        glob->etsitls ? "enabled" : "disabled");

    if (glob->sipconfig.trust_sip_from) {
        logger(LOG_INFO, "Allowing SIP From: URIs to be used for target identification");
    }

    logger(LOG_INFO, "Redirection of packets between SIP threads is %s",
            glob->sipconfig.disable_sip_redirect ? "disabled": "allowed");

    if (glob->mask_imap_creds) {
        logger(LOG_INFO, "Email interception: rewriting IMAP auth credentials to avoid leaking passwords to agencies");
    }

    if (glob->mask_pop3_creds) {
        logger(LOG_INFO, "Email interception: rewriting POP3 plain text passwords to avoid leaking passwords to agencies");
    }

    if (glob->default_email_domain) {
        logger(LOG_INFO, "Using '%s' as the default email domain",
                glob->default_email_domain);
    }

    if (glob->email_forwarding_headers) {
        string_set_t *s, *tmp;
        HASH_ITER(hh, glob->email_forwarding_headers, s, tmp) {
            if (s->term == NULL) {
                continue;
            }
            logger(LOG_INFO,
                    "Using '%s' as the header to detect email forwards",
                    s->term);
        }
    }

    logger(LOG_DEBUG, "OpenLI: session idle timeout for SMTP sessions: %u minutes", glob->email_timeouts.smtp);
    logger(LOG_DEBUG, "OpenLI: session idle timeout for IMAP sessions: %u minutes", glob->email_timeouts.imap);
    logger(LOG_DEBUG, "OpenLI: session idle timeout for POP3 sessions: %u minutes", glob->email_timeouts.pop3);

    if (create_ssl_context(&(glob->sslconf)) < 0) {
        return NULL;
    }

    if (glob->sharedinfo.provisionerport == NULL) {
        glob->sharedinfo.provisionerport = strdup("8993");
    }

    if (glob->sharedinfo.networkelemid == NULL) {
        logger(LOG_INFO, "OpenLI: No network element ID specified in config file. Exiting.");
        clear_global_config(glob);
        glob = NULL;
    }

    else if (glob->sharedinfo.operatorid == NULL) {
        logger(LOG_INFO, "OpenLI: No operator ID specified in config file. Exiting.");
        clear_global_config(glob);
        glob = NULL;
    }

    else if (glob->sharedinfo.provisionerip == NULL) {
        logger(LOG_INFO, "OpenLI collector: no provisioner IP address specified in config file. Exiting.");
        clear_global_config(glob);
        glob = NULL;
    }


    return glob;

}

static int reload_collector_config(collector_global_t *glob,
        collector_sync_t *sync) {

    collector_global_t newstate;
    int i, tlschanged, ret;
    coreserver_t *tmp;
    x_input_t *xinp, *xtmp;
    char *newjson = NULL;
    ret = 0;

    init_collector_global(&newstate);
    if (parse_collector_config(glob->configfile, &newstate) == -1) {
        ret = -1;
        goto endreload;
    }

    tlschanged = reload_ssl_config(&(glob->sslconf), &(newstate.sslconf));

    if (tlschanged == -1) {
        ret = -1;
        goto endreload;
    }

    pthread_rwlock_wrlock(&(glob->config_mutex));
    if (strcmp(newstate.sharedinfo.provisionerip,
                glob->sharedinfo.provisionerip) != 0 ||
            strcmp(newstate.sharedinfo.provisionerport,
                    glob->sharedinfo.provisionerport) != 0) {
        logger(LOG_INFO,
                "OpenLI collector: disconnecting from provisioner due to config change.");
        sync_disconnect_provisioner(sync, tlschanged);
        sync->instruct_log = 1;
        free(glob->sharedinfo.provisionerip);
        free(glob->sharedinfo.provisionerport);
        glob->sharedinfo.provisionerip = strdup(newstate.sharedinfo.provisionerip);
        glob->sharedinfo.provisionerport = strdup(newstate.sharedinfo.provisionerport);
    } else {
        logger(LOG_INFO,
                "OpenLI collector: provisioner socket configuration is unchanged.");
    }
    pthread_rwlock_unlock(&(glob->config_mutex));

    if (tlschanged) {
        if (sync->instruct_fd != -1) {
            sync_disconnect_provisioner(sync, 1);
            sync->instruct_log = 1;
        }
    } else if (glob->etsitls != newstate.etsitls) {
        sync_reconnect_all_mediators(sync);
    }

    if (tlschanged || (glob->etsitls != newstate.etsitls)) {
        glob->etsitls = newstate.etsitls;

        for (i = 0; i < glob->forwarding_threads; i++) {
            pthread_mutex_lock(&(glob->forwarders[i].sslmutex));
            glob->forwarders[i].ctx = (glob->sslconf.ctx && glob->etsitls)
                    ? glob->sslconf.ctx : NULL;
            pthread_mutex_unlock(&(glob->forwarders[i].sslmutex));
        }

        HASH_ITER(hh, glob->x_inputs, xinp, xtmp) {
            pthread_mutex_lock(&(xinp->sslmutex));
            xinp->ssl_ctx = glob->sslconf.ctx;
            xinp->ssl_ctx_bad = 0;
            pthread_mutex_unlock(&(xinp->sslmutex));
        }
    }

    pthread_rwlock_wrlock(&(glob->config_mutex));

    glob->stat_frequency = newstate.stat_frequency;
    reload_inputs(glob, &newstate);
    reload_x2x3_inputs(glob, &newstate, sync, tlschanged);
    reload_udpsinks(glob, &newstate);
    /* Just update these, regardless of whether they've changed. It's more
     * effort to check for a change than it is worth and there are no
     * flow-on effects to a change.
     */

    tmp = glob->alumirrors;
    glob->alumirrors = newstate.alumirrors;
    free_coreserver_list(tmp);
    newstate.alumirrors = NULL;

    tmp = glob->jmirrors;
    glob->jmirrors = newstate.jmirrors;
    free_coreserver_list(tmp);
    newstate.jmirrors = NULL;

    tmp = glob->ciscomirrors;
    glob->ciscomirrors = newstate.ciscomirrors;
    free_coreserver_list(tmp);
    newstate.ciscomirrors = NULL;

    if (glob->sharedinfo.operatorid) {
        free(glob->sharedinfo.operatorid);
    }
    glob->sharedinfo.operatorid = newstate.sharedinfo.operatorid;
    glob->sharedinfo.operatorid_len = newstate.sharedinfo.operatorid_len;
    newstate.sharedinfo.operatorid = NULL;

    if (glob->sharedinfo.networkelemid) {
        free(glob->sharedinfo.networkelemid);
    }
    glob->sharedinfo.networkelemid = newstate.sharedinfo.networkelemid;
    glob->sharedinfo.networkelemid_len = newstate.sharedinfo.networkelemid_len;
    newstate.sharedinfo.networkelemid = NULL;

    if (glob->sharedinfo.intpointid) {
        free(glob->sharedinfo.intpointid);
    }
    glob->sharedinfo.intpointid = newstate.sharedinfo.intpointid;
    glob->sharedinfo.intpointid_len = newstate.sharedinfo.intpointid_len;
    newstate.sharedinfo.intpointid = NULL;
    glob->sharedinfo.cisco_noradius = newstate.sharedinfo.cisco_noradius;

    pthread_rwlock_unlock(&(glob->config_mutex));

    pthread_rwlock_wrlock(&(glob->sipconfig_mutex));
    glob->sipconfig.trust_sip_from = newstate.sipconfig.trust_sip_from;
    glob->sipconfig.disable_sip_redirect =
            newstate.sipconfig.disable_sip_redirect;
    glob->sipconfig.ignore_sdpo_matches =
            newstate.sipconfig.ignore_sdpo_matches;
    if (glob->sipconfig.sipdebugfile) {
        free(glob->sipconfig.sipdebugfile);
    }
    glob->sipconfig.sipdebugfile = newstate.sipconfig.sipdebugfile;
    newstate.sipconfig.sipdebugfile = NULL;
    pthread_rwlock_unlock(&(glob->sipconfig_mutex));

    pthread_rwlock_wrlock(&(glob->email_config_mutex));
    if (glob->mask_imap_creds != newstate.mask_imap_creds) {
        if (newstate.mask_imap_creds) {
            logger(LOG_INFO, "OpenLI: Email interception: rewriting IMAP auth credentials to avoid leaking passwords to agencies");
        } else {
            logger(LOG_INFO, "OpenLI: Email interception: no longer rewriting IMAP auth credentials to avoid leaking passwords to agencies");
        }
    }

    if (glob->mask_pop3_creds != newstate.mask_pop3_creds) {
        if (newstate.mask_pop3_creds) {
            logger(LOG_INFO, "OpenLI: Email interception: rewriting POP3 plain text passwords to avoid leaking passwords to agencies");
        } else {
            logger(LOG_INFO, "OpenLI: Email interception: no longer rewriting POP3 plain text passwords to avoid leaking passwords to agencies");
        }
    }

    if (glob->email_ingest_use_targetid != newstate.email_ingest_use_targetid) {
        /* TODO log this change once it becomes a mainstream config option */
    }

    if (glob->default_email_domain) {
        if (!newstate.default_email_domain) {
            logger(LOG_INFO, "OpenLI: default email domain has been unset.");
            free(glob->default_email_domain);
            glob->default_email_domain = NULL;
        } else if (strcmp(glob->default_email_domain,
                newstate.default_email_domain) != 0) {
            logger(LOG_INFO,
                    "OpenLI: changing default email domain from '%s' to '%s'",
                    glob->default_email_domain, newstate.default_email_domain);
            free(glob->default_email_domain);
            glob->default_email_domain = newstate.default_email_domain;
            newstate.default_email_domain = NULL;
        }
    } else if (newstate.default_email_domain) {
        logger(LOG_INFO,
                "OpenLI: setting default email domain to be '%s'",
                newstate.default_email_domain);
        glob->default_email_domain = newstate.default_email_domain;
        newstate.default_email_domain = NULL;
    }

    purge_string_set(&(glob->email_forwarding_headers));
    glob->email_forwarding_headers = newstate.email_forwarding_headers;
    newstate.email_forwarding_headers = NULL;

    glob->mask_imap_creds = newstate.mask_imap_creds;
    glob->mask_pop3_creds = newstate.mask_pop3_creds;
    glob->email_ingest_use_targetid = newstate.email_ingest_use_targetid;
    glob->email_timeouts.smtp = newstate.email_timeouts.smtp;
    glob->email_timeouts.imap = newstate.email_timeouts.imap;
    glob->email_timeouts.pop3 = newstate.email_timeouts.pop3;

    logger(LOG_DEBUG, "OpenLI: session idle timeout for SMTP sessions is now %u minutes", glob->email_timeouts.smtp);
    logger(LOG_DEBUG, "OpenLI: session idle timeout for IMAP sessions is now %u minutes", glob->email_timeouts.imap);
    logger(LOG_DEBUG, "OpenLI: session idle timeout for POP3 sessions is now %u minutes", glob->email_timeouts.pop3);
    pthread_rwlock_unlock(&(glob->email_config_mutex));

    newjson = collector_config_to_json(glob);
    if (newjson != NULL) {
        pthread_rwlock_wrlock(&glob->config_mutex);
        free(glob->sharedinfo.jsonconfig);
        glob->sharedinfo.jsonconfig = newjson;
        pthread_rwlock_unlock(&glob->config_mutex);
    } else {
        ret = -1;
    }
endreload:
    clear_global_config(&newstate);
    return ret;
}

void halt_processing_threads(collector_global_t *glob) {
    colinput_t *inp, *tmp;
    HASH_ITER(hh, glob->inputs, inp, tmp) {
        trace_pstop(inp->trace);
    }
}

static void *start_ip_sync_thread(void *params) {

    collector_global_t *glob = (collector_global_t *)params;
    int ret;
    collector_sync_t *sync = init_sync_data(glob);
    sync_sendq_t *sq;
    x_input_t *xinp, *xtmp;

    /* XXX For early development work, we will read intercept instructions
     * from a config file. Eventually this should be replaced with
     * instructions that are received via a network interface.
     */
    if (sync->zmq_colsock == NULL) {
        goto haltsyncthread;
    }

    HASH_ITER(hh, glob->x_inputs, xinp, xtmp) {
        if (add_x2x3_to_sync(sync, xinp->identifier, xinp->listenaddr,
                xinp->listenport) < 0) {
            logger(LOG_INFO, "OpenLI: failed to register X2-X3 input %s with sync thread", xinp->identifier);
            /*
             * try to force the thread to die because the sync thread was
             * our only means of telling the thread to halt normally
             */
            if (xinp->threadid != 0) {
                pthread_cancel(xinp->threadid);
            }
        }
    }

    while (collector_halt == 0) {
        if (__atomic_exchange_n(&config_write_required, 0, __ATOMIC_ACQUIRE)) {
            emit_collector_config(glob->configfile, glob);
            reload_config = 0;
        }

        if (reload_config) {
            if (reload_collector_config(glob, sync) == -1) {
                break;
            }
            sync_thread_publish_reload(sync);
            reload_config = 0;
        }
        if (sync->instruct_fd == -1) {
            ret = sync_connect_provisioner(sync, glob->sslconf.ctx);
            if (ret < 0) {
                /* Fatal error */
                logger(LOG_INFO,
                        "OpenLI: collector is unable to reach provisioner.");
                break;
            }

            if (ret == 0) {
                /* Connection failed, but we should retry */
                usleep(500000);
                continue;
            }
        }

        ret = sync_thread_main(sync);
        if (ret == -1) {
            break;
        }
        if (ret == 0) {
            usleep(200000);
        }
    }

haltsyncthread:
    /* Collector is halting, stop all processing threads */
    halt_processing_threads(glob);
    clean_sync_data(sync);

    /* Wait for all processing threads to de-register their sync queues */
    do {
        pthread_mutex_lock(&(glob->syncip.mutex));
        sq = (sync_sendq_t *)(glob->syncip.collector_queues);
        if (HASH_CNT(hh, sq) == 0) {
            pthread_mutex_unlock(&(glob->syncip.mutex));
            break;
        }
        pthread_mutex_unlock(&(glob->syncip.mutex));
        usleep(500000);
    } while (1);

    free(sync);
    logger(LOG_DEBUG, "OpenLI: exiting sync thread.");
    /* Sync thread may have fatally exited, so halt the entire collector? */
    collector_halt = 1;
    pthread_exit(NULL);

}

static int init_sip_worker_thread(openli_sip_worker_t *sipworker,
        collector_global_t *glob, size_t workerid) {

    char name[1024];

    snprintf(name, 1024, "sipworker-%zu", workerid);

    sipworker->workerid = workerid;
    sipworker->worker_threadname = strdup(name);
    sipworker->zmq_ctxt = glob->zmq_ctxt;
    sipworker->stats_mutex = &(glob->stats_mutex);
    sipworker->stats = &(glob->stats);
    sipworker->shared = &(glob->sipconfig);
    sipworker->shared_mutex = &(glob->sipconfig_mutex);
    sipworker->collector_queues = NULL;
    sipworker->haltinfo = NULL;

    /* It is ok to initialize this mutex here because this method will
     * be called by the main collector thread before we start any packet
     * processing threads.
     */
    pthread_mutex_init(&(sipworker->col_queue_mutex), NULL);
    sipworker->zmq_ii_sock = NULL;
    sipworker->zmq_pubsocks = NULL;
    sipworker->zmq_redirect_insock = NULL;
    sipworker->zmq_fwdsocks = NULL;
    sipworker->zmq_colthread_recvsock = NULL;
    sipworker->zmq_redirect_outsocks = NULL;
    sipworker->tracker_threads = glob->seqtracker_threads;
    sipworker->forwarding_threads = glob->forwarding_threads;
    sipworker->sipworker_threads = glob->sip_threads;
    sipworker->voipintercepts = NULL;
    sipworker->knowncallids = NULL;

    sipworker->debug.sipdebugout = NULL;
    sipworker->debug.sipdebugupdate = NULL;
    sipworker->debug.log_bad_sip = 1;
    sipworker->timeouts = NULL;

    return 0;
}


int main(int argc, char *argv[]) {

	struct sigaction sigact, sigign;
    sigset_t sig_before, sig_block_all;
    char *configfile = NULL;
    char *pidfile = NULL;
    collector_global_t *glob = NULL;
    int i, ret, todaemon;
    colinput_t *inp, *tmp;
    char name[1024];
    x_input_t *xinp, *xtmp;

    todaemon = 0;
    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "daemonise", 0, 0, 'd'},
            { "pidfile", 1, 0, 'p'},
            { NULL, 0, 0, 0 }
        };

        int c = getopt_long(argc, argv, "c:dp:h", long_options,
                &optind);
        if (c == -1) {
            break;
        }

        switch(c) {
            case 'c':
                configfile = optarg;
                break;
            case 'd':
                todaemon = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            case 'p':
                pidfile = optarg;
                break;
            default:
                logger(LOG_INFO, "OpenLI: unsupported option: %c", c);
                usage(argv[0]);
                return 1;
        }
    }

    if (configfile == NULL) {
        logger(LOG_INFO,
                "OpenLI: no config file specified. Use -c to specify one.");
        usage(argv[0]);
        return 1;
    }

    if (todaemon) {
        daemonise(argv[0], pidfile);
    }

    /* Initialise osipparser2 */
    parser_init();

    /* Initialise OpenSSL */
    OpenSSL_add_all_digests();

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    memset(&sigign, 0, sizeof(sigign));
    sigign.sa_handler = SIG_IGN;
    sigign.sa_flags = SA_RESTART;

    sigaction(SIGPIPE, &sigign, NULL);

    sigact.sa_handler = reload_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGHUP, &sigact, NULL);

    /* Read config to generate list of input sources */
    glob = parse_global_config(configfile);
    if (glob == NULL) {
        return 1;
    }

    if (prepare_collector_glob(glob) < 0) {
        clear_global_config(glob);
        return 1;
    }

    sigemptyset(&sig_block_all);
    if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
        logger(LOG_INFO, "Unable to disable signals before starting threads.");
        return 1;
    }

    /* TODO check pthread_create return values... */

    glob->forwarders = calloc(glob->forwarding_threads,
            sizeof(forwarding_thread_data_t));

    for (i = 0; i < glob->forwarding_threads; i++) {

        snprintf(name, 1024, "forwarder-%d", i);

        glob->forwarders[i].zmq_ctxt = glob->zmq_ctxt;
        glob->forwarders[i].forwardid = i;
        glob->forwarders[i].encoders = glob->encoding_threads;
        glob->forwarders[i].zmq_ctrlsock = NULL;
        glob->forwarders[i].zmq_pullressock = NULL;
        pthread_mutex_init(&(glob->forwarders[i].sslmutex), NULL);
        glob->forwarders[i].ctx =
                (glob->sslconf.ctx && glob->etsitls) ? glob->sslconf.ctx : NULL;
        //forwarder only needs CTX if ctx exists and is enabled 
        glob->forwarders[i].RMQ_conf = glob->RMQ_conf;
        glob->forwarders[i].ampq_blocked = 0;
	glob->forwarders[i].haltinfo = NULL;

        pthread_create(&(glob->forwarders[i].threadid), NULL,
                start_forwarding_thread, (void *)&(glob->forwarders[i]));
        pthread_setname_np(glob->forwarders[i].threadid, name);
    }

    if (glob->sip_threads > 0) {
        glob->sipworkers = calloc(glob->sip_threads,
                sizeof(openli_sip_worker_t));
        for (i = 0; i < glob->sip_threads; i++) {
            init_sip_worker_thread(&(glob->sipworkers[i]), glob, i);
            pthread_create(&(glob->sipworkers[i].threadid), NULL,
                    start_sip_worker_thread, (void *)&(glob->sipworkers[i]));
            pthread_setname_np(glob->sipworkers[i].threadid,
                    glob->sipworkers[i].worker_threadname);
        }
    } else {
        glob->sipworkers = NULL;
    }

    if (glob->gtp_threads > 0) {
        glob->gtpworkers = calloc(glob->gtp_threads,
                sizeof(openli_gtp_worker_t));
        for (i = 0; i < glob->gtp_threads; i++) {
            start_gtp_worker_thread(&(glob->gtpworkers[i]), i, glob);
        }
    } else {
        glob->gtpworkers = NULL;
    }

    if (glob->email_threads > 0) {

        glob->emailworkers = calloc(glob->email_threads,
                sizeof(openli_email_worker_t));

        for (i = 0; i < glob->email_threads; i++) {
            snprintf(name, 1024, "emailworker-%d", i);

            glob->emailworkers[i].zmq_ctxt = glob->zmq_ctxt;
            glob->emailworkers[i].topoll = NULL;
            glob->emailworkers[i].topoll_size = 0;
            glob->emailworkers[i].fragreass = NULL;
            glob->emailworkers[i].emailid = i;
            glob->emailworkers[i].tracker_threads = glob->seqtracker_threads;
            glob->emailworkers[i].fwd_threads = glob->forwarding_threads;
            glob->emailworkers[i].zmq_pubsocks = NULL;
            glob->emailworkers[i].zmq_fwdsocks = NULL;
            glob->emailworkers[i].zmq_ingest_recvsock = NULL;
            glob->emailworkers[i].zmq_colthread_recvsock = NULL;
            glob->emailworkers[i].zmq_ii_sock = NULL;
	    glob->emailworkers[i].haltinfo = NULL;

            glob->emailworkers[i].timeouts = NULL;
            glob->emailworkers[i].allintercepts = NULL;
            glob->emailworkers[i].alltargets.addresses = NULL;
            glob->emailworkers[i].alltargets.targets = NULL;
            glob->emailworkers[i].activesessions = NULL;
            glob->emailworkers[i].stats_mutex = &(glob->stats_mutex);
            glob->emailworkers[i].stats = &(glob->stats);

            glob->emailworkers[i].glob_config_mutex =
                    &(glob->email_config_mutex);
            glob->emailworkers[i].mask_imap_creds =
                    &(glob->mask_imap_creds);
            glob->emailworkers[i].mask_pop3_creds = &(glob->mask_pop3_creds);
            glob->emailworkers[i].email_ingest_use_targetid =
                    &(glob->email_ingest_use_targetid);
            glob->emailworkers[i].defaultdomain = &(glob->default_email_domain);
            glob->emailworkers[i].email_forwarding_headers =
                    &(glob->email_forwarding_headers);
            glob->emailworkers[i].timeout_thresholds = &(glob->email_timeouts);
            glob->emailworkers[i].default_compress_delivery =
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;

            pthread_create(&(glob->emailworkers[i].threadid), NULL,
                    start_email_worker_thread,
                    (void *)&(glob->emailworkers[i]));
            pthread_setname_np(glob->emailworkers[i].threadid, name);
        }
    } else {
        glob->emailworkers = NULL;
    }

    glob->seqtrackers = calloc(glob->seqtracker_threads,
            sizeof(seqtracker_thread_data_t));

    for (i = 0; i < glob->seqtracker_threads; i++) {
        snprintf(name, 1024, "seqtracker-%d", i);
        glob->seqtrackers[i].zmq_ctxt = glob->zmq_ctxt;
        glob->seqtrackers[i].trackerid = i;
        glob->seqtrackers[i].zmq_pushjobsock = NULL;
        glob->seqtrackers[i].zmq_recvpublished = NULL;
        glob->seqtrackers[i].intercepts = NULL;
	glob->seqtrackers[i].haltinfo = NULL;
        glob->seqtrackers[i].colident = &(glob->sharedinfo);
        glob->seqtrackers[i].colident_mutex = &(glob->config_mutex);
        glob->seqtrackers[i].encoding_method = glob->encoding_method;
        pthread_create(&(glob->seqtrackers[i].threadid), NULL,
                start_seqtracker_thread, (void *)&(glob->seqtrackers[i]));
        pthread_setname_np(glob->seqtrackers[i].threadid, name);
    }

    glob->encoders = calloc(glob->encoding_threads, sizeof(openli_encoder_t));

    for (i = 0; i < glob->encoding_threads; i++) {
        snprintf(name, 1024, "encoder-%d", i);
        glob->encoders[i].zmq_ctxt = glob->zmq_ctxt;
        glob->encoders[i].zmq_recvjobs = NULL;
        glob->encoders[i].zmq_pushresults = NULL;
        glob->encoders[i].zmq_control = NULL;

        glob->encoders[i].workerid = i;
        glob->encoders[i].shared = &(glob->sharedinfo);
        glob->encoders[i].shared_mutex = &(glob->config_mutex);
        glob->encoders[i].encoder = NULL;
        glob->encoders[i].freegenerics = NULL;
        glob->encoders[i].saved_intercept_templates = NULL;
        glob->encoders[i].saved_global_templates = NULL;

        glob->encoders[i].encrypt.byte_counter = 0;
        glob->encoders[i].encrypt.byte_startts = 0;
        glob->encoders[i].encrypt.saved_encryption_templates = NULL;
        glob->encoders[i].seqtrackers = glob->seqtracker_threads;
        glob->encoders[i].forwarders = glob->forwarding_threads;

        glob->encoders[i].result_array = calloc(glob->forwarding_threads,
                sizeof(openli_encoded_result_t *));
        glob->encoders[i].result_batch = calloc(glob->forwarding_threads,
                sizeof(size_t));

        pthread_create(&(glob->encoders[i].threadid), NULL,
                run_encoder_worker, (void *)&(glob->encoders[i]));
        pthread_setname_np(glob->encoders[i].threadid, name);
    }

    /* Start email ingesting daemon, if required */
    if (glob->emailconf.enabled) {
        glob->emailsockfd = create_listener(glob->emailconf.listenaddr,
                glob->emailconf.listenport, "email ingestor socket");
        if (glob->emailsockfd == -1) {
            logger(LOG_INFO, "OpenLI: WARNING unable to create listening socket for email ingestion service");
        } else if (start_email_mhd_daemon(&(glob->emailconf),
                    glob->emailsockfd, glob->email_ingestor, &glob->sslconf)
                == NULL) {
            logger(LOG_INFO, "OpenLI: WARNING unable to start email ingestion service");
        }
    }

    /* Start IP intercept sync thread */
    ret = pthread_create(&(glob->syncip.threadid), NULL, start_ip_sync_thread,
            (void *)glob);
    if (ret != 0) {
        logger(LOG_INFO, "OpenLI: error creating IP sync thread. Exiting.");
        return 1;
    }
    snprintf(name, 1024, "sync-ip");
    pthread_setname_np(glob->syncip.threadid, name);

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL)) {
        logger(LOG_INFO, "Unable to re-enable signals after starting threads.");
        return 1;
    }

    /* Start processing threads for each input */
    while (!collector_halt) {
        sigemptyset(&sig_block_all);
        if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
            logger(LOG_INFO, "Unable to disable signals before starting threads.");
            return 1;
        }

        pthread_rwlock_wrlock(&(glob->config_mutex));
        HASH_ITER(hh, glob->x_inputs, xinp, xtmp) {
            if (start_xinput(glob, xinp) == 0) {
                logger(LOG_INFO, "OpenLI: failed to start X2-X3 input %s",
                        xinp->identifier);
            }
        }
        pthread_rwlock_unlock(&(glob->config_mutex));

        pthread_rwlock_rdlock(&(glob->config_mutex));
        HASH_ITER(hh, glob->inputs, inp, tmp) {
            if (start_input(glob, inp, todaemon, argv[0]) == 0) {
                logger(LOG_INFO, "OpenLI: failed to start input %s",
                        inp->uri);
            }
        }
        pthread_rwlock_unlock(&(glob->config_mutex));

        if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL)) {
            logger(LOG_INFO, "Unable to re-enable signals after starting threads.");
            return 1;
        }
        usleep(1000000);
    }

    pthread_rwlock_rdlock(&(glob->config_mutex));
    HASH_ITER(hh, glob->inputs, inp, tmp) {
        if (inp->trace) {
            libtrace_stat_t *stat;
            trace_join(inp->trace);
            stat = trace_create_statistics();
            trace_get_statistics(inp->trace, stat);

            if (stat->dropped_valid) {
                logger(LOG_DEBUG, "OpenLI: dropped %lu packets on input %s",
                        stat->dropped, inp->uri);
            }
            if (stat->received_valid) {
                logger(LOG_DEBUG, "OpenLI: received %lu packets on input %s",
                        stat->received, inp->uri);
            }
            if (stat->accepted_valid) {
                logger(LOG_DEBUG, "OpenLI: accepted %lu packets on input %s",
                        stat->accepted, inp->uri);
            }
            free(stat);
        }
    }

    HASH_ITER(hh, glob->x_inputs, xinp, xtmp) {
        pthread_join(xinp->threadid, NULL);
        HASH_DELETE(hh, glob->x_inputs, xinp);
        destroy_x_input(xinp);
    }

    pthread_rwlock_unlock(&(glob->config_mutex));

    if (glob->zmq_encoder_ctrl) {
        /* The only control message required for encoding threads is the
         * "halt" message, so we can just send an empty message and the
         * recipients should treat that as a "halt" command.
         */
        if (zmq_send(glob->zmq_encoder_ctrl, NULL, 0, 0) < 0) {
            logger(LOG_INFO,
                    "OpenLI: error sending halt to encoding threads: %s",
                    strerror(errno));
        }
    }

    if (glob->email_ingestor) {
        stop_email_mhd_daemon(glob->email_ingestor);
    }

    pthread_join(glob->syncip.threadid, NULL);
    for (i = 0; i < glob->seqtracker_threads; i++) {
        pthread_join(glob->seqtrackers[i].threadid, NULL);
    }
    for (i = 0; i < glob->encoding_threads; i++) {
        pthread_join(glob->encoders[i].threadid, NULL);
        destroy_encoder_worker(&(glob->encoders[i]));
    }
    for (i = 0; i < glob->forwarding_threads; i++) {
        pthread_join(glob->forwarders[i].threadid, NULL);
    }
    for (i = 0; i < glob->email_threads; i++) {
        pthread_join(glob->emailworkers[i].threadid, NULL);
    }
    for (i = 0; i < glob->gtp_threads; i++) {
        pthread_join(glob->gtpworkers[i].threadid, NULL);
    }
    for (i = 0; i < glob->sip_threads; i++) {
        pthread_join(glob->sipworkers[i].threadid, NULL);
    }

    logger(LOG_INFO, "OpenLI: exiting OpenLI Collector.");
    /* Tidy up, exit */
    clear_global_config(glob);
    destroy_collector_state(glob);

    if (todaemon && pidfile) {
        remove_pidfile(pidfile);
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
