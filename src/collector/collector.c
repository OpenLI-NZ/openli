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

#include <libtrace_parallel.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "configparser.h"
#include "collector_sync_voip.h"
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

static void cleanup_signal(int signal UNUSED)
{
    collector_halt = 1;
}

static void reload_signal(int signal) {
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
    logger(LOG_INFO, "OpenLI: Packets sent to IP sync: %lu,  sent to VOIP sync: %lu",
            glob->stats.packets_sync_ip, glob->stats.packets_sync_voip);
    logger(LOG_INFO, "OpenLI: Packets sent to Email workers: %lu",
            glob->stats.packets_sync_email);
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

static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, uint64_t tick) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)local;
    libtrace_stat_t *stats;


    if (trace_get_perpkt_thread_id(t) == 0) {

        stats = trace_create_statistics();
        trace_get_statistics(trace, stats);

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
            loc->dropped = stats->dropped;
        }

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

static void init_collocal(colthread_local_t *loc, collector_global_t *glob,
        int threadid) {

    int i, hwm=1000;
    libtrace_message_queue_init(&(loc->fromsyncq_ip),
            sizeof(openli_pushed_t));
    libtrace_message_queue_init(&(loc->fromsyncq_voip),
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
    loc->staticv4ranges = New_Patricia(32);
    loc->staticv6ranges = New_Patricia(128);
    loc->dynamicv6ranges = New_Patricia(128);
    loc->staticcache = NULL;
    loc->tosyncq_ip = NULL;
    loc->tosyncq_voip = NULL;

    loc->accepted = 0;
    loc->dropped = 0;


    loc->zmq_pubsocks = calloc(glob->seqtracker_threads, sizeof(void *));
    for (i = 0; i < glob->seqtracker_threads; i++) {
        char pubsockname[128];

        snprintf(pubsockname, 128, "inproc://openlipub-%d", i);
        loc->zmq_pubsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        zmq_setsockopt(loc->zmq_pubsocks[i], ZMQ_SNDHWM, &hwm, sizeof(hwm));
        zmq_connect(loc->zmq_pubsocks[i], pubsockname);
    }

    loc->email_worker_queues = calloc(glob->email_threads, sizeof(void *));
    for (i = 0; i < glob->email_threads; i++) {
        char pubsockname[128];

        snprintf(pubsockname, 128, "inproc://openliemailworker-colrecv%d", i);
        loc->email_worker_queues[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        zmq_setsockopt(loc->email_worker_queues[i], ZMQ_SNDHWM, &hwm,
                sizeof(hwm));
        zmq_connect(loc->email_worker_queues[i], pubsockname);
    }

    loc->fragreass = create_new_ipfrag_reassembler();

    loc->tosyncq_ip = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    zmq_setsockopt(loc->tosyncq_ip, ZMQ_SNDHWM, &hwm, sizeof(hwm));
    zmq_connect(loc->tosyncq_ip, "inproc://openli-ipsync");

    loc->tosyncq_voip = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    zmq_setsockopt(loc->tosyncq_voip, ZMQ_SNDHWM, &hwm, sizeof(hwm));
    zmq_connect(loc->tosyncq_voip, "inproc://openli-voipsync");

}

static void *start_processing_thread(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = NULL;

    pthread_rwlock_wrlock(&(glob->config_mutex));
    loc = glob->collocals[glob->nextloc];
    glob->nextloc ++;
    pthread_rwlock_unlock(&(glob->config_mutex));

    register_sync_queues(&(glob->syncip), loc->tosyncq_ip,
			&(loc->fromsyncq_ip), t);
    register_sync_queues(&(glob->syncvoip), loc->tosyncq_voip,
			&(loc->fromsyncq_voip), t);

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

static void process_incoming_messages(libtrace_thread_t *t,
        collector_global_t *glob, colthread_local_t *loc,
        openli_pushed_t *syncpush) {

    if (syncpush->type == OPENLI_PUSH_IPINTERCEPT) {
        handle_push_ipintercept(t, loc, syncpush->data.ipsess);
    }

    if (syncpush->type == OPENLI_PUSH_HALT_IPINTERCEPT) {
        handle_halt_ipintercept(t, loc, syncpush->data.ipsess);
    }

    if (syncpush->type == OPENLI_PUSH_IPMMINTERCEPT) {
        handle_push_ipmmintercept(t, loc, syncpush->data.ipmmint);
    }

    if (syncpush->type == OPENLI_PUSH_HALT_IPMMINTERCEPT) {
        handle_halt_ipmmintercept(t, loc, syncpush->data.rtpstreamkey);
    }

    if (syncpush->type == OPENLI_PUSH_CORESERVER) {
        handle_push_coreserver(t, loc, syncpush->data.coreserver);
    }

    if (syncpush->type == OPENLI_PUSH_REMOVE_CORESERVER) {
        handle_remove_coreserver(t, loc, syncpush->data.coreserver);
    }

    if (syncpush->type == OPENLI_PUSH_VENDMIRROR_INTERCEPT) {
        handle_push_mirror_intercept(t, loc, syncpush->data.mirror);
    }

    if (syncpush->type == OPENLI_PUSH_HALT_VENDMIRROR_INTERCEPT) {
        handle_halt_mirror_intercept(t, loc, syncpush->data.mirror);
    }

    if (syncpush->type == OPENLI_PUSH_IPRANGE) {
        handle_iprange(t, loc, syncpush->data.iprange);
    }

    if (syncpush->type == OPENLI_PUSH_REMOVE_IPRANGE) {
        handle_remove_iprange(t, loc, syncpush->data.iprange);
    }

    if (syncpush->type == OPENLI_PUSH_MODIFY_IPRANGE) {
        handle_modify_iprange(t, loc, syncpush->data.iprange);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_VOIPINTERCEPT) {
        handle_change_voip_intercept(t, loc, syncpush->data.ipmmint);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_IPINTERCEPT) {
        handle_change_ipint_intercept(t, loc, syncpush->data.ipsess);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_VENDMIRROR_INTERCEPT) {
        handle_change_vendmirror_intercept(t, loc, syncpush->data.mirror);
    }

    if (syncpush->type == OPENLI_PUSH_UPDATE_IPRANGE_INTERCEPT) {
        handle_change_iprange_intercept(t, loc, syncpush->data.iprange);
    }

}

static void stop_processing_thread(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *tls) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)tls;
    ipv4_target_t *v4, *tmp;
    ipv6_target_t *v6, *tmp2;
    openli_pushed_t syncpush;
    int zero = 0, i;

    if (trace_is_err(trace)) {
        libtrace_err_t err = trace_get_err(trace);
        logger(LOG_INFO, "OpenLI: halting input due to error: %s",
                err.problem);
    }

    while (libtrace_message_queue_try_get(&(loc->fromsyncq_ip),
            (void *)&syncpush) != LIBTRACE_MQ_FAILED) {
        process_incoming_messages(t, glob, loc, &syncpush);
    }

    while (libtrace_message_queue_try_get(&(loc->fromsyncq_voip),
            (void *)&syncpush) != LIBTRACE_MQ_FAILED) {
        process_incoming_messages(t, glob, loc, &syncpush);
    }

    deregister_sync_queues(&(glob->syncip), t);
    deregister_sync_queues(&(glob->syncvoip), t);

    libtrace_message_queue_destroy(&(loc->fromsyncq_ip));
    libtrace_message_queue_destroy(&(loc->fromsyncq_voip));

    for (i = 0; i < glob->seqtracker_threads; i++) {
        zmq_setsockopt(loc->zmq_pubsocks[i], ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(loc->zmq_pubsocks[i]);
    }

    for (i = 0; i < glob->email_threads; i++) {
        zmq_setsockopt(loc->email_worker_queues[i], ZMQ_LINGER, &zero,
                sizeof(zero));
        zmq_close(loc->email_worker_queues[i]);
    }

    zmq_setsockopt(loc->tosyncq_ip, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_close(loc->tosyncq_ip);
    zmq_setsockopt(loc->tosyncq_voip, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_close(loc->tosyncq_voip);

    free(loc->zmq_pubsocks);
    free(loc->email_worker_queues);

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
    int caplen = trace_get_capture_length(pkt);
    int framelen = trace_get_framing_length(pkt);

    if (caplen == -1 || framelen == -1) {
        logger(LOG_INFO, "OpenLI: unable to copy packet for sync thread (caplen=%d, framelen=%d)", caplen, framelen);
        exit(1);
    }

    /* We do this ourselves instead of calling trace_copy_packet() because
     * we don't want to be allocating 64K per copied packet -- we could be
     * doing this a lot and don't want to be wasteful */
    copy = (libtrace_packet_t *)calloc((size_t)1, sizeof(libtrace_packet_t));
    if (!copy) {
        logger(LOG_INFO, "OpenLI: out of memory while copying packet for sync thread");
        exit(1);
    }

    copy->trace = pkt->trace;
    copy->buf_control = TRACE_CTRL_PACKET;
    copy->buffer = malloc(framelen + caplen);
    copy->type = pkt->type;
    copy->header = copy->buffer;
    copy->payload = ((char *)copy->buffer) + framelen;
    copy->order = pkt->order;
    copy->hash = pkt->hash;
    copy->error = pkt->error;
    copy->which_trace_start = pkt->which_trace_start;
    copy->cached.capture_length = caplen;
    copy->cached.framing_length = framelen;
    copy->cached.wire_length = -1;
    copy->cached.payload_length = -1;
    /* everything else in cache should be 0 or NULL due to our earlier
     * calloc() */
    memcpy(copy->header, pkt->header, framelen);
    memcpy(copy->payload, pkt->payload, caplen);

    syncup.type = updatetype;
    syncup.data.pkt = copy;

    //trace_increment_packet_refcount(pkt);
    zmq_send(q, (void *)(&syncup), sizeof(syncup), 0);
}

static void send_packet_to_emailworker(libtrace_packet_t *pkt,
        void **queues, int qcount, uint32_t hashval, uint8_t pkttype) {

    int destind;

    assert(hashval != 0);
    destind = (hashval - 1) % qcount;
    send_packet_to_sync(pkt, queues[destind], pkttype);
}

static inline uint8_t check_for_invalid_sip(libtrace_packet_t *pkt,
        uint16_t fragoff) {

    void *transport, *payload;
    uint32_t plen, fourbytes;
    uint8_t proto;
    uint32_t rem;

    /* STUN can be sent by clients to the SIP servers, so try to detect
     * that.
     *
     * Typical examples so far: 20 byte UDP, with payload beginning with
     * 00 01 00 00.
     */
    if (fragoff > 0) {
        return 0;
    }
    transport = trace_get_transport(pkt, &proto, &rem);

    if (transport == NULL || rem == 0) {
        return 1;
    }

    if (proto == TRACE_IPPROTO_UDP) {
        payload = trace_get_payload_from_udp((libtrace_udp_t *)transport, &rem);

        if (payload == NULL || rem == 0) {
            return 1;
        }

        plen = trace_get_payload_length(pkt);
        fourbytes = ntohl(*((uint32_t *)payload));

        /* STUN matching borrowed from libprotoident */
        if ((fourbytes & 0xffff) == plen - 20) {
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
    }

    return 0;
}

static inline uint32_t is_core_server_packet(libtrace_packet_t *pkt,
        packet_info_t *pinfo, coreserver_t *servers) {

    coreserver_t *rad, *tmp;
    coreserver_t *found = NULL;
    uint32_t hashval = 0;

    if (pinfo->srcport == 0 || pinfo->destport == 0) {
        return 0;
    }

    HASH_ITER(hh, servers, rad, tmp) {
        if (rad->info == NULL) {
            rad->info = populate_addrinfo(rad->ipstr, rad->portstr,
                    SOCK_DGRAM);
            if (!rad->info) {
                logger(LOG_INFO,
                        "Removing %s:%s from %s server list due to getaddrinfo error",
                        rad->ipstr, rad->portstr,
                        coreserver_type_to_string(rad->servertype));

                HASH_DELETE(hh, servers, rad);
                continue;
            }
            if (rad->info->ai_family == AF_INET) {
                rad->portswapped = ntohs(CS_TO_V4(rad)->sin_port);
            } else if (rad->info->ai_family == AF_INET6) {
                rad->portswapped = ntohs(CS_TO_V6(rad)->sin6_port);
            }
        }

        if (pinfo->family == AF_INET) {
            struct sockaddr_in *sa;
            sa = (struct sockaddr_in *)(&(pinfo->srcip));

            if (CORESERVER_MATCH_V4(rad, sa, pinfo->srcport)) {
                found = rad;
                break;
            }
            sa = (struct sockaddr_in *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V4(rad, sa, pinfo->destport)) {
                found = rad;
                break;
            }
        } else if (pinfo->family == AF_INET6) {
            struct sockaddr_in6 *sa6;
            sa6 = (struct sockaddr_in6 *)(&(pinfo->srcip));
            if (CORESERVER_MATCH_V6(rad, sa6, pinfo->srcport)) {
                found = rad;
                break;
            }
            sa6 = (struct sockaddr_in6 *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V6(rad, sa6, pinfo->destport)) {
                found = rad;
                break;
            }
        }
    }

    /* Doesn't match any of our known core servers */
    if (found == NULL) {
        return 0;
    }

    /* Not technically an LIID, but we just need a hashed ID for the server
     * entity.
     */
    hashval = hash_liid(found->serverkey);

    /* 0 is our value for "not found", so make sure we never use it... */
    if (hashval == 0) {
        hashval = 1;
    }
    return hashval;

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
    uint16_t fragoff = 0;
    uint32_t servhash = 0;

    openli_pushed_t syncpush;
    packet_info_t pinfo;

    /* Check for any messages from the sync threads */
    while (libtrace_message_queue_try_get(&(loc->fromsyncq_ip),
            (void *)&syncpush) != LIBTRACE_MQ_FAILED) {

        process_incoming_messages(t, glob, loc, &syncpush);
    }

    while (libtrace_message_queue_try_get(&(loc->fromsyncq_voip),
            (void *)&syncpush) != LIBTRACE_MQ_FAILED) {

        process_incoming_messages(t, glob, loc, &syncpush);
    }


    l3 = trace_get_layer3(pkt, &ethertype, &rem);
    if (l3 == NULL || rem == 0) {
        return pkt;
    }

    //trace_increment_packet_refcount(pkt);

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

        fragoff = trace_get_fragment_offset(pkt, &moreflag);
        if (moreflag || fragoff > 0) {
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

    /* All these special packets are UDP, so we can avoid a whole bunch
     * of these checks for TCP traffic */
    if (proto == TRACE_IPPROTO_UDP) {

        /* Is this from one of our ALU mirrors -- if yes, parse + strip it
         * for conversion to an ETSI record */
        if (glob->alumirrors && check_alu_intercept(&(glob->sharedinfo), loc,
                pkt, &pinfo, glob->alumirrors, loc->activemirrorintercepts)) {
            forwarded = 1;
            pthread_mutex_lock(&(glob->stats_mutex));
            glob->stats.ipcc_created += 1;
            pthread_mutex_unlock(&(glob->stats_mutex));
            goto processdone;
        }

        if (glob->jmirrors && check_jmirror_intercept(&(glob->sharedinfo), loc,
                pkt, &pinfo, glob->jmirrors, loc->activemirrorintercepts)) {

            forwarded = 1;
            pthread_mutex_lock(&(glob->stats_mutex));
            glob->stats.ipcc_created += 1;
            pthread_mutex_unlock(&(glob->stats_mutex));
            goto processdone;
        }

        if (glob->ciscomirrors) {
            coreserver_t *cs;
            if ((cs = match_packet_to_coreserver(glob->ciscomirrors,
                    &pinfo)) != NULL) {
                if (glob->cisco_noradius && generate_cc_from_cisco(
                        &(glob->sharedinfo), loc, pkt, &pinfo,
                        loc->activemirrorintercepts)) {

                    forwarded = 1;
                    pthread_mutex_lock(&(glob->stats_mutex));
                    glob->stats.ipcc_created += 1;
                    pthread_mutex_unlock(&(glob->stats_mutex));
                    goto processdone;
                } else {
                    /* strip the cisco shim and just treat it like an
                     * ordinary packet -- we'll instead rely on RADIUS
                     * or some other session management protocol to tell
                     * us whether we need to intercept this packet or not.
                     */
                    libtrace_packet_t *stripped;
                    stripped = strip_cisco_mirror_header(pkt);
                    if (stripped && process_packet(trace, t, global, tls,
                            stripped)) {
                        trace_destroy_packet(stripped);
                    }
                    goto processdone;
                }
            }
        }

        /* Is this a RADIUS packet? -- if yes, create a state update */
        if (loc->radiusservers && is_core_server_packet(pkt, &pinfo,
                    loc->radiusservers)) {
            send_packet_to_sync(pkt, loc->tosyncq_ip, OPENLI_UPDATE_RADIUS);
            ipsynced = 1;
            goto processdone;
        }

        if (loc->gtpservers && is_core_server_packet(pkt, &pinfo,
                    loc->gtpservers)) {
            send_packet_to_sync(pkt, loc->tosyncq_ip, OPENLI_UPDATE_GTP);
            ipsynced = 1;
            goto processdone;
        }

        /* Is this a SIP packet? -- if yes, create a state update */
        if (loc->sipservers && is_core_server_packet(pkt, &pinfo,
                    loc->sipservers)) {
            if (!check_for_invalid_sip(pkt, fragoff)) {
                send_packet_to_sync(pkt, loc->tosyncq_voip,
                        OPENLI_UPDATE_SIP);
                voipsynced = 1;
            }
        }
    } else if (proto == TRACE_IPPROTO_TCP) {
        /* Is this a SIP packet? -- if yes, create a state update */
        if (loc->sipservers && is_core_server_packet(pkt, &pinfo,
                    loc->sipservers)) {
            send_packet_to_sync(pkt, loc->tosyncq_voip, OPENLI_UPDATE_SIP);
            voipsynced = 1;
        }

        else if (loc->smtpservers &&
                (servhash = is_core_server_packet(pkt, &pinfo,
                    loc->smtpservers))) {
            send_packet_to_emailworker(pkt, loc->email_worker_queues,
                    glob->email_threads, servhash, OPENLI_UPDATE_SMTP);
            emailsynced = 1;

        }

        else if (loc->imapservers &&
                (servhash = is_core_server_packet(pkt, &pinfo,
                    loc->imapservers))) {
            send_packet_to_emailworker(pkt, loc->email_worker_queues,
                    glob->email_threads, servhash, OPENLI_UPDATE_IMAP);
            emailsynced = 1;
        }

        else if (loc->pop3servers &&
                (servhash = is_core_server_packet(pkt, &pinfo,
                    loc->pop3servers))) {
            send_packet_to_emailworker(pkt, loc->email_worker_queues,
                    glob->email_threads, servhash, OPENLI_UPDATE_POP3);
            emailsynced = 1;
        }
    }


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

static int start_input(collector_global_t *glob, colinput_t *inp,
        int todaemon, char *progname) {

    if (inp->running == 1) {
        /* Trace is already running */
        return 1;
    }

    if (!inp->pktcbs) {
        inp->pktcbs = trace_create_callback_set();
    }
    trace_set_starting_cb(inp->pktcbs, start_processing_thread);
    trace_set_stopping_cb(inp->pktcbs, stop_processing_thread);
    trace_set_packet_cb(inp->pktcbs, process_packet);

    if (inp->report_drops) {
        trace_set_tick_interval_cb(inp->pktcbs, process_tick);
    }

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

    trace_set_tick_interval(inp->trace, 1000);

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

static void reload_inputs(collector_global_t *glob,
        collector_global_t *newstate) {

    colinput_t *oldinp, *newinp, *tmp;
    int filterchanged = 0, i;
    int oldcolthreads = glob->total_col_threads;

    logger(LOG_INFO,
            "OpenLI: collector is reloading input configuration.");

    HASH_ITER(hh, glob->inputs, oldinp, tmp) {
        HASH_FIND(hh, newstate->inputs, oldinp->uri, strlen(oldinp->uri),
                newinp);
        filterchanged = 0;
        if (newinp) {
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
                filterchanged) {
            /* This input is no longer wanted at all */
            logger(LOG_INFO,
                    "OpenLI collector: stop reading packets from %s",
                    oldinp->uri);
            trace_pstop(oldinp->trace);
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
        glob->total_col_threads += newinp->threadcount;
    }

    /* XXX one thing to be aware of -- we never reclaim the memory
     * allocated to collector threads that are no longer used (because
     * we called trace_pstop() on the input). In theory, that means
     * we will slowly leak colthread_local_t's whenever the collector
     * config is reloaded AND an input is changed. Realistically, this
     * won't happen often so shouldn't be a big deal but I want to note
     * that I am aware of this potential issue.
     *
     * The correct answer would be to replace this array with a dynamic
     * data structure that we can remove items from easily whenever their
     * parent input is stopped. Not worth the effort right now, but would
     * be a good task to assign to a new developer on the project?
     */

    if (glob->total_col_threads > oldcolthreads) {
        glob->collocals = (colthread_local_t **)realloc(glob->collocals,
                sizeof(colthread_local_t *) * glob->total_col_threads);

        for (i = oldcolthreads; i < glob->total_col_threads; i++) {
            glob->collocals[i] = calloc(1, sizeof(colthread_local_t));
            init_collocal(glob->collocals[i], glob, i);
        }
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
    hash_radius_cleanup(&(input->hashradconf));
}

static inline void init_sync_thread_data(collector_global_t *glob,
        sync_thread_global_t *sup) {

    sup->threadid = 0;
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
	free_sync_thread_data(&(glob->syncvoip));

    if (glob->emailworkers) {
        free(glob->emailworkers);
    }

    libtrace_message_queue_destroy(&(glob->intersyncq));

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

    if (glob->collocals) {
        for (i = 0; i < glob->total_col_threads; i++) {
            if (glob->collocals[i]) {
                free(glob->collocals[i]);
            }
        }
        free(glob->collocals);
    }

    if (glob->default_email_domain) {
        free(glob->default_email_domain);
    }

    pthread_mutex_destroy(&(glob->stats_mutex));
    pthread_rwlock_destroy(&(glob->email_config_mutex));
    pthread_rwlock_destroy(&glob->config_mutex);
    free(glob);
}

static void clear_global_config(collector_global_t *glob) {
    colinput_t *inp, *tmp;

    HASH_ITER(hh, glob->inputs, inp, tmp) {
        HASH_DELETE(hh, glob->inputs, inp);
        clear_input(inp);
        free(inp);
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

    if (glob->alumirrors) {
        free_coreserver_list(glob->alumirrors);
    }
    if (glob->jmirrors) {
        free_coreserver_list(glob->jmirrors);
    }
    if (glob->ciscomirrors) {
        free_coreserver_list(glob->ciscomirrors);
    }

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

    sync_sendq_t *syncq, *sendq_hash;

    syncq = (sync_sendq_t *)malloc(sizeof(sync_sendq_t));
    syncq->q = sendq;
    syncq->parent = parent;

    pthread_mutex_lock(&(glob->mutex));

    sendq_hash = (sync_sendq_t *)(glob->collector_queues);
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
    int i;

    glob->zmq_ctxt = zmq_ctx_new();

    glob->expired_inputs = libtrace_list_init(sizeof(colinput_t *));

    init_sync_thread_data(glob, &(glob->syncip));
    init_sync_thread_data(glob, &(glob->syncvoip));

    glob->collocals = (colthread_local_t **)calloc(glob->total_col_threads,
            sizeof(colthread_local_t *));

    for (i = 0; i < glob->total_col_threads; i++) {
        glob->collocals[i] = calloc(1, sizeof(colthread_local_t));
        init_collocal(glob->collocals[i], glob, i);
    }

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
    glob->zmq_ctxt = NULL;
    glob->inputs = NULL;
    glob->seqtracker_threads = 1;
    glob->forwarding_threads = 1;
    glob->encoding_threads = 2;
    glob->email_threads = 1;
    glob->sharedinfo.intpointid = NULL;
    glob->sharedinfo.intpointid_len = 0;
    glob->sharedinfo.operatorid = NULL;
    glob->sharedinfo.operatorid_len = 0;
    glob->sharedinfo.networkelemid = NULL;
    glob->sharedinfo.networkelemid_len = 0;
    glob->total_col_threads = 0;
    glob->collocals = NULL;
    glob->expired_inputs = NULL;

    glob->configfile = NULL;
    glob->sharedinfo.provisionerip = NULL;
    glob->sharedinfo.provisionerport = NULL;
    glob->alumirrors = NULL;
    glob->jmirrors = NULL;
    glob->ciscomirrors = NULL;
    glob->sipdebugfile = NULL;
    glob->nextloc = 0;
    glob->syncgenericfreelist = NULL;
    glob->trust_sip_from = 0;

    glob->sslconf.certfile = NULL;
    glob->sslconf.keyfile = NULL;
    glob->sslconf.cacertfile = NULL;
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
    glob->ignore_sdpo_matches = 0;
    glob->encoding_method = OPENLI_ENCODING_DER;

    memset(&(glob->stats), 0, sizeof(glob->stats));
    glob->stat_frequency = 0;
    glob->ticks_since_last_stat = 0;

    glob->emailsockfd = -1;
    glob->email_ingestor = NULL;

    /* TODO add config options to change these values
     *      also make sure changes are actions post config-reload */
    glob->email_timeouts.smtp = 5;
    glob->email_timeouts.pop3 = 10;
    glob->email_timeouts.imap = 30;
    glob->mask_imap_creds = 1;      // defaults to "enabled"
    glob->mask_pop3_creds = 1;      // defaults to "enabled"
    glob->cisco_noradius = 0;            // defaults to "expect RADIUS"
    glob->default_email_domain = NULL;
}

static collector_global_t *parse_global_config(char *configfile) {

    collector_global_t *glob = NULL;

    glob = (collector_global_t *)calloc(1, sizeof(collector_global_t));
    init_collector_global(glob);
    glob->configfile = configfile;

    pthread_mutex_init(&(glob->stats_mutex), NULL);
    pthread_rwlock_init(&(glob->email_config_mutex), NULL);

    libtrace_message_queue_init(&glob->intersyncq,
            sizeof(openli_intersync_msg_t));

    pthread_rwlock_init(&glob->config_mutex, NULL);

    if (parse_collector_config(configfile, glob) == -1) {
        clear_global_config(glob);
        return NULL;
    }

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

    if (glob->trust_sip_from) {
        logger(LOG_INFO, "Allowing SIP From: URIs to be used for target identification");
    }

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
    }

    pthread_rwlock_wrlock(&(glob->config_mutex));

    glob->stat_frequency = newstate.stat_frequency;
    reload_inputs(glob, &newstate);

    /* Just update these, regardless of whether they've changed. It's more
     * effort to check for a change than it is worth and there are no
     * flow-on effects to a change.
     */
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

    pthread_rwlock_unlock(&(glob->config_mutex));

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

    glob->mask_imap_creds = newstate.mask_imap_creds;
    glob->mask_pop3_creds = newstate.mask_pop3_creds;
    glob->email_timeouts.smtp = newstate.email_timeouts.smtp;
    glob->email_timeouts.imap = newstate.email_timeouts.imap;
    glob->email_timeouts.pop3 = newstate.email_timeouts.pop3;

    logger(LOG_DEBUG, "OpenLI: session idle timeout for SMTP sessions is now %u minutes", glob->email_timeouts.smtp);
    logger(LOG_DEBUG, "OpenLI: session idle timeout for IMAP sessions is now %u minutes", glob->email_timeouts.imap);
    logger(LOG_DEBUG, "OpenLI: session idle timeout for POP3 sessions is now %u minutes", glob->email_timeouts.pop3);
    pthread_rwlock_unlock(&(glob->email_config_mutex));

endreload:
    clear_global_config(&newstate);
    return ret;
}

static void *start_voip_sync_thread(void *params) {

    collector_global_t *glob = (collector_global_t *)params;
    int ret;
    collector_sync_voip_t *sync = init_voip_sync_data(glob);
    sync_sendq_t *sq;

    while (collector_halt == 0) {
        ret = sync_voip_thread_main(sync);
        if (ret == -1) {
            break;
        }
    }

    clean_sync_voip_data(sync);
    do {
        pthread_mutex_lock(&(glob->syncvoip.mutex));
        sq = (sync_sendq_t *)(glob->syncvoip.collector_queues);
        if (HASH_CNT(hh, sq) == 0) {
            pthread_mutex_unlock(&(glob->syncvoip.mutex));
            break;
        }
        pthread_mutex_unlock(&(glob->syncvoip.mutex));
        usleep(500000);
    } while (1);

    free(sync);
    logger(LOG_DEBUG, "OpenLI: exiting VOIP sync thread.");
    pthread_exit(NULL);
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

    /* XXX For early development work, we will read intercept instructions
     * from a config file. Eventually this should be replaced with
     * instructions that are received via a network interface.
     */
    if (sync->zmq_colsock == NULL) {
        goto haltsyncthread;
    }

    while (collector_halt == 0) {
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


int main(int argc, char *argv[]) {

	struct sigaction sigact, sigign;
    sigset_t sig_before, sig_block_all;
    char *configfile = NULL;
    char *pidfile = NULL;
    collector_global_t *glob = NULL;
    int i, ret, todaemon;
    colinput_t *inp, *tmp;
    char name[1024];

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
        glob->forwarders[i].colthreads = glob->total_col_threads;
        glob->forwarders[i].zmq_ctrlsock = NULL;
        glob->forwarders[i].zmq_pullressock = NULL;
        pthread_mutex_init(&(glob->forwarders[i].sslmutex), NULL);
        glob->forwarders[i].ctx =
                (glob->sslconf.ctx && glob->etsitls) ? glob->sslconf.ctx : NULL;
        //forwarder only needs CTX if ctx exists and is enabled 
        glob->forwarders[i].RMQ_conf = glob->RMQ_conf;

        pthread_create(&(glob->forwarders[i].threadid), NULL,
                start_forwarding_thread, (void *)&(glob->forwarders[i]));
        pthread_setname_np(glob->forwarders[i].threadid, name);
    }

    glob->emailworkers = calloc(glob->email_threads,
            sizeof(openli_email_worker_t));

    for (i = 0; i < glob->email_threads; i++) {
        snprintf(name, 1024, "emailworker-%d", i);

        glob->emailworkers[i].zmq_ctxt = glob->zmq_ctxt;
        glob->emailworkers[i].topoll = NULL;
        glob->emailworkers[i].topoll_size = 0;
        glob->emailworkers[i].emailid = i;
        glob->emailworkers[i].tracker_threads = glob->seqtracker_threads;
        glob->emailworkers[i].fwd_threads = glob->forwarding_threads;
        glob->emailworkers[i].zmq_pubsocks = NULL;
        glob->emailworkers[i].zmq_fwdsocks = NULL;
        glob->emailworkers[i].zmq_ingest_recvsock = NULL;
        glob->emailworkers[i].zmq_colthread_recvsock = NULL;
        glob->emailworkers[i].zmq_ii_sock = NULL;

        glob->emailworkers[i].timeouts = NULL;
        glob->emailworkers[i].allintercepts = NULL;
        glob->emailworkers[i].alltargets = NULL;
        glob->emailworkers[i].activesessions = NULL;
        glob->emailworkers[i].stats_mutex = &(glob->stats_mutex);
        glob->emailworkers[i].stats = &(glob->stats);

        glob->emailworkers[i].glob_config_mutex = &(glob->email_config_mutex);
        glob->emailworkers[i].mask_imap_creds = &(glob->mask_imap_creds);
        glob->emailworkers[i].mask_pop3_creds = &(glob->mask_pop3_creds);
        glob->emailworkers[i].defaultdomain = &(glob->default_email_domain);
        glob->emailworkers[i].timeout_thresholds = &(glob->email_timeouts);
        glob->emailworkers[i].default_compress_delivery =
                OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;

        pthread_create(&(glob->emailworkers[i].threadid), NULL,
                start_email_worker_thread, (void *)&(glob->emailworkers[i]));
        pthread_setname_np(glob->emailworkers[i].threadid, name);
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
        glob->seqtrackers[i].colident = &(glob->sharedinfo);
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
        glob->encoders[i].encoder = NULL;
        glob->encoders[i].freegenerics = NULL;
        glob->encoders[i].saved_intercept_templates = NULL;
        glob->encoders[i].saved_global_templates = NULL;
        glob->encoders[i].saved_encryption_templates = NULL;

        glob->encoders[i].encrypt_byte_counter = 0;
        glob->encoders[i].encrypt_byte_startts = 0;
        glob->encoders[i].evp_ctx = NULL;
        glob->encoders[i].seqtrackers = glob->seqtracker_threads;
        glob->encoders[i].forwarders = glob->forwarding_threads;

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

    /* Start VOIP intercept sync thread */
    ret = pthread_create(&(glob->syncvoip.threadid), NULL,
            start_voip_sync_thread, (void *)glob);
    if (ret != 0) {
        logger(LOG_INFO, "OpenLI: error creating VOIP sync thread. Exiting.");
        return 1;
    }
    snprintf(name, 1024, "sync-voip");
    pthread_setname_np(glob->syncvoip.threadid, name);

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

        pthread_rwlock_rdlock(&(glob->config_mutex));
        HASH_ITER(hh, glob->inputs, inp, tmp) {
            if (start_input(glob, inp, todaemon, argv[0]) == 0) {
                logger(LOG_INFO, "OpenLI: failed to start input %s\n",
                        inp->uri);
            }
        }
        pthread_rwlock_unlock(&(glob->config_mutex));

        if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL)) {
            logger(LOG_INFO, "Unable to re-enable signals after starting threads.");
            return 1;
        }
        usleep(1000);
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
    pthread_join(glob->syncvoip.threadid, NULL);
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
