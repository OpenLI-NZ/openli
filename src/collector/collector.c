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
#include "collector_export.h"
#include "collector_push_messaging.h"
#include "ipcc.h"
#include "ipmmcc.h"
#include "sipparsing.h"
#include "alushim_parser.h"
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

#if 0
static void dump_ip_intercept(ipintercept_t *ipint) {
    char ipbuf[256];

    printf("Intercept %u  %s\n", ipint->internalid,
            ipint->active ? "ACTIVE": "INACTIVE");
    printf("LI ID: %s\n", ipint->liid);
    printf("Auth CC: %s     Delivery CC: %s\n", ipint->authcc,
            ipint->delivcc);
    if (ipint->username) {
        printf("Username: %s\n", ipint->username);
    } else {
        printf("Username: Unknown\n");
    }

    if (ipint->ipaddr && ipint->ai_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ipint->ipaddr;
        inet_ntop(AF_INET, (void *)&(sin->sin_addr), ipbuf, 256);
        printf("User IPv4 address: %s\n", ipbuf);
    } else {
        printf("User IP address: Unknown\n");
    }

    printf("Communication ID: %u\n", ipint->cin);
    printf("------\n");
}
#endif

static void dump_rtp_intercept(rtpstreaminf_t *rtp) {
    char ipbuf[256];

    printf("LI ID: %s\n", rtp->common.liid);
    printf("Auth CC: %s     Delivery CC: %s\n", rtp->common.authcc,
            rtp->common.delivcc);

    if (rtp->targetaddr && rtp->ai_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)rtp->targetaddr;
        inet_ntop(AF_INET, (void *)&(sin->sin_addr), ipbuf, 256);
        printf("Target RTP endpoint: %s:%u\n", ipbuf, rtp->targetport);
    }

    if (rtp->otheraddr && rtp->ai_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)rtp->otheraddr;
        inet_ntop(AF_INET, (void *)&(sin->sin_addr), ipbuf, 256);
        printf("Remote RTP endpoint: %s:%u\n", ipbuf, rtp->otherport);
    }

    printf("Communication ID: %u\n", rtp->cin);
    printf("------\n");
}

static void *start_processing_thread(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = NULL;

    loc = (colthread_local_t *)malloc(sizeof(colthread_local_t));

    libtrace_message_queue_init(&(loc->tosyncq_ip),
            sizeof(openli_state_update_t));
    libtrace_message_queue_init(&(loc->fromsyncq_ip),
            sizeof(openli_pushed_t));
    libtrace_message_queue_init(&(loc->tosyncq_voip),
            sizeof(openli_state_update_t));
    libtrace_message_queue_init(&(loc->fromsyncq_voip),
            sizeof(openli_pushed_t));

    loc->activeipv4intercepts = NULL;
    loc->activeipv6intercepts = NULL;
    loc->activertpintercepts = NULL;
    loc->activealuintercepts = NULL;
    loc->activestaticintercepts = NULL;
    loc->radiusservers = NULL;
    loc->sipservers = NULL;
    loc->staticv4ranges = New_Patricia(32);
    loc->staticv6ranges = New_Patricia(128);
    loc->staticcache = NULL;
    loc->numexporters = glob->exportthreads;

    loc->zmq_pubsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUB);
    zmq_connect(loc->zmq_pubsock, "inproc://subproxy");


    loc->fragreass = create_new_ipfrag_reassembler();

    register_sync_queues(&(glob->syncip), &(loc->tosyncq_ip),
			&(loc->fromsyncq_ip), t);
    register_sync_queues(&(glob->syncvoip), &(loc->tosyncq_voip),
			&(loc->fromsyncq_voip), t);
    //register_export_queues(glob->exporters, loc->exportqueues);

    return loc;
}

static void free_staticrange_data(void *data) {
    liid_set_t *all, *iter, *tmp;

    all = (liid_set_t *)data;
    HASH_ITER(hh, all, iter, tmp) {
        HASH_DELETE(hh, all, iter);
        free(iter->liid);
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

static void stop_processing_thread(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *tls) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)tls;
    ipv4_target_t *v4, *tmp;
    ipv6_target_t *v6, *tmp2;
    int zero = 0;

    if (trace_is_err(trace)) {
        libtrace_err_t err = trace_get_err(trace);
        logger(LOG_INFO, "OpenLI: halting input due to error: %s",
                err.problem);
    }

    deregister_sync_queues(&(glob->syncip), t);
    deregister_sync_queues(&(glob->syncvoip), t);

    /* TODO drain fromsync message queue so we don't leak SIP URIs
     * and any other malloced memory in the messages.
     */

    libtrace_message_queue_destroy(&(loc->tosyncq_ip));
    libtrace_message_queue_destroy(&(loc->fromsyncq_ip));
    libtrace_message_queue_destroy(&(loc->tosyncq_voip));
    libtrace_message_queue_destroy(&(loc->fromsyncq_voip));
    if (loc->zmq_pubsock) {
        if (zmq_setsockopt(loc->zmq_pubsock, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
            logger(LOG_INFO, "OpenLI: unable to set linger period on publishing zeromq socket.");
        }
        zmq_close(loc->zmq_pubsock);
    }

    HASH_ITER(hh, loc->activeipv4intercepts, v4, tmp) {
        free_all_ipsessions(&(v4->intercepts));
        HASH_DELETE(hh, loc->activeipv4intercepts, v4);
        free(v4);
    }

    HASH_ITER(hh, loc->activeipv6intercepts, v6, tmp2) {
        free_all_ipsessions(&(v6->intercepts));
        HASH_DELETE(hh, loc->activeipv6intercepts, v6);
        free(v6);
    }

    free_all_staticipsessions(&(loc->activestaticintercepts));
    free_all_rtpstreams(&(loc->activertpintercepts));
    free_all_aluintercepts(&(loc->activealuintercepts));
    free_coreserver_list(loc->radiusservers);
    free_coreserver_list(loc->sipservers);

    destroy_ipfrag_reassembler(loc->fragreass);

    Destroy_Patricia(loc->staticv4ranges, free_staticrange_data);
    Destroy_Patricia(loc->staticv6ranges, free_staticrange_data);

    free_staticcache(loc->staticcache);
    free(loc);
}

static inline void send_packet_to_sync(libtrace_packet_t *pkt,
        libtrace_message_queue_t *q, uint8_t updatetype) {
    openli_state_update_t syncup;

    syncup.type = updatetype;
    syncup.data.pkt = pkt;

    trace_increment_packet_refcount(pkt);
    libtrace_message_queue_put(q, (void *)(&syncup));

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

    if (syncpush->type == OPENLI_PUSH_ALUINTERCEPT) {
        handle_push_aluintercept(t, loc, syncpush->data.aluint);
    }

    if (syncpush->type == OPENLI_PUSH_HALT_ALUINTERCEPT) {
        handle_halt_aluintercept(t, loc, syncpush->data.aluint);
    }

    if (syncpush->type == OPENLI_PUSH_IPRANGE) {
        handle_iprange(t, loc, syncpush->data.iprange);
    }

    if (syncpush->type == OPENLI_PUSH_REMOVE_IPRANGE) {
        handle_remove_iprange(t, loc, syncpush->data.iprange);
    }

}

static inline int is_core_server_packet(libtrace_packet_t *pkt,
        packet_info_t *pinfo, coreserver_t *servers) {

    coreserver_t *rad, *tmp;

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
        }

        if (rad->info->ai_family == AF_INET) {
            struct sockaddr_in *sa;
            sa = (struct sockaddr_in *)(&(pinfo->srcip));
            if (CORESERVER_MATCH_V4(rad, sa, pinfo->srcport)) {
                return 1;
            }
            sa = (struct sockaddr_in *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V4(rad, sa, pinfo->destport)) {
                return 1;
            }
        } else if (rad->info->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6;
            sa6 = (struct sockaddr_in6 *)(&(pinfo->srcip));
            if (CORESERVER_MATCH_V6(rad, sa6, pinfo->srcport)) {
                return 1;
            }
            sa6 = (struct sockaddr_in6 *)(&(pinfo->destip));
            if (CORESERVER_MATCH_V6(rad, sa6, pinfo->destport)) {
                return 1;
            }
        }
    }

    /* Doesn't match any of our known core servers */
    return 0;
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
    int forwarded = 0, i, ret;
    int synced = 0;
    uint16_t fragoff = 0;

    openli_pushed_t syncpush;
    packet_info_t pinfo;
    openli_export_recv_t finmsg;

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

    trace_increment_packet_refcount(pkt);

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
        libtrace_ip6_t *ip6header = (libtrace_ip6_t *)l3;
        uint8_t *postip6 = (uint8_t *)(trace_get_payload_from_ip6(ip6header,
                &proto, &rem));

        pinfo.srcport = ntohs(*((uint16_t *)postip6));
        pinfo.destport = ntohs(*((uint16_t *)(postip6 + 2)));
        proto = ip6header->nxt;
        pinfo.family = AF_INET6;
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
                pkt, &pinfo, glob->alumirrors, loc->activealuintercepts)) {
            forwarded = 1;
            goto processdone;
        }

        /* Is this a RADIUS packet? -- if yes, create a state update */
        if (loc->radiusservers && is_core_server_packet(pkt, &pinfo,
                    loc->radiusservers)) {
            send_packet_to_sync(pkt, &(loc->tosyncq_ip), OPENLI_UPDATE_RADIUS);
            synced = 1;
        }

        /* Is this a SIP packet? -- if yes, create a state update */
        if (loc->sipservers && is_core_server_packet(pkt, &pinfo,
                    loc->sipservers)) {
            if (!check_for_invalid_sip(pkt, fragoff)) {
                send_packet_to_sync(pkt, &(loc->tosyncq_voip),
                        OPENLI_UPDATE_SIP);
                synced = 1;
            }
        }
    } else if (proto == TRACE_IPPROTO_TCP) {
        /* Is this a SIP packet? -- if yes, create a state update */
        if (loc->sipservers && is_core_server_packet(pkt, &pinfo,
                    loc->sipservers)) {
            send_packet_to_sync(pkt, &(loc->tosyncq_voip), OPENLI_UPDATE_SIP);
            synced = 1;
        }
    }


    if (ethertype == TRACE_ETHERTYPE_IP) {
        /* Is this an IP packet? -- if yes, possible IP CC */
        if (ipv4_comm_contents(pkt, &pinfo, (libtrace_ip_t *)l3, iprem,
                    &(glob->sharedinfo), loc)) {
            forwarded = 1;
        }

        /* Is this an RTP packet? -- if yes, possible IPMM CC */
        if (proto == TRACE_IPPROTO_UDP) {
            if (ip4mm_comm_contents(pkt, &pinfo, (libtrace_ip_t *)l3, iprem,
                        &(glob->sharedinfo), loc)) {
                forwarded = 1;
            }
        }

    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        /* Is this an IP packet? -- if yes, possible IP CC */
        if (ipv6_comm_contents(pkt, &pinfo, (libtrace_ip6_t *)l3, iprem,
                    &(glob->sharedinfo), loc)) {
            forwarded = 1;
        }

        if (proto == TRACE_IPPROTO_UDP) {
            if (ip6mm_comm_contents(pkt, &pinfo, (libtrace_ip6_t *)l3, iprem,
                        &(glob->sharedinfo), loc)) {
                forwarded = 1;
            }
        }
    }

processdone:
    if (forwarded || synced) {
        trace_decrement_packet_refcount(pkt);
        return NULL;
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
        trace_set_starting_cb(inp->pktcbs, start_processing_thread);
        trace_set_stopping_cb(inp->pktcbs, stop_processing_thread);
        trace_set_packet_cb(inp->pktcbs, process_packet);
    }

    assert(!inp->trace);
    inp->trace = trace_create(inp->uri);

    /* Stupid DPDK will "steal" our syslog logid, so we need to reset it
     * after we call trace_create() to ensure our logs have the right
     * program name associated with them.
     */

    if (todaemon) {
        daemonise(progname);
    }

    if (trace_is_err(inp->trace)) {
        libtrace_err_t lterr = trace_get_err(inp->trace);
        logger(LOG_INFO, "OpenLI: Failed to create trace for input %s: %s",
                inp->uri, lterr.problem);
        return 0;
    }

    trace_set_perpkt_threads(inp->trace, inp->threadcount);
    trace_set_hasher(inp->trace, HASHER_BIDIRECTIONAL, NULL, NULL);

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

    HASH_ITER(hh, glob->inputs, oldinp, tmp) {
        HASH_FIND(hh, newstate->inputs, oldinp->uri, strlen(oldinp->uri),
                newinp);
        if (!newinp || newinp->threadcount != oldinp->threadcount) {
            /* This input is no longer wanted at all */
            logger(LOG_INFO,
                    "OpenLI collector: stop reading packets from %s\n",
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
    }

}

static void *start_export_thread(void *params) {
    export_thread_data_t *glob = (export_thread_data_t *)params;
    collector_export_t *exp = init_exporter(glob);
    int connected = 0;

    if (exp == NULL) {
        logger(LOG_INFO, "OpenLI: exporting thread is not functional!");
        collector_halt = 1;
        pthread_exit(NULL);
    }

    while (collector_halt == 0) {
        if (exporter_thread_main(exp) <= 0) {
            break;
        }
    }

    destroy_exporter(exp);
    logger(LOG_DEBUG, "OpenLI: exiting export thread.");
    pthread_exit(NULL);
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
}

static inline void init_support_thread_data(support_thread_global_t *sup) {

    sup->threadid = 0;
    pthread_mutex_init(&(sup->mutex), NULL);
    sup->collector_queues = NULL;
    sup->epollevs = NULL;
    sup->epoll_fd = epoll_create1(0);

}

static inline void free_support_thread_data(support_thread_global_t *sup) {
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


static void clear_global_config(collector_global_t *glob) {
    colinput_t *inp, *tmp;
    int i;

    HASH_ITER(hh, glob->inputs, inp, tmp) {
        HASH_DELETE(hh, glob->inputs, inp);
        clear_input(inp);
        free(inp);
    }

    free_coreserver_list(glob->alumirrors);

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

    pthread_rwlock_destroy(&glob->config_mutex);

	free_support_thread_data(&(glob->syncip));
	free_support_thread_data(&(glob->syncvoip));

    if (glob->exporters) {
        free(glob->exporters);
    }

    libtrace_message_queue_destroy(&(glob->intersyncq));
    logger(LOG_INFO, "OpenLI: waiting for zeromq context to be destroyed.");
    if (glob->zmq_ctxt) {
        zmq_ctx_destroy(glob->zmq_ctxt);
    }

    /* Our proxy thread will only exit once the zeromq context is
     * destroyed, so we have to join now */
    logger(LOG_INFO, "OpenLI: waiting for zeromq proxy to terminate.");
    pthread_join(glob->zmq_proxy_threadid, NULL);

    free(glob);
}

static inline void push_hello_message(libtrace_message_queue_t *atob,
        libtrace_message_queue_t *btoa) {

    openli_state_update_t hello;

    memset(&hello, 0, sizeof(openli_state_update_t));
    hello.type = OPENLI_UPDATE_HELLO;
    hello.data.replyq = btoa;

    libtrace_message_queue_put(atob, (void *)(&hello));
}

int register_sync_queues(support_thread_global_t *glob,
        libtrace_message_queue_t *recvq, libtrace_message_queue_t *sendq,
        libtrace_thread_t *parent) {

    struct epoll_event ev;
    sync_epoll_t *syncev, *syncev_hash;
    sync_sendq_t *syncq, *sendq_hash, *a, *b;
    int ind;

    syncq = (sync_sendq_t *)malloc(sizeof(sync_sendq_t));
    syncq->q = sendq;
    syncq->parent = parent;

    syncev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));
    syncev->fdtype = SYNC_EVENT_PROC_QUEUE;
    syncev->fd = libtrace_message_queue_get_fd(recvq);
    syncev->ptr = recvq;
    syncev->parent = parent;

    ev.data.ptr = (void *)syncev;
    ev.events = EPOLLIN;

    pthread_mutex_lock(&(glob->mutex));
    if (epoll_ctl(glob->epoll_fd, EPOLL_CTL_ADD, syncev->fd,
                &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_INFO, "OpenLI: failed to register processor->sync queue: %s",
                strerror(errno));
        pthread_mutex_unlock(&(glob->mutex));
        return -1;
    }

    sendq_hash = (sync_sendq_t *)(glob->collector_queues);
    HASH_ADD_PTR(sendq_hash, parent, syncq);
    glob->collector_queues = (void *)sendq_hash;

    syncev_hash = (sync_epoll_t *)(glob->epollevs);
    HASH_ADD_PTR(syncev_hash, parent, syncev);
    glob->epollevs = (void *)syncev_hash;

    pthread_mutex_unlock(&(glob->mutex));

    push_hello_message(recvq, sendq);
    return 0;
}

void deregister_sync_queues(support_thread_global_t *glob,
		libtrace_thread_t *t) {

    sync_epoll_t *syncev, *syncev_hash;
    sync_sendq_t *syncq, *sendq_hash;
    struct epoll_event ev;

    pthread_mutex_lock(&(glob->mutex));
    sendq_hash = (sync_sendq_t *)(glob->collector_queues);

    HASH_FIND_PTR(sendq_hash, &t, syncq);
    /* Caller will free the queue itself */
    if (syncq) {
        HASH_DELETE(hh, sendq_hash, syncq);
        free(syncq);
        glob->collector_queues = (void *)sendq_hash;
    }

    syncev_hash = (sync_epoll_t *)(glob->epollevs);
    HASH_FIND_PTR(syncev_hash, &t, syncev);
    if (syncev) {
        if (glob->epoll_fd != -1 && epoll_ctl(glob->epoll_fd,
                    EPOLL_CTL_DEL, syncev->fd, &ev) == -1) {
            logger(LOG_INFO, "OpenLI: failed to de-register processor->sync queue %d: %s", syncev->fd, strerror(errno));
        }
        HASH_DELETE(hh, syncev_hash, syncev);
        free(syncev);
        glob->epollevs = (void *)syncev_hash;
    }

    pthread_mutex_unlock(&(glob->mutex));
}


static collector_global_t *parse_global_config(char *configfile) {

    collector_global_t *glob = NULL;

    glob = (collector_global_t *)malloc(sizeof(collector_global_t));

    glob->zmq_ctxt = zmq_ctx_new();
    glob->inputs = NULL;
    glob->exportthreads = 1;
    glob->sharedinfo.intpointid = NULL;
    glob->sharedinfo.intpointid_len = 0;
    glob->sharedinfo.operatorid = NULL;
    glob->sharedinfo.operatorid_len = 0;
    glob->sharedinfo.networkelemid = NULL;
    glob->sharedinfo.networkelemid_len = 0;

    init_support_thread_data(&(glob->syncip));
    init_support_thread_data(&(glob->syncvoip));
    glob->exporters = NULL;
    //init_support_thread_data(&(glob->exporter));

    glob->configfile = configfile;
    glob->sharedinfo.provisionerip = NULL;
    glob->sharedinfo.provisionerport = NULL;
    glob->alumirrors = NULL;
    glob->expired_inputs = libtrace_list_init(sizeof(colinput_t *));
    glob->sipdebugfile = NULL;

    libtrace_message_queue_init(&glob->intersyncq,
            sizeof(openli_intersync_msg_t));

    pthread_rwlock_init(&glob->config_mutex, NULL);

    if (parse_collector_config(configfile, glob) == -1) {
        clear_global_config(glob);
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

    collector_global_t *newstate;

    newstate = parse_global_config(glob->configfile);
    if (newstate == NULL) {
        logger(LOG_INFO,
                "OpenLI: error reloading config file for collector.");
        return -1;
    }

    if (strcmp(newstate->sharedinfo.provisionerip,
                glob->sharedinfo.provisionerip) != 0 ||
            strcmp(newstate->sharedinfo.provisionerport,
                    glob->sharedinfo.provisionerport) != 0) {
        logger(LOG_INFO,
                "OpenLI collector: disconnecting from provisioner due to config change.");
        sync_disconnect_provisioner(sync);
        free(glob->sharedinfo.provisionerip);
        free(glob->sharedinfo.provisionerport);
        glob->sharedinfo.provisionerip = strdup(newstate->sharedinfo.provisionerip);
        glob->sharedinfo.provisionerport = strdup(newstate->sharedinfo.provisionerport);
    } else {
        logger(LOG_INFO,
                "OpenLI collector: provisioner socket configuration is unchanged.");
    }

    pthread_rwlock_wrlock(&(glob->config_mutex));

    reload_inputs(glob, newstate);

    /* Just update these, regardless of whether they've changed. It's more
     * effort to check for a change than it is worth and there are no
     * flow-on effects to a change.
     */
    if (glob->sharedinfo.operatorid) {
        free(glob->sharedinfo.operatorid);
    }
    glob->sharedinfo.operatorid = newstate->sharedinfo.operatorid;
    glob->sharedinfo.operatorid_len = newstate->sharedinfo.operatorid_len;
    newstate->sharedinfo.operatorid = NULL;

    if (glob->sharedinfo.networkelemid) {
        free(glob->sharedinfo.networkelemid);
    }
    glob->sharedinfo.networkelemid = newstate->sharedinfo.networkelemid;
    glob->sharedinfo.networkelemid_len = newstate->sharedinfo.networkelemid_len;
    newstate->sharedinfo.networkelemid = NULL;

    if (glob->sharedinfo.intpointid) {
        free(glob->sharedinfo.intpointid);
    }
    glob->sharedinfo.intpointid = newstate->sharedinfo.intpointid;
    glob->sharedinfo.intpointid_len = newstate->sharedinfo.intpointid_len;
    newstate->sharedinfo.intpointid = NULL;

    pthread_rwlock_unlock(&(glob->config_mutex));
    clear_global_config(newstate);
    return 0;
}

static void *start_voip_sync_thread(void *params) {

    collector_global_t *glob = (collector_global_t *)params;
    int ret, i;
    collector_sync_voip_t *sync = init_voip_sync_data(glob);
    sync_sendq_t *sq;

    //register_export_queues(glob->exporters, sync->exportqueues);

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

static void *span_thread(void *zmq_ctxt) {
    void *recvr = zmq_socket(zmq_ctxt, ZMQ_PAIR);
    char envelope[24];
    char body[1024];
    int x, zero=0, more=0;
    size_t optlen;
    int done = 0;

    zmq_connect(recvr, "inproc://span");
    while (!done) {
        if ((x = zmq_recv(recvr, envelope, 23, 0)) < 0) {
            done = 1;
            continue;
        }

        envelope[x] = '\0';

        do {
            optlen = sizeof(more);
            zmq_getsockopt(recvr, ZMQ_RCVMORE, &more, &optlen);
            if (more == 0) {
                break;
            }

            if ((x = zmq_recv(recvr, body, 1024, 0)) < 0) {
                done = 1;
                break;
            }
        } while (more);
    }

    zmq_setsockopt(recvr, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_close(recvr);
    pthread_exit(NULL);
}

static void *start_zmq_proxy(void *zmq_ctxt) {

    int zero = 0;
    pthread_t pid;
    void *subside = zmq_socket(zmq_ctxt, ZMQ_XSUB);
    void *pubside = zmq_socket(zmq_ctxt, ZMQ_XPUB);

    void *paira = zmq_socket(zmq_ctxt, ZMQ_PAIR);

    if (!subside || !pubside) {
        goto proxyfail;
    }

    if (zmq_bind(subside, "inproc://subproxy") != 0) {
        logger(LOG_INFO, "OpenLI: failed to bind zeromq subscriber proxy socket");
        goto proxyfail;
    }

    if (zmq_bind(pubside, "inproc://pubproxy") != 0) {
        logger(LOG_INFO, "OpenLI: failed to bind zeromq publisher proxy socket");
        goto proxyfail;
    }

    if (zmq_bind(paira, "inproc://span") != 0) {
        logger(LOG_INFO, "OpenLI: failed to bind zeromq span socket");
        goto proxyfail;
    }

    pthread_create(&pid, NULL, span_thread, zmq_ctxt);
    zmq_proxy(subside, pubside, paira);

    pthread_join(pid, NULL);

    zmq_setsockopt(subside, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_setsockopt(pubside, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_setsockopt(paira, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_close(subside);
    zmq_close(pubside);
    zmq_close(paira);

proxyfail:
    pthread_exit(NULL);
}

static void *start_ip_sync_thread(void *params) {

    collector_global_t *glob = (collector_global_t *)params;
    int ret, i;
    collector_sync_t *sync = init_sync_data(glob);
    sync_sendq_t *sq;

    /* XXX For early development work, we will read intercept instructions
     * from a config file. Eventually this should be replaced with
     * instructions that are received via a network interface.
     */

    //register_export_queues(glob->exporters, sync->exportqueues);

    while (collector_halt == 0) {
        if (reload_config) {
            if (reload_collector_config(glob, sync) == -1) {
                break;
            }
            reload_config = 0;
        }
        if (sync->instruct_fd == -1) {
            ret = sync_connect_provisioner(sync);
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
    }

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
    pthread_exit(NULL);

}


int main(int argc, char *argv[]) {

	struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    char *configfile = NULL;
    collector_global_t *glob = NULL;
    int i, ret, todaemon;
    colinput_t *inp, *tmp;

    todaemon = 0;
    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "daemonise", 0, 0, 'd'},
            { NULL, 0, 0, 0 }
        };

        int c = getopt_long(argc, argv, "c:dh", long_options,
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
        daemonise(argv[0]);
    }

    /* Initialise osipparser2 */
    parser_init();

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
	signal(SIGPIPE, SIG_IGN);

    sigact.sa_handler = reload_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGHUP, &sigact, NULL);

    /* Read config to generate list of input sources */
    glob = parse_global_config(configfile);
    if (glob == NULL) {
        return 1;
    }

    sigemptyset(&sig_block_all);
    if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
        logger(LOG_INFO, "Unable to disable signals before starting threads.");
        return 1;
    }

    /* Start zeromq proxy thread */
    ret = pthread_create(&(glob->zmq_proxy_threadid), NULL,
            start_zmq_proxy, glob->zmq_ctxt);
    if (ret != 0) {
        logger(LOG_INFO,
                "OpenLI: error starting zeromq proxy thread. Exiting.");
        return 1;
    }

    /* Start export threads */
    glob->exporters = (export_thread_data_t *)malloc(
            sizeof(export_thread_data_t) * glob->exportthreads);
    for (i = 0; i < glob->exportthreads; i++) {
        glob->exporters[i].zmq_ctxt = glob->zmq_ctxt;
        glob->exporters[i].exportlabel = i;

        ret = pthread_create(&(glob->exporters[i].threadid), NULL,
                start_export_thread, (void *)&(glob->exporters[i]));
        if (ret != 0) {
            logger(LOG_INFO, "OpenLI: error creating exporter. Exiting.");
            return 1;
        }
    }

    /* XXX temporary to prevent exporters from missing early sync messages */
    usleep(100000);

    /* Start IP intercept sync thread */
    ret = pthread_create(&(glob->syncip.threadid), NULL, start_ip_sync_thread,
            (void *)glob);
    if (ret != 0) {
        logger(LOG_INFO, "OpenLI: error creating IP sync thread. Exiting.");
        return 1;
    }

    /* Start VOIP intercept sync thread */
    ret = pthread_create(&(glob->syncvoip.threadid), NULL,
            start_voip_sync_thread, (void *)glob);
    if (ret != 0) {
        logger(LOG_INFO, "OpenLI: error creating VOIP sync thread. Exiting.");
        return 1;
    }

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
                logger(LOG_DEBUG, "OpenLI: dropped %lu packets on input %s\n",
                        stat->dropped, inp->uri);
            }
            if (stat->received_valid) {
                logger(LOG_DEBUG, "OpenLI: received %lu packets on input %s\n",
                        stat->received, inp->uri);
            }
            if (stat->accepted_valid) {
                logger(LOG_DEBUG, "OpenLI: accepted %lu packets on input %s\n",
                        stat->accepted, inp->uri);
            }
            free(stat);
        }
    }
    pthread_rwlock_unlock(&(glob->config_mutex));

    pthread_join(glob->syncip.threadid, NULL);
    pthread_join(glob->syncvoip.threadid, NULL);
    for (i = 0; i < glob->exportthreads; i++) {
        pthread_join(glob->exporters[i].threadid, NULL);
    }

    logger(LOG_INFO, "OpenLI: exiting OpenLI Collector.");
    /* Tidy up, exit */
    clear_global_config(glob);

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
