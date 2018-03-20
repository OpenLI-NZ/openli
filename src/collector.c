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

#include <libtrace_parallel.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "configparser.h"
#include "collector_sync.h"
#include "collector_export.h"
#include "ipcc.h"
#include "sipparsing.h"

volatile int collector_halt = 0;
volatile int reload_export_config = 0;

static void cleanup_signal(int signal UNUSED)
{
    collector_halt = 1;
}

static void usage(char *prog) {

    fprintf(stderr, "Usage: %s -c configfile\n", prog);
}

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

static void deactivate_ip_intercept(libtrace_list_t *ipint_list,
        char *liid, char *authcc) {

    libtrace_list_node_t *n;
    ipintercept_t *cept;

    /* Search the list for an intercept with a matching ID */

    /* If found, set the intercept to inactive */

    n = ipint_list->head;
    while (n) {
        cept = (ipintercept_t *)(n->data);

        if (strcmp(cept->liid, liid) == 0 && strcmp(cept->authcc, authcc) == 0)
        {
            cept->active = 0;
            break;
        }
        n = n->next;
    }

    /* TODO */
    /* Starting from the back, prune any inactive intercepts until we
     * reach an active one. This isn't perfect, but might help keep
     * the size down a bit. */

    /* Future work: if the list is large and fragmented, just re-create
     * the list from scratch to contain only active intercepts. */

    /* authcc and liid were strdup'd by the sync thread */
    free(authcc);
    free(liid);

    return;
}

static void *start_processing_thread(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = NULL;

    loc = (colthread_local_t *)malloc(sizeof(colthread_local_t));

    libtrace_message_queue_init(&(loc->tosyncq),
            sizeof(openli_state_update_t));
    libtrace_message_queue_init(&(loc->fromsyncq),
            sizeof(openli_pushed_t));
    libtrace_message_queue_init(&(loc->exportq),
            sizeof(openli_export_recv_t));

    loc->activeipintercepts = libtrace_list_init(sizeof(ipintercept_t));
    loc->sip_targets = NULL;

    register_sync_queues(glob, &(loc->tosyncq), &(loc->fromsyncq));
    register_export_queue(glob, &(loc->exportq));

    loc->encoder = NULL;
    loc->sipparser = NULL;
    loc->knownsipservers = libtrace_list_init(sizeof(sipserverdetails_t));

    return loc;
}

static void stop_processing_thread(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *tls) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)tls;

    libtrace_message_queue_destroy(&(loc->tosyncq));
    libtrace_message_queue_destroy(&(loc->fromsyncq));
    libtrace_message_queue_destroy(&(loc->exportq));
    libtrace_list_deinit(loc->knownsipservers);

    free_all_ipintercepts(loc->activeipintercepts);

    if (loc->sip_targets) {
        sipuri_hash_t *sip, *tmp;
        HASH_ITER(hh, loc->sip_targets, sip, tmp) {
            free(sip->uri);
            free(sip);
        }
    }

    if (loc->sipparser) {
        release_sip_parser(loc->sipparser);
    }


    if (loc->encoder) {
        free_wandder_encoder(loc->encoder);
    }

    free(loc);
}

static int process_sip_packet(libtrace_packet_t *pkt,
        colthread_local_t *loc) {

    char *uri;
    sipuri_hash_t *siphash;
    int ret;

    if ((ret = parse_sip_packet(&(loc->sipparser), pkt)) == -1) {
        logger(LOG_DAEMON, "Error while attempting to parse SIP packet");
        return 0;
    }

    if (ret == 0) {
        /* Not a usable SIP packet -- missing payload etc. */
        return 0;
    }

    /* Check the From URI */
    uri = get_sip_from_uri(loc->sipparser);
    if (uri != NULL) {
        HASH_FIND_STR(loc->sip_targets, uri, siphash);
        if (siphash) {
            /* Matches a known target -- push to sync thread */
            return 1;
        }
    }


    /* Check the To URI */
    uri = get_sip_to_uri(loc->sipparser);
    if (uri != NULL) {
        HASH_FIND_STR(loc->sip_targets, uri, siphash);
        if (siphash) {
            /* Matches a known target -- push to sync thread */
            return 1;
        }
    }

    /* None of the URIs in this SIP packet belong to a known target */
    return 0;
}

static inline void send_sip_update(libtrace_packet_t *pkt,
        colthread_local_t *loc) {
    openli_state_update_t sipup;

    sipup.type = OPENLI_UPDATE_SIP;
    sipup.data.pkt = pkt;
    sipup.data.pkt = pkt;

    libtrace_message_queue_put(&(loc->tosyncq), (void *)(&sipup));

}

static libtrace_packet_t *process_packet(libtrace_t *trace,
        libtrace_thread_t *t, void *global, void *tls,
        libtrace_packet_t *pkt) {

    collector_global_t *glob = (collector_global_t *)global;
    colthread_local_t *loc = (colthread_local_t *)tls;
    void *l3;
    uint16_t ethertype;
    uint32_t rem;
    int forwarded = 0;

    openli_pushed_t syncpush;

    /* Check for any messages from the sync thread */
    while (libtrace_message_queue_try_get(&(loc->fromsyncq),
            (void *)&syncpush) != LIBTRACE_MQ_FAILED) {

        if (syncpush.type == OPENLI_PUSH_IPINTERCEPT) {
            libtrace_list_push_front(loc->activeipintercepts,
                    (void *)(syncpush.data.ipint));
            free(syncpush.data.ipint);
        }

        if (syncpush.type == OPENLI_PUSH_HALT_IPINTERCEPT) {
            deactivate_ip_intercept(loc->activeipintercepts,
                    syncpush.data.interceptid.liid,
                    syncpush.data.interceptid.authcc);
        }

        if (syncpush.type == OPENLI_PUSH_SIPURI) {
            sipuri_hash_t *newsip = (sipuri_hash_t *)malloc(
                    sizeof(sipuri_hash_t));
            newsip->uri = syncpush.data.sipuri;
            HASH_ADD_KEYPTR(hh, loc->sip_targets, newsip->uri,
                    strlen(newsip->uri), newsip);
        }

        if (syncpush.type == OPENLI_PUSH_HALT_SIPURI) {
            sipuri_hash_t *torem;
            HASH_FIND_STR(loc->sip_targets, syncpush.data.sipuri, torem);
            if (torem == NULL) {
                logger(LOG_DAEMON, "Asked to halt SIP intercept for target %s, but that is not in our set of known URIs", syncpush.data.sipuri);
                continue;
            }
            HASH_DEL(loc->sip_targets, torem);
            free(torem->uri);
            free(torem);
        }
    }

    l3 = trace_get_layer3(pkt, &ethertype, &rem);
    if (l3 == NULL || rem == 0) {
        return pkt;
    }

    /* TODO increment packet refcount for each state update that
     * we send with the packet in it */

    /* Is this a RADIUS packet? -- if yes, create a state update */

    /* Is this a SIP packet? -- if yes, create a state update */
    if (identified_as_sip(pkt, loc->knownsipservers)) {
        if (process_sip_packet(pkt, loc) == 1) {
            /* Form an OpenLI state update message with this SIP packet
             * attached TODO */
            send_sip_update(pkt, loc);
            trace_increment_packet_refcount(pkt);
            forwarded = 1;
        }
    }

    /* Is this an RTP packet? -- if yes, possible IPMM CC */

    /* Is this an IP packet? -- if yes, possible IP CC */
    if (ethertype == TRACE_ETHERTYPE_IP) {
        if (ipv4_comm_contents(pkt, (libtrace_ip_t *)l3, rem, glob, loc)) {
            trace_increment_packet_refcount(pkt);
            forwarded = 1;
        }
    }


    if (forwarded) {
        return NULL;
    }
    return pkt;


}

static int start_input(collector_global_t *glob, colinput_t *inp) {

    if (inp->pktcbs == NULL) {
        inp->pktcbs = trace_create_callback_set();
    }

    trace_set_starting_cb(inp->pktcbs, start_processing_thread);
    trace_set_stopping_cb(inp->pktcbs, stop_processing_thread);
    trace_set_packet_cb(inp->pktcbs, process_packet);

    inp->trace = trace_create(inp->config.uri);
    if (trace_is_err(inp->trace)) {
        libtrace_err_t lterr = trace_get_err(inp->trace);
        logger(LOG_DAEMON, "OpenLI: Failed to create trace for input %s: %s",
                inp->config.uri, lterr.problem);
        return 0;
    }

    trace_set_perpkt_threads(inp->trace, inp->config.threadcount);

    if (trace_pstart(inp->trace, glob, inp->pktcbs, NULL) == -1) {
        libtrace_err_t lterr = trace_get_err(inp->trace);
        logger(LOG_DAEMON, "OpenLI: Failed to start trace for input %s: %s",
                inp->config.uri, lterr.problem);
        return 0;
    }

    return 1;
}

static void *start_sync_thread(void *params) {
    collector_global_t *glob = (collector_global_t *)params;
    int ret;
    collector_sync_t *sync = init_sync_data(glob);

    /* XXX For early development work, we will read intercept instructions
     * from a config file. Eventually this should be replaced with
     * instructions that are received via a network interface.
     */

    register_export_queue(glob, &(sync->exportq));

    while (collector_halt == 0) {
        if (sync->instruct_fd == -1) {
            ret = sync_connect_provisioner(sync);
            if (ret < 0) {
                /* Fatal error */
                logger(LOG_DAEMON,
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
    logger(LOG_DAEMON, "OpenLI: exiting sync thread.");
    pthread_exit(NULL);

}

static void *start_export_thread(void *params) {
    collector_global_t *glob = (collector_global_t *)params;
    collector_export_t *exp = init_exporter(glob);
    int connected = 0;

    if (exp == NULL) {
        logger(LOG_DAEMON, "OpenLI: exporting thread is not functional!");
        collector_halt = 1;
        pthread_exit(NULL);
    }

    while (collector_halt == 0) {
        if (exporter_thread_main(exp) <= 0) {
            break;
        }
    }

    destroy_exporter(exp);
    logger(LOG_DAEMON, "OpenLI: exiting export thread.");
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {

	struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    char *configfile = NULL;
    collector_global_t *glob = NULL;
    int i, ret;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { NULL, 0, 0, 0 }
        };

        int c = getopt_long(argc, argv, "c:h", long_options,
                &optind);
        if (c == -1) {
            break;
        }

        switch(c) {
            case 'c':
                configfile = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            default:
                logger(LOG_DAEMON, "OpenLI: unsupported option: %c", c);
                usage(argv[0]);
                return 1;
        }
    }

    if (configfile == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: no config file specified. Use -c to specify one.");
        usage(argv[0]);
        return 1;
    }

    /* Initialise osipparser2 */
    parser_init();

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
	signal(SIGPIPE, SIG_IGN);

    /* Read config to generate list of input sources */
    glob = parse_global_config(configfile);
    if (glob == NULL) {
        return 1;
    }

    sigemptyset(&sig_block_all);
    if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
        logger(LOG_DAEMON, "Unable to disable signals before starting threads.");
		return 1;
	}

    /* Start sync thread */
    ret = pthread_create(&(glob->syncthreadid), NULL, start_sync_thread,
            (void *)glob);
    if (ret != 0) {
        logger(LOG_DAEMON, "OpenLI: error creating sync thread. Exiting.");
        return 1;
    }

    /* Start export thread */
    ret = pthread_create(&(glob->exportthreadid), NULL, start_export_thread,
            (void *)glob);
    if (ret != 0) {
        logger(LOG_DAEMON, "OpenLI: error creating export thread. Exiting.");
        return 1;
    }

    /* Start processing threads for each input */
    for (i = 0; i < glob->inputcount; i++) {
        if (start_input(glob, &(glob->inputs[i])) == 0) {
            logger(LOG_DAEMON, "OpenLI: failed to start input %s\n",
                    glob->inputs[i].config.uri);
        }
    }

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL)) {
		logger(LOG_DAEMON, "Unable to re-enable signals after starting threads.");
		return 1;
	}

    pthread_join(glob->syncthreadid, NULL);
    pthread_join(glob->exportthreadid, NULL);

    /* Join on all inputs */
    for (i = 0; i < glob->inputcount; i++) {
        if (glob->inputs[i].trace) {
            trace_join(glob->inputs[i].trace);
        }
    }

    logger(LOG_DAEMON, "OpenLI: exiting OpenLI Collector.");
    /* Tidy up, exit */
    clear_global_config(glob);

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
