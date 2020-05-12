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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <errno.h>
#include <libtrace/linked_list.h>
#include <unistd.h>
#include <assert.h>
#include <libwandder_etsili.h>
#include <Judy.h>

#include "config.h"
#include "configparser.h"
#include "logger.h"
#include "util.h"
#include "agency.h"
#include "netcomms.h"
#include "mediator.h"
#include "etsili_core.h"
#include "openli_tls.h"

/** Flag used to indicate that the mediator is being halted, usually due
 *  to a signal or a fatal error.
 */
volatile int mediator_halt = 0;

/** Flag used to indicate that the user has requested the mediator to
 *  reload its running config.
 */
volatile int reload_config = 0;

/** Signal handler for SIGINT / SIGTERM */
static void halt_signal(int signal) {
    mediator_halt = 1;
}

/** Signal handler for SIGHUP */
static void reload_signal(int signal) {
    reload_config = 1;
}

/** Dumps usage instructions to stderr, only useful if the user is trying
 *  to run the mediator manually -- most users should be using systemd
 *  to run the mediator as a daemon.
 *
 *  @param prog     The name of the mediator executable
 */
static void usage(char *prog) {
        fprintf(stderr, "Usage: %s [ -d ] -c configfile\n", prog);
        fprintf(stderr, "\nSet the -d flag to run as a daemon.\n");
}

/** Disconnects a single mediator handover connection to an LEA.
 *
 *  Typically triggered when an LEA is withdrawn, becomes unresponsive,
 *  or fails a keep-alive test.
 *
 *  @param state    The global state for this mediator
 *  @param ho       The handover that is being disconnected.
 */
static void disconnect_handover(mediator_state_t *state, handover_t *ho) {

    struct epoll_event ev;
    med_agency_state_t *agstate;

    agstate = (med_agency_state_t *)(ho->outev->state);

    /* Tidy up all of the epoll event fds related to the handover
     *
     * main_fd -- the fd we use to send records to the LEA on this handover
     * katimer_fd -- the timer fd that triggers regular keep alives
     * karesptimer_fd -- the timer fd for tracking keep alive timeouts
     */

    if (agstate->main_fd != -1) {
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, agstate->main_fd, &ev)
                == -1 && ho->disconnect_msg == 0) {
            logger(LOG_INFO, "OpenLI Mediator: unable to remove handover fd from epoll: %s.", strerror(errno));
        }
        close(agstate->main_fd);
        agstate->main_fd = -1;
        ho->outev->fd = -1;

        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: Disconnected from handover %s:%s HI%d",
                    ho->ipstr, ho->portstr, ho->handover_type);
        }
    }

    if (agstate->katimer_fd != -1) {
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, agstate->katimer_fd, &ev)
                == -1 && ho->disconnect_msg == 0) {
            logger(LOG_INFO, "OpenLI Mediator: unable to remove keepalive timer fd from epoll: %s.", strerror(errno));
        }
        close(agstate->katimer_fd);
        agstate->katimer_fd = -1;
        agstate->katimer_setsec = 0;
        if (ho->aliveev) {
            ho->aliveev->fd = -1;
        }
    }

    if (agstate->karesptimer_fd != -1) {
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, agstate->karesptimer_fd,
                &ev) == -1 && ho->disconnect_msg == 0) {
            logger(LOG_INFO, "OpenLI Mediator: unable to remove keepalive response timer fd from epoll: %s.", strerror(errno));
        }
        close(agstate->karesptimer_fd);
        agstate->karesptimer_fd = -1;
        if (ho->aliverespev) {
            ho->aliverespev->fd = -1;
        }
    }

    /* Free the encoder for this handover -- used to create keepalive msgs */
    if (agstate->encoder) {
        free_wandder_encoder(agstate->encoder);
        agstate->encoder = NULL;
    }

    /* Free the decoder for this handover -- used to parse keepalive responses
     */
    if (agstate->decoder) {
        wandder_free_etsili_decoder(agstate->decoder);
        agstate->decoder = NULL;
    }

    /* Free any encoded keepalives that we have sitting around */
    if (agstate->pending_ka) {
        wandder_release_encoded_result(NULL, agstate->pending_ka);
        agstate->pending_ka = NULL;
    }

    /* Release the buffer used to store incoming messages from the LEA */
    if (agstate->incoming) {
        libtrace_scb_destroy(agstate->incoming);
        free(agstate->incoming);
        agstate->incoming = NULL;
    }

    /* This handover is officially disconnected, so no more logging for it
     * until / unless it reconnects.
     */
    ho->disconnect_msg = 1;
}


/** Starts a timer and adds it to the global epoll event set.
 *
 *  Examples of timers that would use this function:
 *      - sending the next keep alive to a handover
 *      - attempting to reconnect to a lost provisioner
 *      - deciding that a handover has failed to respond to a keep alive
 *
 *  @param state    The global state for this mediator.
 *  @param timerev  The epoll event for the timer.
 *  @param timeoutval   The number of seconds to wait before triggering the
 *                      timer event.
 *
 *  @return -1 if an error occured, 0 otherwise (including not setting
 *          a timer because the timer is disabled).
 */
static int start_mediator_timer(mediator_state_t *state,
        med_epoll_ev_t *timerev, int timeoutval) {

    int sock;

    /* Timer is disabled, ignore */
    if (timerev == NULL) {
        return 0;
    }

    if ((sock = epoll_add_timer(state->epoll_fd, timeoutval, timerev)) == -1) {
        return -1;
    }

    timerev->fd = sock;
    return 0;

}

/** Halts a timer and removes it from the global epoll event set.
 *
 *  This function applies to the same timers that start_mediator_timer
 *  applies to.
 *
 *  @param state    The global state for this mediator.
 *  @param timerev  The epoll event for the timer.
 *
 *  @return -1 if an error occured, 0 otherwise (including not stopping
 *          a timer because the timer is disabled).
 */
static int halt_mediator_timer(mediator_state_t *state,
        med_epoll_ev_t *timerev) {

    struct epoll_event ev;

    /* Timer is disabled, ignore */
    if (timerev == NULL) {
        return 0;
    }

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, timerev->fd, &ev) == -1) {
        return -1;
    }

    close(timerev->fd);
    timerev->fd = -1;
    return 0;
}

/** Create an epoll timer event for the next attempt to reconnect to the
 *  provisioner.
 *
 *  Should only be called when the provisioner connection has broken down
 *  for some reason, obviously.
 *
 *  @param state    The global state for this mediator.
 */
static inline void setup_provisioner_reconnect_timer(mediator_state_t *state) {

    state->provisioner.tryconnect = 0;
    start_mediator_timer(state, state->provreconnect, 1);

}

/** Releases all memory associated with a provisioner that this mediator
 *  was connected to.
 *
 *  @param epollfd      The global epoll event file descriptor.
 *  @param prov         The provisioner to be released.
 */
static void free_provisioner(int epollfd, mediator_prov_t *prov) {
    struct epoll_event ev;

    /* If we were using SSL to communicate, tidy up the SSL context */
    if (prov->ssl) {
        SSL_free(prov->ssl);
        prov->ssl = NULL;
    }

    /* Remove the provisioner socket from our epoll event set */
    if (prov->provev) {
        if (prov->provev->fd != -1) {
            if (epoll_ctl(epollfd, EPOLL_CTL_DEL, prov->provev->fd,
                        &ev) == -1 && prov->disable_log == 0) {
                logger(LOG_INFO,
                        "OpenLI Mediator: problem removing provisioner fd from epoll: %s.",
                        strerror(errno));
            }
            close(prov->provev->fd);
        }
        free(prov->provev);
        prov->provev = NULL;
    }

    /* Release the buffers used to store messages sent to and received from
     * the provisioner.
     */
    if (prov->outgoing) {
        destroy_net_buffer(prov->outgoing);
        prov->outgoing = NULL;
    }
    if (prov->incoming) {
        destroy_net_buffer(prov->incoming);
        prov->incoming = NULL;
    }
}

/** Releases all memory associated with a single handover object.
 *
 *  @param state        The global state for this mediator.
 *  @param ho       The handover object that is being destroyed
 */
static void free_handover(mediator_state_t *state, handover_t *ho) {

    /* This should close all of our sockets and halt any running timers */
    disconnect_handover(state, ho);

    if (ho->aliveev) {
        free(ho->aliveev);
    }

    if (ho->aliverespev) {
        free(ho->aliverespev);
    }

    if (ho->outev) {
        /* TODO send disconnect messages to all agencies? */
        med_agency_state_t *agstate = (med_agency_state_t *)
                (ho->outev->state);
        release_export_buffer(&(agstate->buf));
        free(agstate);
        free(ho->outev);
    }

    if (ho->ipstr) {
        free(ho->ipstr);
    }
    if (ho->portstr) {
        free(ho->portstr);
    }
    free(ho);
}

/** Drops the connection to a collector and moves the collector to the
 *  disabled collector list.
 *
 *  @param state        The global state for this mediator
 *  @param colev        The epoll event for this collection connection
 *  @param disablelog   A flag that indicates whether we should log about
 *                      this incident
 */
static void drop_collector(mediator_state_t *state, med_epoll_ev_t *colev,
        int disablelog) {
    med_coll_state_t *mstate;

    if (!colev) {
        return;
    }

    mstate = (med_coll_state_t *)(colev->state);
    if (mstate->disabled_log == 0 && colev->fd != -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: disconnecting from collector %d.",
                colev->fd);
    }

    if (mstate && disablelog) {
        disabled_collector_t *discol;

        /* Add this collector to the disabled collectors list. */
        HASH_FIND(hh, state->disabledcols, mstate->ipaddr,
                strlen(mstate->ipaddr), discol);
        if (discol == NULL) {
            discol = (disabled_collector_t *)calloc(1,
                    sizeof(disabled_collector_t));
            discol->ipaddr = mstate->ipaddr;
            mstate->ipaddr = NULL;

            HASH_ADD_KEYPTR(hh, state->disabledcols, discol->ipaddr,
                    strlen(discol->ipaddr), discol);
        }
    }

    if (mstate && mstate->incoming) {
        destroy_net_buffer(mstate->incoming);
        mstate->incoming = NULL;
    }

    if (mstate->ipaddr) {
        free(mstate->ipaddr);
        mstate->ipaddr = NULL;
    }

    if (colev->fd != -1) {
        close(colev->fd);
        colev->fd = -1;
    }
}

/** Drops *all* currently connected collectors.
 *
 *  @param state        The global state for this mediator
 *  @param c            The list of collectors connected to the mediator
 */
static void drop_all_collectors(mediator_state_t *state, libtrace_list_t *c) {

    /* TODO send disconnect messages to all collectors? */
    libtrace_list_node_t *n;
    mediator_collector_t *col;

    n = c->head;
    while (n) {
        col = (mediator_collector_t *)n->data;

        /* No need to log every collector we're dropping, so we pass in 0
         * as the last parameter */
        drop_collector(state, col->colev, 0);
        free(col->colev->state);
        free(col->colev);
        if (col->ssl){
            SSL_free(col->ssl);
        }
        n = n->next;
    }

    libtrace_list_deinit(c);
}

/** Disconnects and drops all known agencies
 *
 *  @param state        The global state for this mediator.
 *  @param a        The list of known agencies
 */
static void drop_all_agencies(mediator_state_t *state, libtrace_list_t *a) {
    mediator_agency_t ag;

    while (libtrace_list_get_size(a) > 0) {
        libtrace_list_pop_back(a, &ag);
        /* Disconnect the HI2 and HI3 handovers */
        free_handover(state, ag.hi2);
        free_handover(state, ag.hi3);
        if (ag.agencyid) {
            free(ag.agencyid);
        }
    }

}

/** Tidy up the global configuration for this mediator instance.
 *
 *  @param state        The global state for this mediator.
 */
static void clear_med_config(mediator_state_t *state) {

    /* This function just covers members of 'state' that were allocated
     * as part of the mediator config parsing (e.g. strdups of various
     * config arguments, etc.).
     *
     * For tidying up of the rest of the mediator state, see
     * destroy_med_state().
     */

    if (state->listenport) {
        free(state->listenport);
    }
    if (state->listenaddr) {
        free(state->listenaddr);
    }
    if (state->provport) {
        free(state->provport);
    }
    if (state->provaddr) {
        free(state->provaddr);
    }
    if (state->pcapdirectory) {
        free(state->pcapdirectory);
    }
    if (state->operatorid) {
        free(state->operatorid);
    }

    free_ssl_config(&(state->sslconf));
    pthread_mutex_destroy(&(state->agency_mutex));
}

/** Frees all global state for a mediator instance.
 *
 *  @param state        The global state for the mediator instance
 */
static void destroy_med_state(mediator_state_t *state) {

    liid_map_t *m;
    PWord_t jval;
    Word_t bytes;
    unsigned char index[1024];
    disabled_collector_t *discol, *dtmp;

    /* Purge the disabled collector list */
    index[0] = '\0';
    HASH_ITER(hh, state->disabledcols, discol, dtmp) {
        HASH_DELETE(hh, state->disabledcols, discol);
        free(discol->ipaddr);
        free(discol);
    }

    /* Remove all known LIIDs */
    JSLF(jval, state->liid_array, index);
    while (jval != NULL) {
        m = (liid_map_t *)(*jval);

        /* If we had a timer running for the removal of a withdrawn LIID,
         * make sure we stop that cleanly.
         */
        if (m->ceasetimer) {
            halt_mediator_timer(state, m->ceasetimer);
            free(m->ceasetimer);
        }
        JSLN(jval, state->liid_array, index);
        free(m->liid);
        free(m);
    }
    JSLFA(bytes, state->liid_array);

    /* Clean up the list of "unknown" LIIDs */
    JSLFA(bytes, state->missing_liids);

    /* Tear down the connection to the provisioner */
    free_provisioner(state->epoll_fd, &(state->provisioner));

    /* Dump all connected collectors */
    drop_all_collectors(state, state->collectors);

    /* Delete all of the agencies and shut down any active handovers */
    pthread_mutex_lock(&(state->agency_mutex));
    drop_all_agencies(state, state->agencies);
    pthread_mutex_unlock(&(state->agency_mutex));

    libtrace_list_deinit(state->agencies);

    /* Close the main epoll file descriptor */
    if (state->epoll_fd != -1) {
        close(state->epoll_fd);
    }

    /* Destroy the instance-level epoll events */
    if (state->signalev) {
        close(state->signalev->fd);
        free(state->signalev);
    }
    if (state->listenerev) {
        close(state->listenerev->fd);
        free(state->listenerev);
    }

    /* Halt the provisioner reconnection timer, if it is running */
    if (state->provreconnect) {
        if (state->provreconnect->fd != -1) {
            close(state->provreconnect->fd);
        }
        free(state->provreconnect);
    }

    /* Halt the epoll loop timer */
	if (state->timerev) {
		if (state->timerev->fd != -1) {
			close(state->timerev->fd);
		}
		free(state->timerev);
	}

    /* Make sure the pcap thread has stopped */
    pthread_join(state->pcapthread, NULL);

    /* Halt the pcap file rotation timer */
    if (state->pcaptimerev) {
        if (state->pcaptimerev->fd != -1) {
            close(state->pcaptimerev->fd);
        }
        free(state->pcaptimerev);
    }

    /* Clean up the message queue for packets to be written as pcap */
    libtrace_message_queue_destroy(&(state->pcapqueue));

    /* Wait for the thread that keeps the handovers up to stop */
    if (state->connectthread != -1) {
        pthread_join(state->connectthread, NULL);
    }
}

/** Initialises the global state for a mediator instance.
 *
 *  This includes parsing the provided configuration file and setting
 *  the corresponding fields in the global state structure.
 *
 *  This method is also run whenver a config reload is triggered by the
 *  user, so some state members are initialised later on to avoid
 *  unnecessary duplicate allocations -- see prepare_mediator_state() for
 *  more details.
 *
 *  @param state        The global state to be initialised
 *  @param configfile   The path to the configuration file
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
static int init_med_state(mediator_state_t *state, char *configfile) {
    state->mediatorid = 0;
    state->conffile = configfile;
    state->listenaddr = NULL;
    state->listenport = NULL;
    state->etsitls = 1;

    state->sslconf.certfile = NULL;
    state->sslconf.keyfile = NULL;
    state->sslconf.cacertfile = NULL;
    state->sslconf.ctx = NULL;
    state->lastsslerror_accept = 0;
    state->lastsslerror_connect = 0;

    state->operatorid = NULL;
    state->provaddr = NULL;
    state->provport = NULL;
    state->pcapdirectory = NULL;
    state->pcapthread = -1;
    state->pcaprotatefreq = 30;
    state->disabledcols = NULL;
    state->listenerev = NULL;
    state->timerev = NULL;
    state->provreconnect = NULL;
    state->pcaptimerev = NULL;
    state->provisioner.provev = NULL;
    state->provisioner.incoming = NULL;
    state->provisioner.outgoing = NULL;
    state->provisioner.disable_log = 0;
    state->provisioner.tryconnect = 1;
    state->provisioner.ssl = NULL;
    state->collectors = NULL;
    state->agencies = NULL;
    state->epoll_fd = -1;

    pthread_mutex_init(&(state->agency_mutex), NULL);
    state->connectthread = -1;

    state->liid_array = NULL;
    state->missing_liids = NULL;

    libtrace_message_queue_init(&(state->pcapqueue),
            sizeof(mediator_pcap_msg_t));

    /* Parse the provided config file */
    if (parse_mediator_config(configfile, state) == -1) {
        return -1;
    }

    logger(LOG_DEBUG, "OpenLI Mediator: ETSI TLS encryption %s",
        state->etsitls ? "enabled" : "disabled");

    if (create_ssl_context(&(state->sslconf)) < 0) {
        return -1;
    }

    if (state->mediatorid == 0) {
        logger(LOG_INFO, "OpenLI Mediator: ID is not present in the config file or is set to zero.");
        return -1;
    }

    /* Set some default ports for inter-component connections */
    if (state->listenport == NULL) {
        state->listenport = strdup("61000");
    }

    if (state->provport == NULL) {
        state->provport = strdup("8993");
    }

    return 0;
}


/** Runs the remaining post-initialisation tasks for the global mediator
 *  state.
 *
 *  Due to possible config reloading, init_mediator_state() can be run
 *  multiple times. Any state that is not defined by a config option AND
 *  has a suitable "null" value AND only makes sense to create when the
 *  mediator starts for the first time should be initialised in this method
 *  instead.
 *
 *  @param state        The global state for this mediator
 */
static void prepare_mediator_state(mediator_state_t *state) {
    sigset_t sigmask;

    state->epoll_fd = epoll_create1(0);
    state->collectors = libtrace_list_init(sizeof(mediator_collector_t));
    state->agencies = libtrace_list_init(sizeof(mediator_agency_t));

    /* Use an fd to catch signals during our main epoll loop, so that we
     * can provide our own signal handling without causing epoll_wait to
     * return EINTR.
     */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGHUP);

    state->signalev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    state->signalev->fdtype = MED_EPOLL_SIGNAL;
    state->signalev->fd = signalfd(-1, &sigmask, 0);

    /* Create an epoll event for regulating reconnect attempts to the
     * provisioner */
    state->provreconnect = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    state->provreconnect->fdtype = MED_EPOLL_PROVRECONNECT;
    state->provreconnect->fd = -1;

    return;
}

/** Creates a flush or rotate message and sends it to the pcap writing thread.
 *
 *  On its own, the pcap trace output would be flushed intermittently
 *  which often gives the impression that no packets are being captured.
 *  In reality, they are captured but are sitting in a buffer in memory
 *  rather than being written to disk.
 *
 *  This method will also cause pcap files to be closed and rotated on a
 *  regular basis as pcap tools tend to have issues working with incomplete
 *  files -- regular file rotation means that only the file with the most
 *  recent packets will be incomplete; the others can be given to LEAs.
 */
static int trigger_pcap_flush(mediator_state_t *state, med_epoll_ev_t *mev) {

    mediator_pcap_msg_t pmsg;
    struct timeval tv;
    int timerfd;

    memset(&pmsg, 0, sizeof(pmsg));
    gettimeofday(&tv, NULL);

    /* Check if we should be rotating -- the time check here is fairly coarse
     * because we cannot guarantee that this event will be triggered in the
     * exact second that the rotation should happen.
     */
    if (tv.tv_sec % (60 * state->pcaprotatefreq) < 60) {
        pmsg.msgtype = PCAP_MESSAGE_ROTATE;
    } else {
        /* Otherwise, just get the thread to flush any outstanding output */
        pmsg.msgtype = PCAP_MESSAGE_FLUSH;
    }
    pmsg.msgbody = NULL;
    pmsg.msglen = 0;

    libtrace_message_queue_put(&(state->pcapqueue), (void *)(&pmsg));

    /* Restart the timer */
    if (halt_mediator_timer(state, mev) < 0) {
        /* don't care? */
    }

    timerfd = epoll_add_timer(state->epoll_fd, 60, state->pcaptimerev);
    if (timerfd == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to create pcap rotation timer");
        return -1;
    }
    state->pcaptimerev->fd = timerfd;
    state->pcaptimerev->fdtype = MED_EPOLL_PCAP_TIMER;
    state->pcaptimerev->state = NULL;
    return 0;
}

/** Creates and sends a keep-alive message over a handover
 *
 *  @param state        The global state for this mediator
 *  @param mev          The epoll event for the keepalive timer that has fired
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
static int trigger_keepalive(mediator_state_t *state, med_epoll_ev_t *mev) {

    med_agency_state_t *ms = (med_agency_state_t *)(mev->state);
    wandder_encoded_result_t *kamsg;
    wandder_etsipshdr_data_t hdrdata;
    char elemstring[16];
    char liidstring[24];

    if (ms->main_fd == -1) {
        return 0;
    }

    if (ms->pending_ka == NULL && get_buffered_amount(&(ms->buf)) == 0) {
        /* Only create a new KA message if we have sent the last one we
         * had queued up.
         * Also only create one if we don't already have data to send. We
         * should only be sending keep alives if the socket is idle.
         */
        if (ms->encoder == NULL) {
            ms->encoder = init_wandder_encoder();
        } else {
            reset_wandder_encoder(ms->encoder);
        }

        /* Include the OpenLI version in the LIID field, so the LEAs can
         * identify which version of the software is being used by the
         * sender.
         */
        /* PACKAGE_NAME and PACKAGE_VERSION come from config.h */
        snprintf(liidstring, 24, "%s-%s", PACKAGE_NAME, PACKAGE_VERSION);
        hdrdata.liid = liidstring;
        hdrdata.liid_len = strlen(hdrdata.liid);

        hdrdata.authcc = "NA";
        hdrdata.authcc_len = strlen(hdrdata.authcc);
        hdrdata.delivcc = "NA";
        hdrdata.delivcc_len = strlen(hdrdata.delivcc);

        if (state->operatorid) {
            hdrdata.operatorid = state->operatorid;
        } else {
            hdrdata.operatorid = "unspecified";
        }
        hdrdata.operatorid_len = strlen(hdrdata.operatorid);

        /* Stupid 16 character limit... */
        snprintf(elemstring, 16, "med-%u", state->mediatorid);
        hdrdata.networkelemid = elemstring;
        hdrdata.networkelemid_len = strlen(hdrdata.networkelemid);

        hdrdata.intpointid = NULL;
        hdrdata.intpointid_len = 0;

        kamsg = encode_etsi_keepalive(ms->encoder, &hdrdata,
                ms->lastkaseq + 1);
        if (kamsg == NULL) {
            logger(LOG_INFO,
                    "OpenLI Mediator: failed to construct a keep-alive.");
            return -1;
        }

        ms->pending_ka = kamsg;
        ms->lastkaseq += 1;

        /* Enable the output event for the handover, so that epoll will
         * trigger a writable event when we are able to send this message. */
        if (!ms->outenabled) {
            struct epoll_event ev;
            ev.data.ptr = ms->parent->outev;
            ev.events = EPOLLRDHUP | EPOLLIN | EPOLLOUT;
            if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, ms->main_fd,
                        &ev) == -1) {
                if (ms->parent->disconnect_msg == 0) {
                    logger(LOG_INFO,
                        "OpenLI Mediator: error while trying to enable xmit for handover %s:%s HI%d -- %s",
                        ms->parent->ipstr, ms->parent->portstr,
                        ms->parent->handover_type, strerror(errno));
                }
                return -1;
            }
            ms->outenabled = 1;
        }
    }

    /* Reset the keep alive timer */
    halt_mediator_timer(state, mev);
    if (start_mediator_timer(state, mev, ms->kafreq) == -1) {
        if (ms->parent->disconnect_msg == 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: unable to reset keepalive timer for  %s:%s HI%d :s",
                ms->parent->ipstr, ms->parent->portstr,
                ms->parent->handover_type, strerror(errno));
        }
        return -1;
    }
    ms->katimer_fd = mev->fd;
    return 0;
}

/** Attempt to create a handover connection to an LEA.
 *
 *  @param state        The global state for this mediator
 *  @param ho           The handover that we attempting to connect
 *
 *  @return -1 if there was a fatal error, 0 if there was a temporary
 *          error (i.e. try again later) or the handover is already
 *          connected, 1 if a new successful connection is made.
 */
static int connect_handover(mediator_state_t *state, handover_t *ho) {
    med_agency_state_t *agstate;
    struct epoll_event ev;

    agstate = (med_agency_state_t *)(ho->outev->state);

    /* Check if we're already connected? */
    if (ho->outev->fd != -1) {
        return 0;
    }

    /* Connect the handover socket */
    ho->outev->fd = connect_socket(ho->ipstr, ho->portstr, ho->disconnect_msg,
            1);
    if (ho->outev->fd == -1) {
        return -1;
    }

    /* If fd is 0, we can try again another time instead */
    if (ho->outev->fd == 0) {
        ho->outev->fd = -1;
        ho->disconnect_msg = 1;
        return 0;
    }

    /* Create a buffer for receiving messages (i.e. keep-alive responses)
     * from the LEA via the handover.
     */
    agstate->incoming = (libtrace_scb_t *)malloc(sizeof(libtrace_scb_t));
    agstate->incoming->fd = -1;
    agstate->incoming->address = NULL;
    libtrace_scb_init(agstate->incoming, (64 * 1024 * 1024),
            (uint16_t)state->mediatorid);

    agstate->main_fd = ho->outev->fd;
    agstate->katimer_fd = -1;
    agstate->katimer_setsec = 0;
    agstate->karesptimer_fd = -1;
    agstate->lastkaseq = 0;
    agstate->pending_ka = NULL;
    agstate->encoder = NULL;
    agstate->decoder = NULL;

    /* Start a keep alive timer */
    if (ho->aliveev && ho->aliveev->fd != -1) {
        halt_mediator_timer(state, ho->aliveev);
    }

    if (start_mediator_timer(state, ho->aliveev, agstate->kafreq) == -1) {
        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: unable to start keepalive timer for  %s:%s HI%d :s",
                ho->ipstr, ho->portstr,
                ho->handover_type, strerror(errno));
        }
        return 1;
    }
    if (ho->aliveev) {
        agstate->katimer_fd = ho->aliveev->fd;
    }

    /* If we've got records to send via this handover, enable it for
     * write events in epoll.
     */
    if (get_buffered_amount(&(agstate->buf)) > 0) {
        ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
        agstate->outenabled = 1;
    } else {
        ev.events = EPOLLIN | EPOLLRDHUP;
        agstate->outenabled = 0;
    }
    ev.data.ptr = (void *)ho->outev;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, ho->outev->fd, &ev) == -1) {
        if (ho->disconnect_msg ==0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: unable to add agency handover fd %d to epoll.",
                    ho->outev->fd);
        }
        ho->disconnect_msg = 1;
        close(ho->outev->fd);
        ho->outev->fd = -1;
        return 0;
    }

    return 1;
}

/** Attempt to connect all handovers for all known agencies
 *
 *  @param state        The global state for this mediator
 */
static void connect_agencies(mediator_state_t *state) {
    libtrace_list_node_t *n;
    mediator_agency_t *ag;
    int ret;

    /* This method will be called regularly by the agency connection
     * thread to ensure that as many handovers as up and running as
     * possible.
     */

    /* Must have agency_mutex at this point! */
    n = state->agencies->head;
    while (n) {
        ag = (mediator_agency_t *)(n->data);
        n = n->next;

        /* Skip any disabled agencies */
        if (ag->disabled) {
            if (!ag->disabled_msg) {
                logger(LOG_INFO,
                    "OpenLI Mediator: cannot connect to agency %s because it is disabled",
                    ag->agencyid);
                ag->disabled_msg = 1;
            }
            continue;
        }

        /* Connect the HI2 handover */
        ret = connect_handover(state, ag->hi2);
        if (ret == -1) {
            continue;
        }

        if (ret == 1) {
            logger(LOG_INFO,
                    "OpenLI Mediator: Connected to agency %s on HI2 %s:%s.",
                    ag->agencyid, ag->hi2->ipstr, ag->hi2->portstr);
            ag->hi2->disconnect_msg = 0;
        }

        /* Connect the HI3 handover */
        ret = connect_handover(state, ag->hi3);
        if (ret == -1) {
            ag->disabled = 1;
            continue;
        }

        if (ret == 1) {
            ag->hi3->disconnect_msg = 0;
            logger(LOG_INFO,
                    "OpenLI Mediator: Connected to agency %s on HI3 %s:%s.",
                    ag->agencyid, ag->hi3->ipstr, ag->hi3->portstr);
        }

    }

}

/** Creates and registers an epoll event for the socket that listens for
 *  connection attempts from collectors.
 *
 *  @param state        The global state for the mediator.
 *
 *  @return -1 if an error occurs, otherwise returns the file descriptor of
 *  the collector listening socket.
 */
static int start_collector_listener(mediator_state_t *state) {
    struct epoll_event ev;
    int sockfd;

    state->listenerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));

    /* Creates a listening socket using the method from utils.c */
    sockfd = create_listener(state->listenaddr, state->listenport,
            "Mediator");
    if (sockfd == -1) {
        return -1;
    }

    /* Create and register an epoll event for the listening socket */
    state->listenerev->fd = sockfd;
    state->listenerev->fdtype = MED_EPOLL_COLL_CONN;
    state->listenerev->state = NULL;

    ev.data.ptr = state->listenerev;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: Failed to register mediator listening socket: %s.",
                strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/** Actions a signal that has been detected via the epoll loop.
 *
 *  @param state        The global state for this mediator
 *  @param fd           The file descriptor that received the signal
 *
 *  @return a negative value if an error occurs, 0 if successful.
 */
static int process_signal(mediator_state_t *state, int sigfd) {

    struct signalfd_siginfo si;
    int ret;

    /* Read the signal number from the file descriptor */
    ret = read(sigfd, &si, sizeof(si));
    if (ret < 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: unable to read from signal fd: %s.",
                strerror(errno));
        return ret;
    }

    /* Partial reads shouldn't happen for such a small object, but we should
     * consider handling a partial read properly... XXX */
    if (ret != sizeof(si)) {
        logger(LOG_INFO,
                "OpenLI Mediator: unexpected partial read from signal fd.");
        return -1;
    }

    /* Trigger the appropriate reaction to the received signal */
    if (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT) {
        halt_signal(si.ssi_signo);
    }
    if (si.ssi_signo == SIGHUP) {
        reload_signal(si.ssi_signo);
    }

    return 0;
}

/** Accepts a connection from a collector and prepares to receive encoded
 *  ETSI records from that collector.
 *
 *  @param state        The global state for the mediator
 *
 *  @return -1 if an error occurs, otherwise the file descriptor for the
 *          collector connection.
 */
static int accept_collector(mediator_state_t *state) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    mediator_collector_t col;
    med_coll_state_t *mstate;
    struct epoll_event ev;
    disabled_collector_t *discol = NULL;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of collectors. Push all active intercepts
     * out to the collector. */
    newfd = accept(state->listenerev->fd, (struct sockaddr *)&saddr, &socklen);
    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
                0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_INFO, "OpenLI Mediator: getnameinfo error in mediator: %s.",
                strerror(errno));
    }

    if (newfd >= 0) {
        int r = OPENLI_SSL_CONNECT_NOSSL;

        mstate = (med_coll_state_t *)malloc(sizeof(med_coll_state_t));
        col.colev = (med_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));
        col.ssl = NULL;

        if (state->etsitls) {
            /* We're using TLS so create an OpenSSL socket */
            r = listen_ssl_socket(&(state->sslconf), &(col.ssl), newfd);

            if (r == OPENLI_SSL_CONNECT_FAILED) {
                close(newfd);
                SSL_free(col.ssl);
                free(mstate);
                free(col.colev);

                if (r != state->lastsslerror_accept) {
                    logger(LOG_INFO,
                            "OpenLI: SSL Handshake failed for collector %s",
                            strbuf);
                }
                state->lastsslerror_accept = r;
                return -1;
            }

            if (r == OPENLI_SSL_CONNECT_WAITING) {
                /* Handshake is not yet complete, so we need to wait for that */
                col.colev->fdtype = MED_EPOLL_COLLECTOR_HANDSHAKE;
            } else {
                /* Handshake completed, go straight to "Ready" mode */
                col.colev->fdtype = MED_EPOLL_COLLECTOR;
                state->lastsslerror_accept = 0;
            }
        } else {
            /* Not using TLS, we're good to go right away */
            col.colev->fdtype = MED_EPOLL_COLLECTOR;
        }

        col.colev->fd = newfd;
        col.colev->state = mstate;
        mstate->ssl = col.ssl;
        mstate->incoming = create_net_buffer(NETBUF_RECV, newfd, col.ssl);
        mstate->ipaddr = strdup(strbuf);

        /* Check if this is a reconnection case */
        HASH_FIND(hh, state->disabledcols, mstate->ipaddr,
                strlen(mstate->ipaddr), discol);

        if (discol) {
            mstate->disabled_log = 1;
        } else {
            logger(LOG_INFO,
                    "OpenLI Mediator: accepted connection from collector %s.",
                    strbuf);
            mstate->disabled_log = 0;
        }

        /* Add fd to epoll */
        ev.data.ptr = (void *)(col.colev);
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, col.colev->fd,
                    &ev) < 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: unable to add collector fd to epoll: %s.",
                    strerror(errno));
            drop_collector(state, col.colev, 1);
            return -1;
        }

        /* Add this collector to the set of active collectors */
        libtrace_list_push_back(state->collectors, &col);
    }

    return newfd;
}

/* Creates a new instance of a handover.
 *
 * @param ipstr         The IP address of the handover recipient (as a string).
 * @param portstr       The port that the handover recipient is listening on
 *                      (as a string).
 * @param handover_type Either HANDOVER_HI2 or HANDOVER_HI3, to indicate which
 *                      type of handover this is.
 * @param kafreq        The frequency to send keep alive requests (in seconds).
 * @param kawait        The time to wait before assuming a keep alive has
 *                      failed (in seconds).
 *
 * @return a pointer to a new handover instance, or NULL if an error occurs.
 */
static handover_t *create_new_handover(char *ipstr, char *portstr,
        int handover_type, uint32_t kafreq, uint32_t kawait) {

    med_epoll_ev_t *agev;
    med_epoll_ev_t *timerev;
    med_epoll_ev_t *respev;
    med_agency_state_t *agstate;

    handover_t *ho = (handover_t *)malloc(sizeof(handover_t));

    if (ho == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: ran out of memory while allocating handover structure.");
        return NULL;
    }

    agev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    agstate = (med_agency_state_t *)malloc(sizeof(med_agency_state_t));

    /* Keep alive frequency of 0 (or less) will mean that no keep alives are
     * sent (this may necessary for some agencies).
     */
    if (kafreq > 0) {
        timerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    } else {
            logger(LOG_INFO, "OpenLI Mediator: Warning, keep alive timer has been disabled for agency %s:%s", ipstr, portstr);
        timerev = NULL;
    }

    /* If keep alive wait is 0 (or less), then we will not require a response
     * for a successful keep alive.
     */
    if (kawait > 0) {
        respev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    } else {
        respev = NULL;
    }

    if (agev == NULL || agstate == NULL || (kafreq > 0 && timerev == NULL) ||
            (kawait > 0 && respev == NULL)) {
        logger(LOG_INFO, "OpenLI Mediator: ran out of memory while allocating handover structure.");
        if (agev) {
            free(agev);
        }
        if (timerev) {
            free(timerev);
        }
        if (respev) {
            free(respev);
        }
        if (agstate) {
            free(agstate);
        }
        free(ho);
        return NULL;
    }

    /* Initialise all of the epoll callback state for this handover */
    init_export_buffer(&(agstate->buf));
    agstate->main_fd = -1;
    agstate->outenabled = 0;
    agstate->katimer_fd = -1;
    agstate->katimer_setsec = 0;
    agstate->karesptimer_fd = -1;
    agstate->parent = ho;
    agstate->incoming = NULL;
    agstate->encoder = NULL;
    agstate->decoder = NULL;
    agstate->pending_ka = NULL;
    agstate->kafreq = kafreq;
    agstate->kawait = kawait;

    agev->fd = -1;
    agev->fdtype = MED_EPOLL_LEA;
    agev->state = agstate;

    if (timerev) {
        timerev->fd = -1;
        timerev->fdtype = MED_EPOLL_KA_TIMER;
        timerev->state = agstate;
    }

    if (respev) {
        respev->fd = -1;
        respev->fdtype = MED_EPOLL_KA_RESPONSE_TIMER;
        respev->state = agstate;
    }

    /* Initialise the remaining handover state */
    ho->ipstr = ipstr;
    ho->portstr = portstr;
    ho->handover_type = handover_type;
    ho->outev = agev;
    ho->aliveev = timerev;
    ho->aliverespev = respev;
    ho->disconnect_msg = 0;

    return ho;
}

/** Starts the thread that continuously attempts to connect any handovers
 *  that are not currently active.
 *
 *  @param params       The global state for the mediator
 */
static void *start_connect_thread(void *params) {

    mediator_state_t *state = (mediator_state_t *)params;

    while (mediator_halt == 0) {

        /* We need a mutex lock here because our set of agencies could
         * be modified by a message from the provisioner, which will be
         * handled in the main epoll thread.
         */
        pthread_mutex_lock(&(state->agency_mutex));

        if (libtrace_list_get_size(state->agencies) == 0) {
            pthread_mutex_unlock(&(state->agency_mutex));
            break;
        }

        connect_agencies(state);
        pthread_mutex_unlock(&(state->agency_mutex));

        /* Try again in 0.5 of a second */
        usleep(500000);
    }

    logger(LOG_INFO, "OpenLI Mediator: has ended agency connection thread.");
    pthread_exit(NULL);

}

/** Creates a new instance of an agency.
 *
 *  @param state        The global state for this mediator.
 *  @param lea          The agency details received from the provisioner.
 */
static void create_new_agency(mediator_state_t *state, liagency_t *lea) {

    mediator_agency_t newagency;

    newagency.agencyid = lea->agencyid;
    newagency.awaitingconfirm = 0;
    newagency.disabled = 0;
    newagency.disabled_msg = 0;

    /* Create the HI2 and HI3 handovers */
    newagency.hi2 = create_new_handover(lea->hi2_ipstr, lea->hi2_portstr,
            HANDOVER_HI2, lea->keepalivefreq, lea->keepalivewait);
    newagency.hi3 = create_new_handover(lea->hi3_ipstr, lea->hi3_portstr,
            HANDOVER_HI3, lea->keepalivefreq, lea->keepalivewait);

    /* This lock protects the agency list that may be being iterated over
     * by the handover connection thread */
    pthread_mutex_lock(&(state->agency_mutex));
    libtrace_list_push_back(state->agencies, &newagency);

    /* Start the handover connection thread if necessary */
    if (libtrace_list_get_size(state->agencies) == 1 &&
            state->connectthread == -1) {
        pthread_create(&(state->connectthread), NULL, start_connect_thread,
                state);
    }
    pthread_mutex_unlock(&(state->agency_mutex));

}

/* Compares a handover announced by the provisioner against an existing
 * local instance of the handover to see if there are any changes that
 * need to made to update the local handover. If so, the changes are
 * actioned (including a possible disconnection of the existing handover if
 * need be).
 *
 * Used when a provisioner re-announces an existing agency -- if the IP
 * address or port for a handover changes, for instance, we would need to
 * close the handover and re-connect to the new IP + port.
 *
 * @param state         The global state for the mediator.
 * @param ho            The existing local handover instance.
 * @param ipstr         The IP address of the announced handover (as a string).
 * @param port          The port number of the announced handover (as a string).
 * @param existing      The existing instance of the parent agency.
 * @param newag         The new agency details received from the provisioner.
 * @param mas           The epoll event state for the existing handover
 *                      instance.
 *
 * @return -1 if an error occurs, 0 if the handover did not require a reconnect,
 *         1 if a reconnect was required.
 */

static int has_handover_changed(mediator_state_t *state,
        handover_t *ho, char *ipstr, char *portstr, mediator_agency_t *existing,
        liagency_t *newag, med_agency_state_t *mas) {

    char *hitypestr;
    int changedloc = 0;
    int changedkaresp = 0;
    int changedkafreq = 0;

    /* TODO this function is a bit awkward at the moment */

    if (ho == NULL) {
        return -1;
    }

    if (!ho->ipstr || !ho->portstr || !ipstr || !portstr) {
        return -1;
    }

    if (newag->keepalivewait != mas->kawait &&
            (newag->keepalivewait == 0 || mas->kawait == 0)) {
        changedkaresp = 1;
    }

    if (newag->keepalivefreq != mas->kafreq &&
            (newag->keepalivefreq == 0 || mas->kafreq == 0)) {
        changedkafreq = 1;
    }

    if (strcmp(ho->ipstr, ipstr) != 0 || strcmp(ho->portstr, portstr) != 0) {
        changedloc = 1;
    }

    /* Update keep alive timer frequencies */
    mas->kawait = newag->keepalivewait;
    mas->kafreq = newag->keepalivefreq;

    if (!changedkaresp && !changedloc && !changedkafreq) {
        /* Nothing has changed so nothing more needs to be done */
        return 0;
    }

    /* Preparing some string bits for logging */
    if (ho->handover_type == HANDOVER_HI2) {
        hitypestr = "HI2";
    } else if (ho->handover_type == HANDOVER_HI3) {
        hitypestr = "HI3";
    } else {
        hitypestr = "Unknown handover";
    }

    if (changedloc) {
        /* Re-connect is going to be required */
        logger(LOG_INFO,
                "OpenLI Mediator: %s connection info for LEA %s has changed from %s:%s to %s:%s.",
                hitypestr, existing->agencyid, ho->ipstr, ho->portstr, ipstr, portstr);
        ho->disconnect_msg = 0;
        disconnect_handover(state, ho);
        free(ho->ipstr);
        free(ho->portstr);
        ho->ipstr = ipstr;
        ho->portstr = portstr;
        return 1;
    }

    if (changedkaresp) {
        if (newag->keepalivewait == 0) {
            /* Keep alive responses are no longer necessary */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: disabled keep-alive response requirement for LEA %s",
                        existing->agencyid);
            }
            /* Stop any existing keep alive response timer to prevent us
             * from dropping the handover for our most recent keep alive.
             */
            if (ho->aliverespev) {
                if (ho->aliverespev->fd != -1) {
                    close(ho->aliverespev->fd);
                }
                free(ho->aliverespev);
                ho->aliverespev = NULL;
            }
        } else {
            /* Keep alive responses are enabled (or have changed frequency) */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: enabled keep-alive response requirement for LEA %s",
                        existing->agencyid);
            }
            if (ho->aliverespev == NULL) {
                ho->aliverespev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
            }
            ho->aliverespev->fd = -1;
            ho->aliverespev->fdtype = MED_EPOLL_KA_RESPONSE_TIMER;
            ho->aliverespev->state = mas;
        }
    }

    if (changedkafreq) {
        if (newag->keepalivefreq == 0) {
            /* Sending keep alives is now disabled */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: disabled keep-alives for LEA %s",
                        existing->agencyid);
            }
            /* Halt the existing keep alive timer */
            halt_mediator_timer(state, ho->aliveev);
            if (ho->aliveev) {
                if (ho->aliveev->fd != -1) {
                    close(ho->aliveev->fd);
                }
                free(ho->aliveev);
                ho->aliveev = NULL;
            }
        } else {
            /* Keep alives have been enabled (or changed frequency) */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: enabled keep-alives for LEA %s",
                        existing->agencyid);
            }

            /* Start a new keep alive timer with the new frequency */
            if (ho->aliveev == NULL) {
                ho->aliveev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
            } else if (ho->aliveev->fd) {
                halt_mediator_timer(state, ho->aliveev);
            }

            ho->aliveev->fd = -1;
            ho->aliveev->fdtype = MED_EPOLL_KA_TIMER;
            ho->aliveev->state = mas;

            if (start_mediator_timer(state, ho->aliveev,
                        newag->keepalivefreq) == -1) {
                logger(LOG_INFO,
                        "OpenLI Mediator: unable to restart keepalive timer for handover %s:%s HI%d.",
                        ho->ipstr, ho->portstr, ho->handover_type,
                        strerror(errno));
                return -1;
            }
        }
    }

    return 0;
}

/** Parse and action a withdrawal of an LEA by the provisioner
 *
 *  @param state        The global state for this mediator
 *  @param msgbody      The buffer containing the withdrawal message content
 *  @param msglen       The length of the withdrawal message
 *
 *  @return -1 if an error occurs, 0 if the LEA is withdrawn successfully
 */
static int receive_lea_withdrawal(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    liagency_t lea;
    libtrace_list_node_t *n;

    /* Call into netcomms.c to decode the message properly */
    if (decode_lea_withdrawal(msgbody, msglen, &lea) == -1) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO, "OpenLI Mediator: received invalid LEA withdrawal from provisioner.");
        }
        return -1;
    }

    if (state->provisioner.disable_log == 0) {
        logger(LOG_INFO, "OpenLI Mediator: received LEA withdrawal for %s.",
                lea.agencyid);
    }

    /* Disable the agency in the agency list -- note that lock to protect
     * concurrent access to the list by the handover connection thread.
     */
    pthread_mutex_lock(&(state->agency_mutex));
    n = state->agencies->head;
    while (n) {
        mediator_agency_t *x = (mediator_agency_t *)(n->data);
        n = n->next;

        if (strcmp(x->agencyid, lea.agencyid) == 0) {
            /* We've found the agency with the appropriate ID to withdraw */
            x->disabled = 1;
            x->disabled_msg = 0;
            disconnect_handover(state, x->hi2);
            disconnect_handover(state, x->hi3);

            /* Note that we leave the agency in the list -- it's simpler to do
             * that than to actually try and remove it.
             *
             * TODO replace agency list with a Judy map keyed by agency id.
             */
            break;
        }
    }
    pthread_mutex_unlock(&(state->agency_mutex));

    return 0;
}

/** Parse and action an LEA announcement received from the provisioner.
 *  @param state        The global state for this mediator
 *  @param msgbody      The buffer containing the announcement message content
 *  @param msglen       The length of the announcement message
 *
 *  @return -1 if an error occurs, 0 if the LEA is added successfully
 */

static int receive_lea_announce(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    liagency_t lea;
    libtrace_list_node_t *n;
    int ret;

    /* Call into netcomms.c to decode the message */
    if (decode_lea_announcement(msgbody, msglen, &lea) == -1) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: received invalid LEA announcement from provisioner.");
        }
        return -1;
    }

    if (state->provisioner.disable_log == 0) {
        logger(LOG_INFO, "OpenLI Mediator: received LEA announcement for %s.",
                lea.agencyid);
        logger(LOG_INFO, "OpenLI Mediator: HI2 = %s:%s    HI3 = %s:%s",
                lea.hi2_ipstr, lea.hi2_portstr, lea.hi3_ipstr, lea.hi3_portstr);
    }

    /* Add / enable the agency in the agency list -- note that lock to protect
     * concurrent access to the list by the handover connection thread.
     */
    pthread_mutex_lock(&(state->agency_mutex));
    n = state->agencies->head;
    while (n) {
        mediator_agency_t *x = (mediator_agency_t *)(n->data);
        n = n->next;

        if (strcmp(x->agencyid, lea.agencyid) == 0) {
            /* Agency with this ID already exists; check if this
             * announcement contains differences to our last knowledge of
             * this agency.
             */
            med_agency_state_t *mas;

            mas = (med_agency_state_t *)(x->hi2->outev->state);
            if ((ret = has_handover_changed(state, x->hi2, lea.hi2_ipstr,
                    lea.hi2_portstr, x, &lea, mas)) == -1) {
                x->disabled = 1;
                x->disabled_msg = 0;
                goto freelea;
            } else if (ret == 1) {
                lea.hi2_portstr = NULL;
                lea.hi2_ipstr = NULL;
            }

            mas = (med_agency_state_t *)(x->hi3->outev->state);
            if ((ret = has_handover_changed(state, x->hi3, lea.hi3_ipstr,
                    lea.hi3_portstr, x, &lea, mas)) == -1) {
                x->disabled = 1;
                x->disabled_msg = 0;
                goto freelea;
            } else if (ret == 1) {
                lea.hi3_portstr = NULL;
                lea.hi3_ipstr = NULL;
            }

            x->awaitingconfirm = 0;
            x->disabled = 0;
            ret = 0;
            goto freelea;
        }
    }

    /* If we get here, this is an entirely new agency so we can create a
     * fresh instance (plus handovers).
     */
    pthread_mutex_unlock(&(state->agency_mutex));
    create_new_agency(state, &lea);
    return 0;

freelea:
    /* If we get here, the agency already existed in our list so we can
     * remove any extra memory left over from the announcement (e.g.
     * IP address or port strings that were unchanged).
     */
    pthread_mutex_unlock(&(state->agency_mutex));
    if (lea.hi2_portstr) {
        free(lea.hi2_portstr);
    }
    if (lea.hi2_ipstr) {
        free(lea.hi2_ipstr);
    }
    if (lea.hi3_portstr) {
        free(lea.hi3_portstr);
    }
    if (lea.hi3_ipstr) {
        free(lea.hi3_ipstr);
    }
    return ret;
}

/** Finds an agency that matches a given ID in the agency list
 *
 *  @param alist        The agency list
 *  @param id           A string containing the agency ID to search for
 *
 *  @return a pointer to the agency with the given ID, or NULL if no such
 *          agency is found.
 */

static mediator_agency_t *lookup_agency(libtrace_list_t *alist, char *id) {

    mediator_agency_t *ma;
    libtrace_list_node_t *n;

    /* Fingers crossed we don't have too many agencies at any one time. */

    n = alist->head;
    while (n) {
        ma = (mediator_agency_t *)(n->data);
        n = n->next;

        if (strcmp(ma->agencyid, id) == 0) {
            return ma;
        }
    }
    return NULL;

}

/* Given a received ETSI record, determine which agency it should be
 * forwarded to by the mediator.
 *
 * See extract_liid_from_exported_msg() for more information on the meaning
 * of the liidlen output parameter.
 *
 * @param state         The global state for this mediator.
 * @param etsimsg       The start of the message received.
 * @param msglen        The length of the message received.
 * @param liidlen[out]  The number of bytes to strip from the front of the
 *                      message to reach the start of the actual ETSI record
 *
 * @return A pointer to the LIID->agency mapping that this record corresponds
 *         to, or NULL if the LIID is not known by this mediator.
 */
static liid_map_t *match_etsi_to_agency(mediator_state_t *state,
        uint8_t *etsimsg, uint16_t msglen, uint16_t *liidlen) {

    unsigned char liidstr[65536];
    PWord_t jval;

    /* Figure out the LIID for this ETSI record */
    extract_liid_from_exported_msg(etsimsg, msglen, liidstr, 65536, liidlen);

    /* Is this an LIID that we have a suitable agency mapping for? */
    JSLG(jval, state->liid_array, liidstr);
    if (jval == NULL) {

        /* If not, have we already alerted about this unexpected LIID? */
        JSLG(jval, state->missing_liids, liidstr);
        if (jval == NULL) {
            /* First time we've seen this LIID, alert then add it to the
             * missing LIID list so we don't log spam if it happens again.
             */
            logger(LOG_INFO, "OpenLI Mediator: was unable to find LIID %s in its set of mappings.", liidstr);

            JSLI(jval, state->missing_liids, liidstr);
            if (jval == NULL) {
                logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for missing LIID.");
                exit(-2);
            }

            *jval = 1;
        }

        return NULL;
    }

    /* Found the LIID in our mapping array, return it */
    return (liid_map_t *)(*jval);
}

/** Append an ETSI record to the outgoing queue for the appropriate handover.
 *
 *  @param state        The global state for this mediator
 *  @param ho           The handover that will send this record
 *  @param etsimsg      Pointer to the start of the ETSI record
 *  @param msglen       Length of the ETSI record, in bytes.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int enqueue_etsi(mediator_state_t *state, handover_t *ho,
        uint8_t *etsimsg, uint16_t msglen) {

    med_agency_state_t *mas;

    mas = (med_agency_state_t *)(ho->outev->state);

    if (append_etsipdu_to_buffer(&(mas->buf), etsimsg, (uint32_t)msglen, 0)
            == 0) {
        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: was unable to enqueue ETSI PDU for handover %s:%s HI%d",
                ho->ipstr, ho->portstr, ho->handover_type);
        }
        return -1;
    }

    /* Got something to send, so make sure we are enable EPOLLOUT */
    if (ho->outev->fd != -1 && !(mas->outenabled)) {
        struct epoll_event ev;
        ev.data.ptr = ho->outev;
        ev.events = EPOLLRDHUP | EPOLLIN | EPOLLOUT;
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, ho->outev->fd, &ev) == -1)
        {
            if (ho->disconnect_msg == 0) {
                logger(LOG_INFO,
                    "OpenLI Mediator: error while trying to enable xmit for handover %s:%s HI%d -- %s",
                    ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
            }
            return -1;
        }
        mas->outenabled = 1;
    }

    return 0;
}

/** Disables the epoll write event for a socket.
 *
 *  @param state            The global state for this mediator.
 *  @param mas              The agency that this socket is sending to.
 *  @param ho               The handover that this socket applies to.
 *  @param mev              The epoll event structure for the socket.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static inline int disable_epoll_write(mediator_state_t *state,
        med_agency_state_t *mas, handover_t *ho, med_epoll_ev_t *mev) {

    struct epoll_event ev;
    ev.data.ptr = mev;
    ev.events = EPOLLIN | EPOLLRDHUP;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, mev->fd, &ev) == -1) {
        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                "OpenLI: error while trying to disable xmit for handover %s:%s HI%d -- %s",
                ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
        }
        return -1;
    }
    mas->outenabled = 0;
    return 0;
}

/** Send some buffered ETSI records out via a handover.
 *
 *  If there is a keep alive message pending for this handover, that will
 *  be sent before sending any buffered records.
 *
 *  @param state            The global state for this mediator
 *  @param mev              The epoll event for the handover
 *
 *  @return -1 is an error occurs, 0 otherwise.
 */
static inline int xmit_handover(mediator_state_t *state, med_epoll_ev_t *mev) {

    med_agency_state_t *mas = (med_agency_state_t *)(mev->state);
    handover_t *ho = mas->parent;
    int ret = 0;
    struct timeval tv;

    if (mas->pending_ka) {
        /* There's a keep alive to be sent */
        ret = send(mev->fd, mas->pending_ka->encoded, mas->pending_ka->len,
                MSG_DONTWAIT);
        if (ret < 0) {
            /* XXX should be worry about EAGAIN here? */

            if (ho->disconnect_msg == 0) {
                logger(LOG_INFO,
                        "OpenLI Mediator: error while transmitting keepalive for handover %s:%s HI%d -- %s",
                        ho->ipstr, ho->portstr, ho->handover_type,
                        strerror(errno));
            }
            return -1;
        }
        if (ret == 0) {
            return -1;
        }
        if (ret == mas->pending_ka->len) {
            /* Sent the whole thing successfully */
            wandder_release_encoded_result(NULL, mas->pending_ka);
            mas->pending_ka = NULL;

/*
            logger(LOG_INFO, "successfully sent keep alive to %s:%s HI%d",
                    ho->ipstr, ho->portstr, ho->handover_type);
*/
            /* Start the timer for the response */
            if (start_mediator_timer(state, ho->aliverespev,
                        mas->kawait) == -1) {
                if (ho->disconnect_msg == 0) {
                    logger(LOG_INFO,
                            "OpenLI Mediator: unable to start keepalive response timer: %s",
                            strerror(errno));
                }
                return -1;
            }
            if (ho->aliverespev) {
                /* Make sure we're ready to receive the response */
                mas->karesptimer_fd = ho->aliverespev->fd;
            } else if (ho->aliverespev == NULL && ho->disconnect_msg == 1) {
                /* Not expecting a response, so we have to assume that
                 * the connection is good again as soon as we successfully
                 * send a KA */
                ho->disconnect_msg = 0;
                logger(LOG_INFO,
                    "OpenLI Mediator: reconnected to handover %s:%s HI%d successfully.",
                    ho->ipstr, ho->portstr, ho->handover_type);
            }

            /* If there are no actual records waiting to be sent, then
             * we can disable write on this handover and go back to the
             * epoll loop.
             */
            if (get_buffered_amount(&(mas->buf)) == 0) {
                if (disable_epoll_write(state, mas, ho, mev) < 0) {
                    return -1;
                }
            }

        } else {
            /* Partial send -- try the rest next time */
            memmove(mas->pending_ka->encoded, mas->pending_ka->encoded + ret,
                    mas->pending_ka->len - ret);
            mas->pending_ka->len -= ret;
        }
        return 0;
    }

    /* As long as we have an unanswered keep alive, hold off on sending
     * any buffered records -- the recipient may be unavailable and we'd
     * be better off to keep those records in our buffer until we're
     * confident that they're able to receive them.
     */
    if (ho->aliverespev && mas->karesptimer_fd != -1) {
        return 0;
    }

    /* Send some of our buffered records, but no more than 16,000 bytes at
     * a time -- we need to go back to our epoll loop to handle other events
     * rather than getting stuck trying to send massive amounts of data in
     * one go.
     */
    if ((ret = transmit_buffered_records(&(mas->buf), mev->fd, 16000, NULL)) == -1) {
        return -1;
    }

    if (ret == 0) {
        return 0;
    }

    /* If we've sent everything that we've got, we can disable the epoll
     * write event for this handover.
     */
    if (get_buffered_amount(&(mas->buf)) == 0) {
        if (disable_epoll_write(state, mas, ho, mev) < 0) {
            return -1;
        }
    }

    /* Reset the keep alive timer */
    gettimeofday(&tv, NULL);
    if (ho->aliveev && mas->katimer_setsec < tv.tv_sec) {
        if (ho->aliveev->fd != -1) {
            halt_mediator_timer(state, ho->aliveev);
        }
        if (start_mediator_timer(state, ho->aliveev,
                    mas->kafreq) == -1) {
            if (ho->disconnect_msg == 0) {
                logger(LOG_INFO,
                    "OpenLI Mediator: error while trying to disable xmit for handover %s:%s HI%d -- %s",
                    ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
            }
            return -1;
        }
        mas->katimer_setsec = tv.tv_sec;
    }

    if (ho->aliveev == NULL && ho->disconnect_msg == 1) {
        /* Keep alives are disabled, so we are going to use a successful
         * transmit as an indicator that the connection is stable again
         * and we can stop suppressing logs */
        logger(LOG_INFO,
                "OpenLI Mediator: reconnected to handover %s:%s HI%d successfully.",
                ho->ipstr, ho->portstr, ho->handover_type);

        ho->disconnect_msg = 0;
    }

    return 0;
}

/** Parse and action an instruction from a provisioner to remove an
 *  LIID->agency mapping.
 *
 *  @param state            The global state for this mediator
 *  @param msgbody          Pointer to the start of the cease message body
 *  @param msglen           The size of the cease message, in bytes.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_cease(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    char *liid = NULL;
    liid_map_t *m;
    int sock;
    PWord_t jval;

    /** See netcomms.c for this method */
    if (decode_cease_mediation(msgbody, msglen, &liid) == -1) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: received invalid cease mediation command from provisioner.");
        }
        return -1;
    }

    /* Error while decoding, stop */
    if (liid == NULL) {
        return -1;
    }

    /* Is this LIID in our existing LIID->agency map */
    JSLG(jval, state->liid_array, (unsigned char *)liid);
    if (jval == NULL) {
        /* If not, ceasing is pretty straightforward */
        free(liid);
        return 0;
    }

    m = (liid_map_t *)(*jval);

    /* TODO end any pcap trace for this LIID */

    /* We cease mediation on a time-wait basis, i.e. we wait 15 seconds
     * after receiving the cease instruction before removing the LIID mapping.
     * This allows any remaining records that were actually intercepted
     * before the cease was issued, but are sitting in a buffer somewhere
     * (either on the mediator or the collector), to be forwarded to the
     * agencies.
     */

    if (m->ceasetimer != NULL) {
        /* This LIID has already been scheduled to cease? */
        free(liid);
        return 0;
    }

    logger(LOG_INFO,
            "OpenLI Mediator: scheduled removal of agency mapping for LIID %s.",
            m->liid);
    m->ceasetimer = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    m->ceasetimer->fd = -1;
    m->ceasetimer->fdtype = MED_EPOLL_CEASE_LIID_TIMER;
    m->ceasetimer->state = m;

    if ((sock = epoll_add_timer(state->epoll_fd, 15, m->ceasetimer)) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: warning -- cease timer was not able to be set for LIID %s: %s", liid, strerror(errno));
        return -1;
    }
    m->ceasetimer->fd = sock;

    return 0;
}

/** Removes an entry from the LIID->agency map, following the expiry of
 *  a "cease mediation" timer.
 *
 *  @param state            The global state for this mediator
 *  @param mev              The epoll event for the cease mediation timer that
 *                          has triggered.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static inline int remove_mediator_liid_mapping(mediator_state_t *state,
        med_epoll_ev_t *mev) {

    liid_map_t *m = (liid_map_t *)(mev->state);
    int err;

    logger(LOG_INFO, "OpenLI Mediator: removed agency mapping for LIID %s.",
            m->liid);
    JSLD(err, state->liid_array, (unsigned char *)m->liid);

    /* Make sure that the timer event is removed from epoll */
    halt_mediator_timer(state, mev);
    free(m->ceasetimer);
    free(m->liid);
    free(m);
    return 0;
}

/** Parses and actions a new LIID->agency mapping received from the
 *  provisioner.
 *
 *  @param state            The global state for this mediator
 *  @param msgbody          Pointer to the start of the LIID mapping message
 *                          body
 *  @param msglen           Length of the LIID mapping message, in bytes.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_liid_mapping(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    char *agencyid, *liid;
    mediator_agency_t *agency;
    liid_map_t *m;
    PWord_t jval;
    int err;

    agencyid = NULL;
    liid = NULL;

    /* See netcomms.c for this method */
    if (decode_liid_mapping(msgbody, msglen, &agencyid, &liid) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: receive invalid LIID mapping from provisioner.");
        return -1;
    }

    if (agencyid == NULL || liid == NULL) {
        return -1;
    }

    /* "Special" agency ID for intercepts that need to be written to a
     * PCAP file instead of sent to an agency...
     */
    if (strcmp((char *)agencyid, "pcapdisk") == 0) {
        agency = NULL;
    } else {
        /* Try to find the agency in our agency list */
        pthread_mutex_lock(&(state->agency_mutex));
        agency = lookup_agency(state->agencies, agencyid);
        pthread_mutex_unlock(&(state->agency_mutex));

        /* We *could* consider waiting for an LEA announcement that will resolve
         * this discrepancy, but any relevant announcement should have been sent
         * before the LIID mapping.
         *
         * Also, what are we going to do with any records matching that LIID?
         * Buffer them? Our buffers are tied to handovers, so we'd need
         * somewhere else to store them. Drop them?
         */
        if (agency == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: agency %s is not recognised by the mediator, yet LIID %s is intended for it?",
                    agencyid, liid);
            return -1;
        }
    }

    JSLG(jval, state->liid_array, (unsigned char *)liid);
    if (jval != NULL) {
        /* We've seen this LIID before? Possibly a re-announcement? */
        m = (liid_map_t *)(*jval);

        if (m->ceasetimer) {
            /* was scheduled to be ceased, so halt the timer */
            halt_mediator_timer(state, m->ceasetimer);
            free(m->ceasetimer);
        }
        free(m->liid);
    } else {
        /* Create a new entry in the mapping array */
        JSLI(jval, state->liid_array, (unsigned char *)liid);
        if (jval == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for new LIID.");
            return -1;
        }

        m = (liid_map_t *)malloc(sizeof(liid_map_t));
        if (m == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for new LIID.");
            return -1;
        }
        *jval = (Word_t)m;

        /* If this was previously a "unknown" LIID, we can now remove
         * it from our missing LIID list -- if it gets withdrawn later,
         * we will then alert again about it being missing. */
        JSLG(jval, state->missing_liids, (unsigned char *)liid);
        if (jval != NULL) {
            JSLD(err, state->missing_liids, (unsigned char *)liid);
        }
    }
    m->liid = liid;
    m->agency = agency;
    m->ceasetimer = NULL;
    free(agencyid);

    if (agency) {
        logger(LOG_DEBUG, "OpenLI Mediator: added %s -> %s to LIID map",
                m->liid, m->agency->agencyid);
    } else {
        logger(LOG_INFO, "OpenLI Mediator: added %s -> pcapdisk to LIID map",
                m->liid);
    }
    return 0;
}

/** Sends any pending messages to the provisioner.
 *
 *  @param state            The global state for this mediator.
 *  @param mev              The epoll event for the provisioner socket.
 *
 *  @return -1 if an error occurs, 1 otherwise.
 */
static int transmit_provisioner(mediator_state_t *state, med_epoll_ev_t *mev) {

    mediator_prov_t *prov = &(state->provisioner);
    struct epoll_event ev;
    int ret;
    openli_proto_msgtype_t err;

    /* Try to send whatever we've got in the netcomms buffer */
    ret = transmit_net_buffer(prov->outgoing, &err);
    if (ret == -1) {
        if (prov->disable_log == 0) {
            nb_log_transmit_error(err);
            logger(LOG_INFO, "OpenLI Mediator: failed to transmit message to provisioner.");
        }
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        ev.data.ptr = mev;
        ev.events = EPOLLIN | EPOLLRDHUP;
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, mev->fd, &ev) == -1) {
            if (prov->disable_log == 0) {
                logger(LOG_INFO,
                        "OpenLI Mediator: error disabling EPOLLOUT for provisioner fd: %s.",
                        strerror(errno));
            }
            return -1;
        }
    }

    return 1;
}

/** React to a handover's failure to respond to a keep alive before the
 *  response timer expired.
 *
 *  @param state            The global state for this mediator
 *  @param mev              The epoll event for the keep alive response timer
 *
 *  @return 0 always.
 */
static int trigger_ka_failure(mediator_state_t *state, med_epoll_ev_t *mev) {
    med_agency_state_t *ms = (med_agency_state_t *)(mev->state);

    if (ms->parent->disconnect_msg == 0) {
        logger(LOG_INFO, "OpenLI Mediator: failed to receive KA response from LEA on handover %s:%s HI%d, dropping connection.",
                ms->parent->ipstr, ms->parent->portstr,
                ms->parent->handover_type);
    }

    pthread_mutex_lock(&(state->agency_mutex));
    disconnect_handover(state, ms->parent);
    pthread_mutex_unlock(&(state->agency_mutex));
    return 0;
}

/** Receives and actions one or more messages received from the provisioner.
 *
 *  @param state            The global state for this mediator
 *  @param mev              The epoll event for the provisioner socket
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_provisioner(mediator_state_t *state, med_epoll_ev_t *mev) {

    uint8_t *msgbody = NULL;
    uint16_t msglen = 0;
    uint64_t internalid;

    openli_proto_msgtype_t msgtype;

    do {
        msgtype = receive_net_buffer(state->provisioner.incoming, &msgbody,
                &msglen, &internalid);
        if (msgtype < 0) {
            if (state->provisioner.disable_log == 0) {
                nb_log_receive_error(msgtype);
            }
            return -1;
        }

        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                if (state->provisioner.disable_log == 0) {
                    logger(LOG_INFO,
                            "OpenLI Mediator: error receiving message from provisioner.");
                }
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_ANNOUNCE_LEA:
                if (receive_lea_announce(state, msgbody, msglen) == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_WITHDRAW_LEA:
                if (receive_lea_withdrawal(state, msgbody, msglen) == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_MEDIATE_INTERCEPT:
                if (receive_liid_mapping(state, msgbody, msglen) == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_CEASE_MEDIATION:
                if (receive_cease(state, msgbody, msglen) == -1) {
                    return -1;
                }
                break;
            default:
                if (state->provisioner.disable_log == 0) {
                    logger(LOG_INFO,
                            "OpenLI Mediator: unexpected message type %d received from provisioner.",
                            msgtype);
                }
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    return 0;
}

/** Receives and actions a message sent to the mediator over a handover
 *  (typically a keep alive response).
 *
 *  @param state            The global state for the mediator
 *  @param mev              The epoll event for the handover
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_handover(mediator_state_t *state, med_epoll_ev_t *mev) {
    med_agency_state_t *mas = (med_agency_state_t *)(mev->state);
    int ret;
    uint8_t *ptr = NULL;
    uint32_t reclen = 0;
    uint32_t available;

    /* receive the incoming message into a local SCB */
    ret = libtrace_scb_recv_sock(mas->incoming, mev->fd, MSG_DONTWAIT);
    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (mas->parent->disconnect_msg == 0) {
            logger(LOG_INFO, "OpenLI Mediator: error receiving data from LEA on handover %s:%s HI%d: %s",
                    mas->parent->ipstr, mas->parent->portstr,
                    mas->parent->handover_type, strerror(errno));
        }
        return -1;
    }

    if (ret == 0) {
        if (mas->parent->disconnect_msg == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: disconnect on LEA handover %s:%s HI%d",
                    mas->parent->ipstr, mas->parent->portstr,
                    mas->parent->handover_type);
        }
        return -1;
    }

    do {
        ptr = libtrace_scb_get_read(mas->incoming, &available);
        if (available == 0 || ptr == NULL) {
            break;
        }

        /* We're only expecting to get keep alive responses back over the
         * handover socket -- however, we will need to decode them to
         * make sure they are valid.
         */
        if (mas->decoder == NULL) {
            mas->decoder = wandder_create_etsili_decoder();
        }
        wandder_attach_etsili_buffer(mas->decoder, ptr, available, false);
        reclen = wandder_etsili_get_pdu_length(mas->decoder);
        if (reclen == 0) {
            break;
        }
        if (available < reclen) {
            /* Still need to recv more data */
            break;
        }

        if (wandder_etsili_is_keepalive_response(mas->decoder)) {
            int64_t recvseq;
            recvseq = wandder_etsili_get_sequence_number(mas->decoder);

            if (recvseq != mas->lastkaseq) {
                if (mas->parent->disconnect_msg == 0) {
                    logger(LOG_INFO, "OpenLI Mediator: -- unexpected KA response from handover %s:%s HI%d",
                        mas->parent->ipstr, mas->parent->portstr,
                        mas->parent->handover_type);
                    logger(LOG_INFO, "OpenLI Mediator: -- expected %ld, got %ld",
                        mas->lastkaseq, recvseq);
                }
                return -1;
            }
            /*
            logger(LOG_INFO, "OpenLI mediator -- received KA response for %ld from LEA handover %s:%s HI%d",
                    recvseq, mas->parent->ipstr, mas->parent->portstr,
                    mas->parent->handover_type);
            */
            halt_mediator_timer(state, mas->parent->aliverespev);
            libtrace_scb_advance_read(mas->incoming, reclen);
            mas->karesptimer_fd = -1;

            /* Successful KA response is a good indicator that the
             * connection is stable.
             */
            if (mas->parent->disconnect_msg == 1) {
                logger(LOG_INFO,
                        "OpenLI Mediator: reconnected to handover %s:%s HI%d successfully.",
                        mas->parent->ipstr, mas->parent->portstr,
                        mas->parent->handover_type);
            }
            mas->parent->disconnect_msg = 0;
        } else {
            if (mas->parent->disconnect_msg == 0) {
                logger(LOG_INFO, "OpenLI Mediator: -- received unknown data from LEA handover %s:%s HI%d",
                    mas->parent->ipstr, mas->parent->portstr,
                    mas->parent->handover_type);
            }
            return -1;
        }
    } while (1);

    return 0;
}

/** Re-enables log messages for a collector that has re-connected.
 *
 *  @param state            The global state for this mediator
 *  @param cs               The collector that has re-connected
 *
 */
static inline void reenable_collector_logging(mediator_state_t *state,
        med_coll_state_t *cs) {

    disabled_collector_t *discol = NULL;

    cs->disabled_log = 0;
    HASH_FIND(hh, state->disabledcols, cs->ipaddr, strlen(cs->ipaddr), discol);
    if (discol) {
        HASH_DELETE(hh, state->disabledcols, discol);
        free(discol->ipaddr);
        free(discol);
        logger(LOG_INFO, "collector %s has successfully re-connected",
                cs->ipaddr);
    }
}

/** Receives and actions a message from a collector, which can include
 *  an encoded ETSI CC or IRI.
 *
 *  @param state            The global state for this mediator.
 *  @param mev              The epoll event for the collector socket.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_collector(mediator_state_t *state, med_epoll_ev_t *mev) {

    uint8_t *msgbody = NULL;
    uint16_t msglen = 0;
    uint64_t internalid;
    liid_map_t *thisint;
    med_coll_state_t *cs = (med_coll_state_t *)(mev->state);
    openli_proto_msgtype_t msgtype;
    mediator_pcap_msg_t pcapmsg;
    uint16_t liidlen;

    do {
        msgtype = receive_net_buffer(cs->incoming, &msgbody,
                &msglen, &internalid);

        if (msgtype < 0) {
            if (cs->disabled_log == 0) {
                nb_log_receive_error(msgtype);
                logger(LOG_INFO,
                        "OpenLI Mediator: error receiving message from collector.");
            }
            return -1;
        }

        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                logger(LOG_INFO,
                        "OpenLI Mediator: error receiving message from collector.");
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_RAWIP_SYNC:
                /* This is a raw IP packet capture, rather than a properly
                 * encoded ETSI CC. */
                /* msgbody should be an LIID + an IP packet */
                thisint = match_etsi_to_agency(state, msgbody, msglen,
                        &liidlen);
                if (thisint == NULL) {
                    break;
                }
                if (cs->disabled_log == 1) {
                    reenable_collector_logging(state, cs);
                }

                if (thisint->agency == NULL) {
                    /* Write IP packet directly to pcap */
                    pcapmsg.msgtype = PCAP_MESSAGE_RAWIP;
                    pcapmsg.msgbody = (uint8_t *)malloc(msglen);
                    memcpy(pcapmsg.msgbody, msgbody, msglen);
                    pcapmsg.msglen = msglen;
                    libtrace_message_queue_put(&(state->pcapqueue), &pcapmsg);
                }

                break;
            case OPENLI_PROTO_ETSI_CC:
                /* msgbody should contain an LIID + a full ETSI CC record */
                thisint = match_etsi_to_agency(state, msgbody, msglen,
                        &liidlen);
                if (thisint == NULL) {
                    break;
                }
                if (cs->disabled_log == 1) {
                    reenable_collector_logging(state, cs);
                }
                if (thisint->agency == NULL) {
                    /* Destined for a pcap file rather than an agency */
                    /* TODO freelist rather than repeated malloc/free */
                    pcapmsg.msgtype = PCAP_MESSAGE_PACKET;
                    pcapmsg.msgbody = (uint8_t *)malloc(msglen - liidlen);
                    memcpy(pcapmsg.msgbody, msgbody + liidlen,
                            msglen - liidlen);
                    pcapmsg.msglen = msglen - liidlen;
                    libtrace_message_queue_put(&(state->pcapqueue), &pcapmsg);
                } else if (enqueue_etsi(state, thisint->agency->hi3,
                        msgbody + liidlen, msglen - liidlen) == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_ETSI_IRI:
                /* msgbody should contain an LIID + a full ETSI IRI record */
                thisint = match_etsi_to_agency(state, msgbody, msglen,
                        &liidlen);
                if (thisint == NULL) {
                    break;
                }
                if (cs->disabled_log == 1) {
                    reenable_collector_logging(state, cs);
                }
                if (thisint->agency == NULL) {
                    /* Destined for a pcap file rather than an agency */
                    /* IRIs don't make sense for a pcap, so just ignore it */
                    break;
                }
                if (enqueue_etsi(state, thisint->agency->hi2, msgbody + liidlen,
                            msglen - liidlen) == -1) {
                    return -1;
                }
                break;
            default:
                if (cs->disabled_log == 0) {
                   logger(LOG_INFO,
                            "OpenLI Mediator: unexpected message type %d received from collector.",
                            msgtype);
                }
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    return 0;
}

/** Attempts to complete an ongoing TLS handshake with a collector.
 *
 *  @param state            The global state for the mediator
 *  @param mev              The epoll event for the collector socket
 *
 *  @return -1 if an error occurs, 0 if the handshake is not yet complete,
 *          1 if the handshake has now completed.
 */
static int continue_handshake(mediator_state_t *state, med_epoll_ev_t *mev) {
    med_coll_state_t *cs = (med_coll_state_t *)(mev->state);

    //either keep running handshake or return when error
    int ret = SSL_accept(cs->ssl);

    if (ret <= 0){
        ret = SSL_get_error(cs->ssl, ret);
        if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE){
            //keep trying
            return 0;
        }
        else {
            //fail out
            logger(LOG_INFO,
                    "OpenLI: Pending SSL Handshake for collector failed");
            return -1;
        }
    }
    logger(LOG_INFO, "OpenLI: Pending SSL Handshake for collector accepted");
    state->lastsslerror_accept = 0;

    //handshake has finished
    mev->fdtype = MED_EPOLL_COLLECTOR;
    return 1;
}

/** React to an event on a file descriptor reported by our epoll loop.
 *
 *  @param state            The global state for the mediator
 *  @param ev               The epoll event that has triggered
 *
 *  @return -1 if an error occurs, 1 if the epoll loop timer event has
 *          triggered, 0 otherwise.
 */
static int check_epoll_fd(mediator_state_t *state, struct epoll_event *ev) {

	med_epoll_ev_t *mev = (med_epoll_ev_t *)(ev->data.ptr);
    int ret = 0;

	switch(mev->fdtype) {
		case MED_EPOLL_SIGCHECK_TIMER:
            /* Time to stop epolling and do some housekeeping */
			if (ev->events & EPOLLIN) {
				return 1;
			}
			logger(LOG_INFO,
                    "OpenLI Mediator: main epoll timer has failed.");
            return -1;
        case MED_EPOLL_PCAP_TIMER:
            /* pcap timer has fired, flush or rotate any pcap output */
            assert(ev->events == EPOLLIN);
            ret = trigger_pcap_flush(state, mev);
            break;
        case MED_EPOLL_SIGNAL:
            /* we got a signal that needs to be handled */
            ret = process_signal(state, mev->fd);
            break;
        case MED_EPOLL_COLL_CONN:
            /* a connection is occuring on our listening socket */
            ret = accept_collector(state);
            break;
        case MED_EPOLL_CEASE_LIID_TIMER:
            /* an LIID->agency mapping can now be safely removed */
            assert(ev->events == EPOLLIN);
            ret = remove_mediator_liid_mapping(state, mev);
            break;
        case MED_EPOLL_KA_TIMER:
            /* a handover is due to send a keep alive message */
            assert(ev->events == EPOLLIN);
            ret = trigger_keepalive(state, mev);
            break;
        case MED_EPOLL_KA_RESPONSE_TIMER:
            /* a handover target has not responded to a keep alive message
             * and is due to be disconnected */
            assert(ev->events == EPOLLIN);
            ret = trigger_ka_failure(state, mev);
            break;
        case MED_EPOLL_PROVRECONNECT:
            /* we're due to try reconnecting to a lost provisioner */
            assert(ev->events == EPOLLIN);
            halt_mediator_timer(state, mev);
            state->provisioner.tryconnect = 1;
            break;

        case MED_EPOLL_LEA:
            /* the handover is available for writing or reading */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                /* message from LEA -- hopefully a keep-alive response */
                ret = receive_handover(state, mev);
            } else if (ev->events & EPOLLOUT) {
                /* handover is able to send buffered records */
                ret = xmit_handover(state, mev);
            } else {
                ret = -1;
            }
            if (ret == -1) {
                med_agency_state_t *mas = (med_agency_state_t *)(mev->state);
                pthread_mutex_lock(&(state->agency_mutex));
                disconnect_handover(state, mas->parent);
                pthread_mutex_unlock(&(state->agency_mutex));
            }
            break;

        case MED_EPOLL_PROVISIONER:
            /* the provisioner socket is available for reading or writing */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLOUT) {
                /* we can send a pending message to the provisioner */
                ret = transmit_provisioner(state, mev);
            } else if (ev->events & EPOLLIN) {
                /* provisioner has sent us an instruction */
                ret = receive_provisioner(state, mev);
                if (ret == 0 && state->provisioner.disable_log == 1) {
                    logger(LOG_INFO,
                            "OpenLI Mediator: Connected to provisioner at %s:%s",
                            state->provaddr, state->provport);
                    state->provisioner.disable_log = 0;
                }
            } else {
                ret = -1;
            }

            if (ret == -1) {
                if (state->provisioner.disable_log == 0) {
                    logger(LOG_INFO,
                            "OpenLI Mediator: Disconnected from provisioner.");
                }
                free_provisioner(state->epoll_fd, &(state->provisioner));
                setup_provisioner_reconnect_timer(state);
                state->provisioner.disable_log = 1;
            }
            break;
        case MED_EPOLL_COLLECTOR_HANDSHAKE:
            /* socket with an incomplete SSL handshake is available */
            ret = continue_handshake(state, mev);
            if (ret == -1) {
                drop_collector(state, mev, 1);
            }
            break;
        case MED_EPOLL_COLLECTOR:
            /* a collector is sending us some data */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                ret = receive_collector(state, mev);
            }
            if (ret == -1) {
                drop_collector(state, mev, 1);
            }
            break;
        default:
            logger(LOG_INFO,
                    "OpenLI Mediator: invalid fd triggering epoll event.");
            assert(0);
            return -1;
    }

    return ret;

}

/** Forms a message containing the IP address and port of this mediator's
 *  listening socket (for collector connections) and queues it to be sent
 *  to the provisioner. The provisioner will then pass that on to all
 *  registered collectors, so they can connect to us and forward ETSI
 *  that we can then distribute to the agencies.
 *
 *  @param state            The global state for this mediator.
 *  @param justcreated      A boolean flag indicating whether the connection
 *                          to the provisioner has recently been completed.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int send_mediator_listen_details(mediator_state_t *state,
        int justcreated) {
    openli_mediator_t meddeets;
    mediator_prov_t *prov = (mediator_prov_t *)&(state->provisioner);
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(struct sockaddr_storage);
    char listenname[NI_MAXHOST];
    int ret;
    struct epoll_event ev;

    memset(&sa, 0, sizeof(sa));
    meddeets.mediatorid = state->mediatorid;

    /* Use a combination of getsockname and getnameinfo to get the listening
     * address, as listenaddr may be NULL, 0.0.0.0, or ::1 because the user
     * didn't care about the listening interface for some reason (BTW,
     * listening on all interfaces is NOT recommended!).
     */
    if (getsockname(state->listenerev->fd, (struct sockaddr *)(&sa),
                &salen) < 0) {
        logger(LOG_INFO, "OpenLI Mediator: getsockname() failed for listener socket: %s.",
                strerror(errno));
        return -1;
    }

    if ((ret = getnameinfo((struct sockaddr *)(&sa), salen, listenname,
            sizeof(listenname), NULL, 0, NI_NUMERICHOST)) < 0) {
        logger(LOG_INFO, "OpenLI Mediator: getnameinfo() failed for listener socket: %s.",
                gai_strerror(ret));
        return -1;
    }
    meddeets.ipstr = listenname;

    /* The configured port should match though, so we can just use that. */
    meddeets.portstr = state->listenport;

    /* Add the mediator details message to the outgoing buffer for the
     * provisioner socket.
     */
    if (push_mediator_onto_net_buffer(prov->outgoing, &meddeets) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: unable to push mediator details to provisioner.");
        return -1;
    }

    /* If the socket was just created, then we've already configured the
     * corresponding epoll event for writing.
     */
    if (justcreated) {
        return 0;
    }


    /* Otherwise, we may have disabled writing when we last emptied the
     * outgoing buffer so make sure it is enabled again to send this queued
     * message.
     */
    ev.data.ptr = prov->provev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, prov->provev->fd, &ev)
            == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to re-enable transmit on provisioner socket: %s.",
                strerror(errno));
        return -1;
    }

    return 0;
}

/** Initialises local state for a successful connection to the provisioner
 *
 *  @param state            The global state for this mediator
 *  @param sock             The file descriptor of the provisioner connection
 *  @param ctx              The SSL context for this process
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int init_provisioner_connection(mediator_state_t *state, int sock, SSL_CTX *ctx) {

    struct epoll_event ev;
    mediator_prov_t *prov = (mediator_prov_t *)&(state->provisioner);

    if (sock == 0) {
        return 0;
    }

    if (prov->provev == NULL) {
        prov->provev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    }

    prov->provev->fd = sock;
    prov->provev->fdtype = MED_EPOLL_PROVISIONER;
    prov->provev->state = NULL;

    if (ctx != NULL) {
        /* We're using TLS, so attempt an SSL connection */

        /* mediator can't do anything until it has instructions from
         * provisioner so blocking is fine */
        fd_set_block(sock);

        int errr;
        prov->ssl = SSL_new(ctx);
        SSL_set_fd(prov->ssl, sock);

        errr = SSL_connect(prov->ssl);
        fd_set_nonblock(sock);

        if (errr <= 0){
            errr = SSL_get_error(prov->ssl, errr);
            if (errr != SSL_ERROR_WANT_WRITE && errr != SSL_ERROR_WANT_READ){ //handshake failed badly
                SSL_free(prov->ssl);
                free(prov->provev);
                prov->provev = NULL;
                prov->ssl = NULL;
                if (state->lastsslerror_connect == 0) {
                    logger(LOG_INFO, "OpenLI: SSL Handshake failed when connecting to provisioner");
                    state->lastsslerror_connect = 1;
                }
                return -1;
            }
        }
        logger(LOG_INFO,
                "OpenLI mediator: SSL Handshake complete for connection to provisioner");
        state->lastsslerror_connect = 0;
    }
    else {
        prov->ssl = NULL;
    }

    /* Create buffers for both receiving and sending messages on this socket */
    prov->sentinfo = 0;
    prov->outgoing = create_net_buffer(NETBUF_SEND, sock, prov->ssl);
    prov->incoming = create_net_buffer(NETBUF_RECV, sock, prov->ssl);

    /* We're about to enqueue our "auth" message, so immediately configure
     * this socket for an epoll write event (as well as read, of course).
     */
    ev.data.ptr = prov->provev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sock, &ev) == -1) {
        if (prov->disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: failed to register provisioner socket: %s.",
                    strerror(errno));
        }
        return -1;
    }

    if (push_auth_onto_net_buffer(prov->outgoing,
                OPENLI_PROTO_MEDIATOR_AUTH) == -1) {
        if (prov->disable_log == 0) {
            logger(LOG_INFO, "OpenLI Mediator: unable to push auth message for provisioner.");
        }
        return -1;
    }

    /* Epoll write is enabled, so pass in '1' here */
    return send_mediator_listen_details(state, 1);
}

/** Disconnects a provisioner socket and releases local state for that
 *  connection.
 *
 *  @param currstate            The global state for this mediator.
 */
static inline void drop_provisioner(mediator_state_t *currstate) {

    liid_map_t *m;
    PWord_t pval;
    unsigned char index[1024];
    Word_t bytes;

    /* Disconnect from provisioner and reset all state received
     * from the old provisioner (just to be safe). */

    /* Purge the LIID->agency mappings */
    index[0] = '\0';
    JSLF(pval, currstate->liid_array, index);
    while (pval != NULL) {
        m = (liid_map_t *)(*pval);

        if (m->ceasetimer) {
            halt_mediator_timer(currstate, m->ceasetimer);
            free(m->ceasetimer);
        }
        JSLN(pval, currstate->liid_array, index);
        free(m->liid);
        free(m);
    }
    JSLFA(bytes, currstate->liid_array);

    free_provisioner(currstate->epoll_fd, &(currstate->provisioner));

    /* Dump all known agencies -- we'll get new ones when we get a usable
     * provisioner again */
    pthread_mutex_lock(&(currstate->agency_mutex));
    drop_all_agencies(currstate, currstate->agencies);
    pthread_mutex_unlock(&(currstate->agency_mutex));

}

/** Applies any changes to the provisioner socket configuration following
 *  a user-triggered config reload.
 *
 *  @param currstate            The pre-reload global state of the mediator.
 *  @param newstate             A global state instance containing the updated
 *                              configuration.
 *  @return 0 if the configuration is unchanged, 1 if it has changed.
 */
static int reload_provisioner_socket_config(mediator_state_t *currstate,
        mediator_state_t *newstate) {

    int changed = 0;

    if (strcmp(newstate->provaddr, currstate->provaddr) != 0 ||
            strcmp(newstate->provport, currstate->provport) != 0) {

        /* The provisioner is supposedly listening on a different IP and/or
         * port to before, so we should definitely not be talking to
         * whoever is on the old IP+port.
         */
        drop_provisioner(currstate);

        /* Replace existing IP and port strings */
        free(currstate->provaddr);
        free(currstate->provport);
        currstate->provaddr = strdup(newstate->provaddr);
        currstate->provport = strdup(newstate->provport);

        /* Don't bother connecting right now, the run() loop will do this
         * as soon as we return.
         */
        changed = 1;
    }

    if (!changed) {
        logger(LOG_INFO,
                "OpenLI Mediator: provisioner socket configuration is unchanged.");
    }

    return changed;
}

/** Closes the socket that is listening for collector connections and
 *  drops any collectors that are connected through it.
 *
 *  @param currstate            The global state for the mediator
 */
static inline void halt_listening_socket(mediator_state_t *currstate) {
    struct epoll_event ev;

    /* Disconnect all collectors */
    drop_all_collectors(currstate, currstate->collectors);
    currstate->collectors = libtrace_list_init(
            sizeof(mediator_collector_t));


    /* Close listen socket and disable epoll event */
    if (currstate->listenerev) {
        if (currstate->listenerev->fd != -1) {
            logger(LOG_INFO, "OpenLI mediator: closing listening socket on %s:%s",
                    currstate->listenaddr, currstate->listenport);
            if (epoll_ctl(currstate->epoll_fd, EPOLL_CTL_DEL,
                        currstate->listenerev->fd, &ev) == -1) {
                logger(LOG_INFO,
                        "OpenLI mediator: failed to remove listener fd %d from epoll: %s",
                        currstate->listenerev->fd, strerror(errno));
            }
            close(currstate->listenerev->fd);
        }
        free(currstate->listenerev);
    }

    currstate->listenerev = NULL;
}

/** Applies any changes to the listening socket configuration following
 *  a user-triggered config reload.
 *
 *  @param currstate            The pre-reload global state of the mediator.
 *  @param newstate             A global state instance containing the updated
 *                              configuration.
 *  @return 0 if the configuration is unchanged, 1 if it has changed.
 */
static int reload_listener_socket_config(mediator_state_t *currstate,
        mediator_state_t *newstate) {

    int changed = 0;

    if (strcmp(newstate->listenaddr, currstate->listenaddr) != 0 ||
            strcmp(newstate->listenport, currstate->listenport) != 0) {

        /* We're supposed to be listening on a different port and/or IP,
         * so we should close the existing socket and drop any collectors
         * that used it to reach us.
         */
        halt_listening_socket(currstate);

        /* Replace existing IP and port strings */
        free(currstate->listenaddr);
        free(currstate->listenport);
        currstate->listenaddr = strdup(newstate->listenaddr);
        currstate->listenport = strdup(newstate->listenport);

        /* Open new listen socket */
        if (start_collector_listener(currstate) < 0) {
            logger(LOG_INFO, "OpenLI Mediator: Warning, listening socket did not restart. Will not be able to accept connections from collectors.");
            return -1;
        }
        changed = 1;
    }

    if (currstate->mediatorid != newstate->mediatorid) {
        logger(LOG_INFO,
                "OpenLI Mediator: changing mediator ID from %u to %u",
                currstate->mediatorid, newstate->mediatorid);
        currstate->mediatorid = newstate->mediatorid;
        changed = 1;
    }

    if (!changed) {
        logger(LOG_INFO,
                "OpenLI Mediator: inbound connection listening socket configuration is unchanged.");
    }

    return changed;
}

/** Attempts to connect to the provisioner.
 *
 *  @param state            The global state for this mediator.
 *  @param provfail         Set to 1 if the most recent connection attempt
 *                          failed, 0 otherwise.
 *
 *  @return 1 if the connection attempt fails, 0 otherwise.
 */
static int attempt_provisioner_connect(mediator_state_t *state, int provfail) {

    /* If provfail is 1, this function won't log any failures to connect.
     * This prevents log spam in cases where we repeatedly fail to connect,
     * e.g. because the provisioner is down.
     */
    int s = connect_socket(state->provaddr, state->provport, provfail,
            0);

    provfail = 0;
    if (s == -1) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: Error - Unable to connect to provisioner.");
        }
        setup_provisioner_reconnect_timer(state);
        provfail = 1;
    } else if (s == 0) {
        setup_provisioner_reconnect_timer(state);
        provfail = 1;
    }

    if (!provfail) {
        if (init_provisioner_connection(state, s, state->sslconf.ctx) == -1) {
            /* Something went wrong (probably an SSL error), so clear any
             * initialised state and set a timer to try again soon.
             */
            destroy_net_buffer(state->provisioner.outgoing);
            destroy_net_buffer(state->provisioner.incoming);
            close(s);
            if (state->provisioner.provev) {
                state->provisioner.provev->fd = -1;
            }
            state->provisioner.outgoing = NULL;
            state->provisioner.incoming = NULL;
            setup_provisioner_reconnect_timer(state);
        } else if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI mediator has connected to provisioner at %s:%s",
                    state->provaddr, state->provport);
        }
    }
    return provfail;
}

/** Re-read the mediator configuration file and apply any changes to the
 *  running config.
 *
 *  @param currstate            The pre-reload global state of this mediator
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
static int reload_mediator_config(mediator_state_t *currstate) {

    mediator_state_t newstate;
    int listenchanged = 0;
    int provchanged = 0;
    int tlschanged = 0;

    /* Load the updated config into a spare "global state" instance */
    if (init_med_state(&newstate, currstate->conffile) == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: error reloading config file for mediator.");
        return -1;
    }

    /* Check if the location of the provisioner has changed -- we'll need
     * to reconnect if that is the case.
     */
    if ((provchanged = reload_provisioner_socket_config(currstate,
            &newstate)) < 0) {
        return -1;
    }

    /* Check if we are going to be listening on a different IP or port
     * for collection connections -- if so, we need to close the old
     * listen socket and create a new one.
     */
    if ((listenchanged = reload_listener_socket_config(currstate,
            &newstate)) < 0) {
        return -1;
    }

    /* Check if our TLS configuration has changed. If so, we'll need to
     * drop all connections to other OpenLI components and create them anew.
     */
    tlschanged = reload_ssl_config(&(currstate->sslconf), &(newstate.sslconf));
    if (tlschanged == -1) {
        return -1;
    }

    if (tlschanged != 0 || newstate.etsitls != currstate->etsitls) {
        currstate->etsitls = newstate.etsitls;

        if (!listenchanged) {
            /* Disconnect all collectors */
            drop_all_collectors(currstate, currstate->collectors);
            currstate->collectors = libtrace_list_init(
                    sizeof(mediator_collector_t));

            listenchanged = 1;
        }
        if (!provchanged) {
            drop_provisioner(currstate);
            provchanged = 1;
        }
    }

    if (listenchanged && !provchanged) {
        /* Need to re-announce our listen socket (or mediator ID) details */
        if (send_mediator_listen_details(currstate, 0) < 0) {
            return -1;
        }

    }

    /* newstate was just temporary, so we can tidy it up now */
    clear_med_config(&newstate);
    return 0;

}

/** The main loop of the mediator process.
 *
 *  Continually checks for registered epoll events, e.g. timers expiring,
 *  sockets available for reading or writing, signals being received, then
 *  acts upon on those events that do occur.
 *
 *  Loops until an error occurs or a signal causes the 'mediator_halt' flag
 *  to be set (i.e. SIGTERM or SIGINT).
 *
 *  @param state        The global state for the mediator
 */
static void run(mediator_state_t *state) {

	int i, nfds;
	int timerfd;
	int timerexpired = 0;
	struct epoll_event evs[64];
	struct epoll_event ev;
    int provfail = 0;
    struct timeval tv;
    uint32_t firstflush;

    /* Register the epoll event for received signals */
	ev.data.ptr = state->signalev;
	ev.events = EPOLLIN;

	if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->signalev->fd, &ev)
			== -1) {
		logger(LOG_INFO,
				"OpenLI: Failed to register signal socket: %s.",
				strerror(errno));
		return;
	}

    logger(LOG_INFO,
            "OpenLI Mediator: pcap output file rotation frequency is set to %d minutes.",
            state->pcaprotatefreq);

    gettimeofday(&tv, NULL);
	state->timerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
	state->pcaptimerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));

    /* Set our first pcap file flush timer */
    firstflush = (((tv.tv_sec / 60) * 60) + 60) - tv.tv_sec;
    timerfd = epoll_add_timer(state->epoll_fd, firstflush, state->pcaptimerev);
    if (timerfd == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to create pcap rotation timer");
        return;
    }
    state->pcaptimerev->fd = timerfd;
    state->pcaptimerev->fdtype = MED_EPOLL_PCAP_TIMER;
    state->pcaptimerev->state = NULL;

	while (!mediator_halt) {
        /* If we've had a SIGHUP recently, reload the config file */
        if (reload_config) {
            if (reload_mediator_config(state) == -1) {
                break;
            }
            reload_config = 0;
        }

	    /* Attempt to connect to the provisioner, if we don't already have
         * a connection active */
        if (state->provisioner.provev == NULL &&
                state->provisioner.tryconnect) {
            provfail = attempt_provisioner_connect(state, provfail);
        }

        /* This timer will force us to stop checking epoll and go back
         * to the start of this loop (i.e. checking if we should halt the
         * entire mediator) every second.
         *
         * Otherwise, if we're very busy, we may never respond to a halt
         * request.
         */
        timerfd = epoll_add_timer(state->epoll_fd, 1, state->timerev);
        if (timerfd == -1) {
            logger(LOG_INFO,
                "OpenLI Mediator: Failed to add timer to epoll in mediator.");
            break;
        }
        state->timerev->fd = timerfd;
        state->timerev->fdtype = MED_EPOLL_SIGCHECK_TIMER;
        state->timerev->state = NULL;
        timerexpired = 0;

        /* Simple epoll loop -- check for active fds or expired timers
         * continuously, but break out once per second to allow us to act
         * on any signals.
         */
        while (!timerexpired) {
            nfds = epoll_wait(state->epoll_fd, evs, 64, -1);
            if (nfds < 0) {
                if (errno == EINTR) {
                    continue;
                }
                logger(LOG_INFO,
						"OpenLI: error while waiting for epoll events in mediator: %s.",
                        strerror(errno));
                mediator_halt = true;
                continue;
            }

            for (i = 0; i < nfds; i++) {
                timerexpired = check_epoll_fd(state, &(evs[i]));
                /* timerexpired will be set to 1 if the one second loop
                 * breaking timer fires.
                 */

                if (timerexpired == -1) {
                    /* Something went wrong, may also be a good time to
                     * break out.
                     */
                    break;
                }
            }
        }

        /* Remove the old 1 second timer, but it will get replaced if we
         * go around again.
         */
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, timerfd, &ev) == -1) {
            logger(LOG_INFO,
                "OpenLI Mediator: unable to remove mediator timer from epoll set: %s",
                strerror(errno));
            break;
        }

        close(timerfd);
		state->timerev->fd = -1;
    }

    /* Make sure mediator_halt is set so that any other threads can recognise
     * that it is time to stop (i.e. if we broke out of the main loop due to
     * an error condition rather than a user signal).
     */
    mediator_halt = true;
}

/** Main function for the OpenLI mediator.
 *
 *  Tasks:
 *    - parses user configuration and initialises global state
 *    - starts supporting threads (pcap output thread, listener thread)
 *    - enters main loop via run()
 *    - once loop exits, wait for supporting threads to exit
 *    - free remaining global state
 */
int main(int argc, char *argv[]) {
    char *configfile = NULL;
    sigset_t sigblock;
    int todaemon = 0;
    char *pidfile = NULL;

    mediator_state_t medstate;
    mediator_pcap_msg_t pcapmsg;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "daemonise", 0, 0, 'd'},
            { "pidfile", 1, 0, 'p'},
            { NULL, 0, 0, 0},
        };

        int c = getopt_long(argc, argv, "c:dp:h", long_options, &optind);
        if (c == -1) {
            break;
        }

        switch (c) {
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
                logger(LOG_INFO, "OpenLI Mediator: unsupported option: %c",
                        c);
                usage(argv[0]);
                return 1;
        }
    }

    if (configfile == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: no config file specified. Use -c to specify one.");
        usage(argv[0]);
        return 1;
    }

    if (todaemon) {
        daemonise(argv[0], pidfile);
    }

    sigemptyset(&sigblock);
    sigaddset(&sigblock, SIGHUP);
    sigaddset(&sigblock, SIGTERM);
    sigaddset(&sigblock, SIGINT);
    sigprocmask(SIG_BLOCK, &sigblock, NULL);

    /* Read the config file and set up our global state structure */
    if (init_med_state(&medstate, configfile) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: Error initialising mediator.");
        return 1;
    }

    prepare_mediator_state(&medstate);

    logger(LOG_INFO, "OpenLI Mediator: '%u' has started.", medstate.mediatorid);

    /* A directory for pcap output has been configured, so send that through
     * to the pcap output thread.
     */
    if (medstate.pcapdirectory != NULL) {
        memset(&pcapmsg, 0, sizeof(pcapmsg));
        pcapmsg.msgtype = PCAP_MESSAGE_CHANGE_DIR;
        pcapmsg.msgbody = (uint8_t *)strdup(medstate.pcapdirectory);
        pcapmsg.msglen = strlen(medstate.pcapdirectory);

        libtrace_message_queue_put(&(medstate.pcapqueue), &pcapmsg);
    }

    /* Start the pcap output thread */
    pthread_create(&(medstate.pcapthread), NULL, start_pcap_thread,
            &(medstate.pcapqueue));

    /* Start the thread that listens for connections from collectors */
    if (start_collector_listener(&medstate) == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: could not start collector listener socket.");
        return 1;
    }

    /* Start the main epoll loop - this will return when the mediator is
     * ready to be shut down.
     */
    run(&medstate);

    /* Tell the pcap thread to halt */
    memset(&pcapmsg, 0, sizeof(pcapmsg));
    pcapmsg.msgtype = PCAP_MESSAGE_HALT;
    pcapmsg.msgbody = NULL;
    pcapmsg.msglen = 0;
    libtrace_message_queue_put(&(medstate.pcapqueue), &pcapmsg);

    /* Clean up */
    destroy_med_state(&medstate);
    clear_med_config(&medstate);

    if (todaemon && pidfile) {
        remove_pidfile(pidfile);
    }

    logger(LOG_INFO, "OpenLI Mediator: '%u' has exited.", medstate.mediatorid);
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
