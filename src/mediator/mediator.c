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
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include <amqp.h>

#include "config.h"
#include "configparser.h"
#include "logger.h"
#include "util.h"
#include "agency.h"
#include "netcomms.h"
#include "mediator.h"
#include "etsili_core.h"
#include "openli_tls.h"
#include "handover.h"
#include "med_epoll.h"
#include "pcapthread.h"

#define AMPQ_BYTES_FROM(x) (amqp_bytes_t){.len=sizeof(x),.bytes=&x}

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
    if (state->pcapdirectory) {
        free(state->pcapdirectory);
    }
    if (state->operatorid) {
        free(state->operatorid);
    }
    if (state->RMQ_conf.name) {
        free(state->RMQ_conf.name);
    }
    if (state->RMQ_conf.pass) {
        free(state->RMQ_conf.pass);
    }

    free_ssl_config(&(state->sslconf));
}

/** Frees all global state for a mediator instance.
 *
 *  @param state        The global state for the mediator instance
 */
static void destroy_med_state(mediator_state_t *state) {

    liid_map_t *m;
    PWord_t jval;
    Word_t bytes;

    /* Remove all known LIIDs */
    purge_liid_map(&(state->liidmap));

    /* Clean up the list of "unknown" LIIDs */
    purge_missing_liids(&(state->liidmap));

    /* Tear down the connection to the provisioner */
    free_provisioner(&(state->provisioner));

    destroy_med_collector_state(&(state->collectors));

    /* Delete all of the agencies and shut down any active handovers */
    drop_all_agencies(&(state->handover_state));

    libtrace_list_deinit(state->handover_state.agencies);

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

    /* Halt the epoll loop timer */
	if (state->timerev) {
		if (state->timerev->fd != -1) {
			close(state->timerev->fd);
		}
		free(state->timerev);
	}

    if (state->RMQtimerev) {
        if (state->RMQtimerev->fd != -1) {
            close(state->RMQtimerev->fd);
        }
        free(state->RMQtimerev);
    }

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
    pthread_mutex_lock(state->handover_state.agency_mutex);
    if (state->handover_state.connectthread != -1) {
        pthread_mutex_unlock(state->handover_state.agency_mutex);
        pthread_join(state->handover_state.connectthread, NULL);
    } else {
        pthread_mutex_unlock(state->handover_state.agency_mutex);
    }

    pthread_mutex_destroy(state->handover_state.agency_mutex);
    free(state->handover_state.agency_mutex);
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

    state->RMQ_conf.name = NULL;
    state->RMQ_conf.pass = NULL;
    state->RMQ_conf.hostname = NULL;
    state->RMQ_conf.port = 0;
    state->RMQ_conf.heartbeatFreq = 0;
    state->RMQ_conf.enabled = 0;
    state->RMQ_conf.SSLenabled = 0;

    state->operatorid = NULL;
    state->pcapdirectory = NULL;
    state->pcapthread = -1;
    state->pcaprotatefreq = 30;
    state->listenerev = NULL;
    state->timerev = NULL;
    state->pcaptimerev = NULL;
    state->epoll_fd = -1;

    state->handover_state.epoll_fd = -1;
    state->handover_state.agencies = NULL;
    state->handover_state.halt_flag = 0;
    state->handover_state.agency_mutex = calloc(1, sizeof(pthread_mutex_t));
    state->handover_state.connectthread = -1;
    state->handover_state.next_handover_id = 1;

    pthread_mutex_init(state->handover_state.agency_mutex, NULL);


    state->liidmap.liid_array = NULL;
    state->liidmap.missing_liids = NULL;

    libtrace_message_queue_init(&(state->pcapqueue),
            sizeof(mediator_pcap_msg_t));

    init_provisioner_instance(&(state->provisioner), &(state->sslconf.ctx));
    /* Parse the provided config file */
    if (parse_mediator_config(configfile, state) == -1) {
        return -1;
    }

    if (create_ssl_context(&(state->sslconf)) < 0) {
        return -1;
    }

    init_med_collector_state(&(state->collectors), &(state->etsitls),
            &(state->sslconf), &(state->RMQ_conf), state->mediatorid);

    logger(LOG_DEBUG, "OpenLI Mediator: ETSI TLS encryption %s",
        state->etsitls ? "enabled" : "disabled");

    if (state->mediatorid == 0) {
        logger(LOG_INFO, "OpenLI Mediator: ID is not present in the config file or is set to zero.");
        return -1;
    }

    /* Set some default ports for inter-component connections */
    if (state->listenport == NULL) {
        state->listenport = strdup("61000");
    }

    if (state->provisioner.provport == NULL) {
        state->provisioner.provport = strdup("8993");
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

    state->handover_state.agencies = libtrace_list_init(sizeof(mediator_agency_t));
    state->handover_state.epoll_fd = state->epoll_fd;
    state->provisioner.epoll_fd = state->epoll_fd;
    state->collectors.epoll_fd = state->epoll_fd;
    state->collectors.collectors =
            libtrace_list_init(sizeof(active_collector_t *));
    
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
    state->signalev->epoll_fd = state->epoll_fd;
    state->signalev->state = NULL;

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
    if (halt_mediator_timer(mev) < 0) {
        /* don't care? */
    }

    if (start_mediator_timer(state->pcaptimerev, 60) < 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to create pcap rotation timer");
        return -1;
    }
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

    handover_t *ho = (handover_t *)(mev->state);
    wandder_encoded_result_t *kamsg;
    wandder_etsipshdr_data_t hdrdata;
    char elemstring[16];
    char liidstring[24];

    if (ho->outev == NULL) {
        return 0;
    }

    if (ho->ho_state->pending_ka == NULL &&
            get_buffered_amount(&(ho->ho_state->buf)) == 0) {
        /* Only create a new KA message if we have sent the last one we
         * had queued up.
         * Also only create one if we don't already have data to send. We
         * should only be sending keep alives if the socket is idle.
         */
        if (ho->ho_state->encoder == NULL) {
            ho->ho_state->encoder = init_wandder_encoder();
        } else {
            reset_wandder_encoder(ho->ho_state->encoder);
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

        kamsg = encode_etsi_keepalive(ho->ho_state->encoder, &hdrdata,
                ho->ho_state->lastkaseq + 1);
        if (kamsg == NULL) {
            logger(LOG_INFO,
                    "OpenLI Mediator: failed to construct a keep-alive.");
            return -1;
        }

        ho->ho_state->pending_ka = kamsg;
        ho->ho_state->lastkaseq += 1;

        /* Enable the output event for the handover, so that epoll will
         * trigger a writable event when we are able to send this message. */
        if (enable_handover_writing(ho) < 0) {
            return -1;
        }
    }

    /* Reset the keep alive timer */
    return restart_handover_keepalive(ho);
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
    state->listenerev = create_mediator_fdevent(state->epoll_fd,
            NULL, MED_EPOLL_COLL_CONN, sockfd, EPOLLIN);

    if (state->listenerev == NULL) {
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

    withdraw_agency(&(state->handover_state), lea.agencyid);
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

    return enable_agency(&(state->handover_state), &lea);
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
static liid_map_entry_t *match_etsi_to_agency(mediator_state_t *state,
        uint8_t *etsimsg, uint16_t msglen, uint16_t *liidlen) {

    unsigned char liidstr[65536];
    liid_map_entry_t *found = NULL;

    /* Figure out the LIID for this ETSI record */
    extract_liid_from_exported_msg(etsimsg, msglen, liidstr, 65536, liidlen);

    /* Is this an LIID that we have a suitable agency mapping for? */
    found = lookup_liid_agency_mapping(&(state->liidmap), liidstr);
    if (!found) {
        if (add_missing_liid(&(state->liidmap), liidstr) < 0) {
            exit(-2);
        }
        return NULL;
    }

    return found;
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

    if (append_etsipdu_to_buffer(&(ho->ho_state->buf), etsimsg,
            (uint32_t)msglen, 0) == 0) {

        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: was unable to enqueue ETSI PDU for handover %s:%s HI%d",
                ho->ipstr, ho->portstr, ho->handover_type);
        }
        return -1;
    }

    /* Got something to send, so make sure we are enable EPOLLOUT */
    if (enable_handover_writing(ho) < 0) {
        return -1;
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
    liid_map_entry_t *m;
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
    m = lookup_liid_agency_mapping(&(state->liidmap), liid);
    if (m == NULL) {
        /* If not, ceasing is pretty straightforward */
        free(liid);
        return 0;
    }

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
            "OpenLI Mediator: scheduling removal of agency mapping for LIID %s.",
            m->liid);

    m->ceasetimer = create_mediator_timer(state->epoll_fd, (void *)m,
            MED_EPOLL_CEASE_LIID_TIMER, 15);

    if (m->ceasetimer == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: warning -- cease timer was not able to be set for LIID %s: %s", liid, strerror(errno));
    }

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

    liid_map_entry_t *m = (liid_map_entry_t *)(mev->state);

    remove_liid_agency_mapping(&(state->liidmap), m->liid);

    /* Make sure that the timer event is removed from epoll */
    halt_mediator_timer(mev);
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
        agency = lookup_agency(&(state->handover_state), agencyid);

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
    free(agencyid);

    if (add_liid_agency_mapping(&(state->liidmap), liid, agency) < 0) {
        return -1;
    }

    return 0;
}

/** React to a handover's failure to respond to a keep alive before the
 *  response timer expired.
 *
 *  @param mev              The epoll event for the keep alive response timer
 *
 *  @return 0 always.
 */
static int trigger_ka_failure(med_epoll_ev_t *mev) {
    handover_t *ho = (handover_t *)(mev->state);

    if (ho->disconnect_msg == 0) {
        logger(LOG_INFO, "OpenLI Mediator: failed to receive KA response from LEA on handover %s:%s HI%d, dropping connection.",
                ho->ipstr, ho->portstr, ho->handover_type);
    }

    disconnect_handover(ho);
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
    liid_map_entry_t *thisint;
    single_coll_state_t *cs = (single_coll_state_t *)(mev->state);
    openli_proto_msgtype_t msgtype;
    mediator_pcap_msg_t pcapmsg;
    uint16_t liidlen;

    do {
        if (mev->fdtype == MED_EPOLL_COL_RMQ) {
            msgtype = receive_RMQ_buffer(cs->incoming_rmq, cs->amqp_state,
                    &msgbody, &msglen, &internalid);
        } else {
            msgtype = receive_net_buffer(cs->incoming, &msgbody,
                        &msglen, &internalid);
        }

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
            case OPENLI_PROTO_HEARTBEAT:
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
                    reenable_collector_logging(&(state->collectors), cs);
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
                    reenable_collector_logging(&(state->collectors), cs);
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
                    reenable_collector_logging(&(state->collectors), cs);
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
        case MED_EPOLL_RMQCHECK_TIMER:
            halt_mediator_timer(mev);
            service_RMQ_connections(&(state->collectors));
            if (start_mediator_timer(state->RMQtimerev,
                    state->RMQ_conf.heartbeatFreq) < 0) {
                logger(LOG_INFO, "OpenLI Mediator: unable to reset RMQ heartbeat timer: %s", strerror(errno));
                return -1;
            }
            return 1;
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
            ret = mediator_accept_collector(&(state->collectors),
                    state->listenerev->fd);
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
            ret = trigger_ka_failure(mev);
            break;
        case MED_EPOLL_PROVRECONNECT:
            /* we're due to try reconnecting to a lost provisioner */
            assert(ev->events == EPOLLIN);
            halt_mediator_timer(mev);
            state->provisioner.tryconnect = 1;
            break;

        case MED_EPOLL_LEA:
            /* the handover is available for writing or reading */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                /* message from LEA -- hopefully a keep-alive response */
                ret = receive_handover(mev);
            } else if (ev->events & EPOLLOUT) {
                /* handover is able to send buffered records */
                ret = xmit_handover(mev);
            } else {
                ret = -1;
            }
            if (ret == -1) {
                handover_t *ho = (handover_t *)(mev->state);
                disconnect_handover(ho);
            }
            break;

        case MED_EPOLL_PROVISIONER:
            /* the provisioner socket is available for reading or writing */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLOUT) {
                /* we can send a pending message to the provisioner */
                ret = transmit_provisioner(&(state->provisioner), mev);
            } else if (ev->events & EPOLLIN) {
                /* provisioner has sent us an instruction */
                ret = receive_provisioner(state, mev);
                if (ret == 0 && state->provisioner.disable_log == 1) {
                    logger(LOG_INFO,
                            "OpenLI Mediator: Connected to provisioner at %s:%s",
                            state->provisioner.provaddr,
                            state->provisioner.provport);
                    state->provisioner.disable_log = 0;
                }
            } else {
                ret = -1;
            }

            if (ret == -1) {
                disconnect_provisioner(&(state->provisioner), 1);
            }
            break;
        case MED_EPOLL_COLLECTOR_HANDSHAKE:
            /* socket with an incomplete SSL handshake is available */
            ret = continue_collector_handshake(&(state->collectors), mev);
            if (ret == -1) {
                drop_collector(&(state->collectors), mev, 1);
            }
            break;
        case MED_EPOLL_COLLECTOR:
        case MED_EPOLL_COL_RMQ:
            /* a collector is sending us some data */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                ret = receive_collector(state, mev);
            }
            if (ret == -1) {
                drop_collector(&(state->collectors), mev, 1);
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
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(struct sockaddr_storage);
    char listenname[NI_MAXHOST];
    int ret;

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

    return send_mediator_details_to_provisioner(&(state->provisioner),
            &meddeets, justcreated);
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
    purge_liid_map(&(currstate->liidmap));

    disconnect_provisioner(&(currstate->provisioner), 1);

    /* Dump all known agencies -- we'll get new ones when we get a usable
     * provisioner again */
    drop_all_agencies(&(currstate->handover_state));

}

/** Closes the socket that is listening for collector connections and
 *  drops any collectors that are connected through it.
 *
 *  @param currstate            The global state for the mediator
 */
static inline void halt_listening_socket(mediator_state_t *currstate) {
    struct epoll_event ev;

    /* Disconnect all collectors */
    drop_all_collectors(&(currstate->collectors));
    currstate->collectors.collectors = libtrace_list_init(
            sizeof(active_collector_t *));


    /* Close listen socket and disable epoll event */
    remove_mediator_fdevent(currstate->listenerev);
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
    if ((provchanged = reload_provisioner_socket_config(
            &(currstate->provisioner), &(newstate.provisioner))) < 0) {
        return -1;
    }

    if (provchanged) {
        /* The provisioner is supposedly listening on a different IP and/or
         * port to before, so we should definitely not be talking to
         * whoever is on the old IP+port.
         */

        drop_provisioner(currstate);
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
            drop_all_collectors(&(currstate->collectors));
            currstate->collectors.collectors = libtrace_list_init(
                    sizeof(active_collector_t *));

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
    med_epoll_ev_t *signalev;

    /* Register the epoll event for received signals */
    signalev = create_mediator_fdevent(state->epoll_fd, NULL,
            MED_EPOLL_SIGNAL, state->signalev->fd, EPOLLIN);

    logger(LOG_INFO,
            "OpenLI Mediator: pcap output file rotation frequency is set to %d minutes.",
            state->pcaprotatefreq);

    gettimeofday(&tv, NULL);

    /* Set our first pcap file flush timer */
    firstflush = (((tv.tv_sec / 60) * 60) + 60) - tv.tv_sec;

    state->pcaptimerev = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_PCAP_TIMER, firstflush);

    if (state->pcaptimerev == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to create pcap rotation timer");
    }

    state->timerev = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_SIGCHECK_TIMER, 0);

    if (state->timerev == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: failed to create main loop timer");
        goto runfailure;
    }

    state->RMQtimerev = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_RMQCHECK_TIMER, state->RMQ_conf.heartbeatFreq);

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
        provfail = attempt_provisioner_connect(&(state->provisioner), provfail);

        if (!provfail) {
            if (send_mediator_listen_details(state, 1) < 0) {
                disconnect_provisioner(&(state->provisioner), 1);
                continue;
            }
        }
        /* This timer will force us to stop checking epoll and go back
         * to the start of this loop (i.e. checking if we should halt the
         * entire mediator) every second.
         *
         * Otherwise, if we're very busy, we may never respond to a halt
         * request.
         */
        if (start_mediator_timer(state->timerev, 1) < 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: Failed to add timer to epoll in mediator.");
            break;
        }
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
        halt_mediator_timer(state->timerev);
    }

runfailure:
    /* Make sure mediator_halt is set so that any other threads can recognise
     * that it is time to stop (i.e. if we broke out of the main loop due to
     * an error condition rather than a user signal).
     */
    mediator_halt = true;

    /* Tell our agency connection thread to stop when it can */
    pthread_mutex_lock(state->handover_state.agency_mutex);
    state->handover_state.halt_flag = 1;
    pthread_mutex_unlock(state->handover_state.agency_mutex);

    if (signalev) {
        remove_mediator_fdevent(signalev);
    }
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
