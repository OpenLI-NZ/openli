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
#include <rabbitmq-c/tcp_socket.h>
#include <rabbitmq-c/ssl_socket.h>
#include <rabbitmq-c/amqp.h>

#include "config.h"
#include "configparser_mediator.h"
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
#include "coll_recv_thread.h"
#include "lea_send_thread.h"

/** This file implements the "main" thread for an OpenLI mediator.
 */

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
    (void)signal;
    mediator_halt = 1;
}

/** Signal handler for SIGHUP */
static void reload_signal(int signal) {
    (void)signal;
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
    if (state->pcaptemplate) {
        free(state->pcaptemplate);
    }
    if (state->operatorid) {
        free(state->operatorid);
    }
    if (state->shortoperatorid) {
        free(state->shortoperatorid);
    }
    if (state->RMQ_conf.name) {
        free(state->RMQ_conf.name);
    }
    if (state->RMQ_conf.pass) {
        free(state->RMQ_conf.pass);
    }
    if (state->RMQ_conf.internalpass) {
        free(state->RMQ_conf.internalpass);
    }

    free_ssl_config(&(state->sslconf));

}

/** Frees all global state for a mediator instance.
 *
 *  @param state        The global state for the mediator instance
 */
static void destroy_med_state(mediator_state_t *state) {
    agency_digest_config_t *ag, *tmp;

    /* Tear down the connection to the provisioner */
    free_provisioner(&(state->provisioner));

    destroy_med_collector_config(&(state->collector_threads.config));
    destroy_med_agency_config(&(state->agency_threads.config));

    HASH_ITER(hh, state->saved_agencies, ag, tmp) {
        HASH_DELETE(hh, state->saved_agencies, ag);
        if (ag->agencyid) {
            free(ag->agencyid);
        }
        free_liagency(ag->config);
        free(ag);
    }

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

	if (state->col_clean_timerev) {
		if (state->col_clean_timerev->fd != -1) {
			close(state->col_clean_timerev->fd);
		}
		free(state->col_clean_timerev);
	}

}

/** Reads the configuration for a mediator instance and sets the relevant
 *  members of the global state structure accordingly.
 *
 *  @param state        The global state to be initialised with configuration
 *  @param configfile   The path to the configuration file
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
static int init_mediator_config(mediator_state_t *state,
        char *configfile) {

    state->conffile = configfile;
    state->mediatorid = 0;
    state->listenaddr = NULL;
    state->listenport = NULL;
    state->etsitls = 1;

    state->sslconf.certfile = NULL;
    state->sslconf.keyfile = NULL;
    state->sslconf.cacertfile = NULL;
    state->sslconf.logkeyfile = NULL;
    state->sslconf.ctx = NULL;

    state->RMQ_conf.name = NULL;
    state->RMQ_conf.pass = NULL;
    state->RMQ_conf.internalpass = NULL;
    state->RMQ_conf.hostname = NULL;
    state->RMQ_conf.port = 0;
    state->RMQ_conf.heartbeatFreq = 0;
    state->RMQ_conf.enabled = 0;
    state->RMQ_conf.SSLenabled = 0;

    state->operatorid = NULL;
    state->shortoperatorid = NULL;
    state->pcapdirectory = NULL;
    state->pcaptemplate = NULL;
    state->pcapcompress = 1;
    state->pcaprotatefreq = 30;

    /* Parse the provided config file */
    if (parse_mediator_config(configfile, state) == -1) {
        return -1;
    }

    if (state->RMQ_conf.internalpass == NULL) {
        /* First, try to read a password from /etc/openli/rmqinternalpass */
        FILE *f = fopen("/etc/openli/rmqinternalpass", "r");
        char line[2048];
        if (f != NULL) {
            if (fgets(line, 2048, f) != NULL) {
                if (line[strlen(line) - 1] == '\n') {
                    line[strlen(line) - 1] = '\0';
                }
                state->RMQ_conf.internalpass = strdup(line);
            }
        }
        /* If we can't do that, throw an error */
        if (state->RMQ_conf.internalpass == NULL) {
            logger(LOG_ERR, "OpenLI mediator: unable to determine password for internal RMQ vhost -- mediator must exit");
            return -1;
        }
    }

    if (state->shortoperatorid == NULL) {
        if (state->operatorid != NULL) {
            state->shortoperatorid = strndup(state->operatorid, 5);
        } else {
            state->shortoperatorid = strdup("?????");
        }
    }

    if (state->operatorid == NULL) {
        state->operatorid = strdup("unspecified");
    }
    return 0;
}

/** Initialises the global state for a mediator instance.
 *
 *  This includes parsing the provided configuration file and setting
 *  the corresponding fields in the global state structure.
 *
 *  @param state        The global state to be initialised
 *  @param configfile   The path to the configuration file
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
static int init_med_state(mediator_state_t *state, char *configfile) {
    state->listenerev = NULL;
    state->timerev = NULL;
    state->col_clean_timerev = NULL;
    state->epoll_fd = -1;
    state->saved_agencies = NULL;

    init_provisioner_instance(&(state->provisioner), &(state->sslconf.ctx));
    if (init_mediator_config(state, configfile) < 0) {
        return -1;
    }

    if (create_ssl_context(&(state->sslconf)) < 0) {
        return -1;
    }
    /* Initialise state and config for the LEA send threads */
    state->agency_threads.threads = NULL;
    state->agency_threads.next_handover_id = 0;
    init_med_agency_config(&(state->agency_threads.config),
            &(state->RMQ_conf), state->mediatorid, state->operatorid,
            state->shortoperatorid,
            state->pcapdirectory, state->pcaptemplate, state->pcapcompress,
            state->pcaprotatefreq);

    /* Initialise state and config for the collector receive threads */
    state->collector_threads.threads = NULL;
    init_med_collector_config(&(state->collector_threads.config),
            state->etsitls,
            &(state->sslconf), &(state->RMQ_conf), state->mediatorid,
            state->operatorid);

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

    state->provisioner.epoll_fd = state->epoll_fd;

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

/** Updates the shared configuration for the LEA send threads and tells those
 *  threads to update their own local copies of this configuration.
 *
 *  @param state            The global state for this mediator
 */
static void update_lea_thread_config(mediator_state_t *state) {
    lea_thread_state_t *lea_t, *tmp;

    lea_thread_msg_t msg;

    update_med_agency_config(&(state->agency_threads.config),
            state->mediatorid, state->operatorid,
            state->shortoperatorid,
            state->pcapdirectory, state->pcaptemplate, state->pcapcompress,
            state->pcaprotatefreq);

    /* Send the "reload your config" message to every LEA thread */
    memset(&msg, 0, sizeof(msg));

    HASH_ITER(hh, state->agency_threads.threads, lea_t, tmp) {
        msg.type = MED_LEA_MESSAGE_RELOAD_CONFIG;
        msg.data = NULL;
        libtrace_message_queue_put(&(lea_t->in_main), &msg);
    }

}

static void update_coll_recv_thread_config(mediator_state_t *state) {
    coll_recv_t *col_t, *tmp;
    col_thread_msg_t msg;

    update_med_collector_config(&(state->collector_threads.config),
                state->etsitls, state->mediatorid, state->operatorid);

    /* Send the "reload your config" message to every collector thread */
    memset(&msg, 0, sizeof(msg));

    HASH_ITER(hh, state->collector_threads.threads, col_t, tmp) {
        msg.type = MED_COLL_MESSAGE_RELOAD;
        libtrace_message_queue_put(&(col_t->in_main), &msg);
    }
}


/** Tells every LEA send thread to start a shutdown timer.
 *
 *  This method should be called whenever we lose our connection to the
 *  provisioner.
 *
 *  @param state        The global state for this mediator
 *  @param timeout      The number of seconds to set the shutdown timer for
 */
static void trigger_lea_thread_shutdown_timers(mediator_state_t *state,
        uint16_t timeout) {

    lea_thread_state_t *lea_t, *tmp;
    lea_thread_msg_t msg;

    memset(&msg, 0, sizeof(msg));

    HASH_ITER(hh, state->agency_threads.threads, lea_t, tmp) {
        msg.type = MED_LEA_MESSAGE_SHUTDOWN_TIMER;
        msg.data_uint = timeout;

        libtrace_message_queue_put(&(lea_t->in_main), &msg);
    }

}

/** Disconnects a provisioner socket and releases local state for that
 *  connection.
 *
 *  @param currstate            The global state for this mediator.
 */
static inline void drop_provisioner(mediator_state_t *currstate) {

    disconnect_provisioner(&(currstate->provisioner), 1);

    /* Shutdown all handovers if we haven't heard from the provisioner
     * again within the next 30 minutes.
     */
    trigger_lea_thread_shutdown_timers(currstate, 1800);

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
    int sockfd;

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
static int process_signal(int sigfd) {

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

/** Sends a message to all collector receive threads to tell them that
 *  a particular agency is no longer active.
 *
 *  @param state        The global state for this mediator
 *  @param agencyid     The ID of the agency being withdrawn
 *
 *  @return 0 if successful, -1 if an error occurs
 */
static int withdraw_lea_from_collector_threads(mediator_state_t *state,
        char *agencyid) {

    coll_recv_t *col_thread, *tmp;
    col_thread_msg_t msg;
    char *copy;

    HASH_ITER(hh, state->collector_threads.threads, col_thread, tmp) {
        while (col_thread) {
            copy = strdup(agencyid);
            if (!copy) {
                return -1;
            }
            memset(&msg, 0, sizeof(msg));
            msg.type = MED_COLL_LEA_WITHDRAW;
            msg.arg = (uint64_t)copy;
            libtrace_message_queue_put(&(col_thread->in_main), &msg);
            col_thread = col_thread->next;
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

    liagency_t *lea = calloc(1, sizeof(liagency_t));

    /* Call into netcomms.c to decode the message properly */
    if (decode_lea_withdrawal(msgbody, msglen, lea) == -1) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO, "OpenLI Mediator: received invalid LEA withdrawal from provisioner.");
        }
        free_liagency(lea);
        return -1;
    }

    if (state->provisioner.disable_log == 0) {
        logger(LOG_INFO, "OpenLI Mediator: received LEA withdrawal for %s.",
                lea->agencyid);
    }

    /* Tell the collector threads to not worry about digest calculations
     * for this agency any more */
    withdraw_lea_from_collector_threads(state, lea->agencyid);
    remove_liid_mapping_by_agency_collector_config(
            &(state->collector_threads.config), lea->agencyid);

    mediator_halt_agency_thread(&(state->agency_threads), lea->agencyid);
    free_liagency(lea);
    return 0;
}


/** Sends a message to a single collector receive thread to tell them about a
 *  new or updated agency
 *
 *  @param col_thread   The collector receive thread to send the message to
 *  @param lea          The current configuration for the agency being announced
 *
 *  @return 0 if successful, -1 if an error occurs
 */
static inline int announce_lea_to_single_collector_thread(
        coll_recv_t *col_thread, liagency_t *lea) {

    liagency_t *copy;
    col_thread_msg_t msg;

    copy = copy_liagency(lea);
    if (!copy) {
        return -1;
    }
    memset(&msg, 0, sizeof(msg));
    msg.type = MED_COLL_LEA_ANNOUNCE;
    msg.arg = (uint64_t)copy;
    libtrace_message_queue_put(&(col_thread->in_main), &msg);
    return 0;
}

/** Sends a message to all collector receive threads to tell them about a
 *  new or updated agency
 *
 *  @param state        The global state for this mediator
 *  @param lea          The current configuration for the agency being announced
 *
 *  @return 0 if successful, -1 if an error occurs
 */
static int announce_lea_to_collector_threads(mediator_state_t *state,
        liagency_t *lea) {

    coll_recv_t *col_thread, *tmp;
    agency_digest_config_t *agd;
    liagency_t *copy;

    HASH_ITER(hh, state->collector_threads.threads, col_thread, tmp) {
        while (col_thread) {
            if (announce_lea_to_single_collector_thread(col_thread, lea) < 0) {
                return -1;
            }
            col_thread = col_thread->next;
        }
    }

    copy = copy_liagency(lea);
    HASH_FIND(hh, state->saved_agencies, lea->agencyid, strlen(lea->agencyid),
            agd);
    if (!agd) {
        agd = calloc(1, sizeof(agency_digest_config_t));
        agd->agencyid = strdup(lea->agencyid);
        agd->config = copy;
        agd->disabled = 0;
        HASH_ADD_KEYPTR(hh, state->saved_agencies, agd->agencyid,
                strlen(agd->agencyid), agd);
    } else {
        if (agd->config) {
            free_liagency(agd->config);
        }
        agd->config = copy;
    }
    return 0;
}

static int announce_all_leas_to_collector_thread(mediator_state_t *state,
        char *collectorid) {

    /* Because we can have multiple threads per "collectorid" (because of
     * a collector having multiple forwarding threads which each result
     * in a separate thread on the mediator side), we will end up having
     * to announce all LEAs to all receive threads associated with this
     * "collectorid". This means there is going to be a bit of duplication
     * of announcements to some receive threads, but it's not enough of an
     * issue to be worth the hassle of trying to avoid the duplication in
     * the first place.
     */

    agency_digest_config_t *lea, *tmp;
    coll_recv_t *col;

    HASH_FIND(hh, state->collector_threads.threads, collectorid,
            strlen(collectorid), col);
    if (!col) {
        /* weird, but ok */
        return 0;
    }

    while (col) {
        HASH_ITER(hh, state->saved_agencies, lea, tmp) {
            if (announce_lea_to_single_collector_thread(col, lea->config) < 0) {
                return -1;
            }
        }
        col = col->next;
    }

    return 1;
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

    liagency_t *lea = calloc(1, sizeof(liagency_t));
    lea_thread_state_t *existing = NULL;
    int ret = 0;

    /* Call into netcomms.c to decode the message */
    if (decode_lea_announcement(msgbody, msglen, lea) == -1) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: received invalid LEA announcement from provisioner.");
        }
        free_liagency(lea);
        return -1;
    }

    if (state->provisioner.disable_log == 0) {
        logger(LOG_INFO, "OpenLI Mediator: received LEA announcement for %s.",
                lea->agencyid);
        logger(LOG_INFO, "OpenLI Mediator: HI2 = %s:%s    HI3 = %s:%s",
                lea->hi2_ipstr, lea->hi2_portstr, lea->hi3_ipstr,
                lea->hi3_portstr);
        logger(LOG_INFO, "OpenLI Mediator: integrity checks: %s",
                lea->digest_required ? "enabled" : "disabled");
    }

    HASH_FIND(hh, state->agency_threads.threads, lea->agencyid,
            strlen(lea->agencyid), existing);
    if (!existing) {
        ret = mediator_start_agency_thread(&(state->agency_threads), lea);

        /* tell coll threads about this new agency */
        announce_lea_to_collector_threads(state, lea);

    } else {
        ret = mediator_update_agency_thread(existing, lea);
        /* Don't free lea -- it will get sent to the LEA thread */

        /* tell coll threads about this modified agency */
        announce_lea_to_collector_threads(state, lea);
    }

    return ret;
}

/** Parse and action an instruction from a provisioner to publish an HI1
 *  notification to an agency.
 *
 *  @param state            The global state for this mediator
 *  @param msgbody          Pointer to the start of the cease message body
 *  @param msglen           The size of the cease message, in bytes.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_hi1_notification(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    hi1_notify_data_t *ndata = calloc(1, sizeof(hi1_notify_data_t));
    lea_thread_msg_t msg;
    lea_thread_state_t *lea_t;

    char *nottype_strings[] = {
        "INVALID", "Activated", "Deactivated", "Modified", "ALARM"
    };

    /** See netcomms.c for this method */
    if (decode_hi1_notification(msgbody, msglen, ndata) == -1) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: received invalid HI1 notification from provisioner.");
        }
        goto freehi1;
    }

    if (ndata->notify_type < 0 || ndata->notify_type > HI1_ALARM) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: invalid HI1 notification type %u received from provisioner.", ndata->notify_type);
        }
        goto freehi1;
    }

    /* Forward the notification on to the appropriate LEA thread, which will
     * encode the notification and forward it to the agency via HI2
     */
    HASH_FIND(hh, state->agency_threads.threads, ndata->agencyid,
            strlen(ndata->agencyid), lea_t);
    if (lea_t == NULL) {
        if (state->provisioner.disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: received \"%s\" HI1 Notification from provisioner for LIID %s, but target agency '%s' is not recognisable?",
                    nottype_strings[ndata->notify_type], ndata->liid,
                    ndata->agencyid);
        }
        goto freehi1;
    }

    if (state->provisioner.disable_log == 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: received \"%s\" HI1 Notification from provisioner for LIID %s (target agency = %s)",
                nottype_strings[ndata->notify_type], ndata->liid,
                ndata->agencyid);
    }

    memset(&msg, 0, sizeof(msg));
    msg.type = MED_LEA_MESSAGE_SEND_HI1_NOTIFICATION;
    msg.data = (void *)ndata;
    libtrace_message_queue_put(&(lea_t->in_main), &msg);

    return 0;

freehi1:
    if (ndata->agencyid) {
        free(ndata->agencyid);
    }
    if (ndata->liid) {
        free(ndata->liid);
    }
    if (ndata->authcc) {
        free(ndata->authcc);
    }
    if (ndata->delivcc) {
        free(ndata->delivcc);
    }
    free(ndata);
    return -1;
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
    lea_thread_msg_t msg;
    lea_thread_state_t *lea_t, *tmp;
    col_thread_msg_t cmsg;
    coll_recv_t *col_t, *ctmp;

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

    /* Send the remove message to all LEA threads -- this shouldn't be a
     * huge workload for the LEA threads to deal with.
     *
     * Note: this will include the pcap output thread.
     */
    memset(&msg, 0, sizeof(msg));
    HASH_ITER(hh, state->agency_threads.threads, lea_t, tmp) {
        msg.type = MED_LEA_MESSAGE_REMOVE_LIID;
        msg.data = strdup(liid);

        libtrace_message_queue_put(&(lea_t->in_main), &msg);
    }

    memset(&cmsg, 0, sizeof(cmsg));
    HASH_ITER(hh, state->collector_threads.threads, col_t, ctmp) {
        cmsg.type = MED_COLL_LIID_WITHDRAW;
        cmsg.arg = (uint64_t)strdup(liid);
        libtrace_message_queue_put(&(col_t->in_main), &cmsg);
    }

    remove_liid_mapping_collector_config(&(state->collector_threads.config),
            liid);

    free(liid);
    return 0;
}

/**  new LIID->agency mapping received from the
 *  provisioner.
 *
 *  @param state            The global state for this mediator
 *  @param msgbody          Pointer to the start of the LIID mapping message
 *                          body
 *  @param msglen           Length of the LIID mapping message, in bytes.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_ics_signature(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    int ret = -1;
    coll_recv_t *col = NULL;
    struct ics_sign_response_message *resp;
    col_thread_msg_t msg;

    resp = calloc(1, sizeof(struct ics_sign_response_message));

    if (decode_ics_signing_response(msgbody, msglen, resp) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: receive invalid integrity check signature from provisioner.");
        goto tidyup_err;
    }

    if (!resp->requestedby) {
        logger(LOG_INFO, "OpenLI Mediator: received integrity check signature from provisioner without a 'requestedby'.");
        goto tidyup_err;
    }

    /* Find the collector receive thread that requested this signature */
    HASH_FIND(hh, state->collector_threads.threads, resp->requestedby,
            strlen(resp->requestedby), col);
    if (col == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: integrity check signature was supposedly requested by '%s' but we don't recognise it?", resp->requestedby);
        // not a fatal error, maybe the collector has disappeared since the
        // request was made?
        ret = 0;
        goto tidyup_err;
    }

    memset(&msg, 0, sizeof(msg));
    msg.type = MED_COLL_INTEGRITY_SIGN_RESULT;
    msg.arg = (uint64_t)resp;

    libtrace_message_queue_put(&(col->in_main), &msg);

    return 0;

tidyup_err:
    if (resp) {
        if (resp->requestedby) {
            free(resp->requestedby);
        }
        if (resp->signature) {
            free(resp->signature);
        }
        if (resp->ics_key) {
            free(resp->ics_key);
        }
        free(resp);
    }
    return ret;
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

    char *agencyid = NULL, *liid = NULL, *encryptkey = NULL;
    int found = 0, ret = 0;
    lea_thread_msg_t msg;
    lea_thread_state_t *target;
    added_liid_t *added;
    lea_thread_state_t *tmp;
    payload_encryption_method_t encmethod;

    agencyid = NULL;
    liid = NULL;

    /* See netcomms.c for this method */
    if (decode_liid_mapping(msgbody, msglen, &agencyid, &liid, &encryptkey,
            &encmethod) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: receive invalid LIID mapping from provisioner.");
        ret = -1;
        goto tidyup;
    }

    if (agencyid == NULL || liid == NULL) {
        ret = -1;
        goto tidyup;
    }

    /*
     * Include agencyid and LIID in msg.data and send msg to ALL LEA
     * threads.
     *
     * LEA threads who have the LIID in their active LIID map but do
     * NOT match the agencyid in the message must immediately deregister
     * any RMQs for the LIID and remove it from their map. This ensures
     * that any LIID that changes agencies is properly transitioned
     * (although this should ideally never happen).
     *
     * The LEA thread that does match the agencyid obviously adds the
     * mapping as per usual.
     */
    found = 0;

    HASH_ITER(hh, state->agency_threads.threads, target, tmp) {
        if (strcmp(target->agencyid, agencyid) == 0) {
            found = 1;
        }

        added = calloc(1, sizeof(added_liid_t));
        added->liid = strdup(liid);
        added->agencyid = strdup(agencyid);
        added->encryptkey = NULL;       // not required in LEA threads
        added->encrypt = encmethod;

        memset(&msg, 0, sizeof(msg));
        msg.type = MED_LEA_MESSAGE_ADD_LIID;
        msg.data = (void *)added;

        libtrace_message_queue_put(&(target->in_main), &msg);
    }

    if (found == 0) {
        logger(LOG_INFO, "OpenLI Mediator: agency %s is not recognised by the mediator, yet LIID %s is intended for it?",
                agencyid, liid);
        ret = -1;
        goto tidyup;
    }

    add_liid_mapping_collector_config(&(state->collector_threads.config),
            liid, agencyid, encmethod, encryptkey);

tidyup:
    if (encryptkey) {
        free(encryptkey);
    }

    if (liid) {
        free(liid);
    }
    if (agencyid) {
        free(agencyid);
    }
    return ret;
}

/** Receives and actions one or more messages received from the provisioner.
 *
 *  @param state            The global state for this mediator
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int receive_provisioner(mediator_state_t *state) {

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
            case OPENLI_PROTO_SSL_REQUIRED:
                if (state->provisioner.disable_log == 0) {
                    logger(LOG_INFO,
                            "OpenLI Mediator: provisioner requires the mediator to use TLS encryption, disconnecting.");
                }
                mediator_halt = true;
                return -1;
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
            case OPENLI_PROTO_HI1_NOTIFICATION:
                if (receive_hi1_notification(state, msgbody, msglen) == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_INTEGRITY_SIGNATURE_RESPONSE:
                if (receive_ics_signature(state, msgbody, msglen) == -1) {
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
    char colname[INET6_ADDRSTRLEN];

	switch(mev->fdtype) {
		case MED_EPOLL_SIGCHECK_TIMER:
            /* Time to stop epolling and do some housekeeping */
			if (ev->events & EPOLLIN) {
				return 1;
			}
			logger(LOG_INFO,
                    "OpenLI Mediator: main epoll timer has failed.");
            return -1;
        case MED_EPOLL_CLEAN_DEAD_COLRECV:
            assert(ev->events == EPOLLIN);
            halt_mediator_timer(mev);
            mediator_clean_collectors(&(state->collector_threads));
            ret = start_mediator_timer(state->col_clean_timerev, 30);
            break;
        case MED_EPOLL_SIGNAL:
            /* we got a signal that needs to be handled */
            ret = process_signal(mev->fd);
            break;
        case MED_EPOLL_COLL_CONN:
            /* a connection is occuring on our listening socket */
            ret = mediator_accept_collector_connection(
                    &(state->collector_threads), state->listenerev->fd,
                    colname, INET6_ADDRSTRLEN);
            if (ret > 0) {
                ret = announce_all_leas_to_collector_thread(state, colname);
            }
            break;
        case MED_EPOLL_CEASE_LIID_TIMER:
            /* an LIID->agency mapping can now be safely removed */
            assert(ev->events == EPOLLIN);
            //ret = remove_mediator_liid_mapping(state, mev);
            break;
        case MED_EPOLL_PROVRECONNECT:
            /* we're due to try reconnecting to a lost provisioner */
            assert(ev->events == EPOLLIN);
            halt_mediator_timer(mev);
            state->provisioner.tryconnect = 1;
            break;

        case MED_EPOLL_PROVISIONER:
            /* the provisioner socket is available for reading or writing */
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLOUT) {
                /* we can send a pending message to the provisioner */
                ret = transmit_provisioner(&(state->provisioner));
            } else if (ev->events & EPOLLIN) {
                /* provisioner has sent us an instruction */
                ret = receive_provisioner(state);
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
                drop_provisioner(state);
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

/** Closes the socket that is listening for collector connections and
 *  drops any collectors that are connected through it.
 *
 *  @param currstate            The global state for the mediator
 */
static inline void halt_listening_socket(mediator_state_t *currstate) {

    /* Disconnect all collectors */
    mediator_disconnect_all_collectors(&(currstate->collector_threads));

    /* Close listen socket and disable epoll event */
    remove_mediator_fdevent(currstate->listenerev);
    currstate->listenerev = NULL;
}

/** Updates the global state with any modified values for any of the
 *  config options that are related to pcap file output.
 *
 *  @param currstate            The current global state for the mediator
 *  @param newstate             The state as derived from a recent re-read of
 *                              the config file.
 *
 *  @return 0 if no pcap config has unchanged, 1 if at least one option has
 *          changed value.
 */
static int reload_pcap_config(mediator_state_t *currstate,
        mediator_state_t *newstate) {

    int changed = 0;
    char *tmp;

    if (newstate->pcapdirectory == NULL && currstate->pcapdirectory != NULL) {
        free(currstate->pcapdirectory);
        changed = 1;
    } else if (currstate->pcapdirectory == NULL &&
            newstate->pcapdirectory != NULL) {
        changed = 1;
    } else if (currstate->pcapdirectory == NULL &&
            newstate->pcapdirectory == NULL) {
        changed = 0;
    } else if (strcmp(currstate->pcapdirectory, newstate->pcapdirectory) == 0) {
        changed = 0;
    } else {
        changed = 1;
    }

    if (newstate->pcaptemplate == NULL && currstate->pcaptemplate != NULL) {
        free(currstate->pcaptemplate);
        changed = 1;
    } else if (currstate->pcaptemplate == NULL &&
            newstate->pcaptemplate != NULL) {
        changed = 1;
    } else if (currstate->pcaptemplate == NULL &&
            newstate->pcaptemplate == NULL) {
        /* leave changed as is */
    } else if (strcmp(currstate->pcaptemplate, newstate->pcaptemplate) == 0) {
        /* leave changed as is */
    } else {
        changed = 1;
    }

    if (currstate->pcapcompress != newstate->pcapcompress) {
        changed = 1;
    }

    if (currstate->pcaprotatefreq != newstate->pcaprotatefreq) {
        changed = 1;
    }

    tmp = currstate->pcapdirectory;
    currstate->pcapdirectory = newstate->pcapdirectory;
    newstate->pcapdirectory = tmp;

    tmp = currstate->pcaptemplate;
    currstate->pcaptemplate = newstate->pcaptemplate;
    newstate->pcaptemplate = tmp;

    currstate->pcapcompress = newstate->pcapcompress;
    currstate->pcaprotatefreq = newstate->pcaprotatefreq;

    

    return changed;
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
    int pcapchanged = 0;
    int rmqchanged = 0;
    int medidchanged = 0;
    int opidchanged = 0;

    /* TODO the logic in here is horrible to try and follow! */

    init_provisioner_instance(&(newstate.provisioner), NULL);
    /* Load the updated config into a spare "global state" instance */
    if (init_mediator_config(&newstate, currstate->conffile) == -1) {
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

    /* Has the mediator ID changed? */
    if (newstate.mediatorid != currstate->mediatorid) {
        medidchanged = 1;
        logger(LOG_INFO,
                "OpenLI Mediator: mediator ID has changed from %u to %u.",
                currstate->mediatorid, newstate.mediatorid);
        currstate->mediatorid = newstate.mediatorid;
    }

    /* Has the operator ID changed? */
    if (strcmp(newstate.operatorid, currstate->operatorid) != 0) {
        char *tmp = currstate->operatorid;
        opidchanged = 1;
        logger(LOG_INFO,
                "OpenLI Mediator: operator ID has changed from %s to %s.",
                currstate->operatorid, newstate.operatorid);
        currstate->operatorid = newstate.operatorid;
        newstate.operatorid = tmp;
    }
    if (strcmp(newstate.shortoperatorid, currstate->shortoperatorid) != 0) {
        char *tmp = currstate->shortoperatorid;
        logger(LOG_INFO,
                "OpenLI Mediator: short operator ID has changed from %s to %s.",
                currstate->shortoperatorid, newstate.shortoperatorid);
        opidchanged = 1;
        currstate->shortoperatorid = newstate.shortoperatorid;
        newstate.shortoperatorid = tmp;
    }

    /* Has the RMQ internal password changed? */
    lock_med_collector_config(&(currstate->collector_threads.config));
    if (strcmp(currstate->RMQ_conf.internalpass,
            newstate.RMQ_conf.internalpass) != 0) {

        char *tmp = currstate->RMQ_conf.internalpass;
        logger(LOG_INFO,
                "OpenLI Mediator: RMQ internal password has changed.");
        rmqchanged = 1;
        currstate->RMQ_conf.internalpass = newstate.RMQ_conf.internalpass;
        newstate.RMQ_conf.internalpass = tmp;
    }
    unlock_med_collector_config(&(currstate->collector_threads.config));

    /* Has the RMQ heartbeat frequency changed? */
    if (currstate->RMQ_conf.heartbeatFreq != newstate.RMQ_conf.heartbeatFreq)
    {
        logger(LOG_INFO, "OpenLI Mediator: RMQ heartbeat check frequency changed from %u to %u seconds.",
                currstate->RMQ_conf.heartbeatFreq,
                newstate.RMQ_conf.heartbeatFreq);
        rmqchanged = 1;
        currstate->RMQ_conf.heartbeatFreq = newstate.RMQ_conf.heartbeatFreq;
    }

    /* Have any pcap-related config options changed? */
    pcapchanged = reload_pcap_config(currstate, &newstate);
    if (pcapchanged == -1) {
        return -1;
    }

    /* RabbitMQ heartbeat, mediator ID or operator ID has changed?
     * Tell LEA threads to update their local copies of this config...
     */
    if (medidchanged || opidchanged || rmqchanged || pcapchanged) {
        update_lea_thread_config(currstate);
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
    lock_med_collector_config(&(currstate->collector_threads.config));
    tlschanged = reload_ssl_config(&(currstate->sslconf), &(newstate.sslconf));
    unlock_med_collector_config(&(currstate->collector_threads.config));
    if (tlschanged == -1) {
        return -1;
    }

    if (tlschanged != 0 || newstate.etsitls != currstate->etsitls ||
            medidchanged || rmqchanged || opidchanged) {
        /* Something has changed that will affect our collector receive
         * threads and therefore we may need to drop them and force them
         * to reconnect.
         */

        if (newstate.etsitls != currstate->etsitls) {
            currstate->etsitls = newstate.etsitls;
            tlschanged = 1;
        }
        update_coll_recv_thread_config(currstate);

    }

    if (tlschanged || medidchanged) {
        /* If TLS changed, then our existing connections are no longer
         * valid.
         *
         * If the mediator ID changed, then we also need to rejoin the
         * collectors -- if we are using RMQ, the queue ID that we are
         * supposed to read from is based on our mediator ID number so
         * it's just easiest to reset our connections.
         */
        if (!listenchanged) {
            /* Disconnect all collectors */
            mediator_disconnect_all_collectors(&(currstate->collector_threads));
            listenchanged = 1;
        }
    }
    if (tlschanged) {
        if (!provchanged) {
            drop_provisioner(currstate);
            provchanged = 1;
        }
    }

    if ((listenchanged || medidchanged) && !provchanged) {
        /* Need to re-announce our listen socket (or mediator ID) details */
        if (send_mediator_listen_details(currstate, 0) < 0) {
            return -1;
        }

    }

    /* newstate was just temporary and should only contain config,
     * so we can tidy it up now using clear_med_config() */
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
	int timerexpired = 0;
	struct epoll_event evs[64];
    int provfail = 0;
    med_epoll_ev_t *signalev;
    coll_recv_t *col_t, *tmp;

    /* Register the epoll event for received signals */
    signalev = create_mediator_fdevent(state->epoll_fd, NULL,
            MED_EPOLL_SIGNAL, state->signalev->fd, EPOLLIN);

    logger(LOG_INFO,
            "OpenLI Mediator: pcap output file rotation frequency is set to %d minutes.",
            state->pcaprotatefreq);

    state->timerev = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_SIGCHECK_TIMER, 0);

    state->col_clean_timerev = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_CLEAN_DEAD_COLRECV, 0);

    if (state->timerev == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: failed to create main loop timer");
        goto runfailure;
    }

    if (state->col_clean_timerev == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to create collector cleanup timer");
        goto runfailure;
    }

    /* TODO this timer should be longer, but for testing I've set to fire
     * more frequently
     */
    if (start_mediator_timer(state->col_clean_timerev, 30) < 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to start collector cleanup timer");
        goto runfailure;
    }

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
                state->provisioner.tryconnect != 0) {
            provfail = attempt_provisioner_connect(&(state->provisioner),
                    provfail);

            if (provfail < 0) {
                break;
            }

            if (!provfail) {
                if (send_mediator_listen_details(state, 1) < 0) {
                    drop_provisioner(state);
                    continue;
                }

                /* Any LEA threads for LEAs that the provisioner does
                 * not announce within the next 60 seconds should be
                 * halted, as presumably those agencies were removed
                 * from the provisioner config while we were not
                 * connected to the provisioner.
                 */
                if (state->provisioner.just_connected) {
                    trigger_lea_thread_shutdown_timers(state, 60);
                    state->provisioner.just_connected = 0;
                }
            }
        }

        /* Check for integrity check signing requests from the collector
         * threads.
         */
        HASH_ITER(hh, state->collector_threads.threads, col_t, tmp) {
            col_thread_msg_t colmsg;
            while (libtrace_message_queue_try_get(&(col_t->out_main),
                    (void *)&colmsg) != LIBTRACE_MQ_FAILED) {
                if (colmsg.type == MED_COLL_INTEGRITY_SIGN_REQUEST) {
                    struct ics_sign_request_message *signreq;

                    signreq = (struct ics_sign_request_message *)(colmsg.arg);
                    if (send_ics_signing_request_to_provisioner(
                            &state->provisioner, signreq) < 0) {
                        logger(LOG_INFO, "OpenLI mediator: failed to pass on integrity check signing request to the provisioner");
                    }

                } else {
                    logger(LOG_INFO, "OpenLI mediator: invalid message type received by main thread from collector thread (%u)", colmsg.type);
                }
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

    if (signalev) {
        remove_mediator_fdevent(signalev);
    }
}

/** Main function for the OpenLI mediator.
 *
 *  Tasks:
 *    - parses user configuration and initialises global state
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

    /* Start the pcap output thread (which behaves like an LEA thread) */
    mediator_start_pcap_thread(&(medstate.agency_threads));

    /* Open the socket that listens for connections from collectors */
    if (start_collector_listener(&medstate) == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: could not start collector listener socket.");
        return 1;
    }

    /* Start the main epoll loop - this will return when the mediator is
     * ready to be shut down.
     */
    run(&medstate);

    /* Halt all LEA and collector threads that we have started, including the
     * pcap output thread.
     */
    mediator_disconnect_all_collectors(&(medstate.collector_threads));
    mediator_disconnect_all_leas(&(medstate.agency_threads));

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
