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

#include "configparser.h"
#include "logger.h"
#include "util.h"
#include "agency.h"
#include "netcomms.h"
#include "mediator.h"
#include "etsili_core.h"

volatile int mediator_halt = 0;
volatile int reload_config = 0;

static void halt_signal(int signal) {
    mediator_halt = 1;
}

static void reload_signal(int signal) {
    reload_config = 1;
}

static void usage(char *prog) {
        fprintf(stderr, "Usage: %s [ -d ] -c configfile\n", prog);
        fprintf(stderr, "\nSet the -d flag to run as a daemon.\n");
}

static void disconnect_handover(mediator_state_t *state, handover_t *ho) {

    struct epoll_event ev;
    med_agency_state_t *agstate;

    agstate = (med_agency_state_t *)(ho->outev->state);

    logger(LOG_DAEMON,
        "OpenLI: mediator is disconnecting from handover %s:%s HI%d",
        ho->ipstr, ho->portstr, ho->handover_type);

    if (agstate->main_fd != -1) {
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, agstate->main_fd, &ev)
                == -1) {
            logger(LOG_DAEMON, "OpenLI: unable to remove handover fd from epoll: %s.", strerror(errno));
        }
        close(agstate->main_fd);
        agstate->main_fd = -1;
        ho->outev->fd = -1;
    }

    if (agstate->katimer_fd != -1) {
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, agstate->katimer_fd, &ev)
                == -1) {
            logger(LOG_DAEMON, "OpenLI: unable to remove keepalive timer fd from epoll: %s.", strerror(errno));
        }
        close(agstate->katimer_fd);
        agstate->katimer_fd = -1;
        if (ho->aliveev) {
            ho->aliveev->fd = -1;
        }
    }

    if (agstate->karesptimer_fd != -1) {
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, agstate->karesptimer_fd,
                &ev) == -1) {
            logger(LOG_DAEMON, "OpenLI: unable to remove keepalive response timer fd from epoll: %s.", strerror(errno));
        }
        close(agstate->karesptimer_fd);
        agstate->karesptimer_fd = -1;
        if (ho->aliverespev) {
            ho->aliverespev->fd = -1;
        }
    }

    if (agstate->encoder) {
        free_wandder_encoder(agstate->encoder);
        agstate->encoder = NULL;
    }
    if (agstate->decoder) {
        wandder_free_etsili_decoder(agstate->decoder);
        agstate->decoder = NULL;
    }
    if (agstate->pending_ka) {
        wandder_release_encoded_result(NULL, agstate->pending_ka);
        agstate->pending_ka = NULL;
    }
    if (agstate->incoming) {
        libtrace_scb_destroy(agstate->incoming);
        free(agstate->incoming);
        agstate->incoming = NULL;
    }
}


static int start_keepalive_timer(mediator_state_t *state,
        med_epoll_ev_t *timerev, int timeoutval) {

    int sock;

    /* Timer is disabled, ignore */
    if (timerev == NULL) {
        return 0;
    }

    if ((sock = epoll_add_timer(state->epoll_fd, timeoutval, timerev)) == -1) {
        logger(LOG_DAEMON, "OpenLI: warning -- keep alive timer was not able to be set for handover: %s", strerror(errno));
        return -1;
    }

    timerev->fd = sock;
    return 0;

}

static void halt_mediator_timer(mediator_state_t *state,
        med_epoll_ev_t *timerev) {

    struct epoll_event ev;

    if (timerev == NULL) {
        return;
    }

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, timerev->fd, &ev) == -1) {
        logger(LOG_DAEMON, "OpenLI: warning -- timer was not able to be disabled for agency connection: %s.", strerror(errno));
    }

    close(timerev->fd);
    timerev->fd = -1;
}

static void free_provisioner(int epollfd, mediator_prov_t *prov) {
    struct epoll_event ev;

    if (prov->provev) {
        if (prov->provev->fd != -1) {
            if (epoll_ctl(epollfd, EPOLL_CTL_DEL, prov->provev->fd,
                        &ev) == -1) {
                logger(LOG_DAEMON,
                        "OpenLI mediator: problem removing provisioner fd from epoll: %s.",
                        strerror(errno));
            }
            close(prov->provev->fd);
        }
        free(prov->provev);
        prov->provev = NULL;
    }

    if (prov->outgoing) {
        destroy_net_buffer(prov->outgoing);
        prov->outgoing = NULL;
    }
    if (prov->incoming) {
        destroy_net_buffer(prov->incoming);
        prov->incoming = NULL;
    }
}

static void free_handover(handover_t *ho) {

    if (ho->aliveev) {
        if (ho->aliveev->fd != -1) {
            close(ho->aliveev->fd);
        }
        free(ho->aliveev);
    }

    if (ho->aliverespev) {
        if (ho->aliverespev->fd != -1) {
            close(ho->aliverespev->fd);
        }
        free(ho->aliverespev);
    }

    if (ho->outev) {
        /* TODO send disconnect messages to all agencies? */
        med_agency_state_t *agstate = (med_agency_state_t *)
                (ho->outev->state);

        if (ho->outev->fd != -1) {
            close(ho->outev->fd);
        }

        if (agstate->encoder) {
            free_wandder_encoder(agstate->encoder);
        }
        if (agstate->decoder) {
            wandder_free_etsili_decoder(agstate->decoder);
        }
        if (agstate->pending_ka) {
            wandder_release_encoded_result(NULL, agstate->pending_ka);
        }
        if (agstate->incoming) {
            libtrace_scb_destroy(agstate->incoming);
            free(agstate->incoming);
        }
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

static void drop_collector(med_epoll_ev_t *colev) {
    med_coll_state_t *mstate;

    if (!colev) {
        return;
    }

    mstate = (med_coll_state_t *)(colev->state);

    if (mstate && mstate->incoming) {
        destroy_net_buffer(mstate->incoming);
        mstate->incoming = NULL;
    }

    if (mstate) {
        mstate->disabled = 1;
    }

    if (colev->fd != -1) {
        close(colev->fd);
        colev->fd = -1;
    }
}

static void drop_all_collectors(libtrace_list_t *c) {

    /* TODO send disconnect messages to all collectors? */
    libtrace_list_node_t *n;
    mediator_collector_t *col;

    n = c->head;
    while (n) {
        col = (mediator_collector_t *)n->data;
        drop_collector(col->colev);
        free(col->colev->state);
        free(col->colev);
        n = n->next;
    }

    libtrace_list_deinit(c);
}

static void drop_all_agencies(libtrace_list_t *a) {
    libtrace_list_node_t *n;
    mediator_agency_t *ag;

    n = a->head;
    while (n) {
        ag = (mediator_agency_t *)n->data;
        free_handover(ag->hi2);
        free_handover(ag->hi3);
        if (ag->agencyid) {
            free(ag->agencyid);
        }
        n = n->next;
    }

    libtrace_list_deinit(a);
}

static void clear_med_state(mediator_state_t *state) {

    liid_map_t *m, *tmp;

    HASH_ITER(hh, state->liids, m, tmp) {
        HASH_DEL(state->liids, m);
        if (m->ceasetimer) {
            halt_mediator_timer(state, m->ceasetimer);
            free(m->ceasetimer);
        }
        free(m->liid);
        free(m);
    }

    free_provisioner(state->epoll_fd, &(state->provisioner));
    drop_all_collectors(state->collectors);
    drop_all_agencies(state->agencies);

    close(state->epoll_fd);

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
    if (state->signalev) {
        close(state->signalev->fd);
        free(state->signalev);
    }
    if (state->listenerev) {
        close(state->listenerev->fd);
        free(state->listenerev);
    }
	if (state->timerev) {
		if (state->timerev->fd != -1) {
			close(state->timerev->fd);
		}
		free(state->timerev);
	}

    if (state->pcaptimerev) {
        if (state->pcaptimerev->fd != -1) {
            close(state->pcaptimerev->fd);
        }
        free(state->pcaptimerev);
    }

    libtrace_message_queue_destroy(&(state->pcapqueue));

    if (state->etsidecoder) {
        wandder_free_etsili_decoder(state->etsidecoder);
    }

}

static int init_med_state(mediator_state_t *state, char *configfile,
        char *mediatorname) {

    sigset_t sigmask;

    state->mediatorid = 0;
    state->conffile = configfile;
    state->mediatorname = mediatorname;
    state->epoll_fd = epoll_create1(0);
    state->listenaddr = NULL;
    state->listenport = NULL;
    state->operatorid = NULL;
    state->provaddr = NULL;
    state->provport = NULL;
    state->pcapdirectory = NULL;
    state->pcapthread = -1;
    state->pcaprotatefreq = 30;
    state->etsidecoder = NULL;

    state->collectors = libtrace_list_init(sizeof(mediator_collector_t));
    state->agencies = libtrace_list_init(sizeof(mediator_agency_t));

    state->liids = NULL;
    libtrace_message_queue_init(&(state->pcapqueue),
            sizeof(mediator_pcap_msg_t));

    if (parse_mediator_config(configfile, state) == -1) {
        return -1;
    }

    if (state->mediatorid == 0) {
        logger(LOG_DAEMON, "OpenLI: mediator ID is not present in the config file or is set to zero.");
        return -1;
    }

    if (state->listenport == NULL) {
        state->listenport = strdup("61000");
    }

    if (state->provport == NULL) {
        state->provport = strdup("8993");
    }

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

    state->listenerev = NULL;
    state->timerev = NULL;
    state->pcaptimerev = NULL;
    state->provisioner.provev = NULL;
    state->provisioner.incoming = NULL;
    state->provisioner.outgoing = NULL;

    return 0;
}

static int trigger_pcap_flush(mediator_state_t *state, med_epoll_ev_t *mev) {

    mediator_pcap_msg_t pmsg;
    struct timeval tv;
    int timerfd;

    memset(&pmsg, 0, sizeof(pmsg));
    gettimeofday(&tv, NULL);

    if (tv.tv_sec % (60 * state->pcaprotatefreq) < 60) {
        pmsg.msgtype = PCAP_MESSAGE_ROTATE;
    } else {
        pmsg.msgtype = PCAP_MESSAGE_FLUSH;
    }
    pmsg.msgbody = NULL;
    pmsg.msglen = 0;

    libtrace_message_queue_put(&(state->pcapqueue), (void *)(&pmsg));

    halt_mediator_timer(state, mev);

    timerfd = epoll_add_timer(state->epoll_fd, 60, state->pcaptimerev);
    if (timerfd == -1) {
        logger(LOG_DAEMON,
                "OpenLI mediator: failed to create pcap rotation timer");
        return -1;
    }
    state->pcaptimerev->fd = timerfd;
    state->pcaptimerev->fdtype = MED_EPOLL_PCAP_TIMER;
    state->pcaptimerev->state = NULL;
    return 0;
}


static int trigger_keepalive(mediator_state_t *state, med_epoll_ev_t *mev) {

    med_agency_state_t *ms = (med_agency_state_t *)(mev->state);
    wandder_encoded_result_t *kamsg;
    wandder_etsipshdr_data_t hdrdata;
    char elemstring[16];

    if (ms->pending_ka == NULL && ms->main_fd != -1) {
        /* Only create a new KA message if we have sent the last one we
         * had queued up.
         */
        if (ms->encoder == NULL) {
            ms->encoder = init_wandder_encoder();
        } else {
            reset_wandder_encoder(ms->encoder);
        }

        hdrdata.liid = "openlikeepalive";
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
            logger(LOG_DAEMON,
                    "OpenLI: mediator failed to construct a keep-alive.");
            return -1;
        }

        ms->pending_ka = kamsg;
        ms->lastkaseq += 1;

        if (!ms->outenabled) {
            struct epoll_event ev;
            ev.data.ptr = ms->parent->outev;
            ev.events = EPOLLRDHUP | EPOLLIN | EPOLLOUT;
            if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, ms->main_fd,
                        &ev) == -1) {
                logger(LOG_DAEMON,
                    "OpenLI: error while trying to enable xmit for handover %s:%s HI%d -- %s",
                    ms->parent->ipstr, ms->parent->portstr,
                    ms->parent->handover_type, strerror(errno));
                return -1;
            }
            ms->outenabled = 1;
        }

    /*
        logger(LOG_DAEMON, "OpenLI: queued keep alive %ld for %s:%s HI%d",
                ms->lastkaseq, ms->parent->ipstr, ms->parent->portstr,
                ms->parent->handover_type);
    */
        if (start_keepalive_timer(state, ms->parent->aliverespev,
                ms->kawait) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: unable to start keepalive response timer.");
            return -1;
        }
        if (ms->parent->aliverespev) {
            ms->karesptimer_fd = ms->parent->aliverespev->fd;
        }

    }

    halt_mediator_timer(state, mev);
    if (start_keepalive_timer(state, mev, ms->kafreq) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: unable to reset keepalive timer for  %s:%s HI%d.",
                ms->parent->ipstr, ms->parent->portstr,
                ms->parent->handover_type);
        return -1;
    }
    ms->katimer_fd = mev->fd;
    return 0;
}

static int connect_handover(mediator_state_t *state, handover_t *ho) {
    med_agency_state_t *agstate;
    struct epoll_event ev;

    agstate = (med_agency_state_t *)(ho->outev->state);

    if (ho->outev->fd != -1) {
        return 0;
    }

    ho->outev->fd = connect_socket(ho->ipstr, ho->portstr, agstate->failmsg, 1);
    if (ho->outev->fd == -1) {
        return -1;
    }

    if (ho->outev->fd == 0) {
        ho->outev->fd = -1;
        agstate->failmsg = 1;
        return 0;
    }

    if (get_buffered_amount(&(agstate->buf)) > 0) {
        ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
        agstate->outenabled = 1;
    } else {
        ev.events = EPOLLIN | EPOLLRDHUP;
        agstate->outenabled = 0;
    }
    ev.data.ptr = (void *)ho->outev;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, ho->outev->fd, &ev) == -1
            && agstate->failmsg == 0) {
        logger(LOG_DAEMON,
                "OpenLI: unable to add agency handover fd %d to epoll.",
                ho->outev->fd);
        agstate->failmsg = 1;
        close(ho->outev->fd);
        ho->outev->fd = -1;
        return 0;
    }

    agstate->incoming = (libtrace_scb_t *)malloc(sizeof(libtrace_scb_t));
    libtrace_scb_init(agstate->incoming, (64 * 1024 * 1024),
            (uint16_t)state->mediatorid);

    agstate->failmsg = 0;
    agstate->main_fd = ho->outev->fd;
    agstate->katimer_fd = -1;
    agstate->karesptimer_fd = -1;
    agstate->lastkaseq = 0;
    agstate->pending_ka = NULL;
    agstate->encoder = NULL;
    agstate->decoder = NULL;

    /* Start a keep alive timer */
    if (ho->aliveev && ho->aliveev->fd != -1) {
        halt_mediator_timer(state, ho->aliveev);
    }

    if (start_keepalive_timer(state, ho->aliveev, agstate->kafreq) == -1) {
        return 1;
    }
    if (ho->aliveev) {
        agstate->katimer_fd = ho->aliveev->fd;
    }
    return 1;
}

static void connect_agencies(mediator_state_t *state) {
    libtrace_list_node_t *n;
    mediator_agency_t *ag;
    int ret;

    n = state->agencies->head;
    while (n) {
        ag = (mediator_agency_t *)(n->data);
        n = n->next;

        if (ag->disabled) {
            printf("cannot connect to agency %s because it is disabled\n",
                    ag->agencyid);
            continue;
        }

        ret = connect_handover(state, ag->hi2);
        if (ret == -1) {
            ag->disabled = 1;
            continue;
        }

        if (ret == 1) {
            logger(LOG_DAEMON,
                    "OpenLI: mediator has connected to agency %s on HI2 %s:%s.",
                    ag->agencyid, ag->hi2->ipstr, ag->hi2->portstr);
        }

        ret = connect_handover(state, ag->hi3);
        if (ret == -1) {
            ag->disabled = 1;
            continue;
        }

        if (ret == 1) {
            logger(LOG_DAEMON,
                    "OpenLI: mediator has connected to agency %s on HI3 %s:%s.",
                    ag->agencyid, ag->hi3->ipstr, ag->hi3->portstr);
        }
    }

}

static int start_collector_listener(mediator_state_t *state) {
    struct epoll_event ev;
    int sockfd;

    state->listenerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    sockfd = create_listener(state->listenaddr, state->listenport,
            "mediator");
    if (sockfd == -1) {
        return -1;
    }

    state->listenerev->fd = sockfd;
    state->listenerev->fdtype = MED_EPOLL_COLL_CONN;
    state->listenerev->state = NULL;

    ev.data.ptr = state->listenerev;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Failed to register mediator listening socket: %s.",
                strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int process_signal(mediator_state_t *state, int sigfd) {

    struct signalfd_siginfo si;
    int ret;

    ret = read(sigfd, &si, sizeof(si));
    if (ret < 0) {
        logger(LOG_DAEMON,
                "OpenLI mediator: unable to read from signal fd: %s.",
                strerror(errno));
        return ret;
    }

    if (ret != sizeof(si)) {
        logger(LOG_DAEMON,
                "OpenLI mediator: unexpected partial read from signal fd.");
        return -1;
    }

    if (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT) {
        halt_signal(si.ssi_signo);
    }
    if (si.ssi_signo == SIGHUP) {
        reload_signal(si.ssi_signo);
    }

    return 0;
}

static int accept_collector(mediator_state_t *state) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    mediator_collector_t col;
    med_coll_state_t *mstate;
    libtrace_list_node_t *n;
    struct epoll_event ev;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of collectors. Push all active intercepts
     * out to the collector. */
    newfd = accept(state->listenerev->fd, (struct sockaddr *)&saddr, &socklen);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
                0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_DAEMON, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
    } else {
        logger(LOG_DAEMON,
                "OpenLI: mediator accepted connection from collector %s.",
                strbuf);
    }

    if (newfd >= 0) {
        mstate = (med_coll_state_t *)malloc(sizeof(med_coll_state_t));
        col.colev = (med_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));


        col.colev->fdtype = MED_EPOLL_COLLECTOR;
        col.colev->fd = newfd;
        col.colev->state = mstate;
        mstate->incoming = create_net_buffer(NETBUF_RECV, newfd);
        mstate->disabled = 0;

        /* Add fd to epoll */
        ev.data.ptr = (void *)(col.colev);
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, col.colev->fd,
                    &ev) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI mediator: unable to add collector fd to epoll: %s.",
                    strerror(errno));
            drop_collector(col.colev);
            return -1;
        }

        libtrace_list_push_back(state->collectors, &col);
    }

    return newfd;
}

static handover_t *create_new_handover(char *ipstr, char *portstr,
        int handover_type, uint32_t kafreq, uint32_t kawait) {

    med_epoll_ev_t *agev;
    med_epoll_ev_t *timerev;
    med_epoll_ev_t *respev;
    med_agency_state_t *agstate;

    handover_t *ho = (handover_t *)malloc(sizeof(handover_t));

    if (ho == NULL) {
        logger(LOG_DAEMON, "OpenLI: ran out of memory while allocating handover structure.");
        return NULL;
    }


    agev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    agstate = (med_agency_state_t *)malloc(sizeof(med_agency_state_t));

    if (kafreq > 0) {
        timerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    } else {
        if (handover_type == HANDOVER_HI2) {
            logger(LOG_DAEMON, "OpenLI: warning, keep alive timer has been disabled for agency %s:%s", ipstr, portstr);
        }
        timerev = NULL;
    }

    if (kawait > 0) {
        respev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    } else {
        respev = NULL;
    }

    if (agev == NULL || agstate == NULL || (kafreq > 0 && timerev == NULL) ||
            (kawait > 0 && respev == NULL)) {
        logger(LOG_DAEMON, "OpenLI: ran out of memory while allocating handover structure.");
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


    init_export_buffer(&(agstate->buf), 0);
    agstate->failmsg = 0;
    agstate->main_fd = -1;
    agstate->outenabled = 0;
    agstate->katimer_fd = -1;
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

    ho->ipstr = ipstr;
    ho->portstr = portstr;
    ho->handover_type = handover_type;
    ho->outev = agev;
    ho->aliveev = timerev;
    ho->aliverespev = respev;

    return ho;
}

static void create_new_agency(mediator_state_t *state, liagency_t *lea) {

    mediator_agency_t newagency;

    newagency.agencyid = lea->agencyid;
    newagency.awaitingconfirm = 0;
    newagency.disabled = 0;
    newagency.hi2 = create_new_handover(lea->hi2_ipstr, lea->hi2_portstr,
            HANDOVER_HI2, lea->keepalivefreq, lea->keepalivewait);
    newagency.hi3 = create_new_handover(lea->hi3_ipstr, lea->hi3_portstr,
            HANDOVER_HI3, lea->keepalivefreq, lea->keepalivewait);

    libtrace_list_push_back(state->agencies, &newagency);

}

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

    mas->kawait = newag->keepalivewait;
    mas->kafreq = newag->keepalivefreq;

    if (!changedkaresp && !changedloc && !changedkafreq) {
        return 0;
    }

    if (ho->handover_type == HANDOVER_HI2) {
        hitypestr = "HI2";
    } else if (ho->handover_type == HANDOVER_HI3) {
        hitypestr = "HI3";
    } else {
        hitypestr = "Unknown handover";
    }

    if (changedloc) {
        logger(LOG_DAEMON,
                "OpenLI: %s connection info for LEA %s has changed from %s:%s to %s:%s.",
                hitypestr, existing->agencyid, ho->ipstr, ho->portstr, ipstr, portstr);
    } else if (changedkaresp) {
        if (newag->keepalivewait == 0) {
            if (ho->handover_type == HANDOVER_HI2) {
                logger(LOG_DAEMON,
                        "OpenLI: disabled keep-alive response requirement for LEA %s",
                        existing->agencyid);
            }
            if (ho->aliverespev) {
                if (ho->aliverespev->fd != -1) {
                    close(ho->aliverespev->fd);
                }
                free(ho->aliverespev);
                ho->aliverespev = NULL;
            }
        } else {
            if (ho->handover_type == HANDOVER_HI2) {
                logger(LOG_DAEMON,
                        "OpenLI: enabled keep-alive response requirement for LEA %s",
                        existing->agencyid);
            }
            if (ho->aliverespev == NULL) {
                ho->aliverespev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
            }
            ho->aliverespev->fd = -1;
            ho->aliverespev->fdtype = MED_EPOLL_KA_RESPONSE_TIMER;
            ho->aliverespev->state = mas;
        }
        return 0;
    } else if (changedkafreq) {
        if (newag->keepalivefreq == 0) {
            if (ho->handover_type == HANDOVER_HI2) {
                logger(LOG_DAEMON,
                        "OpenLI: disabled keep-alives for LEA %s",
                        existing->agencyid);
            }
            halt_mediator_timer(state, ho->aliveev);
            if (ho->aliveev) {
                if (ho->aliveev->fd != -1) {
                    close(ho->aliveev->fd);
                }
                free(ho->aliveev);
                ho->aliveev = NULL;
            }
        } else {
            if (ho->handover_type == HANDOVER_HI2) {
                logger(LOG_DAEMON,
                        "OpenLI: enabled keep-alives for LEA %s",
                        existing->agencyid);
            }
            if (ho->aliveev == NULL) {
                ho->aliveev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
            }
            ho->aliveev->fd = -1;
            ho->aliveev->fdtype = MED_EPOLL_KA_TIMER;
            ho->aliveev->state = mas;

            if (start_keepalive_timer(state, ho->aliveev,
                        newag->keepalivefreq) == -1) {
                logger(LOG_DAEMON,
                        "OpenLI: unable to restart keepalive timer for handover %s:%s HI%d.",
                        ho->ipstr, ho->portstr, ho->handover_type,
                        strerror(errno));
                return -1;
            }
        }
        return 0;
    }


    disconnect_handover(state, ho);
    free(ho->ipstr);
    free(ho->portstr);
    ho->ipstr = ipstr;
    ho->portstr = portstr;
    return 1;

}

static int receive_lea_withdrawal(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    liagency_t lea;
    libtrace_list_node_t *n;

    if (decode_lea_withdrawal(msgbody, msglen, &lea) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid LEA withdrawal from provisioner.");
        return -1;
    }

    logger(LOG_DAEMON, "OpenLI: mediator received LEA withdrawal for %s.",
            lea.agencyid);

    n = state->agencies->head;
    while (n) {
        mediator_agency_t *x = (mediator_agency_t *)(n->data);
        n = n->next;

        if (strcmp(x->agencyid, lea.agencyid) == 0) {
            x->disabled = 1;
            break;
        }
    }

    return 0;
}

static int receive_lea_announce(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    liagency_t lea;
    libtrace_list_node_t *n;
    int ret;

    if (decode_lea_announcement(msgbody, msglen, &lea) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid LEA announcement from provisioner.");
        return -1;
    }

    logger(LOG_DAEMON, "OpenLI: mediator received LEA announcement for %s.",
            lea.agencyid);
    logger(LOG_DAEMON, "OpenLI: HI2 = %s:%s    HI3 = %s:%s",
            lea.hi2_ipstr, lea.hi2_portstr, lea.hi3_ipstr, lea.hi3_portstr);

    n = state->agencies->head;
    while (n) {
        mediator_agency_t *x = (mediator_agency_t *)(n->data);
        n = n->next;

        if (strcmp(x->agencyid, lea.agencyid) == 0) {
            med_agency_state_t *mas;

            mas = (med_agency_state_t *)(x->hi2->outev->state);
            if ((ret = has_handover_changed(state, x->hi2, lea.hi2_ipstr,
                    lea.hi2_portstr, x, &lea, mas)) == -1) {
                x->disabled = 1;
                goto freelea;
            } else if (ret == 1) {
                if (mas) {
                    mas->failmsg = 0;
                }
                lea.hi2_portstr = NULL;
                lea.hi2_ipstr = NULL;
            }

            mas = (med_agency_state_t *)(x->hi3->outev->state);
            if ((ret = has_handover_changed(state, x->hi3, lea.hi3_ipstr,
                    lea.hi3_portstr, x, &lea, mas)) == -1) {
                x->disabled = 1;
                goto freelea;
            } else if (ret == 1) {
                if (mas) {
                    mas->failmsg = 0;
                }
                lea.hi3_portstr = NULL;
                lea.hi3_ipstr = NULL;
            }

            x->awaitingconfirm = 0;
            x->disabled = 0;
            ret = 0;
            goto freelea;
        }
    }

    create_new_agency(state, &lea);
    return 0;

freelea:
    free(lea.hi2_portstr);
    free(lea.hi2_ipstr);
    free(lea.hi3_portstr);
    free(lea.hi3_ipstr);
    return ret;
}

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

static liid_map_t *match_etsi_to_agency(mediator_state_t *state,
        uint8_t *etsimsg, uint16_t msglen, uint16_t *liidlen) {

    char liidstr[65536];
    liid_map_t *match = NULL;
    uint16_t l;
    
    l = *(uint16_t *)(etsimsg);
    *liidlen = ntohs(l);

    memcpy(liidstr, etsimsg + 2, *liidlen);
    liidstr[*liidlen] = '\0';

    *liidlen += sizeof(l);

#if 0
    if (state->etsidecoder == NULL) {
        state->etsidecoder = wandder_create_etsili_decoder();
    }
    wandder_attach_etsili_buffer(state->etsidecoder, etsimsg, msglen, false);

    if (wandder_etsili_get_liid(state->etsidecoder, liidstr, 1024) == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: unable to find LIID in ETSI record received from collector.");
        return NULL;
    }
#endif
    HASH_FIND_STR(state->liids, liidstr, match);
    if (match == NULL) {
        logger(LOG_DAEMON, "OpenLI: mediator was unable to find LIID %s in its set of mappings.", liidstr);

        /* TODO what do we do in this case -- buffer it somewhere in case
         * a mapping turns up later? drop it? */
        return NULL;
    }

    return match;
}

static int enqueue_etsi(mediator_state_t *state, handover_t *ho,
        uint8_t *etsimsg, uint16_t msglen) {

    med_agency_state_t *mas;

    mas = (med_agency_state_t *)(ho->outev->state);

    if (append_etsipdu_to_buffer(&(mas->buf), etsimsg, (uint32_t)msglen, 0)
            == 0) {
        logger(LOG_DAEMON,
            "OpenLI: mediator was unable to enqueue ETSI PDU for handover %s:%s HI%d",
            ho->ipstr, ho->portstr, ho->handover_type);
        return -1;
    }

    /* Got something to send, so make sure we are enable EPOLLOUT */
    if (ho->outev->fd != -1 && !(mas->outenabled)) {
        struct epoll_event ev;
        ev.data.ptr = ho->outev;
        ev.events = EPOLLRDHUP | EPOLLIN | EPOLLOUT;
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, ho->outev->fd, &ev) == -1)
        {
            logger(LOG_DAEMON,
                "OpenLI: error while trying to enable xmit for handover %s:%s HI%d -- %s",
                ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
            return -1;
        }
        mas->outenabled = 1;
    }

    return 0;
}

static inline int xmit_handover(mediator_state_t *state, med_epoll_ev_t *mev) {

    med_agency_state_t *mas = (med_agency_state_t *)(mev->state);
    handover_t *ho = mas->parent;
    int ret = 0;

    if (mas->pending_ka) {
        ret = send(mev->fd, mas->pending_ka->encoded, mas->pending_ka->len,
                MSG_DONTWAIT);
        if (ret < 0) {
            logger(LOG_DAEMON,
                    "OpenLI: error while transmitting keepalive for handover %s:%s HI%d -- %s",
                    ho->ipstr, ho->portstr, ho->handover_type,
                    strerror(errno));
            return -1;
        }
        if (ret == 0) {
            return -1;
        }
        if (ret == mas->pending_ka->len) {
            /* Sent the whole thing successfully */
            wandder_release_encoded_result(NULL, mas->pending_ka);
            mas->pending_ka = NULL;
        } else {
            /* Partial send -- try the rest next time */
            memmove(mas->pending_ka->encoded, mas->pending_ka->encoded + ret,
                    mas->pending_ka->len - ret);
            mas->pending_ka->len -= ret;
        }
        return 0;
    }


    if (transmit_buffered_records(&(mas->buf), mev->fd, 65535) == -1) {
        return -1;
    }

    if (get_buffered_amount(&(mas->buf)) == 0) {
        struct epoll_event ev;
        ev.data.ptr = mev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, mev->fd, &ev) == -1) {
            logger(LOG_DAEMON,
                "OpenLI: error while trying to disable xmit for handover %s:%s HI%d -- %s",
                ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
            return -1;
        }
        mas->outenabled = 0;
    }

    /* Reset the keep alive timer */
    halt_mediator_timer(state, mas->parent->aliveev);
    if (start_keepalive_timer(state, mas->parent->aliveev,
                mas->kafreq) == -1) {
        logger(LOG_DAEMON, "OpenLI: unable to reset keepalive timer for handover %s:%s HI%d.",
                ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
        return -1;
    }

    return 0;


}

static int receive_cease(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    char *liid = NULL;
    liid_map_t *m;
    int sock;

    if (decode_cease_mediation(msgbody, msglen, &liid) == -1) {
        logger(LOG_DAEMON, "OpenLI mediator: received invalid cease mediation command from provisioner.");
        return -1;
    }

    if (liid == NULL) {
        return -1;
    }

    HASH_FIND_STR(state->liids, liid, m);
    if (m == NULL) {
        logger(LOG_DAEMON, "OpenLI mediator: asked to cease mediation for LIID %s, but we have no record of this LIID?",
                liid);
        free(liid);
        return 0;
    }


    /* TODO end any pcap trace for this LIID */

    if (m->ceasetimer != NULL) {
        /* This LIID has already been scheduled to cease? */
        free(liid);
        return 0;
    }

    logger(LOG_DAEMON,
            "OpenLI mediator: scheduled removal of agency mapping for LIID %s.",
            m->liid);
    m->ceasetimer = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    m->ceasetimer->fd = -1;
    m->ceasetimer->fdtype = MED_EPOLL_CEASE_LIID_TIMER;
    m->ceasetimer->state = m;

    if ((sock = epoll_add_timer(state->epoll_fd, 15, m->ceasetimer)) == -1) {
        logger(LOG_DAEMON, "OpenLI: warning -- cease timer was not able to be set for LIID %s: %s", liid, strerror(errno));
        return -1;
    }
    m->ceasetimer->fd = sock;

    return 0;
}

static inline int remove_liid_mapping(mediator_state_t *state,
        med_epoll_ev_t *mev) {

    struct epoll_event ev;
    liid_map_t *m = (liid_map_t *)(mev->state);

    logger(LOG_DAEMON, "OpenLI mediator: removed agency mapping for LIID %s.",
            m->liid);
    HASH_DEL(state->liids, m);

    halt_mediator_timer(state, mev);
    free(m->ceasetimer);
    free(m->liid);
    free(m);
    return 0;
}

static int receive_liid_mapping(mediator_state_t *state, uint8_t *msgbody,
        uint16_t msglen) {

    char *agencyid, *liid;
    mediator_agency_t *agency;
    liid_map_t *m;

    agencyid = NULL;
    liid = NULL;

    if (decode_liid_mapping(msgbody, msglen, &agencyid, &liid) == -1) {
        logger(LOG_DAEMON, "OpenLI: receive invalid LIID mapping from provisioner.");
        return -1;
    }

    if (agencyid == NULL || liid == NULL) {
        return -1;
    }

    /* "Special" agency ID for intercepts that need to be written to a
     * PCAP file instead of sent to an agency...
     */
    if (strcmp(agencyid, "pcapdisk") == 0) {
        agency = NULL;
    } else {
        /* Try to find the agency in our agency list */
        agency = lookup_agency(state->agencies, agencyid);

        /* We *could* consider waiting for an LEA announcement that will resolve
         * this discrepancy, but any relevant announcement should have been sent
         * before the LIID mapping.
         *
         * Also, what are we going to do with any records matching that LIID?
         * Buffer them? Our buffers are tied to handovers, so we'd need
         * somewhere else to store them. Drop them?
         */
        if (agency == NULL) {
            logger(LOG_DAEMON, "OpenLI: agency %s is not recognised by the mediator, yet LIID %s is intended for it?",
                    agencyid, liid);
            return -1;
        }
    }

    m = (liid_map_t *)malloc(sizeof(liid_map_t));
    m->liid = liid;
    m->agency = agency;
    m->ceasetimer = NULL;
    free(agencyid);

    HASH_ADD_STR(state->liids, liid, m);

    if (agency) {
        logger(LOG_DAEMON, "OpenLI mediator: added %s -> %s to LIID map",
                m->liid, m->agency->agencyid);
    } else {
        logger(LOG_DAEMON, "OpenLI mediator: added %s -> pcapdisk to LIID map",
                m->liid);
    }
    return 0;
}


static int transmit_provisioner(mediator_state_t *state, med_epoll_ev_t *mev) {

    mediator_prov_t *prov = &(state->provisioner);
    struct epoll_event ev;
    int ret;

    ret = transmit_net_buffer(prov->outgoing);
    if (ret == -1) {
        logger(LOG_DAEMON,
                "OpenLI: error sending message from mediator to provisioner.");
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        ev.data.ptr = mev;
        ev.events = EPOLLIN | EPOLLRDHUP;
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, mev->fd, &ev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error disabling EPOLLOUT for provisioner fd: %s.",
                    strerror(errno));
            return -1;
        }
    }

    return 1;
}

static int trigger_ka_failure(mediator_state_t *state, med_epoll_ev_t *mev) {
    med_agency_state_t *ms = (med_agency_state_t *)(mev->state);

    logger(LOG_DAEMON, "OpenLI mediator: failed to receive KA response from LEA on handover %s:%s HI%d, dropping connection.",
            ms->parent->ipstr, ms->parent->portstr, ms->parent->handover_type);


    disconnect_handover(state, ms->parent);
    return 0;
}

static int receive_provisioner(mediator_state_t *state, med_epoll_ev_t *mev) {

    uint8_t *msgbody = NULL;
    uint16_t msglen = 0;
    uint64_t internalid;

    openli_proto_msgtype_t msgtype;

    do {
        msgtype = receive_net_buffer(state->provisioner.incoming, &msgbody,
                &msglen, &internalid);
        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                logger(LOG_DAEMON,
                        "OpenLI: error receiving message from collector.");
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
                logger(LOG_DAEMON,
                        "OpenLI mediator: unexpected message type %d received from provisioner.",
                        msgtype);
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    return 0;
}

static int receive_handover(mediator_state_t *state, med_epoll_ev_t *mev) {
    med_agency_state_t *mas = (med_agency_state_t *)(mev->state);
    int ret;
    uint8_t *ptr = NULL;
    uint32_t reclen = 0;
    uint32_t available;

    ret = libtrace_scb_recv_sock(mas->incoming, mev->fd, MSG_DONTWAIT);
    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        logger(LOG_DAEMON, "OpenLI mediator: error receiving data from LEA on handover %s:%s HI%d: %s\n",
                mas->parent->ipstr, mas->parent->portstr,
                mas->parent->handover_type, strerror(errno));
        return -1;
    }

    if (ret == 0) {
        logger(LOG_DAEMON,
                "OpenLI mediator: disconnect on LEA handover %s:%s HI%d\n",
                mas->parent->ipstr, mas->parent->portstr,
                mas->parent->handover_type);
        return -1;
    }

    do {
        ptr = libtrace_scb_get_read(mas->incoming, &available);
        if (available == 0 || ptr == NULL) {
            break;
        }
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
                logger(LOG_DAEMON, "OpenLI mediator -- unexpected KA response from handover %s:%s HI%d",
                        mas->parent->ipstr, mas->parent->portstr,
                        mas->parent->handover_type);
                logger(LOG_DAEMON, "OpenLI mediator -- expected %ld, got %ld",
                        mas->lastkaseq, recvseq);
                return -1;
            }
            /*
            logger(LOG_DAEMON, "OpenLI mediator -- received KA response for %ld from LEA handover %s:%s HI%d",
                    recvseq, mas->parent->ipstr, mas->parent->portstr,
                    mas->parent->handover_type);
            */
            halt_mediator_timer(state, mas->parent->aliverespev);
            libtrace_scb_advance_read(mas->incoming, reclen);
            mas->karesptimer_fd = -1;
        } else {
            logger(LOG_DAEMON, "OpenLI mediator -- received unknown data from LEA handover %s:%s HI%d",
                    mas->parent->ipstr, mas->parent->portstr,
                    mas->parent->handover_type);
            return -1;
        }
    } while (1);

    return 0;
}

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
        switch(msgtype) {

            case OPENLI_PROTO_DISCONNECT:
                logger(LOG_DAEMON,
                        "OpenLI: error receiving message from collector.");
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_ETSI_CC:
                /* msgbody should contain a full ETSI record */
                thisint = match_etsi_to_agency(state, msgbody, msglen,
                        &liidlen);
                if (thisint == NULL) {
                    return -1;
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
                /* msgbody should contain a full ETSI record */
                thisint = match_etsi_to_agency(state, msgbody, msglen,
                        &liidlen);
                if (thisint == NULL) {
                    return -1;
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
                logger(LOG_DAEMON,
                        "OpenLI mediator: unexpected message type %d received from collector.",
                        msgtype);
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    return 0;
}

static int check_epoll_fd(mediator_state_t *state, struct epoll_event *ev) {

	med_epoll_ev_t *mev = (med_epoll_ev_t *)(ev->data.ptr);
    int ret = 0;

	switch(mev->fdtype) {
		case MED_EPOLL_SIGCHECK_TIMER:
			if (ev->events & EPOLLIN) {
				return 1;
			}
			logger(LOG_DAEMON,
                    "OpenLI Mediator: main epoll timer has failed.");
            return -1;
        case MED_EPOLL_PCAP_TIMER:
            assert(ev->events == EPOLLIN);
            ret = trigger_pcap_flush(state, mev);
            break;
        case MED_EPOLL_SIGNAL:
            ret = process_signal(state, mev->fd);
            break;
        case MED_EPOLL_COLL_CONN:
            ret = accept_collector(state);
            break;
        case MED_EPOLL_CEASE_LIID_TIMER:
            assert(ev->events == EPOLLIN);
            ret = remove_liid_mapping(state, mev);
            break;
        case MED_EPOLL_KA_TIMER:
            assert(ev->events == EPOLLIN);
            ret = trigger_keepalive(state, mev);
            break;
        case MED_EPOLL_KA_RESPONSE_TIMER:
            assert(ev->events == EPOLLIN);
            ret = trigger_ka_failure(state, mev);
            break;
        case MED_EPOLL_LEA:
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                /* message from LEA -- hopefully a keep-alive response */
                ret = receive_handover(state, mev);
            } else if (ev->events & EPOLLOUT) {
                ret = xmit_handover(state, mev);
            } else {
                ret == -1;
            }
            if (ret == -1) {
                med_agency_state_t *mas = (med_agency_state_t *)(mev->state);
                disconnect_handover(state, mas->parent);
            }
            break;

        case MED_EPOLL_PROVISIONER:
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLOUT) {
                ret = transmit_provisioner(state, mev);
            } else if (ev->events & EPOLLIN) {
                ret = receive_provisioner(state, mev);
            } else {
                ret = -1;
            }

            if (ret == -1) {
                logger(LOG_DAEMON,
                        "OpenLI mediator: disconnecting from provisioner.");
                free_provisioner(state->epoll_fd, &(state->provisioner));
            }
            break;
        case MED_EPOLL_COLLECTOR:
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                ret = receive_collector(state, mev);
            }
            if (ret == -1) {
                logger(LOG_DAEMON,
                        "OpenLI mediator: disconnecting from collector %d.",
                        mev->fd);
                drop_collector(mev);
            }
            break;
        default:
            logger(LOG_DAEMON,
                    "OpenLI Mediator: invalid fd triggering epoll event.");
            assert(0);
            return -1;
    }

    return ret;

}

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
        logger(LOG_DAEMON, "OpenLI mediator: getsockname() failed for listener socket: %s.",
                strerror(errno));
        return -1;
    }

    if ((ret = getnameinfo((struct sockaddr *)(&sa), salen, listenname,
            sizeof(listenname), NULL, 0, NI_NUMERICHOST)) < 0) {
        logger(LOG_DAEMON, "OpenLI mediator: getnameinfo() failed for listener socket: %s.",
                gai_strerror(ret));
        return -1;
    }
    meddeets.ipstr = listenname;

    /* The configured port should match though, so we can just use that. */
    meddeets.portstr = state->listenport;

    if (push_mediator_onto_net_buffer(prov->outgoing, &meddeets) == -1) {
        logger(LOG_DAEMON, "OpenLI mediator: unable to push mediator details to provisioner.");
        return -1;
    }

    if (justcreated) {
        return 0;
    }

    ev.data.ptr = prov->provev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, prov->provev->fd, &ev)
            == -1) {
        logger(LOG_DAEMON,
                "OpenLI mediator: failed to re-enable transmit on provisioner socket: %s.",
                strerror(errno));
        return -1;
    }

    return 0;
}

static int init_provisioner_connection(mediator_state_t *state, int sock) {

    struct epoll_event ev;
    mediator_prov_t *prov = (mediator_prov_t *)&(state->provisioner);

    if (sock == 0) {
        return 0;
    }

    prov->provev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
    prov->provev->fd = sock;
    prov->provev->fdtype = MED_EPOLL_PROVISIONER;
    prov->provev->state = NULL;

    prov->sentinfo = 0;
    prov->outgoing = create_net_buffer(NETBUF_SEND, sock);
    prov->incoming = create_net_buffer(NETBUF_RECV, sock);

    ev.data.ptr = prov->provev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sock, &ev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI mediator: failed to register provisioner socket: %s.",
                strerror(errno));
        return -1;
    }

    if (push_auth_onto_net_buffer(prov->outgoing,
                OPENLI_PROTO_MEDIATOR_AUTH) == -1) {
        logger(LOG_DAEMON, "OpenLI mediator: unable to push auth message for provisioner.");
        return -1;
    }

    return send_mediator_listen_details(state, 1);
}

static int reload_provisioner_socket_config(mediator_state_t *currstate,
        mediator_state_t *newstate) {

    struct epoll_event ev;
    int changed = 0;
    liid_map_t *m, *tmp;

    if (strcmp(newstate->provaddr, currstate->provaddr) != 0 ||
            strcmp(newstate->provport, currstate->provport) != 0) {

        /* Disconnect from provisioner and reset all state received
         * from the old provisioner (just to be safe). */

        HASH_ITER(hh, currstate->liids, m, tmp) {
            HASH_DEL(currstate->liids, m);
            if (m->ceasetimer) {
                halt_mediator_timer(currstate, m->ceasetimer);
                free(m->ceasetimer);
            }
            free(m->liid);
            free(m);
        }
        currstate->liids = NULL;

        free_provisioner(currstate->epoll_fd, &(currstate->provisioner));

        drop_all_agencies(currstate->agencies);
        currstate->agencies = libtrace_list_init(sizeof(mediator_agency_t));

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
        logger(LOG_DAEMON,
                "OpenLI mediator: provisioner socket configuration is unchanged.");
    }

    return changed;
}

static int reload_listener_socket_config(mediator_state_t *currstate,
        mediator_state_t *newstate) {

    struct epoll_event ev;
    int changed = 0;

    if (strcmp(newstate->listenaddr, currstate->listenaddr) != 0 ||
            strcmp(newstate->listenport, currstate->listenport) != 0) {

        /* Disconnect all collectors */
        drop_all_collectors(currstate->collectors);
        currstate->collectors = libtrace_list_init(
                sizeof(mediator_collector_t));


        /* Close listen socket */
        if (currstate->listenerev) {
            if (currstate->listenerev->fd != -1) {
                logger(LOG_DAEMON, "OpenLI mediator: closing listening socket on %s:%s",
                        currstate->listenaddr, currstate->listenport);
                if (epoll_ctl(currstate->epoll_fd, EPOLL_CTL_DEL,
                        currstate->listenerev->fd, &ev) == -1) {
                    logger(LOG_DAEMON,
                            "OpenLI mediator: failed to remove listener fd %d from epoll: %s",
                            currstate->listenerev->fd, strerror(errno));
                }
                close(currstate->listenerev->fd);
            }
            free(currstate->listenerev);
        }

        currstate->listenerev = NULL;

        /* Replace existing IP and port strings */
        free(currstate->listenaddr);
        free(currstate->listenport);
        currstate->listenaddr = strdup(newstate->listenaddr);
        currstate->listenport = strdup(newstate->listenport);

        /* Open new listen socket */
        if (start_collector_listener(currstate) < 0) {
            logger(LOG_DAEMON, "OpenLI mediator: Warning, listening socket did not restart. Will not be able to accept connections from collectors.");
            return -1;
        }
        changed = 1;
    }

    if (currstate->mediatorid != newstate->mediatorid) {
        logger(LOG_DAEMON,
                "OpenLI mediator: changing mediator ID from %u to %u",
                currstate->mediatorid, newstate->mediatorid);
        currstate->mediatorid = newstate->mediatorid;
        changed = 1;
    }

    if (!changed) {
        logger(LOG_DAEMON,
                "OpenLI mediator: inbound connection listening socket configuration is unchanged.");
    }

    return changed;
}

static int reload_mediator_config(mediator_state_t *currstate) {

    mediator_state_t newstate;
    int listenchanged = 0;
    int provchanged = 0;

    if (init_med_state(&newstate, currstate->conffile,
            currstate->mediatorname) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: error reloading config file for mediator.");
        return -1;
    }

    if ((provchanged = reload_provisioner_socket_config(currstate,
            &newstate)) < 0) {
        return -1;
    }

    if ((listenchanged = reload_listener_socket_config(currstate,
            &newstate)) < 0) {
        return -1;
    }

    if (listenchanged && !provchanged) {
        /* Need to re-announce our details */
        if (send_mediator_listen_details(currstate, 0) < 0) {
            return -1;
        }

    }

    clear_med_state(&newstate);
    return 0;

}

static void run(mediator_state_t *state) {

	int i, nfds;
	int timerfd;
	int timerexpired = 0;
	struct itimerspec its;
	struct epoll_event evs[64];
	struct epoll_event ev;
    int provfail = 0;
    struct timeval tv;
    uint32_t firstflush;

	ev.data.ptr = state->signalev;
	ev.events = EPOLLIN;

	if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->signalev->fd, &ev)
			== -1) {
		logger(LOG_DAEMON,
				"OpenLI: Failed to register signal socket: %s.",
				strerror(errno));
		return;
	}

    logger(LOG_DAEMON,
            "OpenLI: rotating pcap output files every %d minutes.",
            state->pcaprotatefreq);

    gettimeofday(&tv, NULL);
	state->timerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
	state->pcaptimerev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));

    firstflush = (((tv.tv_sec / 60) * 60) + 60) - tv.tv_sec;

    timerfd = epoll_add_timer(state->epoll_fd, firstflush, state->pcaptimerev);
    if (timerfd == -1) {
        logger(LOG_DAEMON,
                "OpenLI mediator: failed to create pcap rotation timer");
        return;
    }
    state->pcaptimerev->fd = timerfd;
    state->pcaptimerev->fdtype = MED_EPOLL_PCAP_TIMER;
    state->pcaptimerev->state = NULL;

	while (!mediator_halt) {
        if (reload_config) {
            if (reload_mediator_config(state) == -1) {
                break;
            }
            reload_config = 0;
        }

	    /* Attempt to connect to the provisioner */
        if (state->provisioner.provev == NULL) {
            int s = connect_socket(state->provaddr, state->provport, provfail,
                    0);
            if (s == -1) {
                logger(LOG_DAEMON,
                        "OpenLI mediator: unable to connect to provisioner.");
                break;
            }
            if (s == 0) {
                provfail = 1;
            }

            if (init_provisioner_connection(state, s) == -1) {
                destroy_net_buffer(state->provisioner.outgoing);
                destroy_net_buffer(state->provisioner.incoming);
                close(s);
                state->provisioner.provev->fd = -1;
                state->provisioner.outgoing = NULL;
                state->provisioner.incoming = NULL;
                break;
            }
        }

        /* Attempt to connect to the LEAs, if not already connected. */
        connect_agencies(state);

        timerfd = epoll_add_timer(state->epoll_fd, 1, state->timerev);
        if (timerfd == -1) {
            logger(LOG_DAEMON,
                "OpenLI: Failed to add timer to epoll in mediator.");
            break;
        }
        state->timerev->fd = timerfd;
        state->timerev->fdtype = MED_EPOLL_SIGCHECK_TIMER;
        state->timerev->state = NULL;
        timerexpired = 0;

        while (!timerexpired) {
            nfds = epoll_wait(state->epoll_fd, evs, 64, -1);
            if (nfds < 0) {
                logger(LOG_DAEMON,
						"OpenLI: error while waiting for epoll events in mediator: %s.",
                        strerror(errno));
                return;
            }

            for (i = 0; i < nfds; i++) {
                timerexpired = check_epoll_fd(state, &(evs[i]));
                if (timerexpired == -1) {
                    break;
                }
            }
        }

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, timerfd, &ev) == -1) {
            logger(LOG_DAEMON,
                "OpenLI: unable to remove mediator timer from epoll set: %s",
                strerror(errno));
            return;
        }

        close(timerfd);
		state->timerev->fd = -1;
    }

}

static void halt_pcap_outputs(pcap_thread_state_t *pstate) {

    active_pcap_output_t *out, *tmp;

    HASH_ITER(hh, pstate->active, out, tmp) {
        HASH_DELETE(hh, pstate->active, out);
        free(out->liid);
        trace_destroy_output(out->out);
        free(out);
    }
}

static int open_pcap_output_file(pcap_thread_state_t *pstate,
        active_pcap_output_t *act) {

    char uri[4096];
    int compressmethod = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    int compresslevel = 1;
    struct timeval tv;

    if (pstate->dir == NULL) {
        if (!pstate->dirwarned) {
            logger(LOG_DAEMON,
                    "OpenLI mediator: pcap directory is not configured so will not write any pcap files.");
            pstate->dirwarned = 1;
        }
        return -1;
    }

    if (act == NULL || act->liid == NULL) {
        logger(LOG_DAEMON,
                "OpenLI mediator: attempted to open a pcap trace file for an invalid pcap output.");
        return -1;
    }

    gettimeofday(&tv, NULL);

    snprintf(uri, 4096, "pcapfile:%s/openli-%s-%u.pcap.gz", pstate->dir,
            act->liid, tv.tv_sec);
    act->out = trace_create_output(uri);
    if (trace_is_err_output(act->out)) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_DAEMON,
                "OpenLI mediator: Error opening %s for writing trace file: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    if (trace_config_output(act->out, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
            &compressmethod) == -1) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_DAEMON,
                "OpenLI mediator: Error configuring compression for writing trace file %s: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    if (trace_config_output(act->out, TRACE_OPTION_OUTPUT_COMPRESS,
            &compresslevel) == -1) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_DAEMON,
                "OpenLI mediator: Error configuring compression for writing trace file %s: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    if (trace_start_output(act->out) == -1) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_DAEMON,
                "OpenLI mediator: Error starting output trace file %s: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    logger(LOG_DAEMON, "OpenLI mediator: opened new trace file %s for LIID %s",
            uri, act->liid);

    return 0;

pcaptraceerr:
    trace_destroy_output(act->out);
    act->out = NULL;
    return -1;
}

static active_pcap_output_t *create_new_pcap_output(pcap_thread_state_t *pstate,
        char *liid) {

    active_pcap_output_t *act;

    act = (active_pcap_output_t *)malloc(sizeof(active_pcap_output_t));
    act->liid = strdup(liid);

    if (open_pcap_output_file(pstate, act) == -1) {
        free(act->liid);
        free(act);
        return NULL;
    }
    HASH_ADD_KEYPTR(hh, pstate->active, act->liid, strlen(act->liid), act);
    return act;
}

static void write_pcap_packet(pcap_thread_state_t *pstate,
        mediator_pcap_msg_t *pcapmsg) {

    uint32_t pdulen;
    char liidspace[1024];
    char ccname[128];
    active_pcap_output_t *pcapout;

    if (pcapmsg->msgbody == NULL) {
        return;
    }

    if (pstate->decoder == NULL) {
        pstate->decoder = wandder_create_etsili_decoder();
    }

    wandder_attach_etsili_buffer(pstate->decoder, pcapmsg->msgbody,
            pcapmsg->msglen, false);
    pdulen = wandder_etsili_get_pdu_length(pstate->decoder);
    if (pdulen == 0 || pcapmsg->msglen < pdulen) {
        logger(LOG_DAEMON,
                "OpenLI mediator: pcap thread received incomplete ETSI CC?");
        return;
    }

    if (wandder_etsili_get_liid(pstate->decoder, liidspace, 1024) == NULL) {
        logger(LOG_DAEMON,
                "OpenLI mediator: unable to find LIID for ETSI CC in pcap thread");
        return;
    }

    HASH_FIND(hh, pstate->active, liidspace, strlen(liidspace), pcapout);
    if (!pcapout) {
        pcapout = create_new_pcap_output(pstate, liidspace);
    }

    if (pcapout) {
        uint8_t *rawip;
        uint32_t cclen;

        if (!pstate->packet) {
            pstate->packet = trace_create_packet();
        }

        /* turn the ETSI CC into a pcap packet */
        rawip = wandder_etsili_get_cc_contents(pstate->decoder, &cclen,
                ccname, 128);
        if (cclen > 65535) {
            logger(LOG_DAEMON,
                    "OpenLI mediator: ETSI CC record is too large to write as a pcap packet -- possibly corrupt.");
        } else {
            trace_construct_packet(pstate->packet, TRACE_TYPE_NONE,
                    (const void *)rawip, (uint16_t)cclen);

            /* write resulting packet to libtrace output */
            if (trace_write_packet(pcapout->out, pstate->packet) < 0) {
                libtrace_err_t err = trace_get_err_output(pcapout->out);
                logger(LOG_DAEMON,
                        "OpenLI mediator: error while writing packet to pcap trace file: %s",
                        err.problem);
                trace_destroy_output(pcapout->out);
                HASH_DELETE(hh, pstate->active, pcapout);
                free(pcapout->liid);
                free(pcapout);
            }
        }
    }

    free(pcapmsg->msgbody);
}

static void pcap_flush_traces(pcap_thread_state_t *pstate) {
    active_pcap_output_t *pcapout, *tmp;

    HASH_ITER(hh, pstate->active, pcapout, tmp) {
        if (trace_flush_output(pcapout->out) < 0) {
            libtrace_err_t err = trace_get_err_output(pcapout->out);
            logger(LOG_DAEMON,
                    "OpenLI mediator: error while flushing pcap trace file: %s",
                    err.problem);
            trace_destroy_output(pcapout->out);
            HASH_DELETE(hh, pstate->active, pcapout);
            free(pcapout->liid);
            free(pcapout);
        }
    }
}

static void pcap_rotate_traces(pcap_thread_state_t *pstate) {
    active_pcap_output_t *pcapout, *tmp, *rotated;

    HASH_ITER(hh, pstate->active, pcapout, tmp) {
        HASH_DELETE(hh, pstate->active, pcapout);
        trace_destroy_output(pcapout->out);
        if (open_pcap_output_file(pstate, pcapout) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI mediator: error while rotating pcap trace file");

            trace_destroy_output(pcapout->out);
            HASH_DELETE(hh, pstate->active, pcapout);
            free(pcapout->liid);
            free(pcapout);
        }
    }
}

static void *start_pcap_thread(void *params) {

    pcap_thread_state_t pstate;
    mediator_pcap_msg_t pcapmsg;

    pstate.active = NULL;
    pstate.dir = NULL;
    pstate.dirwarned = 0;
    pstate.inqueue = (libtrace_message_queue_t *)params;
    pstate.decoder = NULL;
    pstate.packet = NULL;

    while (mediator_halt == 0) {
        if (libtrace_message_queue_try_get(pstate.inqueue,
                (void *)&pcapmsg) == LIBTRACE_MQ_FAILED) {
            usleep(500);
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_HALT) {
            break;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_FLUSH) {
            pcap_flush_traces(&pstate);
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_ROTATE) {
            pcap_rotate_traces(&pstate);
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_CHANGE_DIR) {
            if (pstate.dir) {
                free(pstate.dir);
                if (strcmp(pstate.dir, (char *)pcapmsg.msgbody) != 0) {
                    halt_pcap_outputs(&pstate);
                }
            }
            pstate.dir = (char *)pcapmsg.msgbody;
            if (pstate.dir) {
                logger(LOG_DAEMON,
                        "OpenLI mediator: pcap trace files are now being written to %s",
                        pstate.dir);
            } else {
                logger(LOG_DAEMON,
                        "OpenLI mediator: pcap trace file directory has been set to NULL");
            }
            continue;
        }

        write_pcap_packet(&pstate, &pcapmsg);
    }

    if (pstate.dir) {
        free(pstate.dir);
        halt_pcap_outputs(&pstate);
    }
    if (pstate.decoder) {
        wandder_free_etsili_decoder(pstate.decoder);
    }
    if (pstate.packet) {
        trace_destroy_packet(pstate.packet);
    }
    logger(LOG_DAEMON, "OpenLI mediator: exiting pcap thread.");
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    char *mediatorid = NULL;
    sigset_t sigblock;
    int todaemon = 0;

    mediator_state_t medstate;
    mediator_pcap_msg_t pcapmsg;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "daemonise", 0, 0, 'd'},
            { NULL, 0, 0, 0},
        };

        int c = getopt_long(argc, argv, "c:dm:h", long_options, &optind);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'c':
                configfile = optarg;
                break;
            case 'm':
                mediatorid = optarg;
                break;
            case 'd':
                todaemon = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            default:
                logger(LOG_DAEMON, "OpenLI: unsupported option: %c",
                        c);
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

    if (todaemon) {
        daemonise(argv[0]);
    }

    if (mediatorid == NULL) {
        mediatorid = "unknown";
    }

    sigemptyset(&sigblock);
    sigaddset(&sigblock, SIGHUP);
    sigaddset(&sigblock, SIGTERM);
    sigaddset(&sigblock, SIGINT);
    sigprocmask(SIG_BLOCK, &sigblock, NULL);

    if (init_med_state(&medstate, configfile, mediatorid) == -1) {
        logger(LOG_DAEMON, "OpenLI: Error initialising mediator.");
        return 1;
    }

    if (medstate.pcapdirectory != NULL) {
        memset(&pcapmsg, 0, sizeof(pcapmsg));
        pcapmsg.msgtype = PCAP_MESSAGE_CHANGE_DIR;
        pcapmsg.msgbody = (uint8_t *)strdup(medstate.pcapdirectory);
        pcapmsg.msglen = strlen(medstate.pcapdirectory);

        libtrace_message_queue_put(&(medstate.pcapqueue), &pcapmsg);
    }

    pthread_create(&(medstate.pcapthread), NULL, start_pcap_thread,
            &(medstate.pcapqueue));

    if (start_collector_listener(&medstate) == -1) {
        logger(LOG_DAEMON,
                "OpenLI Mediator: could not start collector listener socket.");
        return 1;
    }

    run(&medstate);
    clear_med_state(&medstate);

    pthread_join(medstate.pcapthread, NULL);
    logger(LOG_DAEMON, "OpenLI: Mediator '%s' has exited.", mediatorid);
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
