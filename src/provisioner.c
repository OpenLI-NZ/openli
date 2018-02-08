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
 * GNU Lesser General Public License for more details.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <errno.h>
#include <libtrace/linked_list.h>
#include <unistd.h>
#include <assert.h>

#include "configparser.h"
#include "logger.h"
#include "intercept.h"
#include "provisioner.h"
#include "util.h"
#include "agency.h"
#include "netcomms.h"
#include "mediator.h"

volatile int provisioner_halt = 0;
volatile int reload_config = 0;

static void halt_signal(int signal) {
    provisioner_halt = 1;
}

static void reload_signal(int signal) {
    reload_config = 1;
}

/* XXX these two functions look very similar right now, but avoid merging
 * them as there may be further state that we wish to retain for one but
 * not the other in the future.
 */

static void create_collector_state(prov_epoll_ev_t *pev) {

    prov_coll_state_t *cs = (prov_coll_state_t *)malloc(
            sizeof(prov_coll_state_t));

    cs->incoming = create_net_buffer(NETBUF_RECV, pev->fd);
    cs->outgoing = create_net_buffer(NETBUF_SEND, pev->fd);
    cs->trusted = 0;

    pev->state = cs;

}

static void create_mediator_state(prov_epoll_ev_t *pev) {

    prov_med_state_t *ms = (prov_med_state_t *)malloc(
            sizeof(prov_med_state_t));

    ms->incoming = create_net_buffer(NETBUF_RECV, pev->fd);
    ms->outgoing = create_net_buffer(NETBUF_SEND, pev->fd);
    ms->trusted = 0;

    pev->state = ms;

}

static void free_collector_state(prov_epoll_ev_t *pev) {
    prov_coll_state_t *cs = (prov_coll_state_t *)(pev->state);

    if (cs) {
        destroy_net_buffer(cs->incoming);
        destroy_net_buffer(cs->outgoing);
        free(cs);
    }

}

static void free_mediator_state(prov_epoll_ev_t *pev) {
    prov_med_state_t *ms = (prov_med_state_t *)(pev->state);

    if (ms) {
        destroy_net_buffer(ms->incoming);
        destroy_net_buffer(ms->outgoing);
        free(ms);
    }

}

static int map_intercepts_to_leas(provision_state_t *state) {

    int failed = 0;
    libtrace_list_node_t *intn;
    libtrace_list_node_t *lean;

    ipintercept_t *ipint;
    liagency_t *lea;

    /* Not the most efficient way of doing this, but the LEA list should
     * generally be pretty short (e.g. max of 4 for NZ) and we're only
     * going to do this once on startup.
     */

    intn = state->ipintercepts->head;

    while (intn) {
        ipint = (ipintercept_t *)(intn->data);

        lean = state->leas->head;
        while (lean) {
            lea = (liagency_t *)(lean->data);
            if (strcmp(lea->agencyid, ipint->targetagency) == 0) {
                libtrace_list_push_back(lea->knownliids, ipint->liid);
                break;
            }
            lean = lean->next;
        }

        if (lean == NULL) {
            logger(LOG_DAEMON,
                    "OpenLI: no such agency %s -- requested by intercept %s.",
                    ipint->targetagency, ipint->liid);
            failed ++;
        }
        intn = intn->next;
    }

    return failed;

}

void free_openli_mediator(openli_mediator_t *med) {
    if (!med) {
        return;
    }
    if (med->portstr) {
        free(med->portstr);
    }
    if (med->ipstr) {
        free(med->ipstr);
    }
    free(med);
}

static int init_prov_state(provision_state_t *state, char *configfile) {

    sigset_t sigmask;
    prov_mediator_t testwrap;
    openli_mediator_t *testmed = malloc(sizeof(testmed));
    int ret = 0;

    state->conffile = configfile;

    state->epoll_fd = epoll_create1(0);
    state->ipintercepts = libtrace_list_init(sizeof(ipintercept_t));
    state->mediators = libtrace_list_init(sizeof(prov_mediator_t));
    state->collectors = libtrace_list_init(sizeof(prov_collector_t));
    state->leas = libtrace_list_init(sizeof(liagency_t));

    state->dropped_collectors = 0;

    /* XXX temporary hardcoding of test "mediator" */
    testmed->mediatorid = 6001;
    testmed->ipstr = strdup("10.0.0.2");
    testmed->portstr = strdup("43332");

    testwrap.details = testmed;
    testwrap.commev = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));
    testwrap.commev->fdtype = PROV_EPOLL_MEDIATOR;
    testwrap.commev->fd = -1;
    testwrap.commev->state = NULL;

    libtrace_list_push_back(state->mediators, &testwrap);
    /* Three listening sockets
     *
     * listen:  collectors should connect to this socket to receive IIs
     * mediate: mediators should connect to this socket to receive mediation
     *          instructions
     * push:    new IIs or config changes will come via this socket
     */
    state->listenport = NULL;
    state->listenaddr = NULL;
    state->mediateport = NULL;
    state->mediateaddr = NULL;
    state->pushport = NULL;
    state->pushaddr = NULL;

    if (parse_provisioning_config(configfile, state) == -1) {
        return -1;
    }

    /*
     * XXX could also sanity check intercept->mediator mappings too...
     */
    if ((ret = map_intercepts_to_leas(state)) != 0) {
        logger(LOG_DAEMON,
                "OpenLI: failed to map %d intercepts to agencies. Exiting.",
                ret);
        return -1;
    }

    if (state->pushport == NULL) {
        state->pushport = strdup("8992");
    }
    if (state->listenport == NULL) {
        state->listenport = strdup("8993");
    }
    if (state->mediateport == NULL) {
        state->mediateport = strdup("8994");
    }

    state->clientfd = NULL;
    state->updatefd = NULL;
    state->mediatorfd = NULL;
    state->timerfd = NULL;

    /* Use an fd to catch signals during our main epoll loop, so that we
     * can provide our own signal handling without causing epoll_wait to
     * return EINTR.
     */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGHUP);

    state->signalfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));
    state->signalfd->fdtype = PROV_EPOLL_SIGNAL;
    state->signalfd->fd = signalfd(-1, &sigmask, 0);

    return 0;
}

static void free_all_mediators(libtrace_list_t *m) {

    libtrace_list_node_t *n;
    prov_mediator_t *med;

    n = m->head;
    while (n) {
        med = (prov_mediator_t *)(n->data);
        free_mediator_state(med->commev);
        free_openli_mediator(med->details);
        if (med->commev->fd != -1) {
            close(med->commev->fd);
        }
        free(med->commev);
        n = n->next;
    }

    libtrace_list_deinit(m);
}

static void stop_all_collectors(libtrace_list_t *c) {

    /* TODO send disconnect messages to all collectors? */
    libtrace_list_node_t *n;
    prov_collector_t *col;

    n = c->head;
    while (n) {
        col = (prov_collector_t *)n->data;
        free_collector_state(col->commev);
        if (col->commev->fd != -1) {
            close(col->commev->fd);
        }
        free(col->commev);
        n = n->next;
    }

    libtrace_list_deinit(c);
}

static void free_all_leas(libtrace_list_t *l) {
    libtrace_list_node_t *n;
    liagency_t *lea;

    n = l->head;
    while (n) {
        lea = (liagency_t *)n->data;
        libtrace_list_deinit(lea->knownliids);
        if (lea->ipstr) {
            free(lea->ipstr);
        }
        if (lea->portstr) {
            free(lea->portstr);
        }
        if (lea->agencyid) {
            free(lea->agencyid);
        }
        n = n->next;
    }

    libtrace_list_deinit(l);
}

static void clear_prov_state(provision_state_t *state) {

    free_all_intercepts(state->ipintercepts);
    stop_all_collectors(state->collectors);
    free_all_mediators(state->mediators);
    free_all_leas(state->leas);

    close(state->epoll_fd);

    if (state->clientfd) {
        close(state->clientfd->fd);
        free(state->clientfd);
    }
    if (state->updatefd) {
        close(state->updatefd->fd);
        free(state->updatefd);
    }
    if (state->mediatorfd) {
        close(state->mediatorfd->fd);
        free(state->mediatorfd);
    }
    if (state->timerfd) {
        close(state->timerfd->fd);
        free(state->timerfd);
    }
    if (state->signalfd) {
        close(state->signalfd->fd);
        free(state->signalfd);
    }

    if (state->pushport) {
        free(state->pushport);
    }
    if (state->pushaddr) {
        free(state->pushaddr);
    }
    if (state->listenport) {
        free(state->listenport);
    }
    if (state->listenaddr) {
        free(state->listenaddr);
    }
    if (state->mediateaddr) {
        free(state->mediateaddr);
    }
    if (state->mediateport) {
        free(state->mediateport);
    }

}

static int create_listener(char *addr, char *port) {
    struct addrinfo hints, *res;
    int sockfd;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (addr == NULL) {
        hints.ai_flags = AI_PASSIVE;
    }

    if (getaddrinfo(addr, port, &hints, &res) == -1)
    {
        logger(LOG_DAEMON, "OpenLI: Error while trying to getaddrinfo for main listening socket.");
        return -1;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while creating main listening socket: %s.",
                strerror(errno));
        goto endlistener;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while setting options on main listening socket: %s",
                strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }


    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while trying to bind main listening socket: %s.",
                strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }

    if (listen(sockfd, 10) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while listening on main socket: %s.",
                strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }

endlistener:
    freeaddrinfo(res);
    return sockfd;
}

static int push_all_mediators(libtrace_list_t *mediators, net_buffer_t *nb) {

    libtrace_list_node_t *n;
    openli_mediator_t *med;

    n = mediators->head;
    while (n) {
        med = (openli_mediator_t *)(n->data);

        if (push_mediator_onto_net_buffer(nb, med) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector.",
                    med->ipstr, med->portstr);
            return -1;
        }

        n = n->next;
    }
    return 0;
}

static int push_all_ipintercepts(libtrace_list_t *intercepts,
        net_buffer_t *nb) {

    libtrace_list_node_t *n;
    ipintercept_t *cept;

    n = intercepts->head;
    while (n) {
        cept = (ipintercept_t *)(n->data);

        if (push_ipintercept_onto_net_buffer(nb, cept) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI provisioner: error pushing IP intercept %s onto buffer for writing to collector.",
                    cept->liid);
            return -1;
        }

        n = n->next;
    }
    return 0;
}

static int respond_collector_auth(provision_state_t *state,
        prov_epoll_ev_t *pev, net_buffer_t *outgoing) {

    struct epoll_event ev;

    /* Collector just authed successfully, so we can safely shovel all
     * of known mediators and active intercepts to it.
     */

    if (libtrace_list_get_size(state->mediators) +
            libtrace_list_get_size(state->ipintercepts) == 0) {
        return 0;
    }

    if (push_all_mediators(state->mediators, outgoing) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: unable to queue mediators to be sent to new collector on fd %d",
                pev->fd);
        return -1;
    }

    if (push_all_ipintercepts(state->ipintercepts, outgoing) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: unable to queue IP intercepts to be sent to new collector on fd %d",
                pev->fd);
        return -1;
    }

    ev.data.ptr = (void *)pev;
    ev.events = EPOLLIN | EPOLLOUT;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, pev->fd, &ev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: unable to enable epoll write event for newly authed collector on fd %d: %s",
                pev->fd, strerror(errno));
        return -1;
    }

    return 0;

}

static int receive_collector(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_coll_state_t *cs = (prov_coll_state_t *)(pev->state);
    uint8_t *msgbody;
    uint16_t msglen;
    uint64_t internalid;
    openli_proto_msgtype_t msgtype;
    uint8_t justauthed = 0;

    do {
        msgtype = receive_net_buffer(cs->incoming, &msgbody, &msglen,
                &internalid);
        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                logger(LOG_DAEMON,
                        "OpenLI: error receiving message from collector.");
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_COLLECTOR_AUTH:
                if (internalid != OPENLI_COLLECTOR_MAGIC) {
                    logger(LOG_DAEMON,
                            "OpenLI: invalid auth code from collector.");
                    return -1;
                }
                if (cs->trusted == 1) {
                    logger(LOG_DAEMON,
                            "OpenLI: warning -- double auth from collector.");
                    assert(0);
                    break;
                }
                cs->trusted = 1;
                justauthed = 1;
                break;
            default:
                logger(LOG_DAEMON,
                        "OpenLI: unexpected message type %d received from collector.",
                        msgtype);
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        logger(LOG_DAEMON, "OpenLI: collector on fd %d auth success.",
                pev->fd);
        return respond_collector_auth(state, pev, cs->outgoing);
   }

   return 0;
}

static int transmit_collector(provision_state_t *state, prov_epoll_ev_t *pev) {

    int ret;
    struct epoll_event ev;
    prov_coll_state_t *cs = (prov_coll_state_t *)(pev->state);

    ret = transmit_net_buffer(cs->outgoing);
    if (ret == -1) {
        logger(LOG_DAEMON,
                "OpenLI: error sending message from provisioner to collector.");
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        ev.data.ptr = pev;
        ev.events = EPOLLIN;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, pev->fd, &ev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error disabling EPOLLOUT for collector fd %d: %s.",
                    pev->fd, strerror(errno));
            return -1;
        }
    }

    return 1;
}

static void drop_collector(provision_state_t *state, prov_epoll_ev_t *pev) {

    struct epoll_event ev;
    prov_coll_state_t *cs = (prov_coll_state_t *)(pev->state);

    if (pev->fd == -1) {
        return;
    }

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, pev->fd, &ev) < 0) {
        logger(LOG_DAEMON,
                "OpenLI: unable to remove collector fd from epoll: %s.",
                strerror(errno));
    }

    close(pev->fd);
    pev->fd = -1;

    state->dropped_collectors ++;

    /* If we have a decent number of dropped collectors, re-create our
     * collector list to remove all of the useless items.
     *
     * TODO
     */

}

static int accept_collector(provision_state_t *state) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    prov_collector_t col;
    libtrace_list_node_t *n;
    struct epoll_event ev;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of collectors. Push all active intercepts
     * out to the collector. */
    newfd = accept(state->clientfd->fd, (struct sockaddr *)&saddr, &socklen);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
            0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_DAEMON, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
    } else {
        logger(LOG_DAEMON, "OpenLI: provisioner accepted connection from collector %s.",
                strbuf);
    }

    if (newfd >= 0) {
        col.commev = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

        col.commev->fdtype = PROV_EPOLL_COLLECTOR;
        col.commev->fd = newfd;
        col.commev->state = NULL;

        /* Create outgoing and incoming buffer state */
        create_collector_state(col.commev);

        /* Add fd to epoll */
        ev.data.ptr = (void *)col.commev;
        ev.events = EPOLLIN; /* recv only until we trust the collector */

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, col.commev->fd,
                    &ev) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI: unable to add collector fd to epoll: %s.",
                    strerror(errno));
            close(newfd);
            return -1;
        }

        libtrace_list_push_back(state->collectors, &col);
    }

    return newfd;
}

static int accept_mediator(provision_state_t *state) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    prov_mediator_t med;
    libtrace_list_node_t *n;
    struct epoll_event ev;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of mediators. Push all known LEAs to the
     * mediator, as well as any intercept->LEA mappings that we have.
     */
    newfd = accept(state->mediatorfd->fd, (struct sockaddr *)&saddr, &socklen);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
            0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_DAEMON, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
    } else {
        logger(LOG_DAEMON, "OpenLI: provisioner accepted connection from mediator %s.",
                strbuf);
    }

    if (newfd >= 0) {
        med.fd = newfd;
        med.details = NULL;     /* will receive this from mediator soon */
        med.commev = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

        med.commev->fdtype = PROV_EPOLL_MEDIATOR;
        med.commev->fd = newfd;
        med.commev->state = NULL;

        /* Create outgoing and incoming buffer state */
        create_mediator_state(med.commev);

        /* Add fd to epoll */
        ev.data.ptr = (void *)med.commev;
        ev.events = EPOLLIN; /* recv only until we trust the mediator */

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, med.fd, &ev) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI: unable to add mediator fd to epoll: %s.",
                    strerror(errno));
            close(newfd);
            return -1;
        }
        libtrace_list_push_back(state->mediators, &med);
    }

    return newfd;
}

static int accept_update(provision_state_t *state) {

    /* TODO write this! */
    return -1;
}

static int start_main_listener(provision_state_t *state) {

    struct epoll_event ev;
    int sockfd;

    state->clientfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    sockfd  = create_listener(state->listenaddr, state->listenport);
    if (sockfd == -1) {
        return -1;
    }

    state->clientfd->fd = sockfd;
    state->clientfd->fdtype = PROV_EPOLL_COLL_CONN;
    state->clientfd->state = NULL;

    ev.data.ptr = state->clientfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Failed to register main listening socket: %s.",
                strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int start_push_listener(provision_state_t *state) {
    struct epoll_event ev;
    int sockfd;

    state->updatefd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    sockfd  = create_listener(state->pushaddr, state->pushport);
    if (sockfd == -1) {
        return -1;
    }

    state->updatefd->fd = sockfd;
    state->updatefd->fdtype = PROV_EPOLL_UPDATE_CONN;
    state->updatefd->state = NULL;

    ev.data.ptr = state->updatefd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Failed to register push listening socket: %s.",
                strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int start_mediator_listener(provision_state_t *state) {
    struct epoll_event ev;
    int sockfd;

    state->mediatorfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    sockfd  = create_listener(state->mediateaddr, state->mediateport);
    if (sockfd == -1) {
        return -1;
    }

    state->mediatorfd->fd = sockfd;
    state->mediatorfd->fdtype = PROV_EPOLL_MEDIATE_CONN;
    state->mediatorfd->state = NULL;

    ev.data.ptr = state->mediatorfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Failed to register push listening socket: %s.",
                strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int process_signal(provision_state_t *state, int sigfd) {

    struct signalfd_siginfo si;
    int ret;

    ret = read(sigfd, &si, sizeof(si));
    if (ret < 0) {
        logger(LOG_DAEMON,
                "OpenLI provisioner: unable to read from signal fd: %s.",
                strerror(errno));
        return ret;
    }

    if (ret != sizeof(si)) {
        logger(LOG_DAEMON,
                "OpenLI provisioner: unexpected partial read from signal fd.");
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

static int check_epoll_fd(provision_state_t *state, struct epoll_event *ev) {

    int ret = 0;
    prov_epoll_ev_t *pev = (prov_epoll_ev_t *)(ev->data.ptr);

    switch(pev->fdtype) {
        case PROV_EPOLL_COLL_CONN:
            ret = accept_collector(state);
            break;
        case PROV_EPOLL_MEDIATE_CONN:
            ret = accept_mediator(state);
            break;
        case PROV_EPOLL_UPDATE_CONN:
            ret = accept_update(state);
            break;
        case PROV_EPOLL_MAIN_TIMER:
            if (ev->events & EPOLLIN) {
                return 1;
            }
            logger(LOG_DAEMON,
                    "OpenLI Provisioner: main epoll timer has failed.");
            return -1;
        case PROV_EPOLL_SIGNAL:
            ret = process_signal(state, pev->fd);
            break;
        case PROV_EPOLL_COLLECTOR:
            if (ev->events & EPOLLIN) {
                ret = receive_collector(state, pev);
            }
            else if (ev->events & EPOLLOUT) {
                ret = transmit_collector(state, pev);
            } else {
                ret = -1;
            }

            if (ret == -1) {
                logger(LOG_DAEMON,
                        "OpenLI Provisioner: disconnecting collector %d.",
                        pev->fd);
                drop_collector(state, pev);
            }
            break;

        case PROV_EPOLL_MEDIATOR:
        case PROV_EPOLL_FD_TIMER:
        case PROV_EPOLL_UPDATE:
            /* TODO all of the above */
            break;

        default:
            logger(LOG_DAEMON,
                    "OpenLI Provisioner: invalid fd triggering epoll event,");
            return -1;
    }

    return ret;

}

static void run(provision_state_t *state) {

    int i, nfds;
    int timerfd;
    int timerexpired = 0;
    struct itimerspec its;
    struct epoll_event evs[64];
    struct epoll_event ev;

    ev.data.ptr = state->signalfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->signalfd->fd, &ev)
                == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Failed to register signal socket: %s.",
                strerror(errno));
        return;
    }

    state->timerfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    while (!provisioner_halt) {
        if (reload_config) {

        }

        timerfd = epoll_add_timer(state->epoll_fd, 1, state->timerfd);
        if (timerfd == -1) {
            logger(LOG_DAEMON,
                "OpenLI: Failed to add timer to epoll in provisioner.");
            break;
        }
        state->timerfd->fd = timerfd;
        state->timerfd->fdtype = PROV_EPOLL_MAIN_TIMER;
        state->timerfd->state = NULL;
        timerexpired = 0;

        while (!timerexpired) {
            nfds = epoll_wait(state->epoll_fd, evs, 64, -1);
            if (nfds < 0) {
                logger(LOG_DAEMON, "OpenLI: error while checking for incoming connections on the provisioner: %s.",
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
                "OpenLI: unable to remove provisioner timer from epoll set: %s",
                strerror(errno));
            return;
        }

        close(timerfd);
    }

}

static void usage(char *prog) {
    fprintf(stderr, "Usage: %s -c configfile\n", prog);
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    sigset_t sigblock;

    provision_state_t provstate;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { NULL, 0, 0, 0},
        };

        int c = getopt_long(argc, argv, "c:h", long_options, &optind);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'c':
                configfile = optarg;
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

    sigemptyset(&sigblock);
    sigaddset(&sigblock, SIGHUP);
    sigaddset(&sigblock, SIGTERM);
    sigaddset(&sigblock, SIGINT);
    sigprocmask(SIG_BLOCK, &sigblock, NULL);


    if (init_prov_state(&provstate, configfile) == -1) {
        logger(LOG_DAEMON, "OpenLI: Error initialising provisioner.");
        return 1;
    }

    if (start_main_listener(&provstate) == -1) {
        logger(LOG_DAEMON, "OpenLI: Error, could not start listening socket.");
        return 1;
    }

    if (start_push_listener(&provstate) == -1) {
        logger(LOG_DAEMON, "OpenLI: Warning, push socket did not start. New intercepts cannot be received.");
    }

    if (start_mediator_listener(&provstate) == -1) {
        logger(LOG_DAEMON, "OpenLI: Warning, mediation socket did not start. Will not be able to control mediators.");
    }

    run(&provstate);

    clear_prov_state(&provstate);
    logger(LOG_DAEMON, "OpenLI: Provisioner has exited.");
}




// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
