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

static inline char *get_event_description(prov_epoll_ev_t *pev) {
    if (pev->fdtype == PROV_EPOLL_MEDIATOR) return "mediator";
    if (pev->fdtype == PROV_EPOLL_COLLECTOR) return "collector";
    if (pev->fdtype == PROV_EPOLL_SIGNAL) return "signal";
    if (pev->fdtype == PROV_EPOLL_FD_TIMER) return "auth timer";
    if (pev->fdtype == PROV_EPOLL_UPDATE) return "updater";
    if (pev->fdtype == PROV_EPOLL_MAIN_TIMER) return "main timer";
    return "unknown";
}

static inline int enable_epoll_write(provision_state_t *state,
        prov_epoll_ev_t *pev) {
    struct epoll_event ev;

    ev.data.ptr = (void *)pev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, pev->fd, &ev) == -1) {
        return -1;
    }

    return 0;
}

static void create_socket_state(prov_epoll_ev_t *pev, int authtimerfd) {

    prov_sock_state_t *cs = (prov_sock_state_t *)malloc(
            sizeof(prov_sock_state_t));

    cs->incoming = create_net_buffer(NETBUF_RECV, pev->fd);
    cs->outgoing = create_net_buffer(NETBUF_SEND, pev->fd);
    cs->trusted = 0;
    cs->halted = 0;
    cs->authfd = authtimerfd;
    cs->mainfd = pev->fd;
    cs->clientrole = pev->fdtype;

    pev->state = cs;

}

static void free_socket_state(prov_epoll_ev_t *pev) {
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->state);

    if (cs) {
        destroy_net_buffer(cs->incoming);
        destroy_net_buffer(cs->outgoing);
        free(cs);
    }

}

static int liid_hash_sort(liid_hash_t *a, liid_hash_t *b) {

    int x;

    x = strcmp(a->agency, b->agency);
    if (x != 0) {
        return x;
    }
    return strcmp(a->liid, b->liid);
}

static int map_intercepts_to_leas(provision_state_t *state) {

    int failed = 0;
    libtrace_list_node_t *intn;
    ipintercept_t *ipint;

    intn = state->ipintercepts->head;

    while (intn) {
        liid_hash_t *h;
        ipint = (ipintercept_t *)(intn->data);
        intn = intn->next;

        /* TODO check if targetagency is legit? */

        h = (liid_hash_t *)malloc(sizeof(liid_hash_t));
        h->agency = ipint->targetagency;
        h->liid = ipint->liid;
        HASH_ADD_STR(state->liid_map, agency, h);
    }

    HASH_SORT(state->liid_map, liid_hash_sort);

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
    int ret = 0;

    state->conffile = configfile;

    state->epoll_fd = epoll_create1(0);
    state->ipintercepts = libtrace_list_init(sizeof(ipintercept_t));
    state->mediators = libtrace_list_init(sizeof(prov_mediator_t));
    state->collectors = libtrace_list_init(sizeof(prov_collector_t));
    state->leas = libtrace_list_init(sizeof(liagency_t));

    state->dropped_collectors = 0;
    state->dropped_mediators = 0;

    state->liid_map = NULL;

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

static int update_mediator_details(provision_state_t *state, uint8_t *medmsg,
        uint16_t msglen, int medfd) {

    openli_mediator_t *med = (openli_mediator_t *)malloc(
            sizeof(openli_mediator_t));
    libtrace_list_node_t *n;
    prov_mediator_t *provmed = NULL;
    int updatereq = 0;

    if (decode_mediator_announcement(medmsg, msglen, med) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: provisioner received bogus mediator announcement.");
        free(med);
        return -1;
    }

    /* Find the corresponding mediator in our mediator list */
    n = state->mediators->head;

    while (n) {
        provmed = (prov_mediator_t *)(n->data);
        n = n->next;

        if (provmed->fd != medfd) {
            continue;
        }

        if (provmed->details == NULL) {
            provmed->details = med;
            updatereq = 1;
            break;
        }

        if (provmed->commev->fd == medfd) {
            logger(LOG_DAEMON,
                    "OpenLI: received multiple announcements for mediator %d?",
                    medfd);
        }
        free(provmed->details);
        provmed->details = med;
        updatereq = 1;
        break;
    }

    if (!updatereq) {
        return 0;
    }

    /* All collectors must now know about this mediator */
    n = state->collectors->head;

    while (n) {
        prov_collector_t *col = (prov_collector_t *)(n->data);
        prov_sock_state_t *cs = (prov_sock_state_t *)(col->commev->state);

        n = n->next;
        if (col->commev->fd == -1) {
            continue;
        }

        if (cs->trusted == 0 || cs->mainfd == -1) {
            continue;
        }

        if (push_mediator_onto_net_buffer(cs->outgoing, provmed->details) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector.",
                    provmed->details->ipstr, provmed->details->portstr);
            return -1;
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI provisioner: cannot enable epoll write event to transmit mediator update to collector: %s.",
                    strerror(errno));
            return -1;
        }

        printf("sent mediator %u %s:%s to collector %d\n",
                provmed->details->mediatorid, provmed->details->ipstr,
                provmed->details->portstr, col->commev->fd);
    }
    return 0;
}

static void free_all_mediators(libtrace_list_t *m) {

    libtrace_list_node_t *n;
    prov_mediator_t *med;

    n = m->head;
    while (n) {
        med = (prov_mediator_t *)(n->data);
        free_socket_state(med->commev);
        free_openli_mediator(med->details);
        if (med->commev->fd != -1) {
            close(med->commev->fd);
        }
        free(med->commev);
        n = n->next;
    }

    libtrace_list_deinit(m);
}

static void halt_auth_timer(provision_state_t *state, prov_sock_state_t *cs) {
    struct epoll_event ev;

    if (cs->authfd == -1) {
        return;
    }


    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, cs->authfd, &ev) < 0) {
        logger(LOG_DAEMON,
                "OpenLI: unable to remove collector fd from epoll: %s.",
                strerror(errno));
    }

    close(cs->authfd);
    cs->authfd = -1;
}

static void stop_all_collectors(libtrace_list_t *c) {

    /* TODO send disconnect messages to all collectors? */
    libtrace_list_node_t *n;
    prov_collector_t *col;

    n = c->head;
    while (n) {
        col = (prov_collector_t *)n->data;
        free_socket_state(col->commev);
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
        if (lea->hi2_ipstr) {
            free(lea->hi2_ipstr);
        }
        if (lea->hi2_portstr) {
            free(lea->hi2_portstr);
        }
        if (lea->hi3_ipstr) {
            free(lea->hi3_ipstr);
        }
        if (lea->hi3_portstr) {
            free(lea->hi3_portstr);
        }
        if (lea->agencyid) {
            free(lea->agencyid);
        }
        n = n->next;
    }

    libtrace_list_deinit(l);
}

static void clear_prov_state(provision_state_t *state) {

    liid_hash_t *h, *tmp;

    HASH_ITER(hh, state->liid_map, h, tmp) {
        HASH_DEL(state->liid_map, h);
        free(h);
    }

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
        if (state->timerfd->fd != -1) {
            close(state->timerfd->fd);
        }
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

static int push_all_mediators(libtrace_list_t *mediators, net_buffer_t *nb) {

    libtrace_list_node_t *n;
    prov_mediator_t *pmed;

    n = mediators->head;
    while (n) {
        pmed = (prov_mediator_t *)(n->data);
        n = n->next;
        if (pmed->details == NULL) {
            continue;
        }
        if (push_mediator_onto_net_buffer(nb, pmed->details) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector.",
                    pmed->details->ipstr, pmed->details->portstr);
            return -1;
        }
    }
    if (push_nomore_mediators(nb) < 0) {
        logger(LOG_DAEMON,
                "OpenLI provisioner: error pushing end of mediators onto buffer for writing to collector.");
        return -1;
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

        if (cept->active == 0) {
            continue;
        }

        if (push_ipintercept_onto_net_buffer(nb, cept) < 0) {
            logger(LOG_DAEMON,
                    "OpenLI provisioner: error pushing IP intercept %s onto buffer for writing to collector.",
                    cept->liid);
            return -1;
        }
        n = n->next;
    }
    if (push_nomore_intercepts(nb) < 0) {
        logger(LOG_DAEMON,
                "OpenLI provisioner: error pushing end of intercepts onto buffer for writing to collector.");
        return -1;
    }

    return 0;
}

static int respond_collector_auth(provision_state_t *state,
        prov_epoll_ev_t *pev, net_buffer_t *outgoing) {

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

    if (enable_epoll_write(state, pev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: unable to enable epoll write event for newly authed collector on fd %d: %s",
                pev->fd, strerror(errno));
        return -1;
    }

    return 0;

}

static int respond_mediator_auth(provision_state_t *state,
        prov_epoll_ev_t *pev, net_buffer_t *outgoing) {

    libtrace_list_node_t *n;
    char *lastlea = NULL;
    liid_hash_t *h;

    /* Mediator just authed successfully, so we can safely send it details
     * on any LEAs that we know about */
    n = state->leas->head;
    while (n) {
        liagency_t *lea = (liagency_t *)(n->data);
        n = n->next;

        if (push_lea_onto_net_buffer(outgoing, lea) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error while buffering LEA details to send from provisioner to mediator.");
            return -1;
        }
    }

    h = state->liid_map;
    while (h != NULL) {
        if (push_liid_mapping_onto_net_buffer(outgoing, h->agency, h->liid)
                == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error while buffering LIID mappings to send to mediator.");
            return -1;
        }
        h = h->hh.next;
    }

    /* We also need to send any LIID -> LEA mappings that we know about */


    /* Update our epoll event for this mediator to allow transmit. */
    if (enable_epoll_write(state, pev) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: unable to enable epoll write event for newly authed mediator on fd %d: %s",
                pev->fd, strerror(errno));
        return -1;
    }

    return 0;
}

static int receive_collector(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->state);
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
        halt_auth_timer(state, cs);
        return respond_collector_auth(state, pev, cs->outgoing);
   }

   return 0;
}

static int receive_mediator(provision_state_t *state, prov_epoll_ev_t *pev) {
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->state);
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
                        "OpenLI: error receiving message from mediator.");
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_MEDIATOR_AUTH:
                if (internalid != OPENLI_MEDIATOR_MAGIC) {
                    logger(LOG_DAEMON,
                            "OpenLI: invalid auth code from mediator.");
                    return -1;
                }
                if (cs->trusted == 1) {
                    logger(LOG_DAEMON,
                            "OpenLI: warning -- double auth from mediator.");
                    assert(0);
                    break;
                }
                cs->trusted = 1;
                justauthed = 1;
                break;
            case OPENLI_PROTO_ANNOUNCE_MEDIATOR:
                if (update_mediator_details(state, msgbody, msglen,
                            pev->fd) == -1) {
                    return -1;
                }
                break;
            default:
                logger(LOG_DAEMON,
                        "OpenLI: unexpected message type %d received from mediator.",
                        msgtype);
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        logger(LOG_DAEMON, "OpenLI: mediator on fd %d auth success.",
                pev->fd);
        halt_auth_timer(state, cs);
        return respond_mediator_auth(state, pev, cs->outgoing);
    }

    return 0;
}

static int transmit_socket(provision_state_t *state, prov_epoll_ev_t *pev) {

    int ret;
    struct epoll_event ev;
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->state);

    ret = transmit_net_buffer(cs->outgoing);
    if (ret == -1) {
        logger(LOG_DAEMON,
                "OpenLI: error sending message from provisioner to %s.",
                get_event_description(pev));
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        ev.data.ptr = pev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, pev->fd, &ev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error disabling EPOLLOUT for %s fd %d: %s.",
                    get_event_description(pev), pev->fd, strerror(errno));
            return -1;
        }
    }

    return 1;
}

static inline int drop_generic_socket(provision_state_t *state,
        prov_epoll_ev_t *pev) {

    struct epoll_event ev;
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->state);

    if (cs->mainfd == -1) {
        halt_auth_timer(state, cs);
        return 0;
    }

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, cs->mainfd, &ev) < 0) {
        logger(LOG_DAEMON,
                "OpenLI: unable to remove collector fd from epoll: %s.",
                strerror(errno));
    }

    close(cs->mainfd);
    cs->mainfd = -1;
    pev->fd = -1;
    halt_auth_timer(state, cs);
    return 1;

}

static void drop_collector(provision_state_t *state, prov_epoll_ev_t *pev) {

    state->dropped_collectors += (drop_generic_socket(state, pev));

    /* If we have a decent number of dropped collectors, re-create our
     * collector list to remove all of the useless items.
     *
     * TODO
     */

}

static void drop_mediator(provision_state_t *state, prov_epoll_ev_t *pev) {

    state->dropped_mediators = drop_generic_socket(state, pev);

    /* If we have a decent number of dropped mediators, re-create our
     * mediator list to remove all of the useless items.
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
        col.authev = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

        col.commev->fdtype = PROV_EPOLL_COLLECTOR;
        col.commev->fd = newfd;
        col.commev->state = NULL;

        col.authev->fdtype = PROV_EPOLL_FD_TIMER;
        col.authev->fd = epoll_add_timer(state->epoll_fd, 5, col.authev);
        /* Create outgoing and incoming buffer state */
        create_socket_state(col.commev, col.authev->fd);
        col.authev->state = col.commev->state;


        /* Add fd to epoll */
        ev.data.ptr = (void *)col.commev;
        ev.events = EPOLLIN | EPOLLRDHUP;
        /* recv only until we trust the collector */

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

        med.authev = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

        med.authev->fdtype = PROV_EPOLL_FD_TIMER;
        med.authev->fd = epoll_add_timer(state->epoll_fd, 5, med.authev);
        /* Create outgoing and incoming buffer state */
        create_socket_state(med.commev, med.authev->fd);
        med.authev->state = med.commev->state;

        /* Add fd to epoll */
        ev.data.ptr = (void *)med.commev;
        ev.events = EPOLLIN | EPOLLRDHUP; /* recv only until we trust the mediator */

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

    sockfd  = create_listener(state->listenaddr, state->listenport,
            "provisioner");
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

    sockfd  = create_listener(state->pushaddr, state->pushport, "II push");
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

    sockfd  = create_listener(state->mediateaddr, state->mediateport,
            "incoming mediator");
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

static void expire_unauthed(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->state);

    if (cs->clientrole == PROV_EPOLL_COLLECTOR) {
        logger(LOG_DAEMON,
                "OpenLI Provisioner: dropping unauthed collector.");
        drop_collector(state, pev);
    }

    if (cs->clientrole == PROV_EPOLL_MEDIATOR) {
        logger(LOG_DAEMON,
                "OpenLI Provisioner: dropping unauthed mediator.");
        drop_mediator(state, pev);
    }

}

static int check_epoll_fd(provision_state_t *state, struct epoll_event *ev) {

    int ret = 0;
    prov_epoll_ev_t *pev = (prov_epoll_ev_t *)(ev->data.ptr);

    /* TODO check for EPOLLRDHUP etc. */
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
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                ret = receive_collector(state, pev);
            }
            else if (ev->events & EPOLLOUT) {
                ret = transmit_socket(state, pev);
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
        case PROV_EPOLL_FD_TIMER:
            if (ev->events & EPOLLIN) {
                expire_unauthed(state, pev);
            } else {
                logger(LOG_DAEMON,
                        "OpenLI Provisioner: collector auth timer has failed.");
                return -1;
            }
            break;

        case PROV_EPOLL_MEDIATOR:
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                ret = receive_mediator(state, pev);
            } else if (ev->events & EPOLLOUT) {
                ret = transmit_socket(state, pev);
            } else {
                ret = -1;
            }
            if (ret == -1) {
                logger(LOG_DAEMON,
                        "OpenLI Provisioner: disconnecting mediator %d.",
                        pev->fd);
                drop_mediator(state, pev);
            }
            break;
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
        state->timerfd->fd = -1;
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
