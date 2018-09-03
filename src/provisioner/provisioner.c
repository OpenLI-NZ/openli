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
#include "coreserver.h"

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

    if (pev->fd == -1) {
        return 0;
    }

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

static inline liid_hash_t *add_liid_mapping(provision_state_t *state,
        char *liid, char *agency) {

    liid_hash_t *h;
    prov_agency_t *lea;

    h = (liid_hash_t *)malloc(sizeof(liid_hash_t));

    /* pcapdisk is a special agency that is not user-defined */
    if (strcmp(agency, "pcapdisk") != 0) {
        HASH_FIND_STR(state->leas, agency, lea);
        if (!lea) {
            logger(LOG_INFO,
                    "OpenLI: intercept %s is destined for an unknown agency: %s -- skipping.",
                    liid, agency);
            free(h);
            return NULL;
        }
    }

    h->agency = agency;
    h->liid = liid;
    HASH_ADD_KEYPTR(hh, state->liid_map, h->liid, strlen(h->liid), h);
    return h;
}

static int map_intercepts_to_leas(provision_state_t *state) {

    int failed = 0;
    ipintercept_t *ipint, *iptmp;
    voipintercept_t *vint;
    prov_agency_t *lea;

    /* Do IP Intercepts */
    HASH_ITER(hh_liid, state->ipintercepts, ipint, iptmp) {
        add_liid_mapping(state, ipint->common.liid, ipint->common.targetagency);
    }

    /* Now do the VOIP intercepts */
    for (vint = state->voipintercepts; vint != NULL; vint = vint->hh_liid.next)
    {
        add_liid_mapping(state, vint->common.liid, vint->common.targetagency);
    }

    /* Sort the final mapping nicely */
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
    state->mediators = libtrace_list_init(sizeof(prov_mediator_t));
    state->collectors = libtrace_list_init(sizeof(prov_collector_t));
    state->radiusservers = NULL;
    state->sipservers = NULL;
    state->voipintercepts = NULL;
    state->ipintercepts = NULL;

    state->dropped_collectors = 0;
    state->dropped_mediators = 0;

    state->liid_map = NULL;
    state->leas = NULL;

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
        logger(LOG_INFO, "OpenLI provisioner: error while parsing provisioner config in %s", configfile);
        return -1;
    }

    /*
     * XXX could also sanity check intercept->mediator mappings too...
     */
    if ((ret = map_intercepts_to_leas(state)) != 0) {
        logger(LOG_INFO,
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
    openli_mediator_t *prevmed = NULL;
    int updatereq = 0;
    int ret = 0;

    if (decode_mediator_announcement(medmsg, msglen, med) == -1) {
        logger(LOG_INFO,
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

        prevmed = provmed->details;
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

        if (prevmed) {
            /* The mediator has changed its details somehow, withdraw any
             * references to the old one.
             */
            if (push_mediator_withdraw_onto_net_buffer(cs->outgoing,
                    prevmed) < 0) {
                logger(LOG_INFO,
                        "OpenLI provisioner: error pushing mediator withdrawal %s:%s onto buffer for writing to collector.",
                        prevmed->ipstr, prevmed->portstr);
                ret = -1;
                break;
            }
        }

        if (push_mediator_onto_net_buffer(cs->outgoing, provmed->details) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector.",
                    provmed->details->ipstr, provmed->details->portstr);
            ret = -1;
            break;
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: cannot enable epoll write event to transmit mediator update to collector: %s.",
                    strerror(errno));
            ret = -1;
            break;
        }

    }
    if (prevmed) {
        free(prevmed);
    }
    return ret;
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
        free(med->authev);
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
        logger(LOG_INFO,
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

static void clear_prov_state(provision_state_t *state) {

    liid_hash_t *h, *tmp;
    prov_agency_t *h2, *tmp2;
    liagency_t *lea;

    HASH_ITER(hh, state->liid_map, h, tmp) {
        HASH_DEL(state->liid_map, h);
        free(h);
    }

    HASH_ITER(hh, state->leas, h2, tmp2) {
        HASH_DEL(state->leas, h2);
        lea = h2->ag;
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
        free(lea);
        free(h2);
    }

    free_all_ipintercepts(&(state->ipintercepts));
    free_all_voipintercepts(&(state->voipintercepts));
    stop_all_collectors(state->collectors);
    free_all_mediators(state->mediators);
    free_coreserver_list(state->radiusservers);
    free_coreserver_list(state->sipservers);

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

static int push_coreservers(coreserver_t *servers, uint8_t cstype,
        net_buffer_t *nb) {
    coreserver_t *cs, *tmp;

    HASH_ITER(hh, servers, cs, tmp) {
        if (push_coreserver_onto_net_buffer(nb, cs, cstype) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing %s server %s onto buffer for writing to collector.",
                    coreserver_type_to_string(cstype), cs->ipstr);
            return -1;
        }
    }
    return 0;
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
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector.",
                    pmed->details->ipstr, pmed->details->portstr);
            return -1;
        }
    }
    return 0;
}

static int push_all_sip_targets(net_buffer_t *nb, libtrace_list_t *targets,
        voipintercept_t *vint) {


    libtrace_list_node_t *n;
    openli_sip_identity_t *sipid;

    n = targets->head;
    while (n) {
        sipid = *((openli_sip_identity_t **)(n->data));
        n = n->next;

        if (push_sip_target_onto_net_buffer(nb, sipid, vint) < 0) {
            return -1;
        }
    }
    return 0;
}

static int push_all_voipintercepts(voipintercept_t *voipintercepts,
        net_buffer_t *nb) {

    voipintercept_t *v;

    for (v = voipintercepts; v != NULL; v = v->hh_liid.next) {
        if (v->active == 0) {
            continue;
        }
    
        if (push_voipintercept_onto_net_buffer(nb, v) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing VOIP intercept %s onto buffer for writing to collector.",
                    v->common.liid);
            return -1;
        }

        if (push_all_sip_targets(nb, v->targets, v) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing SIP targets for VOIP intercept %s onto buffer.", v->common.liid);
            return -1;
        }
    }
    return 0;
}

static int push_all_ipintercepts(ipintercept_t *ipintercepts,
        net_buffer_t *nb) {

    ipintercept_t *cept;

    for (cept = ipintercepts; cept != NULL; cept = cept->hh_liid.next) {
        if (push_ipintercept_onto_net_buffer(nb, cept) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing IP intercept %s onto buffer for writing to collector.",
                    cept->common.liid);
            return -1;
        }
    }

    return 0;
}

static int respond_collector_auth(provision_state_t *state,
        prov_epoll_ev_t *pev, net_buffer_t *outgoing) {

    /* Collector just authed successfully, so we can safely shovel all
     * of known mediators and active intercepts to it.
     */

    if (libtrace_list_get_size(state->mediators) +
            HASH_CNT(hh, state->radiusservers) +
            HASH_CNT(hh, state->sipservers) +
            HASH_CNT(hh_liid, state->ipintercepts) +
            HASH_CNT(hh_liid, state->voipintercepts) == 0) {
        return 0;
    }

    if (push_all_mediators(state->mediators, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue mediators to be sent to new collector on fd %d",
                pev->fd);
        return -1;
    }

    if (push_coreservers(state->radiusservers, OPENLI_CORE_SERVER_RADIUS,
            outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue RADIUS server details to be sent to new collector on fd %d", pev->fd);
        return -1;
    }

    if (push_coreservers(state->sipservers, OPENLI_CORE_SERVER_SIP,
            outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue RADIUS server details to be sent to new collector on fd %d", pev->fd);
        return -1;
    }

    if (push_all_ipintercepts(state->ipintercepts, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue IP intercepts to be sent to new collector on fd %d",
                pev->fd);
        return -1;
    }

    if (push_all_voipintercepts(state->voipintercepts, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue VOIP IP intercepts to be sent to new collector on fd %d",
                pev->fd);
        return -1;
    }

    if (push_nomore_intercepts(outgoing) < 0) {
        logger(LOG_INFO,
                "OpenLI provisioner: error pushing end of intercepts onto buffer for writing to collector.");
        return -1;
    }

    if (enable_epoll_write(state, pev) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to enable epoll write event for newly authed collector on fd %d: %s",
                pev->fd, strerror(errno));
        return -1;
    }

    return 0;

}

static int respond_mediator_auth(provision_state_t *state,
        prov_epoll_ev_t *pev, net_buffer_t *outgoing) {

    char *lastlea = NULL;
    liid_hash_t *h;
    prov_agency_t *ag, *tmp;

    /* Mediator just authed successfully, so we can safely send it details
     * on any LEAs that we know about */
    HASH_ITER(hh, state->leas, ag, tmp) {
        if (push_lea_onto_net_buffer(outgoing, ag->ag) == -1) {
            logger(LOG_INFO,
                    "OpenLI: error while buffering LEA details to send from provisioner to mediator.");
            return -1;
        }
    }

    h = state->liid_map;
    while (h != NULL) {
        if (push_liid_mapping_onto_net_buffer(outgoing, h->agency, h->liid)
                == -1) {
            logger(LOG_INFO,
                    "OpenLI: error while buffering LIID mappings to send to mediator.");
            return -1;
        }
        h = h->hh.next;
    }

    /* We also need to send any LIID -> LEA mappings that we know about */


    /* Update our epoll event for this mediator to allow transmit. */
    if (enable_epoll_write(state, pev) == -1) {
        logger(LOG_INFO,
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
                logger(LOG_INFO,
                        "OpenLI: error receiving message from collector.");
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_COLLECTOR_AUTH:
                if (internalid != OPENLI_COLLECTOR_MAGIC) {
                    logger(LOG_INFO,
                            "OpenLI: invalid auth code from collector.");
                    return -1;
                }
                if (cs->trusted == 1) {
                    logger(LOG_INFO,
                            "OpenLI: warning -- double auth from collector.");
                    assert(0);
                    break;
                }
                cs->trusted = 1;
                justauthed = 1;
                break;
            default:
                logger(LOG_INFO,
                        "OpenLI: unexpected message type %d received from collector.",
                        msgtype);
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        logger(LOG_INFO, "OpenLI: collector on fd %d auth success.",
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
                logger(LOG_INFO,
                        "OpenLI: error receiving message from mediator.");
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_MEDIATOR_AUTH:
                if (internalid != OPENLI_MEDIATOR_MAGIC) {
                    logger(LOG_INFO,
                            "OpenLI: invalid auth code from mediator.");
                    return -1;
                }
                if (cs->trusted == 1) {
                    logger(LOG_INFO,
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
                logger(LOG_INFO,
                        "OpenLI: unexpected message type %d received from mediator.",
                        msgtype);
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        logger(LOG_INFO, "OpenLI: mediator on fd %d auth success.",
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
        logger(LOG_INFO,
                "OpenLI: error sending message from provisioner to %s.",
                get_event_description(pev));
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        ev.data.ptr = pev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, pev->fd, &ev) == -1) {
            logger(LOG_INFO,
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
        logger(LOG_INFO,
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

    state->dropped_mediators += (drop_generic_socket(state, pev));

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
        logger(LOG_INFO, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
    } else {
        logger(LOG_INFO, "OpenLI: provisioner accepted connection from collector %s on %d.",
                strbuf, newfd);
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
            logger(LOG_INFO,
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
        logger(LOG_INFO, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
    } else {
        logger(LOG_INFO, "OpenLI: provisioner accepted connection from mediator %s on %d.",
                strbuf, newfd);
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
            logger(LOG_INFO,
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
        logger(LOG_INFO,
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

    if (state->pushaddr == NULL) {
        return -1;
    }

    state->updatefd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    sockfd  = create_listener(state->pushaddr, state->pushport, "II push");
    if (sockfd == -1) {
        return -1;
    }

    logger(LOG_INFO,
            "OpenLI provisioner: listening for updates on %s:%s",
            state->pushaddr, state->pushport);

    state->updatefd->fd = sockfd;
    state->updatefd->fdtype = PROV_EPOLL_UPDATE_CONN;
    state->updatefd->state = NULL;

    ev.data.ptr = state->updatefd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_INFO,
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

    logger(LOG_INFO,
            "OpenLI provisioner: listening for mediators on %s:%s",
            state->mediateaddr, state->mediateport);

    state->mediatorfd->fd = sockfd;
    state->mediatorfd->fdtype = PROV_EPOLL_MEDIATE_CONN;
    state->mediatorfd->state = NULL;

    ev.data.ptr = state->mediatorfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_INFO,
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
        logger(LOG_INFO,
                "OpenLI provisioner: unable to read from signal fd: %s.",
                strerror(errno));
        return ret;
    }

    if (ret != sizeof(si)) {
        logger(LOG_INFO,
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
        logger(LOG_INFO,
                "OpenLI Provisioner: dropping unauthed collector.");
        drop_collector(state, pev);
    }

    if (cs->clientrole == PROV_EPOLL_MEDIATOR) {
        logger(LOG_INFO,
                "OpenLI Provisioner: dropping unauthed mediator.");
        drop_mediator(state, pev);
    }

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
            logger(LOG_INFO,
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
                logger(LOG_INFO,
                        "OpenLI Provisioner: disconnecting collector %d.",
                        pev->fd);
                drop_collector(state, pev);
            }
            break;
        case PROV_EPOLL_FD_TIMER:
            if (ev->events & EPOLLIN) {
                expire_unauthed(state, pev);
            } else {
                logger(LOG_INFO,
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
                logger(LOG_INFO,
                        "OpenLI Provisioner: disconnecting mediator %d.",
                        pev->fd);
                drop_mediator(state, pev);
            }
            break;
        case PROV_EPOLL_UPDATE:
            /* TODO */
            break;

        default:
            logger(LOG_INFO,
                    "OpenLI Provisioner: invalid fd triggering epoll event,");
            return -1;
    }

    return ret;

}

static inline int reload_push_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    struct epoll_event ev;
    int changed = 0;

    /* TODO this will trigger on a whitespace change */
    if (currstate->pushaddr) {

        if (strcmp(newstate->pushaddr, currstate->pushaddr) != 0 ||
                strcmp(newstate->pushport, currstate->pushport) != 0) {

            if (epoll_ctl(currstate->epoll_fd, EPOLL_CTL_DEL,
                    currstate->updatefd->fd, &ev) == -1) {
                logger(LOG_INFO,
                        "OpenLI provisioner: Failed to remove update fd from epoll: %s.",
                        strerror(errno));
                return -1;
            }

            close(currstate->updatefd->fd);
            free(currstate->updatefd);
            free(currstate->pushaddr);
            free(currstate->pushport);

            if (newstate->pushaddr) {
                currstate->pushaddr = strdup(newstate->pushaddr);
            } else {
                currstate->pushaddr = NULL;
            }
            currstate->pushport = strdup(newstate->pushport);
            changed = 1;
        }
    }

    else if (newstate->pushaddr) {
        currstate->pushaddr = strdup(newstate->pushaddr);
        currstate->pushport = strdup(newstate->pushport);
        changed = 1;
    }

    if (changed) {
        if (currstate->pushaddr && start_push_listener(currstate) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, update socket did not restart. Will not be able to receive live updates.");
            return -1;
        }
        return 1;
    } else {
        logger(LOG_INFO,
                "OpenLI provisioner: update socket configuration is unchanged.");
    }
    return 0;

}

static inline int reload_mediator_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    struct epoll_event ev;

    /* TODO this will trigger on a whitespace change */
    if (strcmp(newstate->mediateaddr, currstate->mediateaddr) != 0 ||
            strcmp(newstate->mediateport, currstate->mediateport) != 0) {

        free_all_mediators(currstate->mediators);
        currstate->mediators = libtrace_list_init(sizeof(prov_mediator_t));

        if (epoll_ctl(currstate->epoll_fd, EPOLL_CTL_DEL,
                currstate->mediatorfd->fd, &ev) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Failed to remove mediator fd from epoll: %s.",
                    strerror(errno));
            return -1;
        }

        close(currstate->mediatorfd->fd);
        free(currstate->mediatorfd);
        free(currstate->mediateaddr);
        free(currstate->mediateport);
        currstate->mediateaddr = strdup(newstate->mediateaddr);
        currstate->mediateport = strdup(newstate->mediateport);
        currstate->dropped_mediators = 0;

        if (start_mediator_listener(currstate) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, mediation socket did not restart. Will not be able to control mediators.");
            return -1;
        }
        return 1;
    } else {
        logger(LOG_INFO,
                "OpenLI provisioner: mediation socket configuration is unchanged.");
    }
    return 0;
}

static inline int reload_collector_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    struct epoll_event ev;

    /* TODO this will trigger on a whitespace change */
    if (strcmp(newstate->listenaddr, currstate->listenaddr) != 0 ||
            strcmp(newstate->listenport, currstate->listenport) != 0) {

        stop_all_collectors(currstate->collectors);
        currstate->collectors = libtrace_list_init(sizeof(prov_collector_t));

        if (epoll_ctl(currstate->epoll_fd, EPOLL_CTL_DEL,
                currstate->clientfd->fd, &ev) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Failed to remove mediator fd from epoll: %s.",
                    strerror(errno));
            return -1;
        }

        close(currstate->clientfd->fd);
        free(currstate->clientfd);
        free(currstate->listenaddr);
        free(currstate->listenport);
        currstate->listenaddr = strdup(newstate->listenaddr);
        currstate->listenport = strdup(newstate->listenport);
        currstate->dropped_collectors = 0;

        if (start_main_listener(currstate) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, listening socket did not restart. Will not be able to accept collector clients.");
            return -1;
        }
        return 1;
    } else {
        logger(LOG_INFO,
                "OpenLI provisioner: collector listening socket configuration is unchanged.");
    }
    return 0;
}

static int announce_lea_to_mediators(provision_state_t *state,
        prov_agency_t *lea) {

    libtrace_list_node_t *n;
    prov_mediator_t *med;
    prov_sock_state_t *sock;

    n = state->mediators->head;
    while (n) {
        med = (prov_mediator_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(med->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_lea_onto_net_buffer(sock->outgoing, lea->ag) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send LEA %s to mediator %d.",
                    lea->ag->agencyid, med->fd);
            drop_mediator(state, med->commev);
            continue;
        }

        if (enable_epoll_write(state, med->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for mediator on fd %d: %s",
                    med->fd, strerror(errno));
            drop_mediator(state, med->commev);
        }

    }

    return 0;
}

static int withdraw_agency_from_mediators(provision_state_t *state,
        prov_agency_t *lea) {

    libtrace_list_node_t *n;
    prov_mediator_t *med;
    prov_sock_state_t *sock;

    n = state->mediators->head;
    while (n) {
        med = (prov_mediator_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(med->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_lea_withdrawal_onto_net_buffer(sock->outgoing,
                    lea->ag) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send withdrawal of LEA %s to mediator %d.",
                    lea->ag->agencyid, med->fd);
            drop_mediator(state, med->commev);
            continue;
        }

        if (enable_epoll_write(state, med->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for mediator on fd %d: %s",
                    med->fd, strerror(errno));
            drop_mediator(state, med->commev);
        }

    }

    return 0;

}

static inline int reload_leas(provision_state_t *currstate,
        provision_state_t *newstate, int medchange) {

    prov_agency_t *newleas;
    liid_hash_t *newmap;
    prov_agency_t *lea, *tmp, *newequiv;

    /* If the mediators have not been disconnected, we need to tell them
     * about any changes in the LEA list */
    if (!medchange) {
        HASH_ITER(hh, currstate->leas, lea, tmp) {
            HASH_FIND_STR(newstate->leas, lea->ag->agencyid, newequiv);

            if (!newequiv) {
                /* Agency has been withdrawn entirely */
                withdraw_agency_from_mediators(currstate, lea);
            } else if (agency_equal(lea->ag, newequiv->ag)) {
                /* Agency is unchanged */
                newequiv->announcereq = 0;
            } else {
                /* Agency is changed, withdraw current and announce new */
                withdraw_agency_from_mediators(currstate, lea);
                newequiv->announcereq = 1;
            }
        }

        HASH_ITER(hh, newstate->leas, lea, tmp) {
            if (lea->announcereq) {
                if (announce_lea_to_mediators(currstate, lea) == -1) {
                    logger(LOG_INFO,
                            "OpenLI provisioner: unable to announce new LEA to existing mediators.");
                    return -1;
                }
            }
        }
    }


    /* Swap the lea list and liid map from new to currstate */
    newleas = newstate->leas;
    newmap = newstate->liid_map;

    newstate->leas = currstate->leas;
    newstate->liid_map = currstate->liid_map;

    currstate->leas = newleas;
    currstate->liid_map = newmap;
    return 0;
}

static void add_new_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr) {

    libtrace_list_node_t *n;
    prov_collector_t *col;
    prov_sock_state_t *sock;

    n = state->collectors->head;
    while (n) {
        col = (prov_collector_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(col->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_static_ipranges_onto_net_buffer(sock->outgoing,
                ipint, ipr) < 0) {
            drop_collector(state, col->commev);
            continue;
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for collector on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_collector(state, col->commev);
        }

    }
}

static void remove_existing_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr) {

    libtrace_list_node_t *n;
    prov_collector_t *col;
    prov_sock_state_t *sock;

    n = state->collectors->head;
    while (n) {
        col = (prov_collector_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(col->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_static_ipranges_removal_onto_net_buffer(sock->outgoing,
                ipint, ipr) < 0) {
            drop_collector(state, col->commev);
            continue;
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for collector on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_collector(state, col->commev);
        }

    }
}

static int halt_existing_intercept(provision_state_t *state,
        void *cept, openli_proto_msgtype_t wdtype) {

    libtrace_list_node_t *n;
    prov_collector_t *col;
    prov_sock_state_t *sock;

    n = state->collectors->head;
    while (n) {
        col = (prov_collector_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(col->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_intercept_withdrawal_onto_net_buffer(sock->outgoing,
                cept, wdtype) == -1) {
            drop_collector(state, col->commev);
            continue;
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for collector on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_collector(state, col->commev);
        }

    }

    return 0;

}

/* TODO replace all these functions with a single generic version, much
 * like announce_single_intercept but even more generic.
 */

static int disconnect_mediators_from_collectors(provision_state_t *state) {

    libtrace_list_node_t *n;
    prov_collector_t *col;
    prov_sock_state_t *sock;

    n = state->collectors->head;
    while (n) {
        col = (prov_collector_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(col->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_disconnect_mediators_onto_net_buffer(sock->outgoing) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send 'disconnect mediators' to collector %d.",
                    sock->mainfd);
            drop_collector(state, col->commev);
            continue;
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for collector on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_collector(state, col->commev);
        }

    }

    return 0;

}


static int remove_liid_mapping(provision_state_t *state,
        char *liid, int liid_len, int droppedmeds) {

    libtrace_list_node_t *n;
    prov_mediator_t *med;
    prov_sock_state_t *sock;

    /* Don't need to find and remove the mapping from our LIID map, as
     * reload_lea() has already replaced our map with a new one. */

    if (droppedmeds) {
        return 0;
    }

    /* Still got mediators connected, so tell them about the now disabled
     * LIID.
     */
    n = state->mediators->head;
    while (n) {
        med = (prov_mediator_t *)(n->data);
        n = n->next;
        sock = (prov_sock_state_t *)(med->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_cease_mediation_onto_net_buffer(sock->outgoing,
                    liid, liid_len) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to halt mediation of intercept %s on mediator %d.",
                    liid, sock->mainfd);
            drop_mediator(state, med->commev);
            continue;
        }

        if (enable_epoll_write(state, med->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to enable epoll write event for mediator on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_mediator(state, med->commev);
        }
    }

    return 0;
}

static int announce_liidmapping_to_mediators(provision_state_t *state,
        liid_hash_t *liidmap) {

    libtrace_list_node_t *n;
    prov_mediator_t *med;
    prov_sock_state_t *sock;

    if (liidmap == NULL) {
        return 0;
    }

    n = state->mediators->head;
    while (n) {
        med = (prov_mediator_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(med->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (push_liid_mapping_onto_net_buffer(sock->outgoing, liidmap->agency,
                liidmap->liid) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send mapping for LIID %s to mediator %d.",
                    liidmap->liid, med->fd);
            drop_mediator(state, med->commev);
            continue;
        }

        if (enable_epoll_write(state, med->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for mediator on fd %d: %s",
                    med->fd, strerror(errno));
            drop_mediator(state, med->commev);
        }

    }

    return 0;
}

static int announce_coreserver_change(provision_state_t *state,
        coreserver_t *cs, uint8_t isnew) {
    libtrace_list_node_t *n;
    prov_collector_t *col;
    prov_sock_state_t *sock;

    n = state->collectors->head;
    while (n) {
        col = (prov_collector_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(col->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (isnew) {
            if (push_coreserver_onto_net_buffer(sock->outgoing, cs,
                        cs->servertype) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push new %s server to collector on fd %d",
                        coreserver_type_to_string(cs->servertype),
                        sock->mainfd);
                drop_collector(state, col->commev);
                continue;
            }
        } else {
            if (push_coreserver_withdraw_onto_net_buffer(sock->outgoing,
                        cs, cs->servertype) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push removal of %s server to collector on fd %d",
                        coreserver_type_to_string(cs->servertype),
                        sock->mainfd);
                drop_collector(state, col->commev);
                continue;
            }
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for collector on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_collector(state, col->commev);
        }
    }
    return 0;
}

static int announce_sip_target_change(provision_state_t *state,
        openli_sip_identity_t *sipid, voipintercept_t *vint, uint8_t isnew) {

    libtrace_list_node_t *n;
    prov_collector_t *col;
    prov_sock_state_t *sock;

    n = state->collectors->head;
    while (n) {
        col = (prov_collector_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(col->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (isnew) {
            if (push_sip_target_onto_net_buffer(sock->outgoing, sipid,
                        vint) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push SIP target to collector on fd %d",
                        sock->mainfd);
                drop_collector(state, col->commev);
                continue;
            }
        } else {
            if (push_sip_target_withdrawal_onto_net_buffer(sock->outgoing,
                        sipid, vint) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push removal of SIP target to collector on fd %d",
                        sock->mainfd);
                drop_collector(state, col->commev);
                continue;
            }
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for collector on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_collector(state, col->commev);
        }
    }
    return 0;
}

static int announce_single_intercept(provision_state_t *state,
        void *cept, int (*sendfunc)(net_buffer_t *, void *)) {

    libtrace_list_node_t *n;
    prov_collector_t *col;
    prov_sock_state_t *sock;

    n = state->collectors->head;
    while (n) {
        col = (prov_collector_t *)(n->data);
        n = n->next;

        sock = (prov_sock_state_t *)(col->commev->state);
        if (!sock->trusted || sock->halted) {
            continue;
        }

        if (sendfunc(sock->outgoing, cept) == -1) {
            drop_collector(state, col->commev);
            continue;
        }

        if (enable_epoll_write(state, col->commev) == -1) {
            logger(LOG_INFO,
                    "OpenLI: unable to enable epoll write event for collector on fd %d: %s",
                    sock->mainfd, strerror(errno));
            drop_collector(state, col->commev);
        }

    }


    return 0;
}

static int announce_all_sip_targets(provision_state_t *state,
        libtrace_list_t *siptargets, voipintercept_t *vint) {

    libtrace_list_node_t *n;
    openli_sip_identity_t *sipid;

    n = siptargets->head;
    while (n) {
        sipid = *((openli_sip_identity_t **)(n->data));
        if (announce_sip_target_change(state, sipid, vint, 1) < 0) {
            return -1;
        }
        n = n->next;
    }
    return 0;
}

static inline int compare_sip_targets(provision_state_t *currstate,
        voipintercept_t *existing, voipintercept_t *reload) {

    openli_sip_identity_t *oldtgt, *newtgt;
    libtrace_list_node_t *n1, *n2;

    /* Sluggish (n^2), but hopefully we don't have many IDs per intercept */

    n1 = existing->targets->head;
    while (n1) {
        oldtgt = *((openli_sip_identity_t **)(n1->data));
        n1 = n1->next;

        oldtgt->awaitingconfirm = 1;
        n2 = reload->targets->head;
        while (n2) {
            newtgt = *((openli_sip_identity_t **)(n2->data));
            n2 = n2->next;
            if (newtgt->awaitingconfirm == 0) {
                continue;
            }

            if (are_sip_identities_same(newtgt, oldtgt)) {
                oldtgt->awaitingconfirm = 0;
                newtgt->awaitingconfirm = 0;
                break;
            }
        }

        if (oldtgt->awaitingconfirm) {
            /* This target is no longer in the intercept config so
             * withdraw it. */
            if (announce_sip_target_change(currstate, oldtgt, existing, 0) < 0)
            {
                return -1;
            }
        }
    }

    n2 = reload->targets->head;
    while (n2) {
        newtgt = *((openli_sip_identity_t **)(n2->data));
        n2 = n2->next;
        if (newtgt->awaitingconfirm == 0) {
            continue;
        }

        /* This target has been added since we last reloaded config so
         * announce it. */
        if (announce_sip_target_change(currstate, newtgt, existing, 1) < 0) {
            return -1;
        }
    }

    return 0;
}

static inline int reload_voipintercepts(provision_state_t *currstate,
        provision_state_t *newstate, int droppedcols, int droppedmeds) {

    voipintercept_t *newints, *voipint, *tmp, *newequiv;
    char *str;

    /* TODO error handling in the "inform other components about changes"
     * functions?
     */
    HASH_ITER(hh_liid, currstate->voipintercepts, voipint, tmp) {
        HASH_FIND(hh_liid, newstate->voipintercepts, voipint->common.liid,
                voipint->common.liid_len, newequiv);
        if (!newequiv) {
            /* Intercept has been withdrawn entirely */
            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)voipint,
                        OPENLI_PROTO_HALT_VOIPINTERCEPT);
            }
            remove_liid_mapping(currstate, voipint->common.liid,
                    voipint->common.liid_len, droppedmeds);
            continue;
        } else if (!voip_intercept_equal(voipint, newequiv)) {
            /* VOIP intercept has changed somehow -- this probably
             * shouldn't happen but deal with it anyway
             */
            logger(LOG_INFO,
                    "OpenLI provisioner: Details for VOIP intercept %s have changed?",
                    voipint->common.liid);

            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)voipint,
                        OPENLI_PROTO_HALT_VOIPINTERCEPT);
            }
            remove_liid_mapping(currstate, voipint->common.liid,
                    voipint->common.liid_len, droppedmeds);

        } else {
            if (compare_sip_targets(currstate, voipint, newequiv) < 0) {
                return -1;
            }
            newequiv->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh_liid, newstate->voipintercepts, voipint, tmp) {
        liid_hash_t *h = NULL;
        if (!voipint->awaitingconfirm) {
            continue;
        }

        /* Add the LIID mapping */
        h = add_liid_mapping(currstate, voipint->common.liid,
                voipint->common.targetagency);

        if (!droppedmeds && announce_liidmapping_to_mediators(currstate,
                h) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new VOIP intercept to mediators.");
            return -1;
        }

        if (!droppedcols && announce_single_intercept(currstate,
                (void *)voipint, push_voipintercept_onto_net_buffer) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new VOIP intercept to collectors.");
            return -1;
        }

        if (!droppedcols && announce_all_sip_targets(currstate,
                    voipint->targets, voipint) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing SIP targets for VOIP intercept %s onto buffer.", voipint->common.liid);
            return -1;
        }
    }

    /* Swap the intercept lists */
    newints = newstate->voipintercepts;
    newstate->voipintercepts = currstate->voipintercepts;
    currstate->voipintercepts = newints;
    return 0;
}

static inline void reload_coreservers(provision_state_t *state,
        coreserver_t *currserv, coreserver_t *newserv, int droppedcols) {

    coreserver_t *cs, *tmp, *newequiv;
    HASH_ITER(hh, currserv, cs, tmp) {
        HASH_FIND(hh, newserv, cs->serverkey, strlen(cs->serverkey), newequiv);
        if (!newequiv) {
            /* Core server has been withdrawn */
            if (!droppedcols) {
                announce_coreserver_change(state, cs, false);
            }
        } else {
            newequiv->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh, newserv, cs, tmp) {
        if (!cs->awaitingconfirm) {
            continue;
        }

        /* Announce this server as it has just been added */
        if (!droppedcols) {
            announce_coreserver_change(state, cs, true);
        }
    }
}

static inline int reload_radiusservers(provision_state_t *currstate,
        provision_state_t *newstate, int droppedcols) {

    coreserver_t *newrad;

    reload_coreservers(currstate, currstate->radiusservers,
            newstate->radiusservers, droppedcols);

    newrad = newstate->radiusservers;
    newstate->radiusservers = currstate->radiusservers;
    currstate->radiusservers = newrad;
    return 0;
}

static inline int reload_sipservers(provision_state_t *currstate,
        provision_state_t *newstate, int droppedcols) {

    coreserver_t *newsip;

    reload_coreservers(currstate, currstate->sipservers,
            newstate->sipservers, droppedcols);

    newsip = newstate->sipservers;
    newstate->sipservers = currstate->sipservers;
    currstate->sipservers = newsip;
    return 0;
}

/* define here rather than as a macro, since IP intercepts are now
 * a bit more complicated (i.e. some structure fields are optional).
 */
static inline int ip_intercept_equal(ipintercept_t *a, ipintercept_t *b) {
    if (strcmp(a->common.liid, b->common.liid) != 0) {
        return 0;
    }

    if (strcmp(a->common.authcc, b->common.authcc) != 0) {
        return 0;
    }

    if (strcmp(a->common.delivcc, b->common.delivcc) != 0) {
        return 0;
    }

    if (a->username && b->username && strcmp(a->username, b->username) != 0) {
        return 0;
    }

    if (a->alushimid != b->alushimid) {
        return 0;
    }

    if (strcmp(a->common.targetagency, b->common.targetagency) != 0) {
        return 0;
    }

    if (a->accesstype != b->accesstype) {
        return 0;
    }

    return 1;
}

static inline int reload_staticips(provision_state_t *currstate,
        ipintercept_t *ipint, ipintercept_t *newequiv) {

    static_ipranges_t *ipr, *tmp, *found;

    HASH_ITER(hh, ipint->statics, ipr, tmp) {
        HASH_FIND(hh, newequiv->statics, ipr->rangestr, strlen(ipr->rangestr),
                found);
        if (!found || found->cin != ipr->cin) {
            remove_existing_staticip_range(currstate, ipint, ipr);
        } else {
            found->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh, newequiv->statics, ipr, tmp) {
        if (ipr->awaitingconfirm == 0) {
            continue;
        }
        add_new_staticip_range(currstate, ipint, ipr);
    }

    return 0;
}

static inline int reload_ipintercepts(provision_state_t *currstate,
        provision_state_t *newstate, int droppedcols, int droppedmeds) {

    ipintercept_t *newints, *ipint, *tmp, *newequiv;
    char *str;

    /* TODO error handling in the "inform other components about changes"
     * functions?
     */
    HASH_ITER(hh_liid, currstate->ipintercepts, ipint, tmp) {
        HASH_FIND(hh_liid, newstate->ipintercepts, ipint->common.liid,
                ipint->common.liid_len, newequiv);
        if (!newequiv) {
            /* Intercept has been withdrawn entirely */
            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)ipint,
                        OPENLI_PROTO_HALT_IPINTERCEPT);
            }
            remove_liid_mapping(currstate, ipint->common.liid,
                    ipint->common.liid_len, droppedmeds);
            logger(LOG_INFO, "OpenLI provisioner: LIID %s has been withdrawn",
                    ipint->common.liid);
            continue;
        } else if (!ip_intercept_equal(ipint, newequiv)) {
            /* IP intercept has changed somehow -- this probably
             * shouldn't happen but deal with it anyway
             */
            logger(LOG_INFO, "OpenLI provisioner: Details for IP intercept %s have changed?",
                    ipint->common.liid);

            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)ipint,
                        OPENLI_PROTO_HALT_IPINTERCEPT);
            }
            remove_liid_mapping(currstate, ipint->common.liid,
                    ipint->common.liid_len, droppedmeds);
        } else {
            reload_staticips(currstate, ipint, newequiv);
            newequiv->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh_liid, newstate->ipintercepts, ipint, tmp) {
        liid_hash_t *h = NULL;
        if (!ipint->awaitingconfirm) {
            continue;
        }

        /* Add the LIID mapping */
        h = add_liid_mapping(currstate, ipint->common.liid,
                ipint->common.targetagency);

        if (!droppedmeds && announce_liidmapping_to_mediators(currstate,
                h) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new IP intercept to mediators.");
            return -1;
        }

        if (!droppedcols && announce_single_intercept(currstate,
                (void *)ipint, push_ipintercept_onto_net_buffer) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new IP intercept to collectors.");
            return -1;
        }
    }

    /* Swap the intercept lists */
    newints = newstate->ipintercepts;
    newstate->ipintercepts = currstate->ipintercepts;
    currstate->ipintercepts = newints;
    return 0;
}

static int reload_provisioner_config(provision_state_t *currstate) {

    provision_state_t newstate;
    int mediatorchanged = 0;
    int clientchanged = 0;
    int pushchanged = 0;
    int leachanged = 0;

    if (init_prov_state(&newstate, currstate->conffile) == -1) {
        logger(LOG_INFO,
                "OpenLI: Error reloading config file for provisioner.");
        return -1;
    }

    /* Only make changes if the relevant configuration has changed, so as
     * to minimise interruptions.
     */
    mediatorchanged = reload_mediator_socket_config(currstate, &newstate);
    if (mediatorchanged == -1) {
        return -1;
    }

    pushchanged = reload_push_socket_config(currstate, &newstate);
    if (pushchanged == -1) {
        return -1;
    }

    clientchanged = reload_collector_socket_config(currstate, &newstate);
    if (clientchanged == -1) {
        return -1;
    }

    if (mediatorchanged && !clientchanged) {
        /* Tell all collectors to drop their mediators until further notice */
        disconnect_mediators_from_collectors(currstate);

    }

    if (reload_leas(currstate, &newstate, mediatorchanged) == -1) {
        return -1;
    }

    if (reload_voipintercepts(currstate, &newstate, clientchanged,
            mediatorchanged) == -1) {
        return -1;
    }

    if (reload_ipintercepts(currstate, &newstate, clientchanged,
            mediatorchanged) == -1) {
        return -1;
    }

    if (reload_radiusservers(currstate, &newstate, clientchanged) == -1) {
        return -1;
    }

    if (reload_sipservers(currstate, &newstate, clientchanged) == -1) {
        return -1;
    }

    clear_prov_state(&newstate);

    return 0;

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
        logger(LOG_INFO,
                "OpenLI: Failed to register signal socket: %s.",
                strerror(errno));
        return;
    }

    state->timerfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    while (!provisioner_halt) {
        if (reload_config) {
            if (reload_provisioner_config(state) == -1) {
                break;
            }
            reload_config = 0;
        }

        timerfd = epoll_add_timer(state->epoll_fd, 1, state->timerfd);
        if (timerfd == -1) {
            logger(LOG_INFO,
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
                logger(LOG_INFO, "OpenLI: error while checking for incoming connections on the provisioner: %s.",
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
            logger(LOG_INFO,
                "OpenLI: unable to remove provisioner timer from epoll set: %s",
                strerror(errno));
            return;
        }

        close(timerfd);
        state->timerfd->fd = -1;
    }

}

static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [ -d ] -c configfile\n", prog);
    fprintf(stderr, "\nSet the -d flag to run this program as a daemon.");
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    sigset_t sigblock;
    int daemonmode = 0;

    provision_state_t provstate;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "daemonise", 0, 0, 'd'},
            { NULL, 0, 0, 0},
        };

        int c = getopt_long(argc, argv, "c:dh", long_options, &optind);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'c':
                configfile = optarg;
                break;
            case 'd':
                daemonmode = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            default:
                logger(LOG_INFO, "OpenLI: unsupported option: %c",
                        c);
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

    if (daemonmode) {
        daemonise(argv[0]);
    }

    sigemptyset(&sigblock);
    sigaddset(&sigblock, SIGHUP);
    sigaddset(&sigblock, SIGTERM);
    sigaddset(&sigblock, SIGINT);
    sigprocmask(SIG_BLOCK, &sigblock, NULL);


    if (init_prov_state(&provstate, configfile) == -1) {
        logger(LOG_INFO, "OpenLI: Error initialising provisioner.");
        return 1;
    }

    if (start_main_listener(&provstate) == -1) {
        logger(LOG_INFO, "OpenLI: Error, could not start listening socket.");
        return 1;
    }

    if (start_push_listener(&provstate) == -1) {
        logger(LOG_INFO, "OpenLI: Warning, push socket did not start. New intercepts cannot be received.");
    }

    if (start_mediator_listener(&provstate) == -1) {
        logger(LOG_INFO, "OpenLI: Warning, mediation socket did not start. Will not be able to control mediators.");
    }

    run(&provstate);

    clear_prov_state(&provstate);
    logger(LOG_INFO, "OpenLI: Provisioner has exited.");
}




// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
