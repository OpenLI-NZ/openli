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
#include "openli_tls.h"
#include "provisioner_client.h"
#include "updateserver.h"

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
    if (pev->fdtype == PROV_EPOLL_FD_IDLETIMER) return "client idle timer";
    return "unknown";
}

static inline void start_mhd_daemon(provision_state_t *state) {

    assert(state->updatesockfd >= 0);

    state->updatedaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
            0,
            NULL,
            NULL,
            &handle_update_request,      // TODO
            state,
            MHD_OPTION_LISTEN_SOCKET,
            state->updatesockfd,
            MHD_OPTION_NOTIFY_COMPLETED,
            &complete_update_request,    // TODO
            state,
            MHD_OPTION_END);
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

static int liid_hash_sort(liid_hash_t *a, liid_hash_t *b) {

    int x;

    x = strcmp(a->agency, b->agency);
    if (x != 0) {
        return x;
    }
    return strcmp(a->liid, b->liid);
}

static int map_intercepts_to_leas(prov_intercept_conf_t *conf) {

    int failed = 0;
    ipintercept_t *ipint, *iptmp;
    voipintercept_t *vint;
    prov_agency_t *lea;

    /* Do IP Intercepts */
    HASH_ITER(hh_liid, conf->ipintercepts, ipint, iptmp) {
        add_liid_mapping(conf, ipint->common.liid, ipint->common.targetagency);
    }

    /* Now do the VOIP intercepts */
    for (vint = conf->voipintercepts; vint != NULL; vint = vint->hh_liid.next)
    {
        add_liid_mapping(conf, vint->common.liid, vint->common.targetagency);
    }

    /* Sort the final mapping nicely */
    HASH_SORT(conf->liid_map, liid_hash_sort);

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
    state->interceptconffile = NULL;
    state->updatedaemon = NULL;
    state->updatesockfd = -1;

    state->epoll_fd = epoll_create1(0);
    state->mediators = NULL;
    state->collectors = NULL;

    state->interceptconf.radiusservers = NULL;
    state->interceptconf.sipservers = NULL;
    state->interceptconf.voipintercepts = NULL;
    state->interceptconf.ipintercepts = NULL;
    state->interceptconf.liid_map = NULL;
    state->interceptconf.leas = NULL;

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

    state->sslconf.certfile = NULL;
    state->sslconf.keyfile = NULL;
    state->sslconf.cacertfile = NULL;
    state->sslconf.ctx = NULL;

    state->ignorertpcomfort = 0;

    if (parse_provisioning_config(configfile, state) == -1) {
        logger(LOG_INFO, "OpenLI provisioner: error while parsing provisioner config in %s", configfile);
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
    state->mediatorfd = NULL;
    state->timerfd = NULL;

    if (create_ssl_context(&(state->sslconf)) < 0) {
        return -1;
    }

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
    state->signalfd->client = NULL;

    return 0;
}

static int update_mediator_details(provision_state_t *state, uint8_t *medmsg,
        uint16_t msglen, char *identifier) {

    openli_mediator_t *med = (openli_mediator_t *)malloc(
            sizeof(openli_mediator_t));
    openli_mediator_t *prevmed = NULL;
    prov_collector_t *col, *coltmp;
    prov_mediator_t *provmed;
    int updatereq = 0;
    int ret = 0;

    if (decode_mediator_announcement(medmsg, msglen, med) == -1) {
        logger(LOG_INFO,
                "OpenLI: provisioner received bogus mediator announcement.");
        free(med);
        return -1;
    }

    /* Find the corresponding mediator in our mediator list */
    HASH_FIND(hh, state->mediators, identifier, strlen(identifier), provmed);

    if (!provmed) {
        free_openli_mediator(med);
        return 0;
    }

    if (provmed->details == NULL) {
        provmed->details = med;
    } else {
        prevmed = provmed->details;
        provmed->details = med;
    }

    /* All collectors must now know about this mediator */
    HASH_ITER(hh, state->collectors, col, coltmp) {

        prov_sock_state_t *cs = (prov_sock_state_t *)(col->client.state);

        if (cs == NULL) {
            continue;
        }

        if (col->client.commev == NULL ||
                col->client.commev->fdtype != PROV_EPOLL_COLLECTOR) {
            continue;
        }

        if (col->client.commev->fd == -1) {
            continue;
        }

        if (cs->trusted == 0) {
            continue;
        }

        if (prevmed) {
            /* The mediator has changed its details somehow, withdraw any
             * references to the old one.
             */
            if (push_mediator_withdraw_onto_net_buffer(cs->outgoing,
                    prevmed) < 0) {
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                        "OpenLI provisioner: error pushing mediator withdrawal %s:%s onto buffer for writing to collectori %s.",
                        prevmed->ipstr, prevmed->portstr, col->identifier);
                }
                ret = -1;
                break;
            }
        }

        if (push_mediator_onto_net_buffer(cs->outgoing, provmed->details) < 0) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector %s.",
                    provmed->details->ipstr, provmed->details->portstr,
                    col->identifier);
            }
            ret = -1;
            break;
        }

        if (enable_epoll_write(state, col->client.commev) == -1) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                    "OpenLI provisioner: cannot enable epoll write event to transmit mediator update to collector %s -- %s.",
                    col->identifier, strerror(errno));
            }
            ret = -1;
            break;
        }

    }
    if (prevmed) {
        free(prevmed->ipstr);
        free(prevmed->portstr);
        free(prevmed);
    }
    return ret;
}

static void free_all_mediators(int epollfd, prov_mediator_t **mediators) {

    prov_mediator_t *med, *medtmp;

    HASH_ITER(hh, *mediators, med, medtmp) {
        HASH_DELETE(hh, *mediators, med);
        free_openli_mediator(med->details);
        destroy_provisioner_client(epollfd, &(med->client), med->identifier);
        free(med->identifier);
        free(med);
    }
}

static void stop_all_collectors(int epollfd, prov_collector_t **collectors) {

    prov_collector_t *col, *coltmp;

    HASH_ITER(hh, *collectors, col, coltmp) {
        HASH_DELETE(hh, *collectors, col);
        destroy_provisioner_client(epollfd, &(col->client), col->identifier);
        free(col->identifier);
        free(col);
    }
}

static void clear_intercept_state(prov_intercept_conf_t *conf) {

    liid_hash_t *h, *tmp;
    prov_agency_t *h2, *tmp2;
    liagency_t *lea;

    HASH_ITER(hh, conf->liid_map, h, tmp) {
        HASH_DEL(conf->liid_map, h);
        free(h);
    }

    HASH_ITER(hh, conf->leas, h2, tmp2) {
        HASH_DEL(conf->leas, h2);
        free_liagency(h2->ag);
        free(h2);
    }

    free_all_ipintercepts(&(conf->ipintercepts));
    free_all_voipintercepts(&(conf->voipintercepts));
    free_coreserver_list(conf->radiusservers);
    free_coreserver_list(conf->sipservers);
}

static void clear_prov_state(provision_state_t *state) {

    clear_intercept_state(&(state->interceptconf));

    stop_all_collectors(state->epoll_fd, &(state->collectors));
    free_all_mediators(state->epoll_fd, &(state->mediators));

    close(state->epoll_fd);

    if (state->clientfd) {
        close(state->clientfd->fd);
        free(state->clientfd);
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
    if (state->interceptconffile) {
        free(state->interceptconffile);
    }


    free_ssl_config(&(state->sslconf));
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

static int push_all_mediators(prov_mediator_t *mediators, net_buffer_t *nb) {

    prov_mediator_t *pmed, *medtmp;

    HASH_ITER(hh, mediators, pmed, medtmp) {
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

static int push_all_voipintercepts(provision_state_t *state,
        voipintercept_t *voipintercepts, net_buffer_t *nb,
        prov_agency_t *agencies) {

    voipintercept_t *v;
    prov_agency_t *lea;
    int skip = 0;

    for (v = voipintercepts; v != NULL; v = v->hh_liid.next) {
        if (v->active == 0) {
            continue;
        }
        skip = 0;
        if (strcmp(v->common.targetagency, "pcapdisk") != 0) {
            HASH_FIND_STR(agencies, v->common.targetagency, lea);
            if (lea == NULL) {
                skip = 1;
            }
        }

        if (skip) {
            continue;
        }

        v->options = 0;
        if (state->ignorertpcomfort == 1) {
            v->options |= (1 << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
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
        net_buffer_t *nb, prov_agency_t *agencies) {

    ipintercept_t *cept;
    prov_agency_t *lea;
    int skip = 0;

    for (cept = ipintercepts; cept != NULL; cept = cept->hh_liid.next) {
        skip = 0;
        if (strcmp(cept->common.targetagency, "pcapdisk") != 0) {
            HASH_FIND_STR(agencies, cept->common.targetagency, lea);
            if (lea == NULL) {
                skip = 1;
            }
        }

        if (skip) {
            continue;
        }

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

    if (HASH_CNT(hh, state->mediators) +
            HASH_CNT(hh, state->interceptconf.radiusservers) +
            HASH_CNT(hh, state->interceptconf.sipservers) +
            HASH_CNT(hh_liid, state->interceptconf.ipintercepts) +
            HASH_CNT(hh_liid, state->interceptconf.voipintercepts) == 0) {
        return 0;
    }

    /* No need to wrap our log messages with checks for log_allowed, as
     * we should have just set log_allowed to 1 before calling this function
     */
    if (push_all_mediators(state->mediators, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue mediators to be sent to new collector on fd %d",
                pev->fd);
        return -1;
    }

    if (push_coreservers(state->interceptconf.radiusservers,
            OPENLI_CORE_SERVER_RADIUS, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue RADIUS server details to be sent to new collector on fd %d", pev->fd);
        return -1;
    }

    if (push_coreservers(state->interceptconf.sipservers,
            OPENLI_CORE_SERVER_SIP, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue RADIUS server details to be sent to new collector on fd %d", pev->fd);
        return -1;
    }

    if (push_all_ipintercepts(state->interceptconf.ipintercepts, outgoing,
                state->interceptconf.leas) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue IP intercepts to be sent to new collector on fd %d",
                pev->fd);
        return -1;
    }

    if (push_all_voipintercepts(state,
            state->interceptconf.voipintercepts, outgoing,
            state->interceptconf.leas) == -1) {
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
    /* No need to wrap our log messages with checks for log_allowed, as
     * we should have just set log_allowed to 1 before calling this function
     */
    HASH_ITER(hh, state->interceptconf.leas, ag, tmp) {
        if (push_lea_onto_net_buffer(outgoing, ag->ag) == -1) {
            logger(LOG_INFO,
                    "OpenLI: error while buffering LEA details to send from provisioner to mediator.");
            return -1;
        }
    }

    /* We also need to send any LIID -> LEA mappings that we know about */
    h = state->interceptconf.liid_map;
    while (h != NULL) {
        if (push_liid_mapping_onto_net_buffer(outgoing, h->agency, h->liid)
                == -1) {
            logger(LOG_INFO,
                    "OpenLI: error while buffering LIID mappings to send to mediator.");
            return -1;
        }
        h = h->hh.next;
    }

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

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    uint8_t *msgbody;
    uint16_t msglen;
    uint64_t internalid;
    openli_proto_msgtype_t msgtype;
    uint8_t justauthed = 0;

    do {
        msgtype = receive_net_buffer(cs->incoming, &msgbody, &msglen,
                &internalid);
        if (msgtype < 0) {
            if (cs->log_allowed) {
                nb_log_receive_error(msgtype);
                logger(LOG_INFO,
                        "OpenLI provisioner: error receiving message from collector.");
            }
            return -1;
        }

        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_COLLECTOR_AUTH:
                if (internalid != OPENLI_COLLECTOR_MAGIC) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "OpenLI: invalid auth code from collector.");
                    }
                    return -1;
                }
                if (cs->trusted == 1) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "OpenLI: warning -- double auth from collector.");
                    }
                    return -1;
                }
                cs->trusted = 1;
                justauthed = 1;
                break;
            default:
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                            "OpenLI: unexpected message type %d received from collector.",
                            msgtype);
                }
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        if (cs->log_allowed == 0) {
            cs->log_allowed = 1;
        }
        logger(LOG_DEBUG, "OpenLI: collector %s on fd %d auth success.",
                cs->ipaddr, pev->fd);
        halt_provisioner_client_authtimer(state->epoll_fd, pev->client,
                cs->ipaddr);
        return respond_collector_auth(state, pev, cs->outgoing);
   }

   return 0;
}

static int receive_mediator(provision_state_t *state, prov_epoll_ev_t *pev) {
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    uint8_t *msgbody;
    uint16_t msglen;
    uint64_t internalid;
    openli_proto_msgtype_t msgtype;
    uint8_t justauthed = 0;

    do {
        msgtype = receive_net_buffer(cs->incoming, &msgbody, &msglen,
                &internalid);
        if (msgtype < 0) {
            if (cs->log_allowed) {
                nb_log_receive_error(msgtype);
                logger(LOG_INFO, "OpenLI provisioner: error receiving message from mediator.");
            }
            return -1;
        }

        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_MEDIATOR_AUTH:
                if (internalid != OPENLI_MEDIATOR_MAGIC) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "OpenLI: invalid auth code from mediator.");
                    }
                    return -1;
                }
                if (cs->trusted == 1) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "OpenLI: warning -- double auth from mediator.");
                    }
                    return -1;
                }
                cs->trusted = 1;
                justauthed = 1;
                break;
            case OPENLI_PROTO_ANNOUNCE_MEDIATOR:
                if (cs->trusted == 0) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "Received mediator announcement from unauthed mediator.");
                    }
                    return -1;
                }

                if (update_mediator_details(state, msgbody, msglen,
                            cs->ipaddr) == -1) {
                    return -1;
                }
                break;
            default:
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                            "OpenLI: unexpected message type %d received from mediator.",
                            msgtype);
                }
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        if (cs->log_allowed == 0) {
            cs->log_allowed = 1;
        }
        logger(LOG_INFO, "OpenLI: mediator %s on fd %d auth success.",
                cs->ipaddr, pev->fd);
        halt_provisioner_client_authtimer(state->epoll_fd, pev->client,
                cs->ipaddr);
        return respond_mediator_auth(state, pev, cs->outgoing);
    }

    return 0;
}

static int continue_collector_handshake(provision_state_t *state,
        prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    prov_collector_t *col;
    int ret;

    HASH_FIND(hh, state->collectors, cs->ipaddr, strlen(cs->ipaddr), col);
    if (col == NULL) {
        logger(LOG_INFO, "OpenLI: unable to continue SSL handshake for collector %s as it is not in our collector list", cs->ipaddr);
        return -1;
    }

    return continue_provisioner_client_handshake(state->epoll_fd,
            &(col->client), cs);
}

static int continue_mediator_handshake(provision_state_t *state,
        prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    prov_mediator_t *med;
    int ret;

    HASH_FIND(hh, state->mediators, cs->ipaddr, strlen(cs->ipaddr), med);
    if (med == NULL) {
        logger(LOG_INFO, "OpenLI: unable to continue SSL handshake for mediator %s as it is not in our collector list", cs->ipaddr);
        return -1;
    }

    return continue_provisioner_client_handshake(state->epoll_fd,
            &(med->client), cs);
}

static int transmit_socket(provision_state_t *state, prov_epoll_ev_t *pev) {

    int ret;
    struct epoll_event ev;
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    openli_proto_msgtype_t err;

    ret = transmit_net_buffer(cs->outgoing, &err);
    if (ret == -1) {
        if (cs->log_allowed) {
            nb_log_transmit_error(err);
            logger(LOG_INFO,
                    "OpenLI: error sending message from provisioner to %s.",
                    get_event_description(pev));
        }
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        ev.data.ptr = pev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, pev->fd, &ev) == -1) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                        "OpenLI: error disabling EPOLLOUT for %s fd %d: %s.",
                        get_event_description(pev), pev->fd, strerror(errno));
            }
            return -1;
        }
    }

    return 1;
}

static int accept_collector(provision_state_t *state) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    char portbuf[10];
    prov_collector_t *col;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of collectors. Push all active intercepts
     * out to the collector. */
    newfd = accept(state->clientfd->fd, (struct sockaddr *)&saddr, &socklen);
    if (newfd < 0) {
        return newfd;
    }

    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
            portbuf, sizeof(portbuf), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        logger(LOG_INFO, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
    }

    /* See if this collector already exists */
    HASH_FIND(hh, state->collectors, strbuf, strlen(strbuf), col);

    if (!col) {
        col = calloc(1, sizeof(prov_collector_t));
        col->identifier = strdup(strbuf);
        init_provisioner_client(&(col->client));

        HASH_ADD_KEYPTR(hh, state->collectors, col->identifier,
                strlen(col->identifier), col);
    }

    halt_provisioner_client_idletimer(state->epoll_fd, &(col->client),
            col->identifier);

    return accept_provisioner_client(&(state->sslconf), state->epoll_fd,
            col->identifier, &(col->client), newfd, PROV_EPOLL_COLLECTOR,
            PROV_EPOLL_COLLECTOR_HANDSHAKE);

}

static int accept_mediator(provision_state_t *state) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    char portbuf[10];
    prov_mediator_t *med;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of mediators. Push all known LEAs to the
     * mediator, as well as any intercept->LEA mappings that we have.
     */
    newfd = accept(state->mediatorfd->fd, (struct sockaddr *)&saddr, &socklen);
    if (newfd < 0) {
        return newfd;
    }
    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
            portbuf, sizeof(portbuf), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        logger(LOG_INFO, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
    }

    /* See if this mediator already exists */
    HASH_FIND(hh, state->mediators, strbuf, strlen(strbuf), med);

    if (!med) {
        med = calloc(1, sizeof(prov_mediator_t));
        med->identifier = strdup(strbuf);
        init_provisioner_client(&(med->client));

        HASH_ADD_KEYPTR(hh, state->mediators, med->identifier,
                strlen(med->identifier), med);
    }

    halt_provisioner_client_idletimer(state->epoll_fd, &(med->client),
            med->identifier);

    return accept_provisioner_client(&(state->sslconf), state->epoll_fd,
            med->identifier, &(med->client), newfd, PROV_EPOLL_MEDIATOR,
            PROV_EPOLL_MEDIATOR_HANDSHAKE);

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
    state->clientfd->client = NULL;

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

static int start_mediator_listener(provision_state_t *state) {
    struct epoll_event ev;
    int sockfd;

    state->mediatorfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    if (state->mediateaddr == NULL) {
        state->mediateaddr = strdup("0.0.0.0");
        logger(LOG_INFO, "OpenLI provisioner: warning, no mediator listen address configured, listening on ALL addresses.");
        logger(LOG_INFO, "OpenLI provisioner: set 'mediationaddr' config option to resolve this.");
    }

    sockfd  = create_listener(state->mediateaddr, state->mediateport,
            "incoming mediator");
    if (sockfd == -1) {
        return -1;
    }

    state->mediatorfd->fd = sockfd;
    state->mediatorfd->fdtype = PROV_EPOLL_MEDIATE_CONN;
    state->mediatorfd->client = NULL;

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

static void remove_idle_client(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);

    if (cs->clientrole == PROV_EPOLL_COLLECTOR) {
        prov_collector_t *col;

        HASH_FIND(hh, state->collectors, cs->ipaddr, strlen(cs->ipaddr), col);
        destroy_provisioner_client(state->epoll_fd, pev->client, cs->ipaddr);
        if (col) {
            logger(LOG_DEBUG, "OpenLI: removed collector %s from internal list",
                    col->identifier);
            HASH_DELETE(hh, state->collectors, col);
            free(col->identifier);
            free(col);
        }
    } else if (cs->clientrole == PROV_EPOLL_MEDIATOR) {
        prov_mediator_t *med;

        HASH_FIND(hh, state->mediators, cs->ipaddr, strlen(cs->ipaddr), med);
        destroy_provisioner_client(state->epoll_fd, pev->client, cs->ipaddr);
        if (med) {
            logger(LOG_DEBUG, "OpenLI: removed mediator %s from internal list",
                    med->identifier);
            HASH_DELETE(hh, state->mediators, med);
            free_openli_mediator(med->details);
            free(med->identifier);
            free(med);
        }
    }

}

static void expire_unauthed(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);

    if (cs->clientrole == PROV_EPOLL_COLLECTOR) {
        if (cs->log_allowed) {
            logger(LOG_INFO,
                    "OpenLI Provisioner: dropping unauthed collector.");
        }
    }

    if (cs->clientrole == PROV_EPOLL_MEDIATOR) {
        if (cs->log_allowed) {
            logger(LOG_INFO,
                    "OpenLI Provisioner: dropping unauthed mediator.");
        }
    }
    disconnect_provisioner_client(state->epoll_fd, pev->client, cs->ipaddr);

}

static int check_epoll_fd(provision_state_t *state, struct epoll_event *ev) {

    int ret = 0;
    prov_epoll_ev_t *pev = (prov_epoll_ev_t *)(ev->data.ptr);
    prov_sock_state_t *cs = NULL;

    if (pev->client) {
        cs = (prov_sock_state_t *)(pev->client->state);
    }

    switch(pev->fdtype) {
        case PROV_EPOLL_COLL_CONN:
            ret = accept_collector(state);
            break;
        case PROV_EPOLL_MEDIATE_CONN:
            ret = accept_mediator(state);
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
                if (cs->log_allowed) {
                    logger(LOG_DEBUG,
                        "OpenLI Provisioner: disconnecting collector %s.",
                        cs->ipaddr);
                }
                cs->log_allowed = 0;
                disconnect_provisioner_client(state->epoll_fd, pev->client,
                        cs->ipaddr);
            }
            break;
        case PROV_EPOLL_FD_TIMER:
            if (ev->events & EPOLLIN) {
                expire_unauthed(state, pev);
            } else {
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                        "OpenLI Provisioner: client auth timer has failed.");
                }
                return -1;
            }
            break;

        case PROV_EPOLL_FD_IDLETIMER:
            if (ev->events & EPOLLIN) {
                remove_idle_client(state, pev);
            } else {
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                        "OpenLI Provisioner: client idle timer has failed.");
                }
                return -1;
            }
            break;

        case PROV_EPOLL_COLLECTOR_HANDSHAKE:
        case PROV_EPOLL_MEDIATOR_HANDSHAKE:
            //continue handshake process
            ret = continue_provisioner_client_handshake(state->epoll_fd,
                    pev->client, cs);
            if (ret == -1) {
                disconnect_provisioner_client(state->epoll_fd, pev->client,
                        cs->ipaddr);
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
                if (cs->log_allowed) {
                    logger(LOG_DEBUG,
                        "OpenLI Provisioner: disconnecting mediator %s.",
                        cs->ipaddr);
                }
                cs->log_allowed = 0;
                disconnect_provisioner_client(state->epoll_fd, pev->client,
                        cs->ipaddr);
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

            MHD_stop_daemon(currstate->updatedaemon);
            currstate->updatedaemon = NULL;

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
    } else if (newstate->pushaddr) {
        currstate->pushaddr = strdup(newstate->pushaddr);
        currstate->pushport = strdup(newstate->pushport);
        changed = 1;
    }

    if (changed) {
        logger(LOG_INFO,
                "OpenLI provisioner: update socket configuration has changed.");
        currstate->updatesockfd = create_listener(currstate->pushaddr,
                currstate->pushport, "update socket");

        if (currstate->updatesockfd != -1) {
            start_mhd_daemon(currstate);
        }

        if (currstate->updatesockfd == -1 || currstate->updatedaemon == NULL) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, update socket did not restart. Will not be able to receive live updates.");
            return -1;
        }
        return 1;
    }
    return 0;

}

static inline int reload_mediator_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    struct epoll_event ev;

    /* TODO this will trigger on a whitespace change */
    if (strcmp(newstate->mediateaddr, currstate->mediateaddr) != 0 ||
            strcmp(newstate->mediateport, currstate->mediateport) != 0) {

        free_all_mediators(currstate->epoll_fd, &(currstate->mediators));

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

        logger(LOG_INFO,
                "OpenLI provisioner: mediation socket configuration has changed.");
        if (start_mediator_listener(currstate) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, mediation socket did not restart. Will not be able to control mediators.");
            return -1;
        }
        return 1;
    }
    return 0;
}

static inline int reload_collector_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    struct epoll_event ev;

    /* TODO this will trigger on a whitespace change */
    if (strcmp(newstate->listenaddr, currstate->listenaddr) != 0 ||
            strcmp(newstate->listenport, currstate->listenport) != 0) {

        logger(LOG_INFO,
                "OpenLI provisioner: collector listening socket configuration has changed.");
        stop_all_collectors(currstate->epoll_fd, &(currstate->collectors));

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

        if (start_main_listener(currstate) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, listening socket did not restart. Will not be able to accept collector clients.");
            return -1;
        }
        return 1;
    }
    return 0;
}

static int reload_provisioner_config(provision_state_t *currstate) {

    provision_state_t newstate;
    int mediatorchanged = 0;
    int clientchanged = 0;
    int pushchanged = 0;
    int leachanged = 0;
    int tlschanged = 0;

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

    tlschanged = reload_ssl_config(&(currstate->sslconf), &(newstate.sslconf));
    if (tlschanged == -1) {
        return -1;
    }

    /* TODO update voip-ignorecomfort settings if necessary
     * -- includes calling modify_existing_intercept_options() on *all*
     *    VOIP intercepts if this does change and clientchanged == 0 */

    if (tlschanged != 0) {
        if (!mediatorchanged) {
            free_all_mediators(currstate->epoll_fd, &(currstate->mediators));
            mediatorchanged = 1;
        }
        if (!clientchanged) {
            stop_all_collectors(currstate->epoll_fd, &(currstate->collectors));
            clientchanged = 1;
        }
    }

    if (mediatorchanged && !clientchanged) {
        /* Tell all collectors to drop their mediators until further notice */
        disconnect_mediators_from_collectors(currstate);

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
        state->timerfd->client = NULL;
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

    if (state->updatedaemon) {
        MHD_stop_daemon(state->updatedaemon);
    }

}

static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [ -d ] -c configfile\n", prog);
    fprintf(stderr, "\nSet the -d flag to run this program as a daemon.\n");
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    sigset_t sigblock;
    int daemonmode = 0;
    char *pidfile = NULL;
    int ret;

    provision_state_t provstate;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "daemonise", 0, 0, 'd'},
            { "pidfile", 1, 0, 'p'},
            { NULL, 0, 0, 0},
        };

        int c = getopt_long(argc, argv, "c:p:dh", long_options, &optind);
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
            case 'p':
                pidfile = optarg;
                break;
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
        daemonise(argv[0], pidfile);
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

    if (provstate.interceptconffile == NULL) {
        provstate.interceptconffile = strdup(DEFAULT_INTERCEPT_CONFIG_FILE);
    }
    if ((ret = parse_intercept_config(provstate.interceptconffile,
            &(provstate.interceptconf))) < 0) {
        /* -2 means the config file was empty, but this is allowed for
         * the intercept config.
         */
        if (ret == -1) {
            logger(LOG_INFO, "OpenLI provisioner: error while parsing intercept config file '%s'", provstate.interceptconffile);
            return -1;
        }
    }

    /*
     * XXX could also sanity check intercept->mediator mappings too...
     */
    if ((ret = map_intercepts_to_leas(&(provstate.interceptconf))) != 0) {
        logger(LOG_INFO,
                "OpenLI: failed to map %d intercepts to agencies. Exiting.",
                ret);
        return -1;
    }

    if (start_main_listener(&provstate) == -1) {
        logger(LOG_INFO, "OpenLI: Error, could not start listening socket.");
        return 1;
    }

    if (start_mediator_listener(&provstate) == -1) {
        logger(LOG_INFO, "OpenLI: Warning, mediation socket did not start. Will not be able to control mediators.");
    }

    provstate.updatesockfd = create_listener(provstate.pushaddr,
            provstate.pushport, "update socket");
    if (provstate.updatesockfd == -1) {
        logger(LOG_INFO, "OpenLI: warning, update microhttpd server did not start. Will not be able to receive live updates via REST API.");
    } else {
        start_mhd_daemon(&provstate);
        if (provstate.updatedaemon == NULL) {
            logger(LOG_INFO, "OpenLI: warning, update microhttpd server did not start. Will not be able to receive live updates via REST API.");
        }
    }

    run(&provstate);

    clear_prov_state(&provstate);

    if (daemonmode && pidfile) {
        remove_pidfile(pidfile);
    }
    logger(LOG_INFO, "OpenLI: Provisioner has exited.");
}




// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
