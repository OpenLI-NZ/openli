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

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#include "provisioner.h"
#include "logger.h"
#include "netcomms.h"
#include "provisioner_client.h"
#include "intercept.h"

/* XXX Duplicated from provisioner.c */
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


#define SEND_ALL_COLLECTORS_BEGIN \
    prov_collector_t *col, *coltmp; \
    prov_sock_state_t *sock; \
    HASH_ITER(hh, state->collectors, col, coltmp) { \
        if (col->client == NULL || col->client->commev == NULL) { \
            continue; \
        } \
        sock = (prov_sock_state_t *)(col->client->state); \
        if (!sock->trusted || sock->halted) { \
            continue; \
        }

#define SEND_ALL_COLLECTORS_END \
        if (enable_epoll_write(state, col->client->commev) == -1) { \
            if (sock->log_allowed) { \
                logger(LOG_INFO, \
                        "OpenLI: unable to enable epoll write event for collector %s -- %s", \
                        col->identifier, strerror(errno)); \
            } \
            disconnect_provisioner_client(state->epoll_fd, \
                    col->client, col->identifier); \
        } \
    }

#define SEND_ALL_MEDIATORS_BEGIN \
    prov_mediator_t *med, *medtmp; \
    prov_sock_state_t *sock; \
    HASH_ITER(hh, state->mediators, med, medtmp) { \
        if (med->client == NULL || med->client->commev == NULL) { \
            continue; \
        } \
        sock = (prov_sock_state_t *)(med->client->state); \
        if (!sock->trusted || sock->halted) { \
            continue; \
        }

#define SEND_ALL_MEDIATORS_END \
        if (enable_epoll_write(state, med->client->commev) == -1) { \
            if (sock->log_allowed) { \
                logger(LOG_INFO, \
                        "OpenLI: unable to enable epoll write event for mediator %u -- %s", \
                        med->mediatorid, strerror(errno)); \
            } \
            disconnect_provisioner_client(state->epoll_fd, \
                    med->client, med->details->ipstr); \
        } \
    }


int announce_lea_to_mediators(provision_state_t *state,
        prov_agency_t *lea) {

    SEND_ALL_MEDIATORS_BEGIN
        if (push_lea_onto_net_buffer(sock->outgoing, lea->ag) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send LEA %s to mediator %u.",
                    lea->ag->agencyid, med->mediatorid);
            disconnect_provisioner_client(state->epoll_fd, med->client,
                    med->details->ipstr);
            continue;
        }
    SEND_ALL_MEDIATORS_END

    return 0;
}

int withdraw_agency_from_mediators(provision_state_t *state,
        prov_agency_t *lea) {

    SEND_ALL_MEDIATORS_BEGIN

        if (push_lea_withdrawal_onto_net_buffer(sock->outgoing,
                    lea->ag) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send withdrawal of LEA %s to mediator %u.",
                    lea->ag->agencyid, med->mediatorid);
            disconnect_provisioner_client(state->epoll_fd, med->client,
                    med->details->ipstr);
            continue;
        }
    SEND_ALL_MEDIATORS_END

    return 0;
}

int announce_default_radius_username(provision_state_t *state,
        default_radius_user_t *raduser) {

    SEND_ALL_COLLECTORS_BEGIN

        if (push_default_radius_onto_net_buffer(sock->outgoing, raduser) < 0) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END
    return 0;
}

int withdraw_default_radius_username(provision_state_t *state,
        default_radius_user_t *raduser) {

    SEND_ALL_COLLECTORS_BEGIN

        if (push_default_radius_withdraw_onto_net_buffer(sock->outgoing,
                raduser) < 0) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END
    return 0;
}

void add_new_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr) {

    SEND_ALL_COLLECTORS_BEGIN

        if (push_static_ipranges_onto_net_buffer(sock->outgoing,
                ipint, ipr) < 0) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END
}

void modify_existing_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr) {


    SEND_ALL_COLLECTORS_BEGIN

        if (push_static_ipranges_modify_onto_net_buffer(sock->outgoing,
                ipint, ipr) < 0) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END
}

void remove_existing_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr) {


    SEND_ALL_COLLECTORS_BEGIN

        if (push_static_ipranges_removal_onto_net_buffer(sock->outgoing,
                ipint, ipr) < 0) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END
}

int halt_existing_intercept(provision_state_t *state,
        void *cept, openli_proto_msgtype_t wdtype) {

    SEND_ALL_COLLECTORS_BEGIN

        if (push_intercept_withdrawal_onto_net_buffer(sock->outgoing,
                cept, wdtype) == -1) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END

    return 0;

}

int modify_existing_intercept_options(provision_state_t *state,
        void *cept, openli_proto_msgtype_t modtype) {

    SEND_ALL_COLLECTORS_BEGIN
        if (push_intercept_modify_onto_net_buffer(sock->outgoing,
                cept, modtype) == -1) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END

    return 0;

}

/* TODO replace all these functions with a single generic version, much
 * like announce_single_intercept but even more generic.
 */

int disconnect_mediators_from_collectors(provision_state_t *state) {

    SEND_ALL_COLLECTORS_BEGIN

        if (push_disconnect_mediators_onto_net_buffer(sock->outgoing) == -1) {
            disconnect_provisioner_client(state->epoll_fd,
                    col->client, col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END

    return 0;

}

int announce_hi1_notification_to_mediators(provision_state_t *state,
        intercept_common_t *intcomm, hi1_notify_t not_type) {

    /* For now, I'm just going to send the notification to all mediators
     * and rely on them to ignore those that are not for agencies that
     * they talk to -- ideally, we would limit these announcements to
     * only mediators that need to know, but that can be future work...
     */

    hi1_notify_data_t ndata;
    struct timeval tv;

    if (intcomm == NULL) {
        return -1;
    }

    gettimeofday(&tv, NULL);

    ndata.notify_type = not_type;
    ndata.liid = intcomm->liid;
    ndata.authcc = intcomm->authcc;
    ndata.delivcc = intcomm->delivcc;
    ndata.agencyid = intcomm->targetagency;
    ndata.seqno = intcomm->hi1_seqno;
    ndata.ts_sec = tv.tv_sec;
    ndata.ts_usec = tv.tv_usec;

    SEND_ALL_MEDIATORS_BEGIN
        if (push_hi1_notification_onto_net_buffer(sock->outgoing, &ndata) == -1)
        {
            if (sock->log_allowed) {
                logger(LOG_INFO,
                        "OpenLI provisioner: unable to send HI1 notification for intercept %s to mediator %u.", intcomm->liid, med->mediatorid);
            }
            disconnect_provisioner_client(state->epoll_fd, med->client,
                    med->details->ipstr);
            continue;
        }
    SEND_ALL_MEDIATORS_END
    return 0;
}

int remove_liid_mapping(provision_state_t *state,
        char *liid, int liid_len, int droppedmeds) {

    liid_hash_t *found;
    /* Don't need to find and remove the mapping from our LIID map, as
     * reload_lea() has already replaced our map with a new one. */

    if (droppedmeds) {
        return 0;
    }

    HASH_FIND(hh, state->interceptconf.liid_map, liid, strlen(liid), found);
    if (found) {
        HASH_DELETE(hh, state->interceptconf.liid_map, found);
        free(found);
    }

    SEND_ALL_MEDIATORS_BEGIN

    /* Still got mediators connected, so tell them about the now disabled
     * LIID.
     */

        if (push_cease_mediation_onto_net_buffer(sock->outgoing,
                    liid, liid_len) == -1) {
            if (sock->log_allowed) {
                logger(LOG_INFO,
                        "OpenLI provisioner: unable to halt mediation of intercept %s on mediator %u.",
                        liid, med->mediatorid);
            }
            disconnect_provisioner_client(state->epoll_fd, med->client,
                    med->details->ipstr);
            continue;
        }
    SEND_ALL_MEDIATORS_END

    return 0;
}

int announce_liidmapping_to_mediators(provision_state_t *state,
        liid_hash_t *liidmap) {

    if (liidmap == NULL) {
        return 0;
    }

    SEND_ALL_MEDIATORS_BEGIN
        if (push_liid_mapping_onto_net_buffer(sock->outgoing, liidmap->agency,
                liidmap->liid) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send mapping for LIID %s to mediator %u.",
                    liidmap->liid, med->mediatorid);
            disconnect_provisioner_client(state->epoll_fd, med->client,
                    med->details->ipstr);
            continue;
        }
    SEND_ALL_MEDIATORS_END

    return 0;
}

int announce_coreserver_change(provision_state_t *state,
        coreserver_t *cs, uint8_t isnew) {
    SEND_ALL_COLLECTORS_BEGIN

        if (isnew) {
            if (push_coreserver_onto_net_buffer(sock->outgoing, cs,
                        cs->servertype) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push new %s server to collector %s",
                        coreserver_type_to_string(cs->servertype),
                        col->identifier);
                disconnect_provisioner_client(state->epoll_fd, col->client,
                        col->identifier);
                continue;
            }
        } else {
            if (push_coreserver_withdraw_onto_net_buffer(sock->outgoing,
                        cs, cs->servertype) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push removal of %s server to collector %s",
                        coreserver_type_to_string(cs->servertype),
                        col->identifier);
                disconnect_provisioner_client(state->epoll_fd, col->client,
                        col->identifier);
                continue;
            }
        }

    SEND_ALL_COLLECTORS_END
    return 0;
}

int announce_sip_target_change(provision_state_t *state,
        openli_sip_identity_t *sipid, voipintercept_t *vint, uint8_t isnew) {

    SEND_ALL_COLLECTORS_BEGIN
        if (isnew) {
            if (push_sip_target_onto_net_buffer(sock->outgoing, sipid,
                        vint) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push SIP target to collector %s",
                        col->identifier);
                disconnect_provisioner_client(state->epoll_fd, col->client,
                        col->identifier);
                continue;
            }
        } else {
            if (push_sip_target_withdrawal_onto_net_buffer(sock->outgoing,
                        sipid, vint) == -1) {
                logger(LOG_INFO,
                        "OpenLI: Unable to push removal of SIP target to collector %s",
                        col->identifier);
                disconnect_provisioner_client(state->epoll_fd, col->client,
                        col->identifier);
                continue;
            }
        }
    SEND_ALL_COLLECTORS_END

    return 0;
}

int announce_all_sip_targets(provision_state_t *state, voipintercept_t *vint) {
    libtrace_list_node_t *n;
    openli_sip_identity_t *sipid;

    n = vint->targets->head;
    while (n) {
        sipid = *((openli_sip_identity_t **)(n->data));
        if (sipid->awaitingconfirm && announce_sip_target_change(state,
				sipid, vint, 1) < 0) {
            return -1;
        }
		sipid->awaitingconfirm = 0;
        n = n->next;
    }
    return 0;
}

int remove_all_sip_targets(provision_state_t *state, voipintercept_t *vint) {
    libtrace_list_node_t *n;
    openli_sip_identity_t *sipid;

    n = vint->targets->head;
    while (n) {
        sipid = *((openli_sip_identity_t **)(n->data));
        if (sipid->awaitingconfirm == 0 && announce_sip_target_change(state,
				sipid, vint, 1) < 0) {
            return -1;
        }
        n = n->next;
    }
    return 0;
}

int announce_single_intercept(provision_state_t *state,
        void *cept, int (*sendfunc)(net_buffer_t *, void *)) {

    SEND_ALL_COLLECTORS_BEGIN

        if (sendfunc(sock->outgoing, cept) == -1) {
            disconnect_provisioner_client(state->epoll_fd, col->client,
                    col->identifier);
            continue;
        }

    SEND_ALL_COLLECTORS_END

    return 0;
}

liid_hash_t *add_liid_mapping(prov_intercept_conf_t *conf,
        char *liid, char *agency) {

    liid_hash_t *h, *found;
    prov_agency_t *lea;

    /* pcapdisk is a special agency that is not user-defined */
    if (strcmp(agency, "pcapdisk") != 0) {
        HASH_FIND_STR(conf->leas, agency, lea);
        if (!lea) {
            logger(LOG_INFO,
                    "OpenLI: intercept %s is destined for an unknown agency: %s -- skipping.",
                    liid, agency);
            return NULL;
        }
    }

    HASH_FIND(hh, conf->liid_map, liid, strlen(liid), found);
    if (found) {
        found->agency = agency;
        h = found;
    } else {
        h = (liid_hash_t *)malloc(sizeof(liid_hash_t));
        h->agency = agency;
        h->liid = liid;
        HASH_ADD_KEYPTR(hh, conf->liid_map, h->liid, strlen(h->liid), h);
    }

    return h;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
