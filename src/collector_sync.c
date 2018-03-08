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


#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libtrace_parallel.h>
#include <assert.h>
#include <netdb.h>

#include "collector.h"
#include "collector_sync.h"
#include "collector_export.h"
#include "configparser.h"
#include "logger.h"
#include "intercept.h"
#include "netcomms.h"
#include "util.h"

collector_sync_t *init_sync_data(collector_global_t *glob) {

	collector_sync_t *sync = (collector_sync_t *)
			malloc(sizeof(collector_sync_t));

    sync->glob = glob;
    sync->ipintercepts = libtrace_list_init(sizeof(ipintercept_t));
    sync->voipintercepts = NULL;
    sync->instruct_fd = -1;
    sync->instruct_fail = 0;
    sync->ii_ev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));
    sync->glob->sync_epollfd = epoll_create1(0);

    libtrace_message_queue_init(&(sync->exportq), sizeof(openli_exportmsg_t));

    sync->outgoing = NULL;
    sync->incoming = NULL;

    return sync;

}

void clean_sync_data(collector_sync_t *sync) {

    int i = 0;

	if (sync->instruct_fd != -1) {
		close(sync->instruct_fd);
	}

	if (sync->glob->sync_epollfd != -1) {
		close(sync->glob->sync_epollfd);
	}

    /* XXX possibly need to lock this? */
    for (i = 0; i < sync->glob->registered_syncqs; i++) {
        free(sync->glob->syncepollevs[i]);
    }

    free_all_ipintercepts(sync->ipintercepts);
    free_all_voipintercepts(sync->voipintercepts);
	libtrace_message_queue_destroy(&(sync->exportq));

    if (sync->outgoing) {
        destroy_net_buffer(sync->outgoing);
    }

    if (sync->incoming) {
        destroy_net_buffer(sync->incoming);
    }

    if (sync->ii_ev) {
        free(sync->ii_ev);
    }

	free(sync);

}

static inline void push_single_intercept(libtrace_message_queue_t *q,
        ipintercept_t *orig) {

    ipintercept_t *copy;
    openli_pushed_t msg;

    copy = (ipintercept_t *)malloc(sizeof(ipintercept_t));

    copy->internalid = orig->internalid;
    copy->liid = strdup(orig->liid);
    copy->liid_len = strlen(copy->liid);
    copy->authcc = strdup(orig->authcc);
    copy->authcc_len = strlen(copy->authcc);
    copy->delivcc = strdup(orig->delivcc);
    copy->delivcc_len = strlen(copy->delivcc);
    copy->cin = orig->cin;
    copy->ai_family = orig->ai_family;
    copy->destid = orig->destid;

    if (orig->targetagency) {
        copy->targetagency = strdup(orig->targetagency);
    } else {
        copy->targetagency = NULL;
    }

    if (orig->ipaddr) {
        copy->ipaddr = (struct sockaddr_storage *)malloc(
                sizeof(struct sockaddr_storage));
        memcpy(copy->ipaddr, orig->ipaddr, sizeof(struct sockaddr_storage));
    } else {
        copy->ipaddr = NULL;
    }

    if (orig->username) {
        copy->username = strdup(orig->username);
        copy->username_len = strlen(copy->username);
    } else {
        copy->username = NULL;
        copy->username_len = 0;
    }

    copy->active = 1;
    copy->nextseqno = 0;
    copy->awaitingconfirm = 0;

    msg.type = OPENLI_PUSH_IPINTERCEPT;
    msg.data.ipint = copy;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static inline void push_single_voipstreamintercept(libtrace_message_queue_t *q,
        rtpstreaminf_t *orig) {

    rtpstreaminf_t *copy;
    openli_pushed_t msg;

    copy = (rtpstreaminf_t *)malloc(sizeof(rtpstreaminf_t));

    copy->liid = strdup(orig->liid);
    copy->authcc = strdup(orig->authcc);
    copy->delivcc = strdup(orig->delivcc);
    copy->destid = orig->destid;

    if (orig->targetagency) {
        copy->targetagency = strdup(orig->targetagency);
    } else {
        copy->targetagency = NULL;
    }

    copy->cin = orig->cin;
    copy->ai_family = orig->ai_family;
    copy->addr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));
    memcpy(copy->addr, orig->addr, sizeof(struct sockaddr_storage));
    copy->port = orig->port;

    msg.type = OPENLI_PUSH_IPMMINTERCEPT;
    msg.data.ipmmint = copy;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static int send_to_provisioner(collector_sync_t *sync) {

    int ret;
    struct epoll_event ev;

    ret = transmit_net_buffer(sync->outgoing);
    if (ret == -1) {
        /* Something went wrong */
        logger(LOG_DAEMON,
                "OpenLI: error sending message from collector to provisioner.");
        return -1;
    }

    if (ret == 0) {
        /* Everything has been sent successfully, no more to send right now. */
        ev.data.ptr = sync->ii_ev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_MOD,
                    sync->instruct_fd, &ev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error disabling EPOLLOUT on provisioner fd: %s.",
                    strerror(errno));
            return -1;
        }
    }

    return 1;
}

static void disable_unconfirmed_intercepts(collector_sync_t *sync) {
    libtrace_list_node_t *n;
    voipintercept_t *v;
    int i;

    n = sync->ipintercepts->head;

    /* TODO count total inactive as we go and reconstruct the list
     * if the inactive count is relatively high?
     */

    while (n) {
        ipintercept_t *cept = (ipintercept_t *)(n->data);

        if (cept->awaitingconfirm && cept->active) {
            cept->active = 0;

            for (i = 0; i < sync->glob->registered_syncqs; i++) {
                openli_pushed_t pmsg;

                /* strdup because we might end up freeing this intercept
                 * shortly.
                 */
                pmsg.type = OPENLI_PUSH_HALT_IPINTERCEPT;
                pmsg.data.interceptid.liid = strdup(cept->liid);
                pmsg.data.interceptid.authcc = strdup(cept->authcc);
                libtrace_message_queue_put(sync->glob->syncsendqs[i], &pmsg);
            }
        }
        n = n->next;
    }

    for (v = sync->voipintercepts; v != NULL; v = v->hh.next) {
        if (v->awaitingconfirm && v->active) {
            v->active = 0;

            if (v->active_cins == NULL ||
                    libtrace_list_get_size(v->active_cins) == 0) {
                continue;
            }

            for (i = 0; i < sync->glob->registered_syncqs; i++) {
                openli_pushed_t pmsg;

                /* strdup because we might end up freeing this intercept
                 * shortly.
                 */
                pmsg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
                pmsg.data.interceptid.liid = strdup(v->liid);
                pmsg.data.interceptid.authcc = strdup(v->authcc);
                libtrace_message_queue_put(sync->glob->syncsendqs[i], &pmsg);
            }
        }
    }
}

static int new_mediator(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    openli_mediator_t med;
    openli_export_recv_t expmsg;

    if (decode_mediator_announcement(provmsg, msglen, &med) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid mediator announcement from provisioner.");
        return -1;
    }

    expmsg.type = OPENLI_EXPORT_MEDIATOR;
    expmsg.data.med = med;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);
    return 0;
}

static void finish_init_mediators(collector_sync_t *sync) {
    openli_export_recv_t expmsg;

    expmsg.type = OPENLI_EXPORT_INIT_MEDIATORS_OVER;
    expmsg.data.packet = NULL;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);
}

static void temporary_map_user_to_address(ipintercept_t *cept) {

    char *knownip;
    struct addrinfo *res = NULL;
    struct addrinfo hints;

    if (strcmp(cept->username, "RogerMegently") == 0) {
        knownip = "130.217.250.112";
    } else if (strcmp(cept->username, "Everything") == 0) {
        knownip = "130.217.250.111";
    } else {
        return;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(knownip, NULL, &hints, &res) != 0) {
        logger(LOG_DAEMON, "OpenLI: getaddrinfo cannot parse IP address %s: %s",
                knownip, strerror(errno));
    }

    cept->ai_family = res->ai_family;
    cept->ipaddr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));
    memcpy(cept->ipaddr, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
}

static void push_all_active_voipstreams(libtrace_message_queue_t *q,
        voipintercept_t *vint) {

    libtrace_list_node_t *n;

    if (vint->active_cins == NULL) {
        return;
    }

    n = vint->active_cins->head;
    while (n) {
        libtrace_list_node_t *ms;
        voipcin_t *cin = (voipcin_t *)(n->data);
        if (!cin || cin->ended || cin->callid == NULL) {
            n = n->next;
            continue;
        }

        ms = cin->mediastreams->head;

        while (ms) {
            rtpstreaminf_t *rtp = (rtpstreaminf_t *)(ms->data);

            push_single_voipstreamintercept(q, rtp);
            ms = ms->next;
        }
        n = n->next;
    }

}

static int new_voipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    voipintercept_t *vint, toadd;
    int i;

    if (decode_voipintercept_start(intmsg, msglen, &toadd) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid VOIP intercept from provisioner.");
        return -1;
    }

    HASH_FIND_STR(sync->voipintercepts, toadd.liid, vint);
    if (vint) {
        /* Duplicate LIID */
        if (strcmp(toadd.sipuri, vint->sipuri) != 0) {
            logger(LOG_DAEMON,
                    "OpenLI: duplicate VOIP intercept ID %s seen, but targets are different (was %s, now %s).",
                    vint->liid, vint->sipuri, toadd.sipuri);
            return -1;
        }
        vint->internalid = toadd.internalid;
        vint->awaitingconfirm = 0;
        vint->active = 1;
        return 0;
    }

    vint = (voipintercept_t *)malloc(sizeof(voipintercept_t));
    memcpy(vint, &toadd, sizeof(voipintercept_t));
    HASH_ADD_KEYPTR(hh, sync->voipintercepts, vint->liid, vint->liid_len, vint);

    fprintf(stderr, "received VOIP intercept %lu %s %s\n", vint->internalid,
            vint->liid, vint->sipuri);
    /* TODO look up any CINs that we already have for this SIP URI. */

    /* XXX do we need to do this? can we just worry about calls that
     * start from now onwards, rather than having to keep track of every
     * ongoing call just in case we get an intercept request in the middle
     * of it?
     */

    if (vint->active_cins == NULL) {
        return 0;
    }

    for (i = 0; i < sync->glob->registered_syncqs; i++) {

        /* Forward all active CINs to our collector threads */
        push_all_active_voipstreams(sync->glob->syncsendqs[i], vint);

    }
}

static int new_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t cept;
    libtrace_list_node_t *n;
    int i;

    if (decode_ipintercept_start(intmsg, msglen, &cept) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid IP intercept from provisioner.");
        return -1;
    }

    /* Check if we already have this intercept */
    n = sync->ipintercepts->head;
    while (n) {
        ipintercept_t *x = (ipintercept_t *)(n->data);
        if (strcmp(x->liid, cept.liid) == 0 &&
                strcmp(x->authcc, cept.authcc) == 0) {
            /* Duplicate LIID */

            /* OpenLI-internal fields that could change value
             * if the provisioner was restarted.
             */
            if (strcmp(x->username, cept.username) != 0) {
                logger(LOG_DAEMON,
                        "OpenLI: duplicate IP ID %s seen, but targets are different (was %s, now %s).",
                        x->liid, x->username, cept.username);
                return -1;
            }
            x->internalid = cept.internalid;
            x->awaitingconfirm = 0;
            x->active = 1;
            /* our collector threads should already know about this intercept?
             */
            return 0;
        }

        n = n->next;
    }

    /* TODO try to find a CIN and IP address for this intercept, based on our
     * known RADIUS (or equivalent) state.
     *
     * Only push the intercept to the processing threads once we've
     * assigned a suitable CIN.
     */

    /* Temporary hard-coded mappings for testing.
     * Please remove once proper RADIUS support is added.
     */

    fprintf(stderr, "received IP intercept %lu %s %s\n", cept.internalid,
            cept.liid, cept.username);
    if (n == NULL) {
        temporary_map_user_to_address(&cept);

        libtrace_list_push_front(sync->ipintercepts, &cept);
        n = sync->ipintercepts->head;
    }

    for (i = 0; i < sync->glob->registered_syncqs; i++) {
        push_single_intercept(sync->glob->syncsendqs[i],
                (ipintercept_t *)(n->data));
    }

    return 0;

}

static int recv_from_provisioner(collector_sync_t *sync) {
    struct epoll_event ev;
    int ret = 0;
    uint8_t *provmsg;
    uint16_t msglen = 0;
    uint64_t intid = 0;

    openli_proto_msgtype_t msgtype;

    do {
        msgtype = receive_net_buffer(sync->incoming, &provmsg, &msglen, &intid);
        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_ANNOUNCE_MEDIATOR:
                ret = new_mediator(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_START_IPINTERCEPT:
                ret = new_ipintercept(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_START_VOIPINTERCEPT:
                ret = new_voipintercept(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_NOMORE_INTERCEPTS:
                disable_unconfirmed_intercepts(sync);
                break;
            case OPENLI_PROTO_NOMORE_MEDIATORS:
                finish_init_mediators(sync);
                break;
        }

    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    return 1;
}

int sync_connect_provisioner(collector_sync_t *sync) {

    struct epoll_event ev;
    int sockfd;


    sockfd = connect_socket(sync->glob->provisionerip,
            sync->glob->provisionerport, sync->instruct_fail);

    if (sockfd == -1) {
        return -1;
    }

    if (sockfd == 0) {
        sync->instruct_fail = 1;
        return 0;
    }

    sync->instruct_fail = 0;
    sync->instruct_fd = sockfd;

    assert(sync->outgoing == NULL && sync->incoming == NULL);

    sync->outgoing = create_net_buffer(NETBUF_SEND, sync->instruct_fd);
    sync->incoming = create_net_buffer(NETBUF_RECV, sync->instruct_fd);

    /* Put our auth message onto the outgoing buffer */
    if (push_auth_onto_net_buffer(sync->outgoing, OPENLI_PROTO_COLLECTOR_AUTH)
            < 0) {
        logger(LOG_DAEMON,"OpenLI: collector is unable to queue auth message.");
        return -1;
    }

    /* Add instruct_fd to epoll for both reading and writing */
    sync->ii_ev->fdtype = SYNC_EVENT_PROVISIONER;
    sync->ii_ev->fd = sync->instruct_fd;
    sync->ii_ev->msgq = NULL;

    ev.data.ptr = (void *)(sync->ii_ev);
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

    if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register provisioner fd: %s",
                strerror(errno));
        return -1;
    }

    return 1;

}

static inline void touch_all_intercepts(libtrace_list_t *intlist) {
    libtrace_list_node_t *n;
    ipintercept_t *ipint;

    /* Set all intercepts to be "awaiting confirmation", i.e. if the
     * provisioner doesn't announce them in its initial batch of
     * intercepts then they are to be halted.
     */
    n = intlist->head;
    while (n) {
        ipint = (ipintercept_t *)(n->data);
        ipint->awaitingconfirm = 1;
        n = n->next;
    }
}

static inline void touch_all_voipintercepts(voipintercept_t *vints) {
    voipintercept_t *v;

    for (v = vints; v != NULL; v = v->hh.next) {
        v->awaitingconfirm = 1;
    }
}

static inline void disconnect_provisioner(collector_sync_t *sync) {

    struct epoll_event ev;
    openli_export_recv_t expmsg;

    destroy_net_buffer(sync->outgoing);
    destroy_net_buffer(sync->incoming);

    sync->outgoing = NULL;
    sync->incoming = NULL;

    if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL, sync->instruct_fd,
            &ev) == -1) {
        logger(LOG_DAEMON, "OpenLI: error de-registering provisioner fd: %s.",
                strerror(errno));
    }

    close(sync->instruct_fd);
    sync->instruct_fd = -1;

    /* Leave all intercepts running, but require them to be confirmed
     * as active when we reconnect to the provisioner.
     */
    touch_all_intercepts(sync->ipintercepts);
    touch_all_voipintercepts(sync->voipintercepts);

    /* Same with mediators -- keep exporting to them, but flag them to be
     * disconnected if they are not announced after we reconnect. */
    expmsg.type = OPENLI_EXPORT_FLAG_MEDIATORS;
    expmsg.data.packet = NULL;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);


}

static void push_all_active_intercepts(libtrace_list_t *intlist,
        libtrace_message_queue_t *q) {

    libtrace_list_node_t *n = intlist->head;
    ipintercept_t *orig;

    while (n) {
        orig = (ipintercept_t *)(n->data);
        if (!orig->active) {
            n = n->next;
            continue;
        }
        push_single_intercept(q, orig);

        n = n->next;
    }

}

int sync_thread_main(collector_sync_t *sync) {

    int i, nfds;
    struct epoll_event evs[64];
    openli_state_update_t recvd;
    libtrace_message_queue_t *srcq = NULL;
    sync_epoll_t *syncev;

    nfds = epoll_wait(sync->glob->sync_epollfd, evs, 64, 50);

    if (nfds <= 0) {
        return nfds;
    }

    for (i = 0; i < nfds; i++) {
        syncev = (sync_epoll_t *)(evs[i].data.ptr);

	    /* Check for incoming messages from processing threads and II fd */
        if ((evs[i].events & EPOLLERR) || (evs[i].events & EPOLLHUP) ||
                (evs[i].events & EPOLLRDHUP)) {
            /* Some error detection / handling? */

            /* Don't close any fds on error -- they should get closed when
             * their parent structures are tidied up */


            if (syncev->fd == sync->instruct_fd) {
                logger(LOG_DAEMON, "OpenLI: collector lost connection to central provisioner");
                disconnect_provisioner(sync);
                return 0;

            } else {
                logger(LOG_DAEMON, "OpenLI: processor->sync message queue pipe has broken down.");
                epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL,
                        syncev->fd, NULL);
            }

            continue;
        }

        if (syncev->fd == sync->instruct_fd) {
            /* Provisioner fd */
            if (evs[i].events & EPOLLOUT) {
                if (send_to_provisioner(sync) <= 0) {
                    disconnect_provisioner(sync);
                    return 0;
                }
            } else {
                if (recv_from_provisioner(sync) <= 0) {
                    disconnect_provisioner(sync);
                    return 0;
                }
            }
            continue;
        }

        /* Must be from a processing thread queue, figure out which one */
        libtrace_message_queue_get(syncev->msgq, (void *)(&recvd));

        /* If a hello from a thread, push all active intercepts back */
        if (recvd.type == OPENLI_UPDATE_HELLO) {
            voipintercept_t *v;

            push_all_active_intercepts(sync->ipintercepts, recvd.data.replyq);
            for (v = sync->voipintercepts; v != NULL; v = v->hh.next) {
                push_all_active_voipstreams(recvd.data.replyq, v);
            }
        }


        /* If an update from a thread, update appropriate internal state */

        /* If this resolves an unknown mapping or changes an existing one,
         * push II update messages to processing threads */

        /* If this relates to an active intercept, create IRI and export */

    }

    return nfds;
}

static inline void push_hello_message(libtrace_message_queue_t *atob,
        libtrace_message_queue_t *btoa) {

    openli_state_update_t hello;

    hello.type = OPENLI_UPDATE_HELLO;
    hello.data.replyq = btoa;

    libtrace_message_queue_put(atob, (void *)(&hello));
}

void register_sync_queues(collector_global_t *glob,
        libtrace_message_queue_t *recvq, libtrace_message_queue_t *sendq) {

    struct epoll_event ev;
    sync_epoll_t *syncev;
    int ind;

    syncev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));
    syncev->fdtype = SYNC_EVENT_PROC_QUEUE;
    syncev->fd = libtrace_message_queue_get_fd(recvq);
    syncev->msgq = recvq;

    ev.data.ptr = (void *)syncev;
    ev.events = EPOLLIN;

    if (epoll_ctl(glob->sync_epollfd, EPOLL_CTL_ADD, syncev->fd, &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register processor->sync queue: %s",
                strerror(errno));
    }

    pthread_mutex_lock(&(glob->syncq_mutex));
    ind  = glob->registered_syncqs;

    glob->syncsendqs[ind] = sendq;
    glob->syncepollevs[ind] = syncev;
    glob->registered_syncqs ++;
    pthread_mutex_unlock(&(glob->syncq_mutex));

    printf("Registered sync queue %d\n", ind);

    push_hello_message(recvq, sendq);
}

void halt_processing_threads(collector_global_t *glob) {
    int i;

    for (i = 0; i < glob->inputcount; i++) {
        trace_pstop(glob->inputs[i].trace);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
