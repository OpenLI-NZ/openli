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

#include "collector.h"
#include "collector_sync.h"
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

    free_all_intercepts(sync->ipintercepts);
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
        ev.events = EPOLLIN;

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
                //ret = new_mediator(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
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

    /* Add instruct_fd to epoll for both reading and writing */
    sync->ii_ev->fdtype = SYNC_EVENT_PROVISIONER;
    sync->ii_ev->fd = sync->instruct_fd;
    sync->ii_ev->msgq = NULL;

    ev.data.ptr = (void *)(sync->ii_ev);
    ev.events = EPOLLIN | EPOLLOUT;

    if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register provisioner fd: %s",
                strerror(errno));
        return -1;
    }

    return 1;

}

static inline void disconnect_provisioner(collector_sync_t *sync) {

    struct epoll_event ev;

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
}

static void push_all_active_intercepts(libtrace_list_t *intlist,
        libtrace_message_queue_t *q) {

    libtrace_list_node_t *n = intlist->head;
    openli_pushed_t msg;
    ipintercept_t *orig;
    ipintercept_t *copy;

    while (n) {
        orig = (ipintercept_t *)(n->data);
        if (!orig->active) {
            n = n->next;
            continue;
        }

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

        msg.type = OPENLI_PUSH_IPINTERCEPT;
        msg.data.ipint = copy;

        libtrace_message_queue_put(q, (void *)(&msg));

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
                !(evs[i].events & EPOLLIN)) {
            /* Some error detection / handling? */

            /* Don't close any fds on error -- they should get closed when
             * their parent structures are tidied up */

            epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL,
                    syncev->fd, NULL);

            if (syncev->fd == sync->instruct_fd) {
                logger(LOG_DAEMON, "OpenLI: collector lost connection to central provisioner");
                disconnect_provisioner(sync);
                return 0;

            } else {
                logger(LOG_DAEMON, "OpenLI: processor->sync message queue pipe has broken down.");
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
            push_all_active_intercepts(sync->ipintercepts, recvd.data.replyq);
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
