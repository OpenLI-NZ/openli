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

#include "collector.h"
#include "collector_sync.h"
#include "configparser.h"
#include "logger.h"
#include "intercept.h"

collector_sync_t *init_sync_data(collector_global_t *glob) {

	collector_sync_t *sync = (collector_sync_t *)
			malloc(sizeof(collector_sync_t));

    sync->glob = glob;
    sync->ipintercepts = libtrace_list_init(sizeof(ipintercept_t));
    sync->instruct_fd = -1;
    sync->glob->sync_epollfd = epoll_create1(0);

    libtrace_message_queue_init(&(sync->exportq), sizeof(openli_exportmsg_t));

    return sync;

}

void clean_sync_data(collector_sync_t *sync) {

	if (sync->instruct_fd != -1) {
		close(sync->instruct_fd);
	}

	if (sync->glob->sync_epollfd != -1) {
		close(sync->glob->sync_epollfd);
	}

    free_all_intercepts(sync->ipintercepts);
	libtrace_message_queue_destroy(&(sync->exportq));

	free(sync);

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

    nfds = epoll_wait(sync->glob->sync_epollfd, evs, 64, 50);

    if (nfds <= 0) {
        return nfds;
    }

    for (i = 0; i < nfds; i++) {
	    /* Check for incoming messages from processing threads and II fd */
        if ((evs[i].events & EPOLLERR) || (evs[i].events & EPOLLHUP) ||
                !(evs[i].events & EPOLLIN)) {
            /* Some error detection / handling? */

            /* Don't close any fds on error -- they should get closed when
             * their parent structures are tidied up */

            if (evs[i].data.fd == sync->instruct_fd) {
                logger(LOG_DAEMON, "OpenLI: collector lost connection to central provisioner");
                /* TODO reconnect */
            } else {
                logger(LOG_DAEMON, "OpenLI: processor->sync message queue pipe has broken down.");
            }

            epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL,
                    evs[i].data.fd, NULL);
            continue;
        }

	    /* If II message, update intercept list and search for known mapping */
        if (evs[i].data.fd == sync->instruct_fd) {

		    /* If mapping exists, push a II message to all processing
    		 * threads */

             continue;
        }

        /* Must be from a processing thread queue, figure out which one */
        srcq = (libtrace_message_queue_t *) (evs[i].data.ptr);
        libtrace_message_queue_get(srcq, (void *)(&recvd));

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
    int ind;

    ev.data.ptr = (void *)recvq;
    ev.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(glob->sync_epollfd, EPOLL_CTL_ADD,
                libtrace_message_queue_get_fd(recvq), &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register processor->sync queue: %s",
                strerror(errno));
    }

    pthread_mutex_lock(&(glob->syncq_mutex));
    ind  = glob->registered_syncqs;
    glob->syncsendqs[ind] = sendq;
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
