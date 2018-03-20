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

#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>

#include <libtrace.h>
#include <libtrace_parallel.h>

#include "collector.h"
#include "collector_export.h"
#include "export_buffer.h"
#include "configparser.h"
#include "logger.h"
#include "util.h"

enum {
    EXP_EPOLL_MQUEUE = 0,
    EXP_EPOLL_TIMER = 1
};

typedef struct exporter_epoll {
    uint8_t type;
    union {
        libtrace_message_queue_t *q;
        export_dest_t *dest;
    } data;
} exporter_epoll_t;

collector_export_t *init_exporter(collector_global_t *glob) {

    collector_export_t *exp = (collector_export_t *)malloc(
            sizeof(collector_export_t));

    exp->glob = glob;
    exp->dests = libtrace_list_init(sizeof(export_dest_t));

    pthread_mutex_lock(&glob->exportq_mutex);
    exp->glob->export_epollfd = epoll_create1(0);
    pthread_cond_signal(&glob->exportq_cond);
    pthread_mutex_unlock(&glob->exportq_mutex);
    exp->failed_conns = 0;
    return exp;
}

static int connect_single_target(export_dest_t *dest) {

    int sockfd;

    if (dest->details.ipstr == NULL) {
        /* This is an unannounced mediator */
        return -1;
    }

    sockfd = connect_socket(dest->details.ipstr, dest->details.portstr,
            dest->failmsg);

    if (sockfd == -1) {
        /* TODO should probably bail completely on this dest if this
         * happens. */
        return -1;
    }

    if (sockfd == 0) {
        dest->failmsg = 1;
        return -1;
    }

    dest->failmsg = 0;
    /* If we disconnected after a partial send, make sure we re-send the
     * whole record and trust that downstream will figure out how to deal
     * with any duplication.
     */
    dest->buffer.partialfront = 0;
    return sockfd;
}

int connect_export_targets(collector_export_t *exp) {

    int success = 0;
    libtrace_list_node_t *n;
    export_dest_t *d;

    exp->failed_conns = 0;

    n = exp->dests->head;

    while (n) {
        d = (export_dest_t *)n->data;
        n = n->next;

        if (d->halted) {
            continue;
        }

        if (d->fd != -1) {
            /* Already connected */
            success ++;
            continue;
        }

        d->fd = connect_single_target(d);
        if (d->fd != -1) {
            success ++;
        } else {
            exp->failed_conns ++;
        }
    }

    /* Return number of targets which we connected to */
    return success;

}

void destroy_exporter(collector_export_t *exp) {
    libtrace_list_node_t *n;
    export_dest_t *d;

    if (exp->glob->export_epollfd != -1) {
        close(exp->glob->export_epollfd);
    }

    /* Close all dest fds */
    n = exp->dests->head;
    while (n) {
        d = (export_dest_t *)n->data;
        if (d->fd != -1) {
            close(d->fd);
        }
        /* Don't free d->details, let the sync thread tidy this up */
        release_export_buffer(&(d->buffer));

        if (d->details.portstr) {
            free(d->details.portstr);
        }

        if (d->details.ipstr) {
            free(d->details.ipstr);
        }
        n = n->next;
    }

    libtrace_list_deinit(exp->dests);

    n = exp->glob->export_epoll_evs->head;
    while (n) {
        exporter_epoll_t *ev = *((exporter_epoll_t **)n->data);
        free(ev);
        n = n->next;
    }
    libtrace_list_deinit(exp->glob->export_epoll_evs);

    free(exp);
}


static int forward_fd(export_dest_t *dest, openli_exportmsg_t *msg) {

    uint32_t enclen = msg->msglen - msg->ipclen;
    int ret;
    struct iovec iov[3];
    struct msghdr mh;
    int ind = 0;
    int total = 0;

    if (msg->header) {

        iov[ind].iov_base = msg->header;
        iov[ind].iov_len = msg->hdrlen;
        ind ++;
        total += msg->hdrlen;
    }

    iov[ind].iov_base = msg->msgbody;
    iov[ind].iov_len = enclen;
    total += enclen;
    ind ++;

    if (msg->ipclen > 0) {
        iov[ind].iov_base = msg->ipcontents;
        iov[ind].iov_len = msg->ipclen;
        ind ++;
        total += msg->ipclen;
    }

    mh.msg_name = NULL;
    mh.msg_namelen = 0;
    mh.msg_iov = iov;
    mh.msg_iovlen = ind;
    mh.msg_control = NULL;
    mh.msg_controllen = 0;
    mh.msg_flags = 0;

    ret = sendmsg(dest->fd, &mh, MSG_DONTWAIT);
    if (ret < 0) {
        if (append_message_to_buffer(&(dest->buffer), msg, 0) == 0) {

            /* TODO do something if we run out of memory? */

        }
        if (errno != EAGAIN) {
            logger(LOG_DAEMON, "OpenLI: Error exporting to target %s:%s -- %s.",
                dest->details.ipstr, dest->details.portstr, strerror(errno));
            return -1;
        }

        return 0;
    } else if (ret < total && ret >= 0) {
        /* Partial send, save whole message but make sure the buffer knows
         * how much we've already sent so it can continue from there.
         */
        if (append_message_to_buffer(&(dest->buffer), msg, (uint32_t)ret)
                    == 0) {
            /* TODO do something if we run out of memory? */
        }
    }

    return 0;
}

#define BUF_BATCH_SIZE (10 * 1024 * 1024)

static int forward_message(export_dest_t *dest, openli_exportmsg_t *msg) {

    if (dest->fd == -1) {
        /* buffer this message for when we are able to connect */
        if (append_message_to_buffer(&(dest->buffer), msg, 0) == 0) {
            /* TODO do something if we run out of memory? */

        }
        return 0;
    }

    if (get_buffered_amount(&(dest->buffer)) == 0) {
        return forward_fd(dest, msg);
    }

    if (transmit_buffered_records(&(dest->buffer), dest->fd, BUF_BATCH_SIZE)
                == -1) {

        return -1;

    }

    if (get_buffered_amount(&(dest->buffer)) == 0) {
        /* buffer is now empty, try to push out this message too */
        return forward_fd(dest, msg);
    }

    /* buffer was not completely drained, so we have to buffer this
     * message too -- hopefully we'll catch up soon */
    if (append_message_to_buffer(&(dest->buffer), msg, 0) == 0) {
        /* TODO do something if we run out of memory? */

    }

    return 0;
}

static inline export_dest_t *add_unknown_destination(collector_export_t *exp,
        uint32_t medid) {
    export_dest_t newdest, *dest;

    newdest.failmsg = 0;
    newdest.fd = -1;
    newdest.details.mediatorid = medid;
    newdest.details.ipstr = NULL;
    newdest.details.portstr = NULL;
    newdest.awaitingconfirm = 0;
    newdest.halted = 0;
    init_export_buffer(&(newdest.buffer), 1);

    libtrace_list_push_back(exp->dests, &newdest);

    dest = (export_dest_t *)(exp->dests->tail->data);
    return dest;
}

static inline void add_new_destination(collector_export_t *exp,
        openli_mediator_t *med) {

    libtrace_list_node_t *n;
    export_dest_t newdest, *dest;

    n = exp->dests->head;
    while (n) {
        dest = (export_dest_t *)(n->data);
        if (dest->details.ipstr == NULL &&
                dest->details.mediatorid == med->mediatorid) {
            /* This is the announcement for a previously unannounced
             * mediator. */
            dest->failmsg = 0;
            dest->fd = -1;
            dest->details = *(med);
            return;
        } else if (dest->details.mediatorid == med->mediatorid) {

            /* This is a re-announcement of an existing mediator -- this
             * could be due to reconnecting to the provisioner so don't
             * panic just yet. */
            if (strcmp(dest->details.ipstr, med->ipstr) != 0 ||
                    strcmp(dest->details.portstr, med->portstr) != 0) {
                logger(LOG_DAEMON, "OpenLI: mediator %u has changed location from %s:%s to %s:%s.",
                        med->mediatorid, dest->details.ipstr,
                        dest->details.portstr, med->ipstr, med->portstr);

                dest->details = *(med);
                if (dest->fd != -1) {
                    close(dest->fd);
                    dest->fd = -1;
                }
            }
            dest->awaitingconfirm = 0;
            dest->halted = 0;

            return;

        }
        n = n->next;
    }

    /* Entirely new mediator ID */

    newdest.failmsg = 0;
    newdest.fd = -1;
    newdest.awaitingconfirm = 0;
    newdest.halted = 0;
    newdest.details = *(med);
    init_export_buffer(&(newdest.buffer), 1);

    libtrace_list_push_back(exp->dests, &newdest);

}

#define MAX_READ_BATCH 25

static int read_mqueue(collector_export_t *exp, libtrace_message_queue_t *srcq)
{
    int x;
	openli_export_recv_t recvd;
    libtrace_list_node_t *n;
    export_dest_t *dest;

    x = libtrace_message_queue_try_get(srcq, (void *)(&recvd));
    if (x == LIBTRACE_MQ_FAILED) {
        return 0;
    }

    if (recvd.type == OPENLI_EXPORT_MEDIATOR) {
        add_new_destination(exp, &(recvd.data.med));
        return 0;
    }

    if (recvd.type == OPENLI_EXPORT_FLAG_MEDIATORS) {
        n = exp->dests->head;
        while (n) {
            dest = (export_dest_t *)(n->data);
            dest->awaitingconfirm = 1;
            n = n->next;
        }
        return 0;
    }

    if (recvd.type == OPENLI_EXPORT_INIT_MEDIATORS_OVER) {

        n = exp->dests->head;
        while (n) {
            dest = (export_dest_t *)(n->data);
            if (dest->awaitingconfirm) {
                if (dest->fd != -1) {
                    logger(LOG_DAEMON, "closing connection to unwanted mediator %d", dest->fd);
                    close(dest->fd);
                    dest->fd = -1;
                }
                dest->halted = 1;
            }
            n = n->next;
        }
        return 0;
    }

    if (recvd.type == OPENLI_EXPORT_ETSIREC) {
        n = exp->dests->head;

        /* TODO replace with a hash map? */
        while (n) {
            dest = (export_dest_t *)(n->data);

            if (dest->details.mediatorid ==
                    recvd.data.toexport.destid) {
                x = forward_message(dest, &(recvd.data.toexport));
                if (x == -1) {
                    close(dest->fd);
                    dest->fd = -1;
                    return -1;
                }
                break;
            }
            n = n->next;
        }

        if (n == NULL) {
            /* We don't recognise this mediator ID, but the
             * announcement for it could be coming soon. Create an
             * export_dest for it and buffer received messages
             * until we get an announcement.
             *
             * TODO need some way to recognise that an announcement
             * is NOT coming so we don't buffer forever...
             */
            printf("adding unknown destination %u\n", recvd.data.toexport.destid);
            dest = add_unknown_destination(exp,
                    recvd.data.toexport.destid);
            x = forward_message(dest, &(recvd.data.toexport));
            if (x == -1) {
                return -1;
            }
        }
        if (recvd.data.toexport.header) {
            free(recvd.data.toexport.header);
        }
        free(recvd.data.toexport.msgbody);
        return 1;
    }

    if (recvd.type == OPENLI_EXPORT_PACKET_FIN) {
        /* All ETSIRECs relating to this packet have been seen, so
         * we can safely free the packet.
         */

        trace_decrement_packet_refcount(recvd.data.packet);
        return 0;
    }

    logger(LOG_DAEMON,
            "OpenLI: invalid message type %d received from export queue.",
            recvd.type);
    return -1;
}

static int check_epoll_fd(collector_export_t *exp, struct epoll_event *ev) {

    libtrace_message_queue_t *srcq = NULL;
    exporter_epoll_t *epptr = NULL;
    int ret = 0;
    int readmsgs = 0;

    /* Got a message to export */
    if ((ev->events & EPOLLERR) || (ev->events & EPOLLHUP) ||
            !(ev->events & EPOLLIN)) {
        /* Something has gone wrong with a thread -> exporter message
         * queue. This is probably very bad, but we'll try to carry
         * on for now.
         */

        logger(LOG_DAEMON, "OpenLI: Thread lost connection to exporter?");
        return 0;
    }

    /* TODO mediator fds should be part of epoll as well, so we can
     *   a) check for mediator disconnections
     *   b) check if we can send buffered data again
     * without requiring a new MQUEUE event.
     */


    epptr = (exporter_epoll_t *)(ev->data.ptr);

    if (epptr->type == EXP_EPOLL_MQUEUE) {
        srcq = epptr->data.q;

        while (readmsgs < MAX_READ_BATCH) {
            ret = read_mqueue(exp, srcq);
            if (ret == -1) {
                break;
            }
            if (ret == 0) {
                break;
            }
            if (ret > 0) {
                readmsgs ++;
            }
        }
    }

    if (epptr->type == EXP_EPOLL_TIMER) {
        if (ev->events & EPOLLIN) {
            return 1;
        }
        logger(LOG_DAEMON, "OpenLI: export thread timer has misbehaved.");
        return -1;
    }

    return ret;
}

int exporter_thread_main(collector_export_t *exp) {

	int i, nfds, timerfd;
	struct epoll_event evs[64];
    int timerexpired = 0;
    exporter_epoll_t *epoll_ev = NULL;

    /* XXX this could probably be static, but just to be safe... */
    epoll_ev = (exporter_epoll_t *)malloc(sizeof(exporter_epoll_t));
    epoll_ev->type = EXP_EPOLL_TIMER;
    epoll_ev->data.q = NULL;

    timerfd = epoll_add_timer(exp->glob->export_epollfd, 1, epoll_ev);
    if (timerfd == -1) {
        logger(LOG_DAEMON, "OpenLI: failed to add export timer fd to epoll set: %s.", strerror(errno));
        return -1;
    }

    /* Try to connect to any targets which we have buffered records for */
    connect_export_targets(exp);

    /* TODO */


    while (timerexpired == 0) {
    	nfds = epoll_wait(exp->glob->export_epollfd, evs, 64, -1);

        if (nfds < 0) {
            logger(LOG_DAEMON, "OpenLI: error while checking for messages to export: %s.", strerror(errno));
            return -1;
        }

        for (i = 0; i < nfds; i++) {
            timerexpired = check_epoll_fd(exp, &(evs[i]));
            if (timerexpired == -1) {
                break;
            }
        }
    }

    if (epoll_ctl(exp->glob->export_epollfd, EPOLL_CTL_DEL, timerfd, NULL) == -1)
    {
        logger(LOG_DAEMON, "OpenLI: failed to remove export timer fd to epoll set: %s.", strerror(errno));
        return -1;
    }

    free(epoll_ev);
    close(timerfd);
    return 1;

}

void register_export_queue(collector_global_t *glob,
        libtrace_message_queue_t *q) {

    struct epoll_event ev;
    exporter_epoll_t *epoll_ev = (exporter_epoll_t *)malloc(
            sizeof(exporter_epoll_t));

    epoll_ev->type = EXP_EPOLL_MQUEUE;
    epoll_ev->data.q = q;

    ev.data.ptr = (void *)epoll_ev;
    ev.events = EPOLLIN;

    pthread_mutex_lock(&glob->exportq_mutex);
    while (glob->export_epollfd == -1) {
        pthread_cond_wait(&glob->exportq_cond, &glob->exportq_mutex);
    }

    if (glob->export_epoll_evs == NULL) {
        glob->export_epoll_evs = libtrace_list_init(sizeof(exporter_epoll_t **));
    }

    libtrace_list_push_back(glob->export_epoll_evs, &epoll_ev);
    pthread_mutex_unlock(&glob->exportq_mutex);

	if (epoll_ctl(glob->export_epollfd, EPOLL_CTL_ADD,
                libtrace_message_queue_get_fd(q), &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register export queue: %s",
                strerror(errno));
    }

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
