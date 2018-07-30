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
#include "ipmmcc.h"
#include "ipcc.h"
#include "ipmmiri.h"
#include "ipiri.h"
#include "logger.h"
#include "util.h"

enum {
    EXP_EPOLL_MQUEUE = 0,
    EXP_EPOLL_TIMER = 1,
    EXP_EPOLL_FLAG_TIMEOUT = 2,
};

collector_export_t *init_exporter(support_thread_global_t *glob) {

    collector_export_t *exp = (collector_export_t *)malloc(
            sizeof(collector_export_t));

    exp->glob = glob;
    exp->dests = libtrace_list_init(sizeof(export_dest_t));
    exp->intercepts = NULL;
    exp->encoder = NULL;
    exp->freegenerics = NULL;

    exp->failed_conns = 0;
    exp->flagged = 0;
    exp->flag_timer_ev = NULL;
    exp->flagtimerfd = -1;
    return exp;
}

static int connect_single_target(export_dest_t *dest) {

    int sockfd;

    if (dest->details.ipstr == NULL) {
        /* This is an unannounced mediator */
        return -1;
    }

    sockfd = connect_socket(dest->details.ipstr, dest->details.portstr,
            dest->failmsg, 0);

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

static inline void free_intercept_msg(exporter_intercept_msg_t *msg) {
    free(msg->liid);
    free(msg->authcc);
    free(msg->delivcc);
    free(msg);
}

static inline void free_cinsequencing(exporter_intercept_state_t *intstate) {
    cin_seqno_t *c, *tmp;

    HASH_ITER(hh, intstate->cinsequencing, c, tmp) {
        HASH_DELETE(hh, intstate->cinsequencing, c);
        free(c);
    }
}

static inline void remove_all_destinations(collector_export_t *exp) {
    export_dest_t *d;
    libtrace_list_node_t *n;
    struct epoll_event ev;

    /* Close all dest fds */
    n = exp->dests->head;
    while (n) {
        d = (export_dest_t *)n->data;

        if (d->fd != -1) {
            epoll_ctl(exp->glob->epoll_fd, EPOLL_CTL_DEL, d->fd, &ev);
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
    exp->dests = NULL;

}

void destroy_exporter(collector_export_t *exp) {
    libtrace_list_t *evlist;
    libtrace_list_node_t *n;
    exporter_intercept_state_t *intstate, *tmpexp;

    remove_all_destinations(exp);

    pthread_mutex_lock(&(exp->glob->mutex));
    evlist = (libtrace_list_t *)(exp->glob->epollevs);
    n = evlist->head;
    while (n) {
        exporter_epoll_t *ev = *((exporter_epoll_t **)n->data);
        free(ev);
        n = n->next;
    }
    pthread_mutex_unlock(&(exp->glob->mutex));

    if (exp->freegenerics) {
        free_etsili_generics(exp->freegenerics);
    }

    if (exp->encoder) {
        free_wandder_encoder(exp->encoder);
    }

    HASH_ITER(hh, exp->intercepts, intstate, tmpexp) {
        HASH_DELETE(hh, exp->intercepts, intstate);
        free_intercept_msg(intstate->details);
        free_cinsequencing(intstate);
        free(intstate);
    }

    /* Don't free evlist, this will be done when the main thread
     * frees the exporter support data. */
    //libtrace_list_deinit(evlist);

    free(exp);
}


static int forward_fd(export_dest_t *dest, openli_exportmsg_t *msg) {

    uint32_t enclen = msg->msgbody->len - msg->ipclen;
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

    iov[ind].iov_base = msg->msgbody->encoded;
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

    int ret = 0;
    if (dest->fd == -1) {
        /* buffer this message for when we are able to connect */
        if (append_message_to_buffer(&(dest->buffer), msg, 0) == 0) {
            /* TODO do something if we run out of memory? */

        }
        goto endforward;
    }

    if (get_buffered_amount(&(dest->buffer)) == 0) {
        ret = forward_fd(dest, msg);
        goto endforward;
    }

    if (transmit_buffered_records(&(dest->buffer), dest->fd, BUF_BATCH_SIZE)
                == -1) {
        ret = -1;
        goto endforward;

    }

    if (get_buffered_amount(&(dest->buffer)) == 0) {
        /* buffer is now empty, try to push out this message too */
        ret = forward_fd(dest, msg);
        goto endforward;
    }

    /* buffer was not completely drained, so we have to buffer this
     * message too -- hopefully we'll catch up soon */
    if (append_message_to_buffer(&(dest->buffer), msg, 0) == 0) {
        /* TODO do something if we run out of memory? */

    }

endforward:
    wandder_release_encoded_result(NULL, msg->msgbody);

    return ret;
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

static void remove_destination(collector_export_t *exp,
        openli_mediator_t *med) {

    libtrace_list_node_t *n;
    export_dest_t *dest;
    struct epoll_event ev;

    n = exp->dests->head;
    while (n) {
        dest = (export_dest_t *)(n->data);
        n = n->next;

        if (dest->details.mediatorid != med->mediatorid) {
            continue;
        }

        logger(LOG_DAEMON,
                "OpenLI exporter: removing mediator %u from export destination list",
                med->mediatorid);

        if (dest->fd != -1) {
            epoll_ctl(exp->glob->epoll_fd, EPOLL_CTL_DEL, dest->fd, &ev);
            close(dest->fd);
            dest->fd = -1;
        }
        dest->halted = 1;
    }
}

static int add_new_destination(collector_export_t *exp,
        openli_mediator_t *med) {

    libtrace_list_node_t *n;
    export_dest_t newdest, *dest;
    struct itimerspec its;

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
            goto destepoll;
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
            goto destepoll;
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

destepoll:
    if (!exp->flagged) {
        return 0;
    }

    exp->flag_timer_ev = (exporter_epoll_t *)malloc(
            sizeof(exporter_epoll_t));
    exp->flag_timer_ev->type = EXP_EPOLL_FLAG_TIMEOUT;
    exp->flag_timer_ev->data.q = NULL;

    if (exp->flagtimerfd == -1) {
        exp->flagtimerfd = epoll_add_timer(exp->glob->epoll_fd, 10,
                exp->flag_timer_ev);
        if (exp->flagtimerfd == -1) {
            logger(LOG_DAEMON, "OpenLI: failed to add export timer fd to epoll set: %s.", strerror(errno));
            return -1;
        }
    } else {
        its.it_value.tv_sec = 10;
        its.it_value.tv_nsec = 0;

        if (timerfd_settime(exp->flagtimerfd, 0, &its, NULL) == -1) {
            logger(LOG_DAEMON, "OpenLI: exporter has failed to reset the export timer fd: %s", strerror(errno));
            return -1;
        }
    }
    return 0;
}

static void purge_unconfirmed_mediators(collector_export_t *exp) {
    libtrace_list_node_t *n;
    export_dest_t *dest;

    n = exp->dests->head;
    while (n) {
        dest = (export_dest_t *)(n->data);
        if (dest->awaitingconfirm) {
            if (dest->fd != -1) {
                logger(LOG_DAEMON,
                        "OpenLI exporter: closing connection to unwanted mediator on fd %d", dest->fd);
                close(dest->fd);
                dest->fd = -1;
            }
            dest->halted = 1;
        }
        n = n->next;
    }
}

static void exporter_new_intercept(collector_export_t *exp,
        exporter_intercept_msg_t *msg) {

    exporter_intercept_state_t *intstate;

    /* If this LIID already exists, we'll need to replace it */
    HASH_FIND(hh, exp->intercepts, msg->liid, strlen(msg->liid), intstate);

    if (intstate) {
        free_intercept_msg(intstate->details);
        /* leave the CIN seqno state as is for now */
        intstate->details = msg;
        return;
    }

    /* New LIID, create fresh intercept state */
    intstate = (exporter_intercept_state_t *)malloc(
            sizeof(exporter_intercept_state_t));
    intstate->details = msg;
    intstate->cinsequencing = NULL;
    HASH_ADD_KEYPTR(hh, exp->intercepts, msg->liid, strlen(msg->liid),
            intstate);
}

static int exporter_end_intercept(collector_export_t *exp,
        exporter_intercept_msg_t *msg) {

    exporter_intercept_state_t *intstate;

    HASH_FIND(hh, exp->intercepts, msg->liid, strlen(msg->liid), intstate);

    if (!intstate) {
        logger(LOG_DAEMON, "Exporter thread was told to end intercept LIID %s, but it is not a valid ID?",
                msg->liid);
        return -1;
    }

    HASH_DELETE(hh, exp->intercepts, intstate);
    free_intercept_msg(msg);
    free_intercept_msg(intstate->details);
    free_cinsequencing(intstate);
    free(intstate);
    return 0;
}

static inline char *extract_liid_from_job(openli_export_recv_t *recvd) {

    switch(recvd->type) {
        case OPENLI_EXPORT_IPMMCC:
            return recvd->data.ipmmcc.liid;
        case OPENLI_EXPORT_IPCC:
            return recvd->data.ipcc.liid;
        case OPENLI_EXPORT_IPIRI:
            return recvd->data.ipiri.liid;
        case OPENLI_EXPORT_IPMMIRI:
            return recvd->data.ipmmiri.liid;
    }
    return NULL;
}

static inline uint32_t extract_cin_from_job(openli_export_recv_t *recvd) {

    switch(recvd->type) {
        case OPENLI_EXPORT_IPMMCC:
            return recvd->data.ipmmcc.cin;
        case OPENLI_EXPORT_IPCC:
            return recvd->data.ipcc.cin;
        case OPENLI_EXPORT_IPIRI:
            return recvd->data.ipiri.cin;
        case OPENLI_EXPORT_IPMMIRI:
            return recvd->data.ipmmiri.cin;
    }
    logger(LOG_DAEMON,
            "OpenLI: invalid message type in extract_cin_from_job: %u",
            recvd->type);
    return 0;
}

static inline void free_job_request(openli_export_recv_t *recvd) {
    switch(recvd->type) {
        case OPENLI_EXPORT_IPMMCC:
            free(recvd->data.ipmmcc.liid);
            break;
        case OPENLI_EXPORT_IPCC:
            free(recvd->data.ipcc.liid);
            break;
        case OPENLI_EXPORT_IPIRI:
            free(recvd->data.ipiri.liid);
            free(recvd->data.ipiri.username);
            if (recvd->data.ipiri.plugin) {
                recvd->data.ipiri.plugin->destroy_parsed_data(
                        recvd->data.ipiri.plugin,
                        recvd->data.ipiri.plugin_data);
            }
            break;
        case OPENLI_EXPORT_IPMMIRI:
            free(recvd->data.ipmmiri.liid);
            break;
    }
}

static int export_encoded_record(collector_export_t *exp,
        openli_exportmsg_t *tosend) {

    libtrace_list_node_t *n;
    export_dest_t *dest;
    int x;

    n = exp->dests->head;

    /* TODO replace with a hash map? */
    while (n) {
        dest = (export_dest_t *)(n->data);

        if (dest->details.mediatorid == tosend->destid) {
            x = forward_message(dest, tosend);
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
        dest = add_unknown_destination(exp, tosend->destid);
        x = forward_message(dest, tosend);
        if (x == -1) {
            return -1;
        }
    }
    if (tosend->header) {
        free(tosend->header);
    }
    return 1;
}
static int run_encoding_job(collector_export_t *exp,
        openli_export_recv_t *recvd, openli_exportmsg_t *tosend) {

    char *liid;
    uint32_t cin;
    cin_seqno_t *cinseq;
    exporter_intercept_state_t *intstate;
    int ret = -1;
    int ind = 0;

    liid = extract_liid_from_job(recvd);
    cin = extract_cin_from_job(recvd);

    HASH_FIND(hh, exp->intercepts, liid, strlen(liid), intstate);
    if (!intstate) {
        logger(LOG_DAEMON, "Received encoding job for an unknown LIID: %s??",
                liid);
        return -1;
    }

    HASH_FIND(hh, intstate->cinsequencing, &cin, sizeof(cin), cinseq);
    if (!cinseq) {
        cinseq = (cin_seqno_t *)malloc(sizeof(cin_seqno_t));

        if (!cinseq) {
            logger(LOG_DAEMON,
                    "OpenLI: out of memory when creating CIN seqno tracker in exporter thread");
            return -1;
        }

        cinseq->cin = cin;
        cinseq->iri_seqno = 0;
        cinseq->cc_seqno = 0;

        HASH_ADD_KEYPTR(hh, intstate->cinsequencing, &(cinseq->cin),
                sizeof(cin), cinseq);
    }

    while (ret != 0) {
        switch(recvd->type) {
            case OPENLI_EXPORT_IPMMCC:
                ret = encode_ipmmcc(&(exp->encoder), &(recvd->data.ipmmcc),
                        intstate->details, cinseq->cc_seqno, tosend);
                cinseq->cc_seqno ++;
                trace_decrement_packet_refcount(recvd->data.ipmmcc.packet);
                break;
            case OPENLI_EXPORT_IPCC:
                ret = encode_ipcc(&(exp->encoder), &(recvd->data.ipcc),
                        intstate->details, cinseq->cc_seqno, tosend);
                cinseq->cc_seqno ++;
                trace_decrement_packet_refcount(recvd->data.ipcc.packet);
                break;
            case OPENLI_EXPORT_IPMMIRI:
                ret = encode_ipmmiri(&(exp->encoder), &(recvd->data.ipmmiri),
                        intstate->details, cinseq->iri_seqno, tosend,
                        &(recvd->ts));
                cinseq->iri_seqno ++;
                if (recvd->data.ipmmiri.packet) {
                    trace_decrement_packet_refcount(recvd->data.ipmmiri.packet);
                }
                break;
            case OPENLI_EXPORT_IPIRI:
                ret = encode_ipiri(&(exp->freegenerics),
                        &(exp->encoder), &(recvd->data.ipiri),
                        intstate->details, cinseq->iri_seqno, tosend, ind);
                cinseq->iri_seqno ++;
                ind ++;
                break;
        }
        if (ret < 0) {
            break;
        }

        tosend->destid = recvd->destid;
        if (export_encoded_record(exp, tosend) < 0) {
            ret = -1;
            break;
        }
    }

    free_job_request(recvd);
    return ret;
}

#define MAX_READ_BATCH 25

static int read_mqueue(collector_export_t *exp, libtrace_message_queue_t *srcq)
{
    int x, ret;
	openli_export_recv_t recvd;
    openli_exportmsg_t tosend;
    libtrace_list_node_t *n;
    export_dest_t *dest;

    memset(&recvd, 0, sizeof(openli_export_recv_t));
    x = libtrace_message_queue_get(srcq, (void *)(&recvd));
    if (x == LIBTRACE_MQ_FAILED) {
        return 0;
    }

    switch(recvd.type) {
        case OPENLI_EXPORT_INTERCEPT_DETAILS:
            exporter_new_intercept(exp, recvd.data.cept);
            return 0;

        case OPENLI_EXPORT_INTERCEPT_OVER:
            return exporter_end_intercept(exp, recvd.data.cept);

        case OPENLI_EXPORT_MEDIATOR:
            return add_new_destination(exp, &(recvd.data.med));

        case OPENLI_EXPORT_DROP_SINGLE_MEDIATOR:
            remove_destination(exp, &(recvd.data.med));
            return 0;

        case OPENLI_EXPORT_DROP_ALL_MEDIATORS:
            logger(LOG_DAEMON,
                    "OpenLI exporter: dropping connections to all known mediators.");
            remove_all_destinations(exp);
            exp->dests = libtrace_list_init(sizeof(export_dest_t));
            return 0;

         case OPENLI_EXPORT_FLAG_MEDIATORS:
            n = exp->dests->head;
            while (n) {
                dest = (export_dest_t *)(n->data);
                dest->awaitingconfirm = 1;
                n = n->next;
            }

            exp->flagged = 1;
            return 0;

        case OPENLI_EXPORT_IPMMCC:
        case OPENLI_EXPORT_IPCC:
        case OPENLI_EXPORT_IPMMIRI:
        case OPENLI_EXPORT_IPIRI:
            ret = 0;
            if (run_encoding_job(exp, &recvd, &tosend) < 0) {
                ret = -1;
            }
            return ret;

        case OPENLI_EXPORT_PACKET_FIN:
            /* All ETSI records relating to this packet have been seen, so
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

    if (epptr->type == EXP_EPOLL_FLAG_TIMEOUT) {
        purge_unconfirmed_mediators(exp);
        exp->flagged = 0;
        free(exp->flag_timer_ev);
        exp->flag_timer_ev = NULL;
        close(exp->flagtimerfd);
        exp->flagtimerfd = -1;
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

    timerfd = epoll_add_timer(exp->glob->epoll_fd, 1, epoll_ev);
    if (timerfd == -1) {
        logger(LOG_DAEMON, "OpenLI: failed to add export timer fd to epoll set: %s.", strerror(errno));
        return -1;
    }

    /* Try to connect to any targets which we have buffered records for */
    connect_export_targets(exp);


    while (timerexpired == 0) {
    	nfds = epoll_wait(exp->glob->epoll_fd, evs, 64, -1);

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

    if (epoll_ctl(exp->glob->epoll_fd, EPOLL_CTL_DEL, timerfd, NULL) == -1)
    {
        logger(LOG_DAEMON, "OpenLI: failed to remove export timer fd to epoll set: %s.", strerror(errno));
        return -1;
    }

    free(epoll_ev);
    close(timerfd);
    return 1;

}

void register_export_queues(support_thread_global_t *glob,
        export_queue_set_t *qset) {

    struct epoll_event ev;
    int i;
    exporter_epoll_t *epoll_ev;

    for (i = 0; i < qset->numqueues; i++) {

        epoll_ev = (exporter_epoll_t *)malloc(
                sizeof(exporter_epoll_t));

        epoll_ev->type = EXP_EPOLL_MQUEUE;
        epoll_ev->data.q = &(qset->queues[i]);

        ev.data.ptr = (void *)epoll_ev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        pthread_mutex_lock(&(glob[i].mutex));

        if (glob[i].epollevs == NULL) {
            glob[i].epollevs = libtrace_list_init(
                    sizeof(exporter_epoll_t **));
        }

        libtrace_list_push_back(glob[i].epollevs, &epoll_ev);
        pthread_mutex_unlock(&(glob[i].mutex));

        if (epoll_ctl(glob[i].epoll_fd, EPOLL_CTL_ADD,
                    libtrace_message_queue_get_fd(&(qset->queues[i])),
                    &ev) == -1) {
            /* TODO Do something? */
            logger(LOG_DAEMON, "OpenLI: failed to register export queue: %s",
                    strerror(errno));
        }
    }
}

export_queue_set_t *create_export_queue_set(int numqueues) {

    int i;
    export_queue_set_t *qset;

    qset = (export_queue_set_t *)malloc(sizeof(export_queue_set_t));
    qset->numqueues = numqueues;

    qset->queues = (libtrace_message_queue_t *)malloc(numqueues *
            sizeof(libtrace_message_queue_t));

    for (i = 0; i < numqueues; i++) {
        libtrace_message_queue_init(&(qset->queues[i]),
                sizeof(openli_export_recv_t));
    }
    return qset;
}

void free_export_queue_set(export_queue_set_t *qset) {

    int i;

    for (i = 0; i < qset->numqueues; i++) {
        libtrace_message_queue_destroy(&(qset->queues[i]));
    }
    free(qset->queues);
    free(qset);
}

void export_queue_put_all(export_queue_set_t *qset, openli_export_recv_t *msg) {

    int i;

    for (i = 0; i < qset->numqueues; i++) {
        libtrace_message_queue_put(&(qset->queues[i]), (void *)msg);
    }
}

int export_queue_put_by_liid(export_queue_set_t *qset,
        openli_export_recv_t *msg, char *liid) {

    uint32_t hash;
    int queueid;

    hash = hashlittle(liid, strlen(liid), 0x188532fa);
    queueid = hash % qset->numqueues;

    libtrace_message_queue_put(&(qset->queues[queueid]), (void *)msg);
    return 0;
}

int export_queue_put_by_queueid(export_queue_set_t *qset,
        openli_export_recv_t *msg, int queueid) {

    if (queueid < 0 || queueid >= qset->numqueues) {
        logger(LOG_DAEMON,
                "OpenLI: bad export queue passed into export_queue_put_by_queueid: %d",
                queueid);
        return -1;
    }
    libtrace_message_queue_put(&(qset->queues[queueid]), (void *)msg);
    return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
