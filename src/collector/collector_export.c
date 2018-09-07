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

collector_export_t *init_exporter(export_thread_data_t *glob) {

    collector_export_t *exp = (collector_export_t *)malloc(
            sizeof(collector_export_t));

    exp->glob = glob;
    exp->dests = libtrace_list_init(sizeof(export_dest_t));
    exp->intercepts = NULL;
    exp->encoder = NULL;
    exp->freegenerics = NULL;

    exp->failed_conns = 0;
    exp->flagged = 0;
    exp->flagtimerfd = -1;


    exp->zmq_subsock = NULL;

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

    if (exp->zmq_subsock) {
        zmq_close(exp->zmq_subsock);
    }

    /* Don't free evlist, this will be done when the main thread
     * frees the exporter support data. */
    //libtrace_list_deinit(evlist);

    free(exp);
}


static int forward_fd(export_dest_t *dest, openli_exportmsg_t *msg) {

    uint32_t enclen = msg->msgbody->len - msg->ipclen;
    int ret;
    struct iovec iov[4];
    struct msghdr mh;
    int ind = 0;
    int total = 0;
    char liidbuf[65542];

    if (msg->header) {

        iov[ind].iov_base = msg->header;
        iov[ind].iov_len = msg->hdrlen;
        ind ++;
        total += msg->hdrlen;
    }

    if (msg->liid) {
        int used = 0;
        uint16_t etsiwraplen = 0;
        uint16_t l = htons(msg->liidlen);

        memcpy(liidbuf + used, &l, sizeof(uint16_t));
        used += sizeof(uint16_t);
        memcpy(liidbuf + used, msg->liid, msg->liidlen);

        iov[ind].iov_base = liidbuf;
        iov[ind].iov_len = msg->liidlen + used;
        total += (msg->liidlen + used);
        ind ++;
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
            logger(LOG_INFO, "OpenLI: Error exporting to target %s:%s -- %s.",
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

        logger(LOG_INFO,
                "OpenLI exporter: removing mediator %u from export destination list",
                med->mediatorid);

        if (dest->fd != -1) {
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
                logger(LOG_INFO, "OpenLI: mediator %u has changed location from %s:%s to %s:%s.",
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
        return 1;
    }

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;

    if (exp->flagtimerfd == -1) {
        exp->flagtimerfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (exp->flagtimerfd == -1) {
            logger(LOG_INFO, "OpenLI: failed to create export timer fd: %s.",
                    strerror(errno));
            return -1;
        }
    }
    timerfd_settime(exp->flagtimerfd, 0, &its, NULL);
    return 1;
}

static void purge_unconfirmed_mediators(collector_export_t *exp) {
    libtrace_list_node_t *n;
    export_dest_t *dest;

    n = exp->dests->head;
    while (n) {
        dest = (export_dest_t *)(n->data);
        if (dest->awaitingconfirm) {
            if (dest->fd != -1) {
                logger(LOG_INFO,
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
        logger(LOG_INFO, "Exporter thread was told to end intercept LIID %s, but it is not a valid ID?",
                msg->liid);
        return -1;
    }

    HASH_DELETE(hh, exp->intercepts, intstate);
    free_intercept_msg(msg);
    free_intercept_msg(intstate->details);
    free_cinsequencing(intstate);
    free(intstate);
    return 1;
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
    logger(LOG_INFO,
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
        logger(LOG_INFO, "Received encoding job for an unknown LIID: %s??",
                liid);
        free_job_request(recvd);
        return 0;
    }

    HASH_FIND(hh, intstate->cinsequencing, &cin, sizeof(cin), cinseq);
    if (!cinseq) {
        cinseq = (cin_seqno_t *)malloc(sizeof(cin_seqno_t));

        if (!cinseq) {
            logger(LOG_INFO,
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
                /*
                ret = encode_ipcc(&(exp->encoder), &(recvd->data.ipcc),
                        intstate->details, cinseq->cc_seqno, tosend);
                cinseq->cc_seqno ++;
                */
                //printf("got ipcc job for %p\n", recvd->data.ipcc.packet);
                trace_destroy_packet(recvd->data.ipcc.packet);
                free_job_request(recvd);
                return 0;
                break;
            case OPENLI_EXPORT_IPMMIRI:
                ret = encode_ipmmiri(&(exp->encoder), &(recvd->data.ipmmiri),
                        intstate->details, cinseq->iri_seqno, tosend,
                        &(recvd->ts));
                if (ret >= 0) {
                    cinseq->iri_seqno ++;
                }
                if (recvd->data.ipmmiri.packet) {
                    trace_decrement_packet_refcount(recvd->data.ipmmiri.packet);
                }
                break;
            case OPENLI_EXPORT_IPIRI:
                ret = encode_ipiri(&(exp->freegenerics),
                        &(exp->encoder), &(recvd->data.ipiri),
                        intstate->details, cinseq->iri_seqno, tosend, ind);
                if (ret >= 0) {
                    cinseq->iri_seqno ++;
                    ind ++;
                }
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

static int read_exported_message(collector_export_t *exp) {
    int x, ret;
    char envelope[24];
	openli_export_recv_t recvd;
    openli_exportmsg_t tosend;
    libtrace_list_node_t *n;
    export_dest_t *dest;

    memset(&recvd, 0, sizeof(openli_export_recv_t));

    x = zmq_recv(exp->zmq_subsock, envelope, 23, ZMQ_DONTWAIT);
    if (x < 0) {
        if (errno == EAGAIN) {
            return 0;
        }
        return -1;
    }
    envelope[x] = '\0';
    x = zmq_recv(exp->zmq_subsock, (char *)(&recvd),
            sizeof(openli_export_recv_t), ZMQ_DONTWAIT);
    if (x < 0) {
        if (errno == EAGAIN) {
            return 0;
        }
        return -1;
    }

    switch(recvd.type) {
        case OPENLI_EXPORT_INTERCEPT_DETAILS:
            exporter_new_intercept(exp, recvd.data.cept);
            return 1;

        case OPENLI_EXPORT_INTERCEPT_OVER:
            return exporter_end_intercept(exp, recvd.data.cept);

        case OPENLI_EXPORT_MEDIATOR:
            return add_new_destination(exp, &(recvd.data.med));

        case OPENLI_EXPORT_DROP_SINGLE_MEDIATOR:
            remove_destination(exp, &(recvd.data.med));
            return 1;

        case OPENLI_EXPORT_DROP_ALL_MEDIATORS:
            logger(LOG_INFO,
                    "OpenLI exporter: dropping connections to all known mediators.");
            remove_all_destinations(exp);
            exp->dests = libtrace_list_init(sizeof(export_dest_t));
            return 1;

         case OPENLI_EXPORT_FLAG_MEDIATORS:
            n = exp->dests->head;
            while (n) {
                dest = (export_dest_t *)(n->data);
                dest->awaitingconfirm = 1;
                n = n->next;
            }

            exp->flagged = 1;
            return 1;

        case OPENLI_EXPORT_IPMMCC:
        case OPENLI_EXPORT_IPCC:
        case OPENLI_EXPORT_IPMMIRI:
        case OPENLI_EXPORT_IPIRI:
            ret = 1;
            if (run_encoding_job(exp, &recvd, &tosend) < 0) {
                ret = -1;
            }
            return ret;

        case OPENLI_EXPORT_PACKET_FIN:
            /* All ETSI records relating to this packet have been seen, so
             * we can safely free the packet.
             */
            trace_decrement_packet_refcount(recvd.data.packet);
            return 1;
    }

    logger(LOG_INFO,
            "OpenLI: invalid message type %d received from export queue.",
            recvd.type);
    return -1;
}

static inline int connect_zmq_socket(collector_export_t *exp) {

    int rc;
    int zero = 0;
    char subfilter[12];

    exp->zmq_subsock = zmq_socket(exp->glob->zmq_ctxt, ZMQ_SUB);
    rc = zmq_connect(exp->zmq_subsock, "inproc://pubproxy");
    if (rc != 0) {
        logger(LOG_INFO, "OpenLI: exporter thread %d was unable to connect to zeromq proxy", exp->glob->exportlabel);
        return -1;
    }
    snprintf(subfilter, 12, "%dX", exp->glob->exportlabel);
    rc = zmq_setsockopt(exp->zmq_subsock, ZMQ_SUBSCRIBE, subfilter,
            strlen(subfilter));
    if (rc != 0) {
        logger(LOG_INFO, "OpenLI: exporter thread %d was unable to set subscription filter for zeromq", exp->glob->exportlabel);
        return -1;
    }
    rc = zmq_setsockopt(exp->zmq_subsock, ZMQ_LINGER, &zero,
            sizeof(zero));
    if (rc != 0) {
        logger(LOG_INFO, "OpenLI: exporter thread %d was unable to set linger period for zeromq", exp->glob->exportlabel);
        return -1;
    }
    return 0;
}

int exporter_thread_main(collector_export_t *exp) {

	int i, nfds, timerfd, itemcount, ret;
	struct epoll_event evs[64];
    int timerexpired = 0;
    struct itimerspec its;
    zmq_pollitem_t items[3];

    /* XXX this could probably be static, but just to be safe... */

    if (exp->zmq_subsock == NULL) {
        if (connect_zmq_socket(exp) < 0) {
            return -1;
        }
    }

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 1;
    its.it_value.tv_nsec = 0;

    timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(timerfd, 0, &its, NULL);

    if (timerfd == -1) {
        logger(LOG_INFO, "OpenLI: failed to create export timer fd: %s.", strerror(errno));
        return -1;
    }

    /* Try to connect to any targets which we have buffered records for */
    connect_export_targets(exp);

    items[0].socket = exp->zmq_subsock;
    items[0].fd = 0;
    items[0].events = ZMQ_POLLIN;
    items[0].revents = 0;

    items[1].socket = NULL;
    items[1].fd = timerfd;
    items[1].events = ZMQ_POLLIN;
    items[1].revents = 0;

    itemcount = 2;
    if (exp->flagtimerfd != -1) {
        items[2].socket = NULL;
        items[2].fd = exp->flagtimerfd;
        items[2].events = ZMQ_POLLIN;
        items[2].revents = 0;
        itemcount ++;
    }

    while (timerexpired == 0) {

        zmq_poll(items, itemcount, -1);
        if (items[0].revents & ZMQ_POLLIN) {
            do {
                ret = read_exported_message(exp);
            } while (ret > 0);

            if (ret == -1) {
                return -1;
            }
        }

        if (items[1].revents & ZMQ_POLLIN) {
            timerexpired = 1;
        }

        if (itemcount > 2 && items[2].revents & ZMQ_POLLIN) {
            purge_unconfirmed_mediators(exp);
            exp->flagged = 0;
            close(exp->flagtimerfd);
            exp->flagtimerfd = -1;
        }
    }

    close(timerfd);
    return 1;

}

static inline int _publish_openli_msg(void *pubsock, openli_export_recv_t *msg,
        int queueid) {

    char envelope[24];
    int rc;

    snprintf(envelope, 24, "%dX", queueid);
    rc = zmq_send(pubsock, envelope, strlen(envelope), ZMQ_SNDMORE);
    if (rc < 0) {
        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    rc = zmq_send(pubsock, (char *)msg, sizeof(openli_export_recv_t), 0);
    if (rc < 0) {
        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}

void export_queue_put_all(void *pubsock, openli_export_recv_t *msg,
        int numexporters) {

    int i;

    for (i = 0; i < numexporters; i++) {
        if (_publish_openli_msg(pubsock, msg, i) < 0) {
            continue;
        }
    }
}

int export_queue_put_by_liid(void *pubsock,
        openli_export_recv_t *msg, char *liid, int numexporters) {

    uint32_t hash;
    int queueid;

    hash = hashlittle(liid, strlen(liid), 0x188532fa);
    queueid = hash % numexporters;
    return _publish_openli_msg(pubsock, msg, queueid);
}

int export_queue_put_by_queueid(void *pubsock,
        openli_export_recv_t *msg, int queueid) {

    if (queueid < 0) {
        logger(LOG_INFO,
                "OpenLI: bad export queue passed into export_queue_put_by_queueid: %d",
                queueid);
        return -1;
    }

    return _publish_openli_msg(pubsock, msg, queueid);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
