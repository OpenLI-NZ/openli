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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "util.h"
#include "logger.h"
#include "collector_base.h"
#include "collector_publish.h"

#define BUF_BATCH_SIZE (100 * 1024 * 1024)
#define MIN_SEND_AMOUNT (1 * 1024 * 1024)

static int add_new_destination(forwarding_thread_data_t *fwd,
        openli_export_recv_t *msg) {

    export_dest_t *newdest, *found;
    struct itimerspec its;
    PWord_t jval;

    JLG(jval, fwd->destinations_by_id, msg->data.med.mediatorid);

    if (jval == NULL) {
        newdest = (export_dest_t *)calloc(1, sizeof(export_dest_t));

        newdest->fd = -1;
        newdest->pollindex = -1;
        newdest->failmsg = 0;
        newdest->awaitingconfirm = 0;
        newdest->halted = 0;
        newdest->mediatorid = msg->data.med.mediatorid;
        newdest->ipstr = msg->data.med.ipstr;
        newdest->portstr = msg->data.med.portstr;
        init_export_buffer(&(newdest->buffer));

        JLI(jval, fwd->destinations_by_id, newdest->mediatorid);
        *jval = (Word_t)newdest;

        logger(LOG_INFO, "OpenLI: adding new mediator %u at %s:%s",
                newdest->mediatorid, newdest->ipstr, newdest->portstr);
    } else {
        found = (export_dest_t *)(*jval);

        if (found->ipstr == NULL) {
            /* Announcement for a previously unknown mediator */
            found->ipstr = msg->data.med.ipstr;
            found->portstr = msg->data.med.portstr;
            found->fd = -1;
            found->failmsg = 0;
        } else {
            if (strcmp(found->ipstr, msg->data.med.ipstr) != 0 ||
                    strcmp(found->portstr, msg->data.med.portstr) != 0) {
                /* Mediator has changed IP or port */
                logger(LOG_INFO, "OpenLI: mediator %u has changed location from %s:%s to %s:%s",
                        found->ipstr, found->portstr, msg->data.med.ipstr,
                        msg->data.med.portstr);
                free(found->ipstr);
                free(found->portstr);
                found->ipstr = msg->data.med.ipstr;
                found->portstr = msg->data.med.portstr;

                if (found->fd != -1) {
                    close(found->fd);
                    found->fd = -1;
                }
            }
            found->awaitingconfirm = 0;
            found->halted = 0;
        }
    }

    free(msg);

    if (fwd->awaitingconfirm) {
        if (fwd->flagtimerfd == -1) {
            fwd->flagtimerfd = timerfd_create(CLOCK_MONOTONIC, 0);
            if (fwd->flagtimerfd == -1) {
                logger(LOG_INFO, "OpenLI: failed to create forwarder timer fd: %s", strerror(errno));
                return -1;
            }
        }

        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
        its.it_value.tv_sec = 5;
        its.it_value.tv_nsec = 0;

        timerfd_settime(fwd->flagtimerfd, 0, &its, NULL);
    }
    return 1;
}

static inline void disconnect_mediator(forwarding_thread_data_t *fwd,
        export_dest_t *med) {

    close(med->fd);
    med->fd = -1;

    if (med->pollindex >= 0) {
        fwd->topoll[med->pollindex].fd = 0;
        fwd->topoll[med->pollindex].events = 0;
    }

}

static void remove_destination(forwarding_thread_data_t *fwd,
        export_dest_t *med) {

    int err;

    JLD(err, fwd->destinations_by_id, med->mediatorid);

    if (med->fd != -1) {
        JLD(err, fwd->destinations_by_fd, med->fd);
        disconnect_mediator(fwd, med);
    }

    release_export_buffer(&(med->buffer));
    if (med->ipstr) {
        free(med->ipstr);
    }
    if (med->portstr) {
        free(med->portstr);
    }

    free(med);
}

static void remove_all_destinations(forwarding_thread_data_t *fwd) {
    export_dest_t *med;
    PWord_t *jval;
    Word_t index;

    index = 0;
    JLF(jval, fwd->destinations_by_id, index);
    while (jval != NULL) {
        med = (export_dest_t *)(*jval);
        JLN(jval, fwd->destinations_by_id, index);

        remove_destination(fwd, med);
    }
}

static void flag_all_destinations(forwarding_thread_data_t *fwd) {
    export_dest_t *med;
    PWord_t *jval;
    Word_t index;

    index = 0;
    JLF(jval, fwd->destinations_by_id, index);
    while (jval != NULL) {
        med = (export_dest_t *)(*jval);
        JLN(jval, fwd->destinations_by_id, index);

        med->awaitingconfirm = 1;
    }
    fwd->awaitingconfirm = 1;
}

static int handle_ctrl_message(forwarding_thread_data_t *fwd,
        openli_export_recv_t *msg) {

    if (msg->type == OPENLI_EXPORT_HALT) {
        free(msg);
        return 0;
    }

    if (msg->type == OPENLI_EXPORT_MEDIATOR) {
        return add_new_destination(fwd, msg);
    } else if (msg->type == OPENLI_EXPORT_DROP_SINGLE_MEDIATOR) {
        PWord_t jval;
        export_dest_t *med;

        JLG(jval, fwd->destinations_by_id, msg->data.med.mediatorid);
        if (jval == NULL) {
            logger(LOG_DEBUG, "asked to remove mediator %d but cannot find it?",
                    msg->data.med.mediatorid);
            return 1;
        }
        med = (export_dest_t *)(*jval);
        remove_destination(fwd, med);
        logger(LOG_DEBUG, "removed mediator %d due to provisioner request",
                msg->data.med.mediatorid);
    } else if (msg->type == OPENLI_EXPORT_DROP_ALL_MEDIATORS) {
        remove_all_destinations(fwd);
    } else if (msg->type == OPENLI_EXPORT_FLAG_MEDIATORS) {
        flag_all_destinations(fwd);
    }

    return 1;
}

static inline void free_encoded_result(openli_encoded_result_t *res) {
    if (res->liid) {
        free(res->liid);
    }

    if (res->cinstr) {
        free(res->cinstr);
    }

    if (res->msgbody) {
        free(res->msgbody->encoded);
        free(res->msgbody);
    }

    if (res->origreq) {
        free_published_message(res->origreq);
    }
}

static inline int enqueue_result(forwarding_thread_data_t *fwd,
        export_dest_t *med, openli_encoded_result_t *res) {

    PWord_t jval;
    int_reorderer_t *reord;
    openli_encoded_result_t *rescopy;
    Pvoid_t *reorderer;
    stored_result_t *stored, *tmp;

    if (res->origreq->type == OPENLI_EXPORT_IPCC ||
            res->origreq->type == OPENLI_EXPORT_IPMMCC) {

        reorderer = &(fwd->intreorderer_cc);
    } else {
        reorderer = &(fwd->intreorderer_iri);
    }


    /* reordering of results if required for each LIID/CIN */
    JSLG(jval, *reorderer, res->cinstr);
    if (jval == NULL) {
        JSLI(jval, *reorderer, res->cinstr);

        if (jval == NULL) {
            logger(LOG_INFO,
                    "OpenLI: unable to create new intercept record reorderer due to lack of memory"
                    );
            return 1;
        }

        reord = (int_reorderer_t *)calloc(1, sizeof(int_reorderer_t));
        reord->liid = strdup(res->liid);
        reord->key = strdup(res->cinstr);
        reord->pending = NULL;
        reord->expectedseqno = 0;

        *jval = (Word_t)reord;
    } else {
        reord = (int_reorderer_t *)(*jval);
    }

    if (res->seqno != reord->expectedseqno) {

        stored = (stored_result_t *)calloc(1, sizeof(stored_result_t));
        memcpy(&(stored->res), res, sizeof(openli_encoded_result_t));

        HASH_ADD_KEYPTR(hh, reord->pending, &(stored->res.seqno),
                sizeof(stored->res.seqno), stored);

        return 0;
    }

    if (append_message_to_buffer(&(med->buffer), res, 0) == 0) {
        logger(LOG_INFO,
                "OpenLI: forced to drop mediator %s:%s because we cannot buffer any more records for it -- please investigate asap!",
                med->ipstr, med->portstr);
        remove_destination(fwd, med);
        return 1;
    }

    reord->expectedseqno = res->seqno + 1;

    HASH_ITER(hh, reord->pending, stored, tmp) {
        if (stored->res.seqno != reord->expectedseqno) {
            break;
        }

        HASH_DELETE(hh, reord->pending, stored);

        if (append_message_to_buffer(&(med->buffer), &(stored->res), 0) == 0) {
            logger(LOG_INFO,
                    "OpenLI: forced to drop mediator %s:%s because we cannot buffer any more records for it -- please investigate asap!",
                    med->ipstr, med->portstr);
            remove_destination(fwd, med);
            break;
        }
        reord->expectedseqno = stored->res.seqno + 1;

        free_encoded_result(&(stored->res));
        free(stored);

    }

    return 1;
}

static int handle_encoded_result(forwarding_thread_data_t *fwd,
        openli_encoded_result_t *res) {

    int ret = 0;
    export_dest_t *med;
    PWord_t jval;

    /* Check if this result is for a mediator we know about. If not,
     * create a destination for that mediator and buffer results until
     * we get a corresponding announcement. */


    JLG(jval, fwd->destinations_by_id, res->destid);
    if (jval == NULL) {
        JLI(jval, fwd->destinations_by_id, res->destid);

        if (jval == NULL) {
            logger(LOG_INFO,
                    "OpenLI: unable to allocate memory for unknown mediator %u",
                    res->destid);
            return -1;
        }

        med = (export_dest_t *)calloc(1, sizeof(export_dest_t));
        med->failmsg = 0;
        med->pollindex = -1;
        med->fd = -1;
        med->ipstr = NULL;
        med->portstr = NULL;
        med->awaitingconfirm = 0;
        med->halted = 0;
        med->mediatorid = res->destid;
        init_export_buffer(&(med->buffer));

        *jval = (Word_t) med;
    } else {
        med = (export_dest_t *)(*jval);
    }

    /* TODO enqueue this result to be forwarded */
    ret = enqueue_result(fwd, med, res);

    if (ret == 1) {
        free_encoded_result(res);
    }

    return ret;
}

static void purge_unconfirmed_mediators(forwarding_thread_data_t *fwd) {

    export_dest_t *med;
    PWord_t *jval;
    Word_t index;

    index = 0;
    JLF(jval, fwd->destinations_by_id, index);
    while (jval != NULL) {
        med = (export_dest_t *)(*jval);
        JLN(jval, fwd->destinations_by_id, index);

        if (med->awaitingconfirm) {
            remove_destination(fwd, med);
        }
    }

}

static int connect_single_target(export_dest_t *dest) {

    int sockfd;

    if (dest->ipstr == NULL) {
        /* This is an unannounced mediator */
        return -1;
    }

    sockfd = connect_socket(dest->ipstr, dest->portstr, dest->failmsg, 0);

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


static void connect_export_targets(forwarding_thread_data_t *fwd) {

    export_dest_t *dest, *tmp;
    int ind;
    PWord_t jval, jval2;
    Word_t index;

    index = 0;
    JLF(jval, fwd->destinations_by_id, index);

    while (jval != NULL) {
        dest = (export_dest_t *)(*jval);

        JLN(jval, fwd->destinations_by_id, index);

        if (dest->fd != -1) {
            continue;
        }

        if (dest->halted) {
            continue;
        }

        dest->fd = connect_single_target(dest);
        if (dest->fd == -1) {
            continue;
        }

        JLI(jval2, fwd->destinations_by_fd, dest->fd);
        if (jval2 == NULL) {
            logger(LOG_INFO, "memory issue while connecting to export target");
            close(dest->fd);
            dest->fd = -1;
            return;
        }

        *jval2 = (Word_t)dest;

        if (dest->pollindex == -1) {
            if (fwd->nextpoll == fwd->pollsize - 1) {
                fwd->topoll = realloc(fwd->topoll, (fwd->pollsize + 10) *
                        sizeof(zmq_pollitem_t));
                fwd->forcesend = realloc(fwd->forcesend,
                        (fwd->pollsize + 10) * sizeof(uint8_t));

                fwd->pollsize += 10;
            }
            ind = fwd->nextpoll;
            fwd->nextpoll ++;
            dest->pollindex = ind;
        } else {
            ind = dest->pollindex;
        }

        fwd->forcesend[ind] = 0;
        fwd->topoll[ind].socket = NULL;
        fwd->topoll[ind].fd = dest->fd;
        fwd->topoll[ind].events = ZMQ_POLLOUT;
        fwd->topoll[ind].revents = 0;
    }

}

static int receive_incoming_etsi(forwarding_thread_data_t *fwd) {
    int x, processed;
    openli_encoded_result_t res;

    processed = 0;
    do {
        x = zmq_recv(fwd->zmq_pullressock, &res, sizeof(res),
                ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving result in forwarder %d: %s",
                    fwd->forwardid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (handle_encoded_result(fwd, &res) < 0) {
            return -1;
        }
        processed ++;
    } while (x > 0 && processed < 100000);
    return 1;
}

static int process_control_message(forwarding_thread_data_t *fwd) {
    openli_export_recv_t *msg;
    int x;

    do {
        /* Got something on the control socket */
        x = zmq_recv(fwd->zmq_ctrlsock, &msg, sizeof(msg),
                ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving command in forwarder %d: %s",
                    fwd->forwardid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (handle_ctrl_message(fwd,msg)  <= 0) {
            return -1;
        }

    } while (x > 0);

    return 1;
}

static inline int forwarder_main_loop(forwarding_thread_data_t *fwd) {
    int topollc, x, i;

    /* Add the mediator confirmation timer to our poll item list, if
     * required.
     */
    if (fwd->awaitingconfirm) {
        fwd->topoll[fwd->nextpoll].socket = NULL;
        fwd->topoll[fwd->nextpoll].fd = fwd->flagtimerfd;
        fwd->topoll[fwd->nextpoll].events = ZMQ_POLLIN;

        topollc = fwd->nextpoll + 1;
    } else {
        topollc = fwd->nextpoll;
    }

    if (zmq_poll(fwd->topoll, topollc, -1) < 0) {
        logger(LOG_INFO,
                "OpenLI: error while polling in forwarder %d: %s",
                fwd->forwardid, strerror(errno));
        return -1;
    }

    if (fwd->topoll[0].revents & ZMQ_POLLIN) {
        x = process_control_message(fwd);
        if (x < 0) {
            return 0;
        }
        fwd->topoll[0].revents = 0;
    }

    if (fwd->topoll[2].revents & ZMQ_POLLIN) {
        struct itimerspec its;

        connect_export_targets(fwd);

        for (i = 3; i < fwd->nextpoll; i++) {
            fwd->forcesend[i] = 1;
        }

        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
        its.it_value.tv_sec = 1;
        its.it_value.tv_nsec = 0;

        timerfd_settime(fwd->conntimerfd, 0, &its, NULL);
    }

    if (fwd->topoll[1].revents & ZMQ_POLLIN) {
        x = receive_incoming_etsi(fwd);
        if (x < 0) {
            return 0;
        }
        fwd->topoll[1].revents = 0;
    }

    if (fwd->awaitingconfirm) {
        if (fwd->topoll[fwd->nextpoll].revents & ZMQ_POLLIN) {
            purge_unconfirmed_mediators(fwd);
            fwd->awaitingconfirm = 0;
            close(fwd->flagtimerfd);
            fwd->flagtimerfd = -1;
        }
    }

    for (i = 3; i < fwd->nextpoll; i++) {
        export_dest_t *dest;
        PWord_t jval;
        uint64_t availsend = 0;
        /* check if any destinations can received any buffered data */
        if (!(fwd->topoll[i].revents & ZMQ_POLLOUT)) {
            continue;
        }
        fwd->topoll[i].revents = 0;

        if (fwd->topoll[i].events == 0) {
            continue;
        }

        JLG(jval, fwd->destinations_by_fd, fwd->topoll[i].fd);
        if (jval == NULL) {
            logger(LOG_INFO, "OpenLI: no matching destination for fd %d?",
                    fwd->topoll[i].fd);
            return -1;
        }

        dest = (export_dest_t *)(*jval);

        if ((availsend = get_buffered_amount(&(dest->buffer))) == 0) {
            /* Nothing available to send */
            continue;
        }

        if (fwd->forcesend[i] == 0 && availsend < MIN_SEND_AMOUNT) {
            /* Not enough data to warrant a send right now */
            continue;
        }

        if (transmit_buffered_records(&(dest->buffer), dest->fd,
                BUF_BATCH_SIZE) < 0) {
            logger(LOG_INFO,
                    "OpenLI: error transmitting records to mediator %s:%s, dropping",
                    dest->ipstr, dest->portstr);
            disconnect_mediator(fwd, dest);
        }
        fwd->forcesend[i] = 0;

    }
    return 1;
}

static void forwarder_main(forwarding_thread_data_t *fwd) {

    int halted = 0, x, i;
    struct itimerspec its;

    fwd->destinations_by_id = NULL;
    fwd->destinations_by_fd = NULL;
    fwd->awaitingconfirm = 0;
    fwd->flagtimerfd = -1;

    fwd->intreorderer_cc = NULL;
    fwd->intreorderer_iri = NULL;

    fwd->conntimerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (fwd->conntimerfd == -1) {
        logger(LOG_INFO, "OpenLI: failed to create export connection timer: %s",
                strerror(errno));
        return;
    }

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 1;
    its.it_value.tv_nsec = 0;

    timerfd_settime(fwd->conntimerfd, 0, &its, NULL);

    fwd->topoll = (zmq_pollitem_t *)calloc(10, sizeof(zmq_pollitem_t));
    fwd->forcesend = (uint8_t *)calloc(10, sizeof(uint8_t));

    fwd->pollsize = 10;
    fwd->nextpoll = 3;

    fwd->topoll[0].socket = fwd->zmq_ctrlsock;
    fwd->topoll[0].events = ZMQ_POLLIN;

    fwd->topoll[1].socket = fwd->zmq_pullressock;
    fwd->topoll[1].events = ZMQ_POLLIN;

    fwd->topoll[2].socket = NULL;
    fwd->topoll[2].fd = fwd->conntimerfd;
    fwd->topoll[2].events = ZMQ_POLLIN;

    do {
        x = forwarder_main_loop(fwd);
    } while (x == 1);

    free(fwd->topoll);
    free(fwd->forcesend);
    close(fwd->conntimerfd);
    if (fwd->flagtimerfd != -1) {
        close(fwd->flagtimerfd);
    }

}

void *start_forwarding_thread(void *data) {

    forwarding_thread_data_t *fwd = (forwarding_thread_data_t *)data;
    char sockname[128];
    int zero = 0, x;
    openli_encoded_result_t res;

    fwd->zmq_ctrlsock = zmq_socket(fwd->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 128, "inproc://openliforwardercontrol_sync-%d",
            fwd->forwardid);
    if (zmq_bind(fwd->zmq_ctrlsock, sockname) != 0) {
        logger(LOG_INFO,
                "OpenLI: forwarding thread %d failed to bind to ctrl sock: %s",
                fwd->forwardid, strerror(errno));
        goto haltforwarder;
    }

    if (zmq_setsockopt(fwd->zmq_ctrlsock, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: forwarding thread %d failed to configure ctrl sock: %s",
                fwd->forwardid, strerror(errno));
        goto haltforwarder;
    }

    fwd->zmq_pullressock = zmq_socket(fwd->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 128, "inproc://openlirespush-%d", fwd->forwardid);
    if (zmq_bind(fwd->zmq_pullressock, sockname) != 0) {
        logger(LOG_INFO,
                "OpenLI: forwarding thread %d failed to bind to result sock: %s",
                fwd->forwardid, strerror(errno));
        goto haltforwarder;
    }

    if (zmq_setsockopt(fwd->zmq_pullressock, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: forwarding thread %d failed to configure result sock: %s",
                fwd->forwardid, strerror(errno));
        goto haltforwarder;
    }

    forwarder_main(fwd);

    do {
        x = zmq_recv(fwd->zmq_pullressock, &res, sizeof(res), ZMQ_DONTWAIT);
        if (x < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        }

        if (res.msgbody) {
            free(res.msgbody->encoded);
            free(res.msgbody);
        }

        if (res.liid) {
            free(res.liid);
        }

        if (res.ipcontents) {
            free(res.ipcontents);
        }
    } while (x > 0);

haltforwarder:
    zmq_close(fwd->zmq_ctrlsock);
    remove_all_destinations(fwd);
    logger(LOG_DEBUG, "OpenLI: halting forwarding thread %d",
            fwd->forwardid);
    pthread_exit(NULL);
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
