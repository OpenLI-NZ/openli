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

#include "logger.h"
#include "collector_base.h"
#include "collector_publish.h"

static int handle_ctrl_message(forwarding_thread_data_t *fwd,
        openli_export_recv_t *msg) {

    if (msg->type == OPENLI_EXPORT_HALT) {
        free(msg);
        return 0;
    }

    /* TODO handle mediator announcements and withdrawals */

    return 1;
}

static int handle_encoded_result(forwarding_thread_data_t *fwd,
        openli_encoded_result_t *res) {

    int ret = 0;

    if (res->msgbody) {
        /* TODO figure out how to recycle encoded message bodies */
        free(res->msgbody->encoded);
        free(res->msgbody);
    }

    if (res->origreq) {
        if (res->origreq->type == OPENLI_EXPORT_IPCC) {
            /* TODO figure out how we can safely release messages, given
             * that the mutex may no longer exist if we're exiting */
            free_published_message(res->origreq);
        } else {
            free(res->origreq);
        }
    }

    return ret;

}

static void forwarder_main(forwarding_thread_data_t *fwd) {

    int halted = 0, x, i;
    int processed;
    openli_encoded_result_t res;
    openli_export_recv_t *msg;

    fwd->topoll = (zmq_pollitem_t *)calloc(10, sizeof(zmq_pollitem_t));
    fwd->pollsize = 10;
    fwd->nextpoll = 2;

    fwd->topoll[0].socket = fwd->zmq_ctrlsock;
    fwd->topoll[0].events = ZMQ_POLLIN;

    fwd->topoll[1].socket = fwd->zmq_pullressock;
    fwd->topoll[1].events = ZMQ_POLLIN;


    while (!halted) {
        processed = 0;

        if (zmq_poll(fwd->topoll, fwd->nextpoll, -1) < 0) {
            logger(LOG_INFO,
                    "OpenLI: error while polling in forwarder %d: %s",
                    fwd->forwardid, strerror(errno));
            break;
        }

        if (fwd->topoll[0].revents & ZMQ_POLLIN) {
            do {
                /* Got something on the control socket */
                x = zmq_recv(fwd->zmq_ctrlsock, &msg, sizeof(msg),
                    ZMQ_DONTWAIT);
                if (x < 0 && x != EAGAIN) {
                    logger(LOG_INFO,
                            "OpenLI: error while receiving command in forwarder %d: %s",
                            fwd->forwardid, strerror(errno));
                    halted = 1;
                    break;
                }

                if (x <= 0) {
                    break;
                }
                if (handle_ctrl_message(fwd,msg)  <= 0) {
                    halted = 1;
                    break;
                }

            } while (x > 0);
        }

        if (halted) {
            break;
        }

        if (fwd->topoll[1].revents & ZMQ_POLLIN) {
            do {
                x = zmq_recv(fwd->zmq_pullressock, &res, sizeof(res),
                        ZMQ_DONTWAIT);
                if (x < 0 && x != EAGAIN) {
                    logger(LOG_INFO,
                            "OpenLI: error while receiving result in forwarder %d: %s",
                            fwd->forwardid, strerror(errno));
                    halted = 1;
                    break;
                }

                if (x <= 0) {
                    break;
                }
                if (handle_encoded_result(fwd, &res) < 0) {
                    halted = 1;
                    break;
                }
                processed ++;
            } while (x > 0 && processed < 10000);
        }

        if (halted) {
            break;
        }

        for (i = 2; i < fwd->nextpoll; i++) {
            /* check if any destinations can received any buffered data */
        }
    }

    free(fwd->topoll);

}

void *start_forwarding_thread(void *data) {

    forwarding_thread_data_t *fwd = (forwarding_thread_data_t *)data;
    char sockname[128];
    int zero = 0, x;
    openli_encoded_result_t res;

    logger(LOG_DEBUG, "OpenLI: starting forwarding thread %d",
            fwd->forwardid);

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

        if (res.ipcontents) {
            free(res.ipcontents);
        }
    } while (x > 0);

haltforwarder:
    zmq_close(fwd->zmq_pullressock);
    zmq_close(fwd->zmq_ctrlsock);
    logger(LOG_DEBUG, "OpenLI: halting forwarding thread %d",
            fwd->forwardid);
    pthread_exit(NULL);
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
