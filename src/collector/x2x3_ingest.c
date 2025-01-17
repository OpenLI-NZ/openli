/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

#include "util.h"
#include "logger.h"
#include "x2x3_ingest.h"
#include "collector_publish.h"

#include <zmq.h>

static int setup_zmq_sockets_for_x2x3(x_input_t *xinp) {
    int zero = 0;
    char sockname[1024];

    xinp->zmq_ctrlsock = zmq_socket(xinp->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 1024, "inproc://openlix2x3_sync-%s", xinp->identifier);
    if (zmq_bind(xinp->zmq_ctrlsock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: X2X3 thread %s failed to bind to control ZMQ: %s",
                xinp->identifier, strerror(errno));
        return -1;
    }

    if (zmq_setsockopt(xinp->zmq_ctrlsock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO,
                "OpenLI: X2X3 thread %s failed to configure control ZMQ: %s",
                xinp->identifier, strerror(errno));
        return -1;
    }
    return 0;
}

static void tidyup_x2x3_ingest_thread(x_input_t *xinp) {
    /* close all client connections */
    /* close listening socket */
    /* close push ZMQs */
    /* close pull ZMQ */
    /* free remaining state */

    if (xinp->zmq_ctrlsock) {
        zmq_close(xinp->zmq_ctrlsock);
    }

    /* Let the sync thread know that this thread is ready to join */
    if (xinp->haltinfo) {
        pthread_mutex_lock(&(xinp->haltinfo->mutex));
        xinp->haltinfo->halted ++;
        pthread_cond_signal(&(xinp->haltinfo->cond));
        pthread_mutex_unlock(&(xinp->haltinfo->mutex));
    }
}

static size_t setup_x2x3_pollset(x_input_t *xinp, zmq_pollitem_t **topoll,
        size_t *topoll_size) {

    size_t topoll_req = 0;

    /* TODO this gets marginally more complex when we have clients */
    topoll_req = 1;

    if (topoll_req > *topoll_size) {
        free(*topoll);
        *topoll = calloc(topoll_req + 32, sizeof(zmq_pollitem_t));
        *topoll_size = topoll_req + 32;
    }

    (*topoll)[0].socket = xinp->zmq_ctrlsock;
    (*topoll)[0].events = ZMQ_POLLIN;

    return topoll_req;
}

static int x2x3_process_sync_thread_message(x_input_t *xinp) {
    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(xinp->zmq_ctrlsock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error receiving message from sync thread in X2/X3 ingest thread %s: %s",
                    xinp->identifier, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            xinp->haltinfo = (halt_info_t *)(msg->data.haltinfo);
            free(msg);
            return -1;
        }

        /* TODO other messages (X1 intercepts, mainly) */
        free(msg);
    } while (x > 0);

    return 1;
}

void x2x3_ingest_main(x_input_t *xinp) {

    zmq_pollitem_t *topoll;
    size_t topoll_size, topoll_cnt, i;
    int rc, x;

    topoll = calloc(128, sizeof(zmq_pollitem_t));
    topoll_size = 128;

    while (1) {
        topoll_cnt = setup_x2x3_pollset(xinp, &topoll, &topoll_size);

        if (topoll_cnt < 1) {
            break;
        }

        rc = zmq_poll(topoll, topoll_cnt, 50);
        if (rc < 0) {
            logger(LOG_INFO,
                    "OpenLI: error in zmq_poll in X2/X3 ingestor %s: %s",
                    xinp->identifier, strerror(errno));
            break;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            /* got a message from the sync thread */
            x = x2x3_process_sync_thread_message(xinp);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }
    }
    free(topoll);
}

void *start_x2x3_ingest_thread(void *param) {
    x_input_t *xinp = (x_input_t *)param;

    /* set up pull ZMQ to get instructions from the sync thread */
    /* set up push ZMQs */
    if (setup_zmq_sockets_for_x2x3(xinp) < 0) {
        goto haltx2x3;
    }
    /* create TLS socket to accept connections */


    /* main loop == zmq_poll on all ZMQs + listening socket + connected
     * client sockets */
    x2x3_ingest_main(xinp);


    /* shutdown */
haltx2x3:
    logger(LOG_INFO, "OpenLI: halting X2/X3 ingestor %s\n", xinp->identifier);
    tidyup_x2x3_ingest_thread(xinp);
    pthread_exit(NULL);
}

void destroy_x_input(x_input_t *xinp) {
    if (xinp->listenaddr) {
        free(xinp->listenaddr);
    }
    if (xinp->listenport) {
        free(xinp->listenport);
    }
    if (xinp->certfile) {
        free(xinp->certfile);
    }
    if (xinp->identifier) {
        free(xinp->identifier);
    }

    free(xinp);
}
