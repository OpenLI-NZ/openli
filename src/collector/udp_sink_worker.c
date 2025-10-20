/*
 *
 * Copyright (c) 2024, 2025 SearchLight Ltd, New Zealand.
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
#include "collector.h"
#include "intercept.h"
#include "collector_sync.h"

#include <zmq.h>
#include <unistd.h>

typedef struct udp_sink_local {

    void *zmq_control;
    void *zmq_publish;

    char *listenaddr;
    char *listenport;
    int sockfd;

    char *expectedliid;
    openli_export_recv_t *cept;
    uint32_t dest_mediator;


} udp_sink_local_t;

static udp_sink_local_t *init_local_state(udp_sink_worker_args_t *args) {

    udp_sink_local_t *local = calloc(1, sizeof(udp_sink_local_t));
    char sockname[1024];
    int zero = 0, hwm = 1000, timeout=1000;

    local->zmq_publish = NULL;
    local->sockfd = -1;

    local->cept = NULL;
    local->dest_mediator = 0;

    local->zmq_control = zmq_socket(args->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 1024, "inproc://openliudpsink_sync-%s", args->key);

    if (zmq_connect(local->zmq_control, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to connect to control ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_control, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure control ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    local->zmq_publish = zmq_socket(args->zmq_ctxt, ZMQ_PUSH);
    snprintf(sockname, 1024, "inproc://openlipub-%d", args->trackerid);
    if (zmq_connect(local->zmq_publish, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to connect to publishing ZMQ %d: %s",
                args->key, args->trackerid, strerror(errno));
        zmq_close(local->zmq_control);
        zmq_close(local->zmq_publish);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_publish, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure publish ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_publish);
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_publish, ZMQ_SNDHWM, &hwm,
            sizeof(hwm)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure publish ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_publish);
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_publish, ZMQ_SNDTIMEO, &timeout,
            sizeof(timeout)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure publish ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_publish);
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }


    local->listenaddr = args->listenaddr;
    args->listenaddr = NULL;

    local->listenport = args->listenport;
    args->listenport = NULL;

    local->expectedliid = args->liid;
    args->liid = NULL;
    return local;
}

static void cleanup_local_udp_sink(udp_sink_local_t *local) {
    if (local->sockfd != -1) {
        close(local->sockfd);
    }
    if (local->listenaddr) {
        free(local->listenaddr);
    }
    if (local->listenport) {
        free(local->listenport);
    }
    if (local->expectedliid) {
        free(local->expectedliid);
    }
    if (local->zmq_control) {
        zmq_close(local->zmq_control);
    }
    if (local->zmq_publish) {
        zmq_close(local->zmq_publish);
    }
    if (local->cept) {
        free_published_message(local->cept);
    }
    free(local);

}

static int process_control_message(udp_sink_local_t *local, char *key) {
    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(local->zmq_control, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error receiving message on control socket in UDP sink worker '%s': %s", key, strerror(errno));
            return -1;
        }
        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            free_published_message(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_INTERCEPT_DETAILS) {
            if (strcmp(local->expectedliid, msg->data.cept.liid) != 0) {
                logger(LOG_INFO,
                        "OpenLI: UDP sink worker '%s' was expecting to be responsible for intercept '%s', but it was provided details for '%s'?",
                        key, local->expectedliid, msg->data.cept.liid);
                return -1;
            }
            local->dest_mediator = msg->destid;
            local->cept = msg;
        } else {
            // not a message we care about
            free_published_message(msg);
        }
    } while (x > 0);

    return 1;
}

static int udp_sink_main_loop(udp_sink_local_t *local, char *key) {

    int x;
    zmq_pollitem_t topoll[2];

    topoll[0].socket = local->zmq_control;
    topoll[0].events = ZMQ_POLLIN;

    x = zmq_poll(topoll, 1, 100);
    if (x < 0) {
        logger(LOG_INFO,
                "OpenLI: error in zmq_poll in UDP sink worker '%s': %s",
                key, strerror(errno));
        return -1;
    }

    if (topoll[0].revents & ZMQ_POLLIN) {
        x = process_control_message(local, key);
        if (x < 0) {
            return -1;
        }
    }

    return 1;
}

void *start_udp_sink_worker(void *arg) {

    udp_sink_worker_args_t *start = (udp_sink_worker_args_t *)arg;
    udp_sink_local_t *local;

    if (start == NULL) {
        pthread_exit(NULL);
    }

    local = init_local_state(start);
    if (local == NULL) {
        goto exitthread;
    }

    logger(LOG_INFO, "OpenLI: started UDP sink worker for '%s'", start->key);
    while (1) {
        if (udp_sink_main_loop(local, start->key) <= 0) {
            break;
        }
    }

exitthread:
    if (local) {
        cleanup_local_udp_sink(local);
    }

    logger(LOG_INFO, "OpenLI: halting UDP sink worker for '%s'", start->key);
    if (start->listenaddr) {
        free(start->listenaddr);
    }
    if (start->listenport) {
        free(start->listenport);
    }
    if (start->liid) {
        free(start->liid);
    }
    if (start->key) {
        free(start->key);
    }
    free(start);
    pthread_exit(NULL);
}
