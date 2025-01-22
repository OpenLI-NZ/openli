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
#include "netcomms.h"
#include "openli_tls.h"

#include <unistd.h>
#include <zmq.h>

#define MAX_ZPOLL_X2X3 (1024)

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

    size_t i;

    if (xinp->clients) {
        for (i = 0; i < xinp->client_count; i++) {
            if (xinp->clients[i].fd != -1) {
                close(xinp->clients[i].fd);
            }
            if (xinp->clients[i].ssl) {
                SSL_free(xinp->clients[i].ssl);
            }
            if (xinp->clients[i].buffer) {
                free(xinp->clients[i].buffer);
            }
        }
        free(xinp->clients);
    }

    if (xinp->zmq_ctrlsock) {
        zmq_close(xinp->zmq_ctrlsock);
    }

    if (xinp->listener_fd != -1) {
        close(xinp->listener_fd);
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
        size_t *topoll_size, size_t *index_map) {

    size_t topoll_req = 0, i, ind;

    memset(index_map, 0, sizeof(size_t) * MAX_ZPOLL_X2X3 * 2);
    topoll_req = 2 + xinp->client_count;

    if (topoll_req > *topoll_size) {
        free(*topoll);
        *topoll = calloc(topoll_req + 32, sizeof(zmq_pollitem_t));
        *topoll_size = topoll_req + 32;
    }

    (*topoll)[0].socket = xinp->zmq_ctrlsock;
    (*topoll)[0].events = ZMQ_POLLIN;

    (*topoll)[1].socket = NULL;
    (*topoll)[1].fd = xinp->listener_fd;
    (*topoll)[1].events = ZMQ_POLLIN;

    ind = 2;

    for (i = 0; i < xinp->client_count; i++) {
        if (xinp->clients[i].fd < 0) {
            continue;
        }
        index_map[ind] = i;
        (*topoll)[ind].socket = NULL;
        (*topoll)[ind].fd = xinp->clients[i].fd;
        (*topoll)[ind].events = ZMQ_POLLIN;
        ind ++;
    }

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

#define X2X3_CLIENT_BUFSIZE (32)        // TODO make this larger ;)

static int x2x3_accept_client_connection(x_input_t *xinp) {

    int r, newfd;
    SSL *newc;
    openli_ssl_config_t sslconf;

    pthread_mutex_lock(&(xinp->sslmutex));
    if (xinp->ssl_ctx == NULL) {
        logger(LOG_INFO, "OpenLI: cannot create X2-X3 listener for %s because this collector has no usable TLS configuration", xinp->identifier);
        pthread_mutex_unlock(&(xinp->sslmutex));
        return -1;
    }

    newfd = accept(xinp->listener_fd, NULL, NULL);
    if (newfd == -1) {
        logger(LOG_INFO, "OpenLI: error while accepting client connection in X2-X3 thread %s: %s", xinp->identifier, strerror(errno));
        pthread_mutex_unlock(&(xinp->sslmutex));
        return -1;
    }
    fd_set_nonblock(newfd);

    sslconf.ctx = xinp->ssl_ctx;
    r = listen_ssl_socket(&sslconf, &newc, newfd);
    pthread_mutex_unlock(&(xinp->sslmutex));

    if (r == OPENLI_SSL_CONNECT_FAILED) {
        logger(LOG_INFO, "OpenLI: client failed to complete SSL handshake");
        close(newfd);
        SSL_free(newc);
        return -1;
    }

    while (xinp->client_count >= xinp->client_array_size) {
        x_input_client_t *replace = calloc(xinp->client_count + 8,
                sizeof(x_input_client_t));

        if (xinp->client_count > 0) {
            memcpy(replace, xinp->clients,
                    sizeof(x_input_client_t) * xinp->client_count);
            free(xinp->clients);
        }
        xinp->clients = replace;
        xinp->client_array_size = xinp->client_count + 8;
    }

    xinp->clients[xinp->client_count].ssl = newc;
    xinp->clients[xinp->client_count].fd = newfd;
    xinp->clients[xinp->client_count].buffer = malloc(X2X3_CLIENT_BUFSIZE);
    xinp->clients[xinp->client_count].buffer_size = X2X3_CLIENT_BUFSIZE;
    xinp->clients[xinp->client_count].bufread = 0;
    xinp->clients[xinp->client_count].bufwrite = 0;
    xinp->client_count ++;
    return 1;
}

static int create_x2x3_listening_socket(x_input_t *xinp) {
    int sockfd;

    if (xinp->listenaddr == NULL || xinp->listenport == NULL) {
        return -1;
    }


    sockfd = create_listener(xinp->listenaddr, xinp->listenport,
            "X2-X3 listener");
    if (sockfd == -1) {
        return -1;
    }
    if (fd_set_block(sockfd) < 0) {
        return -1;
    }
    xinp->listener_fd = sockfd;
    return xinp->listener_fd;
}

static int receive_client_data(x_input_t *xinp, size_t client_ind) {

    x_input_client_t *client = &(xinp->clients[client_ind]);
    size_t maxread = 0;
    int r;

    if (client_ind >= xinp->client_count || client->ssl == NULL ||
            client->fd == -1) {
        return 0;
    }

    maxread = client->buffer_size - client->bufwrite;
    r = SSL_read(client->ssl, client->buffer + client->bufwrite, maxread);
    if (r <= 0) {
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        if (r < 0) {
            logger(LOG_INFO,
                    "OpenLI: X2/X3 client has been disconnected from %s due to an error: %s",
                    xinp->identifier, strerror(errno));
        } else {
            logger(LOG_INFO,
                    "OpenLI: X2/X3 client has been disconnected from %s",
                    xinp->identifier);
        }
        /* other end is no longer connected */
        goto dropclient;
    }

    client->bufwrite += r;

    /* TODO try to parse the data that we have in our buffer */
    fprintf(stderr, "%s %zu %s", xinp->identifier, client_ind,
            (char *)(client->buffer + client->bufread));


    if (client->bufwrite >= client->buffer_size) {
        /* Buffer has filled up but we don't have a parseable X2/X3 PDU?
         * Let's drop this client because they must be sending us something
         * we don't understand (either garbage or something we don't
         * support). Either way, we can't keep buffering stuff forever so
         * better to kill it off now.
         */
        logger(LOG_INFO,
                "OpenLI: X2/X3 client has been disconnected from %s due to sending unknown content",
                xinp->identifier);
        goto dropclient;
    }

    return r;

dropclient:
    SSL_free(client->ssl);
    client->ssl = NULL;
    close(client->fd);
    client->fd = -1;
    free(client->buffer);
    client->buffer = NULL;
    return 0;
}

void x2x3_ingest_main(x_input_t *xinp) {

    zmq_pollitem_t *topoll;
    size_t topoll_size, topoll_cnt, i;
    int rc, x;
    size_t client_index_map[MAX_ZPOLL_X2X3 * 2];

    if (create_x2x3_listening_socket(xinp) < 0) {
        logger(LOG_INFO, "OpenLI: failed to create listening socket for X2-X3 input %s, unable to accept connections!", xinp->identifier);
        xinp->listener_fd = -1;
    }

    topoll = calloc(128, sizeof(zmq_pollitem_t));
    topoll_size = 128;

    while (1) {
        topoll_cnt = setup_x2x3_pollset(xinp, &topoll, &topoll_size,
                client_index_map);

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

        if (topoll[1].revents & ZMQ_POLLIN) {
            // if this fails, we don't really care?
            x2x3_accept_client_connection(xinp);

            topoll[1].revents = 0;
        }

        for (i = 2; i < topoll_cnt; i++) {
            if (topoll[i].fd > 0 && topoll[i].revents & ZMQ_POLLIN) {
                receive_client_data(xinp, client_index_map[i]);
            }
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
    pthread_mutex_destroy(&(xinp->sslmutex));

    if (xinp->listenaddr) {
        free(xinp->listenaddr);
    }
    if (xinp->listenport) {
        free(xinp->listenport);
    }
    if (xinp->identifier) {
        free(xinp->identifier);
    }

    free(xinp);
}
