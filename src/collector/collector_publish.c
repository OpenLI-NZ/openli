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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <zmq.h>

#include "logger.h"
#include "util.h"
#include "collector_publish.h"
#include "internal.pb-c.h"

void **connect_exporter_queues(int queuecount, void *zmq_ctxt) {
    void **pubsocks = malloc(sizeof(void *) * queuecount);
    int i, zero = 0;

    memset(pubsocks, 0, sizeof(void *) * queuecount);
    for (i = 0; i < queuecount; i++) {
        char sockname[128];
        void *psock = zmq_socket(zmq_ctxt, ZMQ_PUSH);

        //snprintf(sockname, 128, "inproc://exporter%d", i);
        snprintf(sockname, 128, "ipc:///tmp/exporter%d", i + 6000);
        if (zmq_connect(psock, sockname) < 0) {
            printf("zmq_connect error: %s\n", strerror(errno));
        }

        zmq_setsockopt(psock, ZMQ_SNDHWM, &zero, sizeof(zero));
        pubsocks[i] = psock;
    }

    return pubsocks;
}

void disconnect_exporter_queues(void **pubsocks, int queuecount) {
    int i, zero = 0;
    for (i = 0; i < queuecount; i++) {
        if (pubsocks[i]) {
            if (zmq_setsockopt(pubsocks[i], ZMQ_LINGER, &zero,
                        sizeof(zero)) != 0) {
                logger(LOG_INFO,
                        "OpenLI: unable to set linger period on publishing zeromq socket.");
            }
            zmq_close(pubsocks[i]);
        }
    }
    free(pubsocks);
}


static int _publish_mediator(void *pubsock, openli_export_recv_t *msg) {

    if (zmq_send(pubsock, (char *)(&msg->data.med.mediatorid),
            sizeof(msg->data.med.mediatorid), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, msg->data.med.ipstr, strlen(msg->data.med.ipstr) + 1,
            ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, msg->data.med.portstr,
            strlen(msg->data.med.portstr) + 1, 0) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int _publish_ipcc_job(void *pubsock, openli_export_recv_t *msg) {

    IPCCJob job = IPCCJOB__INIT;
    void *buf;
    unsigned len;

    job.destid = msg->destid;
    job.cin = msg->data.ipcc.cin;
    job.dir = msg->data.ipcc.dir;
    job.tvsec = msg->data.ipcc.tv.tv_sec;
    job.tvusec = msg->data.ipcc.tv.tv_usec;
    job.liid = msg->data.ipcc.liid;
    job.ipcontent.data = msg->data.ipcc.ipcontent;
    job.ipcontent.len = msg->data.ipcc.ipclen;

    len = ipccjob__get_packed_size(&job);
    buf = malloc(len);
    ipccjob__pack(&job, buf);

    if (zmq_send(pubsock, (char *)buf, len, 0) < 0) {
        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }
    return 0;


}

static int _publish_ipiri_job(void *pubsock, openli_export_recv_t *msg) {

    if (zmq_send(pubsock, (char *)&(msg->destid), sizeof(msg->destid),
            ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.special),
            sizeof(msg->data.ipiri.special), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.cin),
            sizeof(msg->data.ipiri.cin), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.access_tech),
            sizeof(msg->data.ipiri.access_tech), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.ipassignmentmethod),
            sizeof(msg->data.ipiri.ipassignmentmethod), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }
    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.ipfamily),
            sizeof(msg->data.ipiri.ipfamily), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.assignedip_prefixbits),
            sizeof(msg->data.ipiri.assignedip_prefixbits), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (msg->data.ipiri.ipfamily == AF_INET) {
        struct sockaddr_in *in =
                (struct sockaddr_in *)&(msg->data.ipiri.assignedip);

        if (zmq_send(pubsock, (char *)&(in->sin_addr.s_addr),
                sizeof(in->sin_addr.s_addr), ZMQ_SNDMORE) < 0) {
            logger(LOG_INFO,
                    "Error while publishing OpenLI export message: %s",
                    strerror(errno));
            return -1;
        }
    } else if (msg->data.ipiri.ipfamily == AF_INET6) {
        struct sockaddr_in6 *in6 =
                (struct sockaddr_in6 *)&(msg->data.ipiri.assignedip);

        if (zmq_send(pubsock, (char *)&(in6->sin6_addr.s6_addr),
                sizeof(in6->sin6_addr.s6_addr), ZMQ_SNDMORE) < 0) {
            logger(LOG_INFO,
                    "Error while publishing OpenLI export message: %s",
                    strerror(errno));
            return -1;
        }
    }


    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.sessionstartts.tv_sec),
            sizeof(msg->data.ipiri.sessionstartts.tv_sec), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }
    if (zmq_send(pubsock, (char *)&(msg->data.ipiri.sessionstartts.tv_usec),
            sizeof(msg->data.ipiri.sessionstartts.tv_usec), ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, msg->data.ipiri.liid,
            strlen(msg->data.ipiri.liid) + 1, ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, msg->data.ipiri.username,
            strlen(msg->data.ipiri.username) + 1, 0) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    /* TODO plugin_data */

    return 0;
}

static int _publish_nocontent(void *pubsock, openli_export_recv_t *msg) {
    if (zmq_send(pubsock, "", 0, 0) < 0) {
        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}

static int _publish_ipmmcc_job(void *pubsock, openli_export_recv_t *msg) {
    /* TODO */
    return 0;
}

static int _publish_ipmmiri_job(void *pubsock, openli_export_recv_t *msg) {
    /* TODO */
    return 0;
}

static int _publish_intercept(void *pubsock, openli_export_recv_t *msg) {

    if (zmq_send(pubsock, msg->data.cept.liid, strlen(msg->data.cept.liid) + 1,
            ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, msg->data.cept.authcc,
            strlen(msg->data.cept.authcc) + 1, ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_send(pubsock, msg->data.cept.delivcc,
            strlen(msg->data.cept.delivcc) + 1, 0) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }
    return 0;
}



static inline int _publish_openli_msg(void *pubsock, openli_export_recv_t *msg) {

    if (zmq_send(pubsock, (char *)&(msg->type), sizeof(msg->type),
            ZMQ_SNDMORE) < 0) {

        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    switch(msg->type) {
        case OPENLI_EXPORT_MEDIATOR:
        case OPENLI_EXPORT_DROP_SINGLE_MEDIATOR:
            return _publish_mediator(pubsock, msg);
        case OPENLI_EXPORT_FLAG_MEDIATORS:
        case OPENLI_EXPORT_DROP_ALL_MEDIATORS:
            return _publish_nocontent(pubsock, msg);
        case OPENLI_EXPORT_INTERCEPT_DETAILS:
        case OPENLI_EXPORT_INTERCEPT_OVER:
            return _publish_intercept(pubsock, msg);
        case OPENLI_EXPORT_IPCC:
            return _publish_ipcc_job(pubsock, msg);
        case OPENLI_EXPORT_IPMMCC:
            return _publish_ipmmcc_job(pubsock, msg);
        case OPENLI_EXPORT_IPIRI:
            return _publish_ipiri_job(pubsock, msg);
        case OPENLI_EXPORT_IPMMIRI:
            return _publish_ipmmiri_job(pubsock, msg);
        default:
            assert(0);
    }

    return 0;
}

void export_queue_put_all(void **pubsocks, openli_export_recv_t *msg,
        int numexporters) {

    int i;

    for (i = 0; i < numexporters; i++) {
        if (_publish_openli_msg(pubsocks[i], msg) < 0) {
            continue;
        }
    }
}

int export_queue_put_by_liid(void **pubsocks,
        openli_export_recv_t *msg, char *liid, int numexporters) {

    uint32_t hash;
    int queueid;

    hash = hashlittle(liid, strlen(liid), 0x188532fa);
    queueid = hash % numexporters;
    return _publish_openli_msg(pubsocks[queueid], msg);
}

int export_queue_put_by_queueid(void **pubsocks,
        openli_export_recv_t *msg, int queueid) {

    if (queueid < 0) {
        logger(LOG_INFO,
                "OpenLI: bad export queue passed into export_queue_put_by_queueid: %d",
                queueid);
        return -1;
    }

    //printf("sending message type %d to %d\n", msg->type, queueid);
    return _publish_openli_msg(pubsocks[queueid], msg);
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
