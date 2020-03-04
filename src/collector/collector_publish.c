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

#include <pthread.h>
#include <zmq.h>

#include "logger.h"
#include "util.h"
#include "collector_publish.h"

int publish_openli_msg(void *pubsock, openli_export_recv_t *msg) {

    if (zmq_send(pubsock, &msg, sizeof(openli_export_recv_t *), 0) < 0) {
        logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}

void free_published_message(openli_export_recv_t *msg) {

    if (msg->type == OPENLI_EXPORT_IPCC || msg->type == OPENLI_EXPORT_IPMMCC
            || msg->type == OPENLI_EXPORT_UMTSCC) {
        if (msg->data.ipcc.liid) {
            free(msg->data.ipcc.liid);
        }
        if (msg->data.ipcc.ipcontent) {
            free(msg->data.ipcc.ipcontent);
        }
    } else if (msg->type == OPENLI_EXPORT_IPMMIRI) {
        if (msg->data.ipmmiri.liid) {
            free(msg->data.ipmmiri.liid);
        }
        if (msg->data.ipmmiri.content) {
            free(msg->data.ipmmiri.content);
        }
    } else if (msg->type == OPENLI_EXPORT_IPIRI) {
        if (msg->data.ipiri.liid) {
            free(msg->data.ipiri.liid);
        }
        if (msg->data.ipiri.username) {
            free(msg->data.ipiri.username);
        }
        if (msg->data.ipiri.assignedips) {
            free(msg->data.ipiri.assignedips);
        }
    } else if (msg->type == OPENLI_EXPORT_UMTSIRI) {
        if (msg->data.mobiri.liid) {
            free(msg->data.mobiri.liid);
        }
    } else if (msg->type == OPENLI_EXPORT_RAW_SYNC) {
        if (msg->data.rawip.liid) {
            free(msg->data.rawip.liid);
        }
        if (msg->data.rawip.ipcontent) {
            free(msg->data.rawip.ipcontent);
        }
    }

    free(msg);
}

openli_export_recv_t *create_ipcc_job(uint32_t cin, char *liid,
        uint32_t destid, libtrace_packet_t *pkt, uint8_t dir) {

    void *l3;
    uint32_t rem;
    uint16_t ethertype;
    openli_export_recv_t *msg = NULL;
    uint32_t x;
    size_t liidlen = strlen(liid);

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }

    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    msg->type = OPENLI_EXPORT_IPCC;
    msg->destid = destid;
    msg->ts = trace_get_timeval(pkt);

    if (liidlen + 1 > msg->data.ipcc.liidalloc) {
        if (liidlen + 1 < 32) {
            x = 32;
        } else {
            x = liidlen + 1;
        }
        msg->data.ipcc.liid = realloc(msg->data.ipcc.liid, x);
        msg->data.ipcc.liidalloc = x;
    }
    memcpy(msg->data.ipcc.liid, liid, liidlen);
    msg->data.ipcc.liid[liidlen] = '\0';

    if (rem > msg->data.ipcc.ipcalloc) {
        if (rem < 512) {
            x = 512;
        } else {
            x = rem;
        }
        msg->data.ipcc.ipcontent = realloc(msg->data.ipcc.ipcontent, x);
        msg->data.ipcc.ipcalloc = x;
    }

    memcpy(msg->data.ipcc.ipcontent, l3, rem);
    msg->data.ipcc.ipclen = rem;
    msg->data.ipcc.cin = cin;
    msg->data.ipcc.dir = dir;

    return msg;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
