/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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

#include "logger.h"
#include "collector_util.h"
#include "export_buffer.h"
#include <zmq.h>
#include <stdlib.h>
#include <string.h>

int init_zmq_socket_array(void **zmq_socks, int sockcount,
        const char *basename, void *zmq_ctxt) {

    int i;
    char sockname[256];
    int ret = 0;

    for (i = 0; i < sockcount; i++) {
        zmq_socks[i] = zmq_socket(zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 256, "%s-%d", basename, i);
        if (zmq_connect(zmq_socks[i], sockname) < 0) {
            ret = -1;
            logger(LOG_INFO,
                    "OpenLI: failed to bind to publishing zmq %s: %s",
                    sockname, strerror(errno));

            zmq_close(zmq_socks[i]);
            zmq_socks[i] = NULL;
        }
    }
    return ret;
}

void clear_zmq_socket_array(void **zmq_socks, int sockcount) {
    int i, zero = 0;
    if (zmq_socks == NULL) {
        return;
    }

    for (i = 0; i < sockcount; i++) {
        if (zmq_socks[i] == NULL) {
            continue;
        }
        zmq_setsockopt(zmq_socks[i], ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(zmq_socks[i]);
    }
    free(zmq_socks);
}

int send_halt_message_to_zmq_socket_array(void **zmq_socks, int sockcount,
		halt_info_t *haltinfo) {
    openli_export_recv_t *haltmsg;
    int zero = 0, ret, i, failed;

    if (zmq_socks == NULL) {
        return 0;
    }

    failed = 0;
    for (i = 0; i < sockcount; i++) {
        if (zmq_socks[i] == NULL) {
            continue;
        }
        haltmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));
        haltmsg->type = OPENLI_EXPORT_HALT;
	haltmsg->data.haltinfo = haltinfo;

        ret = zmq_send(zmq_socks[i], &haltmsg, sizeof(haltmsg), ZMQ_NOBLOCK);
        if (ret < 0 && errno == EAGAIN) {
            failed ++;
            free(haltmsg);
            continue;
        }
        if (ret <= 0) {
            free(haltmsg);
        }
        zmq_setsockopt(zmq_socks[i], ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(zmq_socks[i]);
	zmq_socks[i] = NULL;
    }
    return failed;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
