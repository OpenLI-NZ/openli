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

#include "sip_worker_redirection.h"
#include "util.h"
#include "sip_worker.h"
#include "logger.h"

void clear_redirection_map(Pvoid_t *map) {
    Word_t *pval;
    uint8_t index[512];
    sip_saved_redirection_t *rd;
    Word_t rc;

    if (*map == NULL) {
        return;
    }

    index[0] = '\0';
    JSLF(pval, *map, index);
    while (pval) {
        rd = (sip_saved_redirection_t *)(*pval);
        if (rd->callid) {
            free(rd->callid);
        }
        JSLN(pval, *map, index);
    }
    JSLFA(rc, *map)

}

void destroy_redirected_message(redirected_sip_message_t *msg) {
    size_t i;

    if (msg->callid) {
        free(msg->callid);
    }

    if (msg->packets) {
        for (i = 0; i < msg->pkt_cnt; i++) {
            if (msg->packets[i]) {
                trace_destroy_packet(msg->packets[i]);
            }
        }
        free(msg->packets);
    }
}

int redirect_sip_worker_packets(openli_sip_worker_t *sipworker,
        char *callid, libtrace_packet_t **pkts, int pkt_cnt) {

    Word_t *pval;
    sip_saved_redirection_t *rd;
    int i, j;
    redirected_sip_message_t msg;
    int success = 0;

    if (callid == NULL) {
        return 0;
    }

    JSLG(pval, sipworker->redir_data.redirections, (uint8_t *)callid);
    if (!pval) {
        rd = calloc(1, sizeof(sip_saved_redirection_t));
        rd->callid = strdup(callid);
        rd->redir_mask = 0xFFFFFFFFFFFFFFFF;    // start out broadcasting
        rd->receive_status = 0;                 // not relevant

        JSLI(pval, sipworker->redir_data.redirections, (uint8_t *)callid);
        *pval = (Word_t)rd;
    } else {
        rd = (sip_saved_redirection_t *)(*pval);
    }

    if (rd->redir_mask == 0) {
        return 0;
    }

    memset(&msg, 0, sizeof(msg));

    for (i = 0; i < sipworker->sipworker_threads; i++) {
        if ((rd->redir_mask & (1 << i)) == 0) {
            continue;
        }
        if (i == sipworker->workerid) {
            continue;
        }
        msg.message_type = REDIRECTED_SIP_PACKET;
        msg.callid = strdup(callid);
        msg.pkt_cnt = pkt_cnt;
        msg.packets = calloc(pkt_cnt, sizeof(libtrace_packet_t *));

        for (j = 0; j < pkt_cnt; j++) {
            if (pkts[j] == NULL) {
                msg.packets[j] = NULL;
                continue;
            }
            msg.packets[j] = openli_copy_packet(pkts[j]);
        }

        if (zmq_send(sipworker->zmq_redirect_outsocks[i], &msg,
                    sizeof(msg), 0) < 0) {
            /* If we get EAGAIN here, then either the recipient is
             * overwhelmed, or they have halted -- either way, the best thing
             * we can probably do now is discard this redirect.
             */
            destroy_redirected_message(&msg);
        } else {
            fprintf(stderr, "DEVDEBUG: redirected SIP packet for %s to %d\n",
                    callid, i);
            success ++;
        }
    }
    return success;
}
