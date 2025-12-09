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
        free(rd);
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

int handle_sip_redirection_claim(openli_sip_worker_t *sipworker,
        char *callid, uint8_t claimer) {

    Word_t *pval;
    sip_saved_redirection_t *rd;

    if (callid == NULL) {
        return 0;
    }
    JSLG(pval, sipworker->redir_data.redirections, (uint8_t *)callid);

    if (!pval) {
        /* we can't do anything with this claim */
        return 0;
    }

    rd = (sip_saved_redirection_t *)(*pval);
    if (rd->redir_mask == 0) {
        /* this call is already over? */
        return 0;
    }

    /* The claimant now has exclusive rights to the call */
    rd->redir_mask = (1 << claimer);
    return 1;
}

int handle_sip_redirection_reject(openli_sip_worker_t *sipworker,
        char *callid, uint8_t rejector) {

    Word_t *pval;
    sip_saved_redirection_t *rd;

    if (callid == NULL) {
        return 0;
    }
    JSLG(pval, sipworker->redir_data.redirections, (uint8_t *)callid);

    if (!pval) {
        /* we can't do anything with this rejection */
        return 0;
    }

    rd = (sip_saved_redirection_t *)(*pval);

    /* The claimant has refused the call */
    rd->redir_mask &= (~(1 << rejector));

    return 1;
}

int handle_sip_redirection_over(openli_sip_worker_t *sipworker,
        char *callid) {

    Word_t *pval, rc;
    sip_saved_redirection_t *rd;

    if (callid == NULL) {
        return 0;
    }
    JSLG(pval, sipworker->redir_data.redirections, (uint8_t *)callid);

    if (!pval) {
        /* we can't do anything with this announcement */
        return 0;
    }

    rd = (sip_saved_redirection_t *)(*pval);
    /* delete the call ID from the map */
    JSLD(rc, sipworker->redir_data.redirections, (uint8_t *)callid);
    free(rd->callid);
    free(rd);
    return 1;
}

int handle_sip_redirection_purge(openli_sip_worker_t *sipworker,
        char *callid) {

    Word_t *pval, rc;
    sip_saved_redirection_t *rd;

    if (callid == NULL) {
        return 0;
    }
    JSLG(pval, sipworker->redir_data.recvd_redirections, (uint8_t *)callid);
    if (!pval) {
        /* can't purge something we never knew about... */
        return 0;
    }

    rd = (sip_saved_redirection_t *)(*pval);
    JSLD(rc, sipworker->redir_data.recvd_redirections, (uint8_t *)callid);
    free(rd->callid);
    free(rd);
    return 1;
}

static inline void send_sip_redirect_instruction(openli_sip_worker_t *sipworker,
        uint8_t msgtype, char *callid, uint8_t dest) {

    redirected_sip_message_t instruct;

    memset(&instruct, 0, sizeof(instruct));
    instruct.sender = sipworker->workerid;
    instruct.message_type = msgtype;
    instruct.callid = strdup(callid);

    if (dest >= sipworker->sipworker_threads ||
            sipworker->zmq_redirect_outsocks[dest] == NULL) {
        return;
    }

    if (zmq_send(sipworker->zmq_redirect_outsocks[dest], &instruct,
                sizeof(instruct), 0) < 0) {
        destroy_redirected_message(&instruct);
    }
}

static inline void send_sip_redirect_reply(openli_sip_worker_t *sipworker,
        uint8_t msgtype, redirected_sip_message_t *src) {

    redirected_sip_message_t reply;

    memset(&reply, 0, sizeof(reply));
    reply.sender = sipworker->workerid;
    reply.message_type = msgtype;
    reply.callid = src->callid;
    src->callid = NULL;

    if (src->sender >= sipworker->sipworker_threads ||
            sipworker->zmq_redirect_outsocks[src->sender] == NULL) {
        return;
    }

    if (zmq_send(sipworker->zmq_redirect_outsocks[src->sender], &reply,
                sizeof(reply), 0) < 0) {
        destroy_redirected_message(&reply);
    }
}

int handle_sip_redirection_packet(openli_sip_worker_t *sipworker,
        redirected_sip_message_t *msg) {

    sip_saved_redirection_t *rd;
    Word_t *pval;


    if (msg->callid == NULL) {
        return 0;
    }
    if (msg->sender == sipworker->workerid) {
        // shouldn't happen, but just in case...
        return 0;
    }

    JSLG(pval, sipworker->redir_data.recvd_redirections,
            (uint8_t *)msg->callid);
    if (pval) {
        rd = (sip_saved_redirection_t *)(*pval);

        if (rd->receive_status == REDIRECTED_SIP_STATUS_REJECTED) {
            return 0;
        }
    } else {
        rd = calloc(1, sizeof(sip_saved_redirection_t));
        rd->callid = strdup(msg->callid);
        rd->redir_mask = 0;         // we're receiving, not redirecting
        rd->receive_status = REDIRECTED_SIP_STATUS_NEW;
        rd->redir_from = msg->sender;

        JSLI(pval, sipworker->redir_data.recvd_redirections,
                (uint8_t *)msg->callid);
        *pval = (Word_t)rd;
    }

    if (lookup_sip_callid(sipworker, msg->callid) == 0) {
        /* we've never seen this call ID before, so reject it */
        send_sip_redirect_reply(sipworker, REDIRECTED_SIP_REJECTED, msg);
        rd->receive_status = REDIRECTED_SIP_STATUS_REJECTED;
        return 0;
    }

    /* claim the call ID if we haven't already */
    if (rd->receive_status != REDIRECTED_SIP_STATUS_CLAIMED) {
        send_sip_redirect_reply(sipworker, REDIRECTED_SIP_CLAIM, msg);
        rd->receive_status = REDIRECTED_SIP_STATUS_CLAIMED;
    }

    return 1;
}

int conclude_redirected_sip_call(openli_sip_worker_t *sipworker, char *callid) {

    Word_t *pval, rc;
    sip_saved_redirection_t *rd;

    if (callid == NULL) {
        return 0;
    }
    JSLG(pval, sipworker->redir_data.recvd_redirections, (uint8_t *)callid);
    if (!pval) {
        /* can't remove a call that is not in our map */
        return 0;
    }

    rd = (sip_saved_redirection_t *)(*pval);

    JSLD(rc, sipworker->redir_data.recvd_redirections, (uint8_t *)callid);

    /* send an OVER message so the worker that was redirecting this call knows
     * they can safely remove their redirection state for this call ID */
    send_sip_redirect_instruction(sipworker, REDIRECTED_SIP_OVER, callid,
            rd->redir_from);

    free(rd->callid);
    free(rd);
    return 1;
}

void purge_redirected_sip_calls(openli_sip_worker_t *sipworker) {

    uint8_t callid[512];
    Word_t *pval, rc;
    sip_saved_redirection_t *rd;
    struct timeval tv;
    int i;
    uint32_t count = 0;

    gettimeofday(&tv, NULL);
    callid[0] = '\0';
    JSLF(pval, sipworker->redir_data.redirections, callid);

    while (pval) {
        rd = (sip_saved_redirection_t *)(*pval);
        fprintf(stderr, "     %p %u -- %s %lu %lu\n", sipworker, count,
                rd->callid, tv.tv_sec - rd->last_packet, rd->redir_mask);
        count++;

        if (rd->redir_mask != 0) {
            /* a worker has claimed this, or at least not all workers have
             * rejected it */
            JSLN(pval, sipworker->redir_data.redirections, callid);
            continue;
        }

        if (tv.tv_sec - rd->last_packet < 120) {
            /* 5 minutes is more than long enough to wait */
            JSLN(pval, sipworker->redir_data.redirections, callid);
            continue;
        }

        JSLD(rc, sipworker->redir_data.redirections, callid);
        if (rd->receive_status == 0) {
            for (i = 0; i < sipworker->sipworker_threads; i++) {
                if (i == sipworker->workerid) {
                    continue;
                }
                send_sip_redirect_instruction(sipworker, REDIRECTED_SIP_PURGE,
                        rd->callid, i);
            }
        }
        free(rd->callid);
        free(rd);
        JSLN(pval, sipworker->redir_data.redirections, callid);
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
        rd->redir_mask = (0xFFFFFFFFFFFFFFFF >>
                (64 - sipworker->sipworker_threads));  // start out broadcasting

        // exclude ourselves from the set of possible recipients...
        rd->redir_mask &= (~(1 << sipworker->workerid));
        rd->receive_status = 0;                 // not relevant
        rd->redir_from = sipworker->workerid;   // not relevant

        JSLI(pval, sipworker->redir_data.redirections, (uint8_t *)callid);
        *pval = (Word_t)rd;
    } else {
        rd = (sip_saved_redirection_t *)(*pval);
    }

    if (rd->redir_mask == 0) {
        return 0;
    }

    if (pkt_cnt > 0) {
        struct timeval tv = trace_get_timeval(pkts[0]);
        rd->last_packet = tv.tv_sec;
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
        msg.sender = (uint8_t) sipworker->workerid;
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
            success ++;
        }
    }
    return success;
}
