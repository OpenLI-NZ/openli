/*
 *
 * Copyright (c) 2018-2023 Searchlight New Zealand Ltd.
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

#include "netcomms.h"
#include "intercept.h"
#include "collector.h"
#include "sms_worker.h"
#include "util.h"
#include "logger.h"
#include "ipmmiri.h"
#include "location.h"

#include <assert.h>
#include <math.h>
#include <sys/timerfd.h>
#include <libtrace.h>

const uint8_t sms_masking_bytes[] = {
    0x20, 0x10, 0x08, 0x04, 0x02, 0x81, 0x40
};

static void free_single_sip_callid(callid_intercepts_t *cid) {
    voip_intercept_ref_t *vint_ref, *tmp;

    HASH_ITER(hh, cid->intlist, vint_ref, tmp) {
        /* vint is just a reference into state->voipintercepts */
        HASH_DELETE(hh, cid->intlist, vint_ref);
        if (vint_ref->liid) {
            free(vint_ref->liid);
        }
        free(vint_ref);
    }
    if (cid->callid) {
        free((void *)cid->callid);
    }
    free(cid);
}

static void free_all_sip_callids(openli_sms_worker_t *state) {

    callid_intercepts_t *iter, *tmp;

    HASH_ITER(hh, state->known_callids, iter, tmp) {
        HASH_DELETE(hh, state->known_callids, iter);
        free_single_sip_callid(iter);
    }

}

static void init_sms_voip_intercept(openli_sms_worker_t *state,
        voipintercept_t *vint) {

    if (state->tracker_threads <= 1) {
        vint->common.seqtrackerid = 0;
    } else {
        vint->common.seqtrackerid = hash_liid(vint->common.liid) %
            state->tracker_threads;
    }

    HASH_ADD_KEYPTR(hh_liid, state->voipintercepts, vint->common.liid,
            vint->common.liid_len, vint);

    /* Don't need to tell the seqtracker about this intercept because
     * hopefully the VOIP sync thread will handle that...
     */
    vint->awaitingconfirm = 0;

}

static int update_modified_sms_voip_intercept(openli_sms_worker_t *state,
        voipintercept_t *found, voipintercept_t *decode) {

    int r = 0, changed = 0;

    if (update_modified_intercept_common(&(found->common),
            &(decode->common), OPENLI_INTERCEPT_TYPE_VOIP, &changed) < 0) {
        r = -1;
    }

    free_single_voipintercept(decode);
    return r;

}

static void remove_sms_voip_intercept(openli_sms_worker_t *state,
        voipintercept_t *vint) {

    /* Really simple, because we don't maintain a map of
     * SIP identities to VoIP intercepts -- SIP identities
     * are complex (wildcards, realms being optional, etc) so
     * it's not something that we can optimise with a
     * lookup table, unlike RADIUS usernames or email addresses.
     */
    HASH_DELETE(hh_liid, state->voipintercepts, vint);
    free_single_voipintercept(vint);
}

static int halt_sms_voip_intercept(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *decode, *found;
    decode = calloc(1, sizeof(voipintercept_t));

    if (decode_voipintercept_halt(provmsg->msgbody, provmsg->msglen,
            decode) < 0) {
        logger(LOG_INFO,
                "OpenLI: SMS worker received invalid VoIP intercept withdrawal");
        return -1;
    }

    HASH_FIND(hh_liid, state->voipintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found && state->workerid == 0) {
        logger(LOG_INFO,
                "OpenLI: tried to halt VoIP intercept %s within SMS worker but it was not in the intercept map?",
                decode->common.liid);
        free_single_voipintercept(decode);
        return -1;
    }
    remove_sms_voip_intercept(state, found);
    free_single_voipintercept(decode);
    return 0;
}

static int modify_sms_voip_intercept(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *vint, *found;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_modify(provmsg->msgbody, provmsg->msglen,
            vint) < 0) {
        logger(LOG_INFO, "OpenLI: SMS worker failed to decode VoIP intercept modify message from provisioner");
        return -1;
    }
    HASH_FIND(hh_liid, state->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);
    if (!found) {
        init_sms_voip_intercept(state, vint);
    } else {
        update_modified_sms_voip_intercept(state, found, vint);
    }
    return 0;
}

static int add_new_sms_voip_intercept(openli_sms_worker_t *state,
        provisioner_msg_t *msg) {

    voipintercept_t *vint, *found;
    int ret = 0;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_start(msg->msgbody, msg->msglen, vint) < 0) {
        logger(LOG_INFO, "OpenLI: SMS worker failed to decode VoIP intercept start message from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);

    if (found) {
        openli_sip_identity_t *tgt;
        libtrace_list_node_t *n;

        /* We already know about this intercept, but don't overwrite
         * anything just yet because hopefully our (updated) targets
         * will be announced to us shortly.
         */
        n = found->targets->head;
        while (n) {
            tgt = *((openli_sip_identity_t **)(n->data));
            tgt->awaitingconfirm = 1;
            n = n->next;
        }
        update_modified_sms_voip_intercept(state, found, vint);
        found->awaitingconfirm = 0;
        ret = 0;
    } else {
        init_sms_voip_intercept(state, vint);
        ret = 1;
    }
    return ret;
}

static inline voipintercept_t *lookup_sip_target_intercept(
        openli_sms_worker_t *state, provisioner_msg_t *provmsg,
        openli_sip_identity_t *sipid) {

    voipintercept_t *found = NULL;
    char liidspace[1024];
    if (decode_sip_target_announcement(provmsg->msgbody,
            provmsg->msglen, sipid, liidspace, 1024) < 0) {
        logger(LOG_INFO,
                "OpenLI: SMS worker thread %d received invalid SIP target",
                state->workerid);
        return NULL;
    }

    HASH_FIND(hh_liid, state->voipintercepts, liidspace, strlen(liidspace),
            found);
    if (!found) {
        logger(LOG_INFO,
                "OpenLI: SMS worker thread %d received SIP target for unknown VoIP LIID %s.",
                liidspace);
    }
    return found;
}

static int add_sms_sip_target(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;

    found = lookup_sip_target_intercept(state, provmsg, &sipid);
    if (!found) {
        return -1;
    }
    add_new_sip_target_to_list(found, &sipid);
    return 0;
}

static int remove_sms_sip_target(openli_sms_worker_t *state,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;

    found = lookup_sip_target_intercept(state, provmsg, &sipid);
    if (found) {
        disable_sip_target_from_list(found, &sipid);
    }
    if (sipid.username) {
        free(sipid.username);
    }
    if (sipid.realm) {
        free(sipid.realm);
    }
    return 0;
}

static void generate_sms_ipmmiri(openli_sms_worker_t *state,
        intercept_common_t *common, int64_t cin, openli_export_recv_t *irimsg,
        openli_location_t *loc, int loc_count) {

    openli_export_recv_t *copy;

    if (common->tostart_time > irimsg->ts.tv_sec) {
        return;
    }
    if (common->toend_time > 0 && common->toend_time <= irimsg->ts.tv_sec) {
        return;
    }
    copy = calloc(1, sizeof(openli_export_recv_t));
    memcpy(copy, irimsg, sizeof(openli_export_recv_t));

    copy->data.ipmmiri.liid = strdup(common->liid);
    copy->destid = common->destid;
    copy->data.ipmmiri.cin = cin;

    copy->data.ipmmiri.content = malloc(copy->data.ipmmiri.contentlen);
    memcpy(copy->data.ipmmiri.content, irimsg->data.ipmmiri.content,
            irimsg->data.ipmmiri.contentlen);

    copy_location_into_ipmmiri_job(copy, loc, loc_count);

    pthread_mutex_lock(state->stats_mutex);
    state->stats->ipmmiri_created ++;
    pthread_mutex_unlock(state->stats_mutex);

    publish_openli_msg(state->zmq_pubsocks[common->seqtrackerid], copy);
}

static int mask_sms_submit_tpdu(uint8_t *ptr, uint8_t len) {

    uint8_t tp_vp_fmt = 0;
    uint8_t da_len = 0;
    uint8_t *start = ptr;
    uint8_t ud_len = 0;
    uint8_t vp_len = 0;
    int i, ind;

    if (len < 4) {
        return 0;
    }

    /* first byte are flags, but we need to check if TP-VPF is set
     * as that will indicate whether a TP-VP field is included and,
     * if so, what format it is using */
    tp_vp_fmt = (((*ptr) & 0x18) >> 3);

    ptr ++;

    /* next byte is the TP-MR -- can just skip */
    ptr ++;

    /* TP-Destination-Address */
    /* length is expressed as "usable" half-octets */
    da_len = *ptr;
    ptr ++;

    /* bits 4-6 of the Type-of-Address field may indicate that the
     * number is being encoded as alphanumeric, in which case da_len
     * should be treated as 7-bit characters instead.
     *
     * XXX get an example for testing!
     */
    if (((*ptr) & 0x70) == 0x50) {
        /* alphanumeric */
        ptr += (1 + (int)(ceil((7 * len) / 8)));
    } else {
        ptr += (1 + (int)(ceil(((double)da_len) / 2)));
    }

    if (ptr - start >= len) {
        return 0;
    }

    /* TP-PID, can just skip */
    ptr ++;

    /* TP-DCS, for now just pray we don't get anything other than the
     * default GSM 7 bit alphabet using class 0 */
    if (*ptr != 0) {
        logger(LOG_INFO, "OpenLI: unsupported TP-DCS when parsing SMS TPDU: %u",
                *ptr);
        return 0;
    }
    ptr ++;

    if (tp_vp_fmt != 0) {
        /* A TP-VP header is present... */
        if (tp_vp_fmt == 1) {
            /* TP-VP with enhanced format, always 7 bytes */
            ptr += 7;
        } else if (tp_vp_fmt == 2) {
            /* TP-VP with relative format, 1 byte length field */
            vp_len = *ptr;
            ptr += (1 + vp_len);
        } else if (tp_vp_fmt == 3) {
            /* TP-VP with absolute format, always 7 bytes */
            ptr += 7;
        }
    }

    if (ptr - start >= len) {
        return 0;
    }
    /* TP-User-Data-Length */
    ud_len = *ptr;
    ptr ++;
    if (ptr - start >= len) {
        return 0;
    }

    /* Finally reached the TP-User-Data */
    for (i = 0; i < ud_len; i++) {
        ind = i % 7;
        if (i == ud_len - 1 && ind >= 5) {
            /* this is the last byte, so we need to make sure that the
             * unused bits are set to zero.
             */
            *ptr = (sms_masking_bytes[ind] & 0x0f);
        } else {
            *ptr = sms_masking_bytes[ind];
        }
        ptr ++;
        if (ptr - start >= len) {
            break;
        }
    }

    return 1;
}

enum {
    RP_MESSAGE_TYPE_DATA_MS_TO_N = 0,
    RP_MESSAGE_TYPE_DATA_N_TO_MS = 1,
    RP_MESSAGE_TYPE_ACK_MS_TO_N = 2,
    RP_MESSAGE_TYPE_ACK_N_TO_MS = 3,
    RP_MESSAGE_TYPE_ERROR_MS_TO_N = 4,
    RP_MESSAGE_TYPE_ERROR_N_TO_MS = 5,
    RP_MESSAGE_TYPE_SMMA_MS_TO_N = 6,
};

static int mask_sms_message_content(openli_sms_worker_t *state,
        uint8_t *sipstart, uint16_t siplen) {

    uint8_t *bodystart;
    size_t bodylen = 0;
    uint8_t *ptr;
    uint8_t msgtype;
    uint8_t len;

    bodystart = (uint8_t *)(strstr((char *)sipstart, "\r\n\r\n"));
    if (bodystart == NULL) {
        return 0;
    }
    assert(bodystart > sipstart);

    bodylen = siplen - (bodystart - sipstart);
    if (bodylen <= 4 || bodylen > siplen) {
        return 0;
    }

    ptr = bodystart + 4;
    /* RP-Message Type */
    msgtype = *ptr;
    ptr ++;

    if (msgtype != RP_MESSAGE_TYPE_DATA_MS_TO_N &&
            msgtype != RP_MESSAGE_TYPE_DATA_N_TO_MS) {
        /* No content to mask */
        return 1;
    }

    /* Message reference */
    ptr ++;

    /* Originator Address -- should be a single byte 0x00 if MS-to-N,
     * otherwise 1 byte length field + contents.
     */
    if (msgtype == RP_MESSAGE_TYPE_DATA_MS_TO_N) {
        if (*ptr != 0x00) {
            /* log an error? */
            logger(LOG_INFO,
                "OpenLI: unexpected originator address when parsing SMS Data");
            return 0;
        }
        ptr ++;
    } else {
        len = *ptr;
        if (len >= bodylen - (ptr - bodystart)) {
            logger(LOG_INFO,
                "OpenLI: bogus length for originator address when parsing SMS Data: %u vs %u",
                len, bodylen - (ptr - bodystart));
            return 0;
        }
        ptr += (len + 1);
    }

    /* Destination Address -- should be a single byte 0x00 if N-to-MS (I think),
     * otherwise 1 byte length field + contents.
     */
    if (msgtype == RP_MESSAGE_TYPE_DATA_N_TO_MS) {
        if (*ptr != 0x00) {
            /* log an error? */
            logger(LOG_INFO,
                "OpenLI: unexpected destination address when parsing SMS Data");
            return 0;
        }
        ptr ++;
    } else {
        len = *ptr;
        if (len >= bodylen - (ptr - bodystart)) {
            logger(LOG_INFO,
                "OpenLI: bogus length for destination address when parsing SMS Data: %u vs %u",
                len, bodylen - (ptr - bodystart));
            return 0;
        }
        ptr += (len + 1);
    }

    /* RP-User Data */
    /* First byte is the length */
    len = *ptr;
    if (len > bodylen - (ptr - bodystart)) {
        logger(LOG_INFO,
                "OpenLI: bogus length for user data when parsing SMS Data: %u vs %u",
                len, bodylen - (ptr - bodystart));
        return 0;
    }
    ptr ++;

    /* TPDU Message Type Indicator is the bottom 2 bits */
    if (((*ptr) & 0x03) == 0x01) {
        /* SMS-SUBMIT */
        return mask_sms_submit_tpdu(ptr, len);
    }

    return 1;
}

static int process_sms_sip_packet(openli_sms_worker_t *state,
        openli_state_update_t *recvd) {

    char *callid;
    openli_sip_identity_set_t all_identities;
    openli_sip_identity_t *matched = NULL;
    voipintercept_t *vint, *tmp;
    voip_intercept_ref_t *vint_ref, *tmp2;
    callid_intercepts_t *cid_list;
    etsili_iri_type_t iritype = ETSILI_IRI_REPORT;
    struct timeval tv;
    openli_export_recv_t irimsg;
    uint8_t trust_sip_from;
    openli_location_t *locptr;
    int loc_cnt, r;

    locptr = NULL;
    loc_cnt = 0;

    if (state->sipparser == NULL) {
        state->sipparser = (openli_sip_parser_t *)calloc(1,
                sizeof(openli_sip_parser_t));
    }

    if (parse_sip_content(state->sipparser, recvd->data.sip.content,
                recvd->data.sip.contentlen) < 0) {
        return 0;
    }

    callid = get_sip_callid(state->sipparser);
    if (strncmp((const char *)recvd->data.sip.content, "MESSAGE ", 8) == 0) {
        HASH_FIND(hh, state->known_callids, callid, strlen(callid),
                cid_list);

        if (!cid_list) {
            /* first time we've seen this call ID? */
            cid_list = calloc(1, sizeof(callid_intercepts_t));
            cid_list->callid = strdup(callid);
            cid_list->cin = hashlittle(callid, strlen(callid),
                    0xceefface);

            HASH_ADD_KEYPTR(hh, state->known_callids, cid_list->callid,
                    strlen(cid_list->callid), cid_list);

            if (extract_sip_identities(state->sipparser, &all_identities,
                        0) < 0) {
                logger(LOG_INFO,
                        "OpenLI: SMS worker thread %d failed to extract identities from SIP packet", state->workerid);
                return 0;
            }

            pthread_rwlock_rdlock(state->shared_mutex);
            trust_sip_from = state->shared->trust_sip_from;
            pthread_rwlock_unlock(state->shared_mutex);

            HASH_ITER(hh_liid, state->voipintercepts, vint, tmp) {
                matched = match_sip_target_against_identities(vint->targets,
                        &all_identities, trust_sip_from);
                if (matched == NULL) {
                    continue;
                }
                vint_ref = calloc(1, sizeof(voip_intercept_ref_t));
                vint_ref->liid = strdup(vint->common.liid);
                vint_ref->vint = vint;
                HASH_ADD_KEYPTR(hh, cid_list->intlist, vint_ref->liid,
                        strlen(vint_ref->liid), vint_ref);
            }
            release_openli_sip_identity_set(&all_identities);
            iritype = ETSILI_IRI_BEGIN;
        }

    } else {
        HASH_FIND(hh, state->known_callids, callid, strlen(callid),
                cid_list);
    }

    if (cid_list == NULL) {
        return 0;
    }

    gettimeofday(&tv, NULL);
    cid_list->last_observed = tv.tv_sec;

    if ((r = get_sip_paccess_network_info(state->sipparser, &locptr,
                    &loc_cnt)) < 0) {
        logger(LOG_INFO,
                "OpenLI: P-Access-Network-Info is malformed?");
    }

    memset(&irimsg, 0, sizeof(openli_export_recv_t));
    irimsg.type = OPENLI_EXPORT_IPMMIRI;
    irimsg.data.ipmmiri.ipmmiri_style = OPENLI_IPMMIRI_SIP;
    irimsg.ts = recvd->data.sip.timestamp;
    irimsg.data.ipmmiri.contentlen = recvd->data.sip.contentlen;
    irimsg.data.ipmmiri.ipfamily = recvd->data.sip.ipfamily;
    irimsg.data.ipmmiri.iritype = iritype;
    memcpy(irimsg.data.ipmmiri.ipsrc, recvd->data.sip.ipsrc, 16);
    memcpy(irimsg.data.ipmmiri.ipdest, recvd->data.sip.ipdest, 16);

    HASH_ITER(hh, cid_list->intlist, vint_ref, tmp2) {
        /* Make sure the intercept hasn't been removed */
        HASH_FIND(hh_liid, state->voipintercepts, vint_ref->liid,
                strlen(vint_ref->liid), vint);
        if (vint == NULL) {
            HASH_DELETE(hh, cid_list->intlist, vint_ref);
            free(vint_ref->liid);
            free(vint);
            continue;
        }

        irimsg.data.ipmmiri.ipmmiri_style = OPENLI_IPMMIRI_SIP;
        irimsg.data.ipmmiri.content = recvd->data.sip.content;

        if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
            /* TODO rewrite message content with spaces and flag that
             * we need to use iRIOnlySIPMessage as our IPMMIRIContents
             */
            mask_sms_message_content(state, irimsg.data.ipmmiri.content,
                    irimsg.data.ipmmiri.contentlen);
        }
        /* build and send an IRI for this particular intercept */
        generate_sms_ipmmiri(state, &(vint->common), cid_list->cin, &irimsg,
                locptr, loc_cnt);
    }
    if (locptr) {
        free(locptr);
    }

    return 1;
}

static int sms_worker_process_packet(openli_sms_worker_t *state) {

    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving packet in SMS worker thread %d: %s",
                    state->workerid, strerror(errno));
            return -1;
        }

        if (recvd.type == OPENLI_UPDATE_SMS_SIP) {
            if (process_sms_sip_packet(state, &recvd) == 0) {
                goto donepkt;
            }
        } else {
            logger(LOG_INFO,
                    "OpenLI: SMS worker thread %d received unexpected update type %u",
                    state->workerid, recvd.type);
        }

donepkt:
        if (recvd.type == OPENLI_UPDATE_SMS_SIP && recvd.data.sip.content) {
            free(recvd.data.sip.content);
        }
    } while (rc > 0);
    return 0;
}

static int sms_worker_handle_provisioner_message(openli_sms_worker_t *state,
        openli_export_recv_t *msg) {

    int ret = 0;
    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_START_VOIPINTERCEPT:
            ret = add_new_sms_voip_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_VOIPINTERCEPT:
            ret = halt_sms_voip_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_VOIPINTERCEPT:
            ret = modify_sms_voip_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_ANNOUNCE_SIP_TARGET:
            ret = add_sms_sip_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_WITHDRAW_SIP_TARGET:
            ret = remove_sms_sip_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            /* No additional per-intercept or per-target behaviour is
             * required?
             */
            disable_unconfirmed_voip_intercepts(&(state->voipintercepts),
                    NULL, NULL, NULL, NULL);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_voip_intercepts_as_unconfirmed(&(state->voipintercepts));
            break;
        default:
            logger(LOG_INFO, "OpenLI: SMS worker thread %d received unexpected message type from provisioner: %u",
                    state->workerid, msg->data.provmsg.msgtype);
            ret = -1;
    }

    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }

    return ret;
}


static int sms_worker_process_sync_thread_message(openli_sms_worker_t *state) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(state->zmq_ii_sock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in SMS thread %d: %s",
                    state->workerid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_PROVISIONER_MESSAGE) {
            if (sms_worker_handle_provisioner_message(state, msg) < 0) {
                free(msg);
                return -1;
            }
        }

        free(msg);
    } while (x > 0);

    return 1;

}

static void sms_worker_main(openli_sms_worker_t *state) {
    zmq_pollitem_t *topoll;
    sync_epoll_t purgetimer;
    struct itimerspec its;
    int x;
    struct timeval tv;
    callid_intercepts_t *cid, *tmp;

    logger(LOG_INFO, "OpenLI: starting SMS worker thread %d", state->workerid);

    topoll = calloc(3, sizeof(zmq_pollitem_t));

    its.it_value.tv_sec = 60;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    while (1) {
        topoll[0].socket = state->zmq_ii_sock;
        topoll[0].events = ZMQ_POLLIN;

        topoll[1].socket = state->zmq_colthread_recvsock;
        topoll[1].events = ZMQ_POLLIN;

        topoll[2].socket = NULL;
        topoll[2].fd = purgetimer.fd;
        topoll[2].events = ZMQ_POLLIN;

        if ((x = zmq_poll(topoll, 3, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO,
                    "OpenLI: error while polling in SMS worker thread %d: %s",
                    state->workerid, strerror(errno));
            break;
        }

        if (x == 0) {
            continue;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            /* message from the sync thread */
            x = sms_worker_process_sync_thread_message(state);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            /* a packet passed on from a collector thread */
            x = sms_worker_process_packet(state);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }

        if (topoll[2].revents & ZMQ_POLLIN) {
            /* expiry check is due for all known call-ids */
            topoll[2].revents = 0;

            /* loop over all known_callids and remove any that
             * have been inactive for 3 minutes */
            /* NOTE: expiry here won't reset the sequence number in
             * the seqtracker thread so if somehow this call ID re-appears
             * later on, then the sequence numbers will continue
             * from where the previous "call" ended. Ideally, this should
             * never happen in practice but I'm making a note here
             * just in case...
             */
            gettimeofday(&tv, NULL);
            HASH_ITER(hh, state->known_callids, cid, tmp) {
                if (cid->last_observed == 0) {
                    continue;
                }
                if (cid->last_observed + 180 <= tv.tv_sec) {
                    HASH_DELETE(hh, state->known_callids, cid);
                    free_single_sip_callid(cid);
                }
            }

            purgetimer.fdtype = 0;
            purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(purgetimer.fd, 0, &its, NULL);

            topoll[2].fd = purgetimer.fd;
        }
    }

    free(topoll);
}

void *start_sms_worker_thread(void *arg) {
    openli_sms_worker_t *state = (openli_sms_worker_t *)arg;
    char sockname[256];
    int zero = 0, x;
    openli_state_update_t recvd;

    state->sipparser = NULL;
    state->known_callids = NULL;
    state->zmq_pubsocks = calloc(state->tracker_threads, sizeof(void *));

    init_zmq_socket_array(state->zmq_pubsocks, state->tracker_threads,
            "inproc://openlipub", state->zmq_ctxt);

    state->zmq_ii_sock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlismscontrol_sync-%d",
            state->workerid);
    if (zmq_bind(state->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to bind to II zmq: %s", state->workerid, strerror(errno));
        goto haltsmsworker;
    }

    if (zmq_setsockopt(state->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to configure II zmq: %s", state->workerid, strerror(errno));
        goto haltsmsworker;
    }

    state->zmq_colthread_recvsock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlismsworker-colrecv%d",
            state->workerid);

    if (zmq_bind(state->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to bind to colthread zmq: %s", state->workerid, strerror(errno));
        goto haltsmsworker;
    }

    if (zmq_setsockopt(state->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
         logger(LOG_INFO, "OpenLI: SMS processing thread %d failed to configure colthread zmq: %s", state->workerid, strerror(errno));
         goto haltsmsworker;
    }


    sms_worker_main(state);

    do {
        /* drain any remaining captured packets in the recv queue */
        x = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltsmsworker:
    logger(LOG_INFO, "OpenLI: halting SMS processing thread %d",
            state->workerid);

    if (state->sipparser) {
        release_sip_parser(state->sipparser);
    }

    zmq_close(state->zmq_ii_sock);
    zmq_close(state->zmq_colthread_recvsock);

    free_all_sip_callids(state);
    free_all_voipintercepts(&(state->voipintercepts));
    clear_zmq_socket_array(state->zmq_pubsocks, state->tracker_threads);

    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
