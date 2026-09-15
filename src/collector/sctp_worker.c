/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <libtrace.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <libwandder.h>

#include "collector.h"
#include "logger.h"
#include "util.h"
#include "intercept.h"
#include "netcomms.h"

struct m3ua_layer {
    uint8_t version;
    uint8_t reserved; 
    uint8_t class;
    uint8_t type;
    uint32_t length;
} PACKED;

struct m2pa_layer {
    uint8_t version;
    uint8_t spare;
    uint8_t class;
    uint8_t type;
    uint32_t length;
    uint8_t bsn_spare;
    uint8_t bsn[3];
    uint8_t fsn_spare; 
    uint8_t fsn[3];
    uint8_t priority;
} PACKED;

struct call_parties {
    uint8_t called[24];
    uint8_t called_len;
    uint8_t calling[24];
    uint8_t calling_len;
};

#define GSM_NEXT_DECODE(dec) \
    if (wandder_decode_next(dec) <= 0) return; \
    itemptr = wandder_get_itemptr(dec); \
    length = wandder_get_itemlen(dec); \
    ident = wandder_get_identifier(dec); \
    class = wandder_get_class(dec);

#define DUMP_IMSI(imsi, imsi_len) \
{ \
   size_t i = 0; \
   for (i = 0; i < imsi_len; i++) { \
       fprintf(stderr, "%02x ", imsi[i]); \
   } \
}


void *sctp_thread_begin(void *arg);

static inline gsm_invoke_saved_t *get_available_invoke_slot(
        gsm_transaction_t *tx, int32_t invokeid) {

    int i, freeidx = -1;

    if (invokeid >= 0xFF) {
        return NULL;
    }

    for (i = 0; i < 8; i++) {
        if (tx->active_invoke_slots & (1 << i)) {
            if (tx->inv_slots[i].id == invokeid) {
                return NULL;
            }
        } else if (freeidx == -1) {
            freeidx = i;
        }
    }

    // All slots are full!
    if (freeidx == -1) return NULL;

    tx->active_invoke_slots |= (1 << freeidx);
    tx->inv_slots[freeidx].id = invokeid;
    return &(tx->inv_slots[freeidx]);
}

static inline void free_gsm_transaction(gsm_transaction_t *tx) {
    size_t i;

    for (i = 0; i < 8; i++) {
        if (tx->inv_slots[i].content) {
            free(tx->inv_slots[i].content);
        }
    }
    free(tx);
}

static inline gsm_invoke_saved_t *find_existing_invoke_id(
        gsm_transaction_t *tx, int invokeid, uint8_t remove) {

    int i;
    if (tx == NULL) {
        return NULL;
    }

    if (tx->active_invoke_slots == 0) {
        return NULL;
    }

    if (invokeid >= 0xFF) {
        return NULL;
    }
    for (i = 0; i < 8; i++) {
        if (tx->active_invoke_slots & (1 << i)) {
            if (invokeid == tx->inv_slots[i].id) {
                if (remove) {
                    tx->active_invoke_slots &= (~(1 << i));
                }
                return &(tx->inv_slots[i]);
            }
        }
    }
    return NULL;
}

static inline void extract_global_title(uint8_t *ptr, size_t len,
        uint8_t *gtspace, uint8_t *gtlen) {

    if (len <= 2 || len > 26) {
        return;
    }

    ptr = ptr + 2;
    len = len - 2;

    memcpy(gtspace, ptr, len);
    *gtlen = len;

}

static gsm_transaction_t *lookup_gsm_transaction(openli_sctp_worker_t *sctp,
       uint32_t otid, uint8_t *gt, uint8_t gtlen, time_t ts, uint8_t create) {

    gsm_transaction_t *tx = NULL;
    gsm_tx_key_t key;

    if (gtlen == 0) {
        return NULL;
    }

    memset(&key, 0, sizeof(key));
    key.tid = otid;
    memcpy(key.global_title, gt, gtlen);
    key.gt_len = gtlen;

    HASH_FIND(hh, sctp->active_transactions, &key, sizeof(key), tx);
    if (tx == NULL && create) {
        tx = calloc(1, sizeof(gsm_transaction_t));
        memcpy(&(tx->tx_key), &key, sizeof(key));
        tx->timestamp = ts;
        tx->active_invoke_slots = 0;
        memset(tx->inv_slots, 0, sizeof(gsm_invoke_saved_t) * 8);

        HASH_ADD_KEYPTR(hh, sctp->active_transactions, &(tx->tx_key),
                sizeof(tx->tx_key), tx);
    }
    return tx;

}

static void convert_gsm_id_to_string(uint8_t *ptr, char *field, size_t maxlen,
        uint16_t ptrlen) {

    int i;
    uint8_t num, j;

    j = 0;
    for (i = 0; i < ptrlen; i++) {
        if (j >= maxlen - 1) {
            break;
        }

        num = *(ptr + i);
        field[j] = (char)('0' + (num & 0x0f));

        j++;
        if (j >= maxlen - 1) {
            break;
        }

        /* bits 8-5 are 1111, which is a filler when there is an odd number
         * of digits.
         */
        if ((num & 0xf0) == 0xf0) {
            break;
        }

        field[j] = (char)('0' + ((num & 0xf0) >> 4));
        j++;
    }

    field[j] = '\0';
}

static gsm_identity_record_t *update_gsm_identity_map(
        openli_sctp_worker_t *sctp,
        uint8_t *imsi, uint8_t imsi_len, uint8_t *msisdn, uint8_t msisdn_len) {

    uint16_t shid;
    gsm_identity_shard_t *shard;
    gsm_identity_record_t *rec;
    struct timeval tv;

    shid = hashlittle(imsi, imsi_len, 50331653) % \
            sctp->imsi_identities->shardcount;
    shard = &(sctp->imsi_identities->shards[shid]);

    gettimeofday(&tv, NULL);

    pthread_rwlock_wrlock(&shard->rwlock);
    HASH_FIND(hh, shard->rec, imsi, imsi_len, rec);
    if (!rec) {
        rec = calloc(1, sizeof(gsm_identity_record_t));
        if (imsi_len > sizeof(rec->imsi)) {
            imsi_len = sizeof(rec->imsi);
        }
        memcpy(rec->imsi, imsi, imsi_len);
        HASH_ADD_KEYPTR(hh, shard->rec, rec->imsi, imsi_len, rec);
    }
    memcpy(rec->msisdn, msisdn, msisdn_len);
    rec->msisdn_len = msisdn_len;
    rec->ts = tv.tv_sec;
    pthread_rwlock_unlock(&shard->rwlock);

    return rec;
}

static gsm_identity_record_t *lookup_gsm_identity_map(
        openli_sctp_worker_t *sctp, uint8_t *imsi, uint8_t imsi_len) {

    uint16_t shid;
    gsm_identity_shard_t *shard;
    gsm_identity_record_t *rec;

    shid = hashlittle(imsi, imsi_len, 50331653) % \
            sctp->imsi_identities->shardcount;
    shard = &(sctp->imsi_identities->shards[shid]);

    pthread_rwlock_rdlock(&shard->rwlock);
    HASH_FIND(hh, shard->rec, imsi, imsi_len, rec);
    if (!rec) {
        pthread_rwlock_unlock(&shard->rwlock);
        return NULL;
    }

    pthread_rwlock_unlock(&shard->rwlock);
    return rec;
}

static void expire_old_transactions(openli_sctp_worker_t *sctp) {
    struct timeval tv;
    gsm_transaction_t *tx, *tmp;

    gettimeofday(&tv, NULL);

    HASH_ITER(hh, sctp->active_transactions, tx, tmp) {
        if (tv.tv_sec - tx->timestamp < 10) {
            continue;
        }

        HASH_DELETE(hh, sctp->active_transactions, tx);
        free_gsm_transaction(tx);
    }
}

static void expire_gsm_identity_map(openli_sctp_worker_t *sctp) {
    struct timeval tv;
    gsm_identity_shard_t *shard;
    uint16_t i;
    gsm_identity_record_t *rec, *rectmp;

    if (sctp->workerid != 0) {
        return;
    }

    gettimeofday(&tv, NULL);
    for (i = 0; i < sctp->imsi_identities->shardcount; i++) {
        shard = &(sctp->imsi_identities->shards[i]);
        pthread_rwlock_wrlock(&shard->rwlock);

        HASH_ITER(hh, shard->rec, rec, rectmp) {
            if (rec->ts < tv.tv_sec - 360) {
                HASH_DELETE(hh, shard->rec, rec);
                free(rec);
            }
        }
        pthread_rwlock_unlock(&shard->rwlock);
    }
}


static uint8_t *parse_sccp_for_tcap_tids(uint8_t *sccp, uint16_t len,
        uint16_t *tcap_len, uint32_t *otid, uint32_t *dtid, uint8_t *tcaptype,
        struct call_parties *parties, wandder_decoder_t **dec) {
    size_t data_offset, i, called_offset, calling_offset;
    size_t calling_len, called_len;
    uint8_t *tcap, *itemptr;
    uint32_t ident, length, val;
    uint8_t is_gsm = 0;
    uint16_t level = 0xFFFF;

    *tcaptype = 0;
    if (sccp == NULL || len < 5) {
        return NULL;
    }

    if ((*sccp) == 0x09) {
        // UDT (unitdata)
        data_offset = 5 + sccp[4];
        called_offset = 3 + sccp[2];
        calling_offset = 4 + sccp[3];
    } else if ((*sccp) == 0x11) {
        data_offset = 6 + sccp[5];
        called_offset = 4 + sccp[3];
        calling_offset = 5 + sccp[4];
    } else {
        return NULL;
    }

    if (data_offset >= len) {
        return NULL;
    }

    called_len = sccp[called_offset - 1];
    calling_len = sccp[calling_offset - 1];

    /* the -1 is important here because the offsets are relative to the
     * position of the byte where the offset is stored -- so the difference
     * between two offset values also includes the distance between the
     * offsets themselves (i.e. 1 byte for consecutive offsets, 2 bytes
     * for the first and third offsets).
     */
    extract_global_title(sccp + called_offset, called_len,
            parties->called, &(parties->called_len));
    extract_global_title(sccp + calling_offset, calling_len,
            parties->calling, &(parties->calling_len));

    tcap = sccp + data_offset;
    len -= data_offset;
    *tcaptype = *tcap;
    *otid = 0;
    *dtid = 0;
    *tcap_len = len;

    *dec = init_wandder_decoder(NULL, tcap, len, true);
    if (!*dec) {
        return NULL;
    }
    if (wandder_decode_next(*dec) <= 0) {
        return NULL;
    }

    while (wandder_decode_next(*dec) > 0) {
        if (level == 0xFFFF) {
            level = wandder_get_level(*dec);
        }

        if (wandder_get_level(*dec) != level) {
            break;
        }
        ident = wandder_get_identifier(*dec);
        length = wandder_get_itemlen(*dec);
        itemptr = wandder_get_itemptr(*dec);

        if (ident == 8) {
            val = 0;
            for (i = 0; i < length && i < 4; i++) {
                val = (val << 8) | *(itemptr + i);
            }
            *otid = val;
        } else if (ident == 9) {
            val = 0;
            for (i = 0; i < length && i < 4; i++) {
                val = (val << 8) | *(itemptr + i);
            }
            *dtid = val;
        } else if (ident == 12) {
            is_gsm = 1;
        } else {
            wandder_decode_skip(*dec);
        }
    }

    if (is_gsm) {
        return tcap;
    }

    // not a packet that is relevant to SIGTRAN interception
    return NULL;
}

uint8_t *parse_m3ua_header_for_sccp(uint8_t *m3ua, uint16_t len,
        uint16_t *sccp_len, uint32_t *opc, uint32_t *dpc) {

    struct m3ua_layer *hdr = (struct m3ua_layer *)m3ua;
    uint32_t newlen;
    uint16_t offset = 0, *ptr;
    uint16_t tag, tvlen;
    uint8_t *si, *sccp;

    if (hdr == NULL || len < sizeof(struct m3ua_layer)) {
        return NULL;
    }

    if (hdr->version != 1 || hdr->class != 1 || hdr->type != 1) {
        return NULL;
    }

    newlen = ntohl(hdr->length);
    if (newlen < len) {
        len = newlen;
    }


    offset = sizeof(struct m3ua_layer);
    sccp = NULL;
    *sccp_len = 0;

    while (offset < len - 4) {
        ptr = (uint16_t *)(m3ua + offset);
        tag = ntohs(*ptr);
        ptr++;
        tvlen = ntohs(*ptr);
        ptr++;

        if (tag == 0x0210) {
            if (tvlen < 16) {
                break;
            }
            if (opc) *opc = ntohl(*((uint32_t *)ptr));
            // offset is 4 bytes
            if (dpc) *dpc = ntohl(*((uint32_t *)(ptr + 2)));
            // offset is 8 bytes
            si = (uint8_t *)(ptr + 4);
            if (*si == 3) {
                sccp = (uint8_t *)(ptr + 6);
                *sccp_len = tvlen - 16;
            }
            break;
        }
        // maintain 4 byte alignment
        offset += ((tvlen + 3) & ~3);
    }
    return sccp;
}

uint8_t *parse_m2pa_header_for_sccp(uint8_t *m2pa, uint16_t len,
        uint16_t *sccp_len, uint32_t *opc, uint32_t *dpc) {

    struct m2pa_layer *hdr = (struct m2pa_layer *)m2pa;
    uint32_t newlen;
    uint16_t offset;
    uint8_t si;
    uint8_t *sccp;
    uint32_t routelabel;

    if (hdr == NULL || len < sizeof(struct m2pa_layer)) {
        return NULL;
    }

    if (hdr->version != 1 || hdr->class != 0x0b || hdr->type != 1) {
        return NULL;
    }

    newlen = ntohl(hdr->length);
    if (newlen < len) {
        len = newlen;
    }

    offset = sizeof(struct m2pa_layer);
    if (len - offset < 5) {
        return NULL;
    }

    si = (*(m2pa + offset)) & 0x0F;
    routelabel = *((uint32_t *)(m2pa + offset + 1));

    if (opc) *opc = (routelabel & 0x0FFFC000) >> 14;
    if (dpc) *dpc = routelabel & 0x00003FFF;

    offset += 5;
    if (si == 3) {
        sccp = m2pa + offset;
        *sccp_len = len - offset;
    } else {
        *sccp_len = 0;
        sccp = NULL;
    }
    return sccp;
}

void start_sctp_worker_thread(openli_sctp_worker_t *sctp, int workerid,
        void *globalstate) {

    char name[1024];
    collector_global_t *glob = (collector_global_t *)globalstate;

    snprintf(name, 1024, "sctpworker-%d", workerid);

    sctp->zmq_ctxt = glob->zmq_ctxt;
    sctp->zmq_packet_return = NULL;
    sctp->workerid = workerid;
    sctp->zmq_ii_sock = NULL;
    sctp->zmq_pubsocks = NULL;
    sctp->zmq_colthread_recvsock = NULL;
    sctp->tracker_threads = glob->seqtracker_threads;
    sctp->sip_worker_threads = glob->sip_threads;
    sctp->voipintercepts = NULL;
    sctp->worker_threadname = strdup(name);
    sctp->haltinfo = NULL;
    sctp->active_transactions = NULL;
    sctp->imsi_identities = &(glob->gsm_identity_map);

    pthread_create(&(sctp->threadid), NULL, sctp_thread_begin, (void *)sctp);
    pthread_setname_np(sctp->threadid, sctp->worker_threadname);

}

static void generate_gsmsms_iri(openli_sctp_worker_t *sctp,
        voipintercept_t *vint, uint64_t cin, uint8_t status,
        uint8_t initiator, uint8_t sms_initiator, gsm_invoke_saved_t *invoke,
        struct timeval *tv, uint8_t *tgt_msisdn, uint8_t tgt_msisdn_len,
        uint8_t *tgt_imsi) {

    openli_export_recv_t *msg;

    msg = calloc(1, sizeof(openli_export_recv_t));
    msg->destid = vint->common.destid;
    msg->type = OPENLI_EXPORT_GSM_SMS_IRI;
    msg->ts.tv_sec = tv->tv_sec;
    msg->ts.tv_usec = tv->tv_usec;

    msg->data.gsmsms.liid = strdup(vint->common.liid);
    msg->data.gsmsms.authcc = strdup(vint->common.authcc);
    msg->data.gsmsms.delivcc = strdup(vint->common.delivcc);
    msg->data.gsmsms.cin = cin;
    if (tgt_imsi) {
        memcpy(msg->data.gsmsms.target_imsi, tgt_imsi, 8);
    } else {
        memset(msg->data.gsmsms.target_imsi, 0, 8);
    }

    if (tgt_msisdn && tgt_msisdn_len > 0) {
        memcpy(msg->data.gsmsms.target_msisdn, tgt_msisdn, tgt_msisdn_len);
        msg->data.gsmsms.target_msisdn_len = tgt_msisdn_len;
    } else {
        memset(msg->data.gsmsms.target_imsi, 0, 9);
        msg->data.gsmsms.target_msisdn_len = 0;
    }

    msg->data.gsmsms.initiator = initiator;
    msg->data.gsmsms.sms_initiator = sms_initiator;
    msg->data.gsmsms.transfer_status = status;
    if (invoke->content && invoke->content_len > 0) {
        msg->data.gsmsms.tpdu = malloc(invoke->content_len);
        memcpy(msg->data.gsmsms.tpdu, invoke->content, invoke->content_len);
        msg->data.gsmsms.tpdu_len = invoke->content_len;
    }

    /* TODO update statistics */

    publish_openli_msg(sctp->zmq_pubsocks[vint->common.seqtrackerid], msg);
}

static void sctp_intercept_sms_ifrequired(openli_sctp_worker_t *sctp,
        gsm_invoke_saved_t *invoke, uint8_t status,
        gsm_tx_key_t *sesskey, struct timeval *tv) {

    voipintercept_t *vint, *tmp;
    uint8_t matched = 0;
    uint64_t cin = 0;
    char msisdn_sender[16];
    char msisdn_recv[16];
    uint8_t *tgt_msisdn = NULL;
    uint8_t tgt_msisdn_len;
    uint8_t *tgt_imsi = NULL;

    /* TODO it would be better to store the target info in BCD format
     * instead so we don't have to do this conversion for every SMS
     * that we see, but that would require a fundamental change in how
     * we store targets for VOIP intercepts...
     */
    if (invoke->sender_msisdn_len > 1) {
        convert_gsm_id_to_string(invoke->sender_msisdn + 1, msisdn_sender,
                sizeof(msisdn_sender), invoke->sender_msisdn_len - 1);
    } else {
        msisdn_sender[0] = '\0';
    }

    if (invoke->receiving_msisdn_len > 1) {
        convert_gsm_id_to_string(invoke->receiving_msisdn + 1, msisdn_recv,
                sizeof(msisdn_recv), invoke->receiving_msisdn_len - 1);
    } else {
        msisdn_recv[0] = '\0';
    }

    HASH_ITER(hh_liid, sctp->voipintercepts, vint, tmp) {
        libtrace_list_node_t *n = vint->targets->head;
        matched = 0;

        if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
            continue;
        }

        if (vint->common.tostart_time > tv->tv_sec) {
            continue;
        }

        if (vint->common.toend_time > 0 &&
                vint->common.toend_time <= tv->tv_sec) {
            continue;
        }

        if (vint->common.targetagency == NULL ||
                strcmp(vint->common.targetagency, "pcapdisk") == 0) {
            // can't really do pcap output since we don't have the full
            // packet
            continue;
        }

        while (n) {
            openli_sip_identity_t *x = *((openli_sip_identity_t **) (n->data));
            n = n->next;

            if (x->active == 0) {
                continue;
            }
            if (x->username == NULL || strlen(x->username) == 0) {
                continue;
            }

            if (strcmp(x->username, msisdn_sender) == 0) {
                matched = 1;        // target is sender
                tgt_msisdn = invoke->sender_msisdn;
                tgt_msisdn_len = invoke->sender_msisdn_len;

                if (invoke->map_opcode == 44) {
                    tgt_imsi = NULL;
                } else if (invoke->map_opcode == 46) {
                    tgt_imsi = invoke->saved_imsi;
                }
                break;
            } else if (strcmp(x->username, msisdn_recv) == 0) {
                matched = 2;        // target is recipient
                tgt_msisdn = invoke->receiving_msisdn;
                tgt_msisdn_len = invoke->receiving_msisdn_len;
                if (invoke->map_opcode == 44) {
                    tgt_imsi = invoke->saved_imsi;
                } else if (invoke->map_opcode == 46) {
                    tgt_imsi = NULL;
                }
                break;
            }

            // ignore realm as that is a SIP construct
        }

        if (matched == 0) {
            continue;
        }

        cin = hashlittle(sesskey, sizeof(sesskey), 3933651277);
        cin ^= (tv->tv_sec << 32);

        if (invoke->map_opcode == 44) {
            generate_gsmsms_iri(sctp, vint, cin, status, matched,
                    OPENLI_GSMSMS_INITIATOR_SERVER, invoke, tv, tgt_msisdn,
                    tgt_msisdn_len, tgt_imsi);
        } else if (invoke->map_opcode == 46) {
            generate_gsmsms_iri(sctp, vint, cin, status, matched,
                    matched == 1 ? OPENLI_GSMSMS_INITIATOR_TARGET : OPENLI_GSMSMS_INITIATOR_UNDEFINED,
                    invoke, tv, tgt_msisdn, tgt_msisdn_len, tgt_imsi);
        }


    }

}

static void sctp_worker_init_voip_intercept(openli_sctp_worker_t *sctp,
        voipintercept_t *vint) {
    openli_export_recv_t *expmsg;

    if (sctp->tracker_threads <= 1) {
        vint->common.seqtrackerid = 0;
    } else {
        vint->common.seqtrackerid = hash_liid(vint->common.liid) %
                sctp->tracker_threads;
    }

    HASH_ADD_KEYPTR(hh_liid, sctp->voipintercepts, vint->common.liid,
            vint->common.liid_len, vint);
    vint->awaitingconfirm = 0;

    if (sctp->sip_worker_threads == 0 && sctp->workerid == 0) {
        // Normally a SIP worker would announce the intercept to the
        // seqtracker, but if there are none configured then we'll
        // need to do it ourselves
        expmsg = create_intercept_details_msg(&(vint->common),
                OPENLI_INTERCEPT_TYPE_VOIP);
        expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
        publish_openli_msg(sctp->zmq_pubsocks[vint->common.seqtrackerid],
                expmsg);
    }
}

static void sctp_worker_update_modified_voip_intercept(
        openli_sctp_worker_t *sctp, voipintercept_t *found,
        voipintercept_t *decoded) {

    int changed = 0, encodingchanged = 0;

    encodingchanged = update_modified_intercept_common(&(found->common),
            &(decoded->common), OPENLI_INTERCEPT_TYPE_VOIP, &changed);

    if (encodingchanged < 0) {
        goto endupdatevint;
    }

    if (found->options != decoded->options) {
        found->options = decoded->options;
        changed = 1;
    }

    if ((encodingchanged || changed) && sctp->sip_worker_threads == 0 &&
            sctp->workerid == 0) {
        openli_export_recv_t *expmsg;
        expmsg = create_intercept_details_msg(&(found->common),
                OPENLI_INTERCEPT_TYPE_VOIP);
        expmsg->type = OPENLI_EXPORT_INTERCEPT_CHANGED;
        publish_openli_msg(sctp->zmq_pubsocks[found->common.seqtrackerid],
                expmsg);
    }

endupdatevint:
    free_single_voipintercept(decoded);
}

static int add_new_sigtran_intercept(openli_sctp_worker_t *sctp,
        provisioner_msg_t *msg) {

    voipintercept_t *vint, *found;
    int ret = 0;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_start(msg->msgbody, msg->msglen, vint) < 0) {
        logger(LOG_INFO, "OpenLI: SCTP worker failed to decode VoIP intercept start message from provisioner");
        free(vint);
        return -1;
    }

    HASH_FIND(hh_liid, sctp->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);
    if (found) {
        openli_sip_identity_t *tgt;
        libtrace_list_node_t *n;

        n = found->targets->head;
        while (n) {
            tgt = *((openli_sip_identity_t **)(n->data));
            tgt->awaitingconfirm = 1;
            n = n->next;
        }
        sctp_worker_update_modified_voip_intercept(sctp, found, vint);
        found->awaitingconfirm = 0;
        found->active = 1;
        ret = 0;
    } else {
        sctp_worker_init_voip_intercept(sctp, vint);
        found = vint;
        ret = 1;
    }

    return ret;
}

static int modify_sigtran_intercept(openli_sctp_worker_t *sctp,
        provisioner_msg_t *provmsg) {

    voipintercept_t *vint, *found;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_modify(provmsg->msgbody, provmsg->msglen,
            vint) < 0) {
        logger(LOG_INFO, "OpenLI: SCTP worker failed to decode VOIP intercept modify message from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, sctp->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);
    if (!found) {
        sctp_worker_init_voip_intercept(sctp, vint);
    } else {
        sctp_worker_update_modified_voip_intercept(sctp, found, vint);
    }
    return 0;
}

static int halt_sigtran_intercept(openli_sctp_worker_t *sctp,
        provisioner_msg_t *provmsg) {
    voipintercept_t *decode, *found;
    decode = calloc(1, sizeof(voipintercept_t));

    if (decode_voipintercept_halt(provmsg->msgbody, provmsg->msglen,
            decode) < 0) {
        logger(LOG_INFO,
                "OpenLI: SCTP worker failed to decode VOIP intercept withdrawal");
        return -1;
    }

    HASH_FIND(hh_liid, sctp->voipintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found) {
        if (sctp->sip_worker_threads == 0 && sctp->workerid == 0) {
            logger(LOG_INFO,
                    "OpenLI: tried to halt VOIP intercept %s within SCTP worker but it was not present in the active intercept map?", decode->common.liid);
        }
        free_single_voipintercept(decode);
        return -1;
    }

    if (sctp->workerid == 0) {
        logger(LOG_INFO,
                "OpenLI: SCTP worker threads are withdrawing VOIP intercept: %s",
                found->common.liid);

        if (sctp->sip_worker_threads == 0) {
            openli_export_recv_t *expmsg;
            expmsg = create_intercept_details_msg(&(found->common),
                    OPENLI_INTERCEPT_TYPE_VOIP);
            expmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
            publish_openli_msg(sctp->zmq_pubsocks[found->common.seqtrackerid],
                    expmsg);
        }
    }

    HASH_DELETE(hh_liid, sctp->voipintercepts, found);
    free_single_voipintercept(found);
    free_single_voipintercept(decode);
    return 0;
}

static inline voipintercept_t *lookup_sigtran_target_intercept(
        openli_sctp_worker_t *sctp, provisioner_msg_t *provmsg,
        openli_sip_identity_t *sipid) {

    voipintercept_t *found = NULL;
    char liidspace[1024];

    sipid->username = NULL;
    sipid->realm = NULL;

    if (decode_sip_target_announcement(provmsg->msgbody,
            provmsg->msglen, sipid, liidspace, 1024) < 0) {
        logger(LOG_INFO,
                "OpenLI: SCTP worker thread %d received invalid target",
                sctp->workerid);
        return NULL;
    }

    HASH_FIND(hh_liid, sctp->voipintercepts, liidspace, strlen(liidspace),
            found);
    if (!found) {
        logger(LOG_INFO,
                "OpenLI: SCTP worker thread %d received a target for unknown VoIP LIID %s.",
                liidspace);
    }
    return found;
}

static int add_sigtran_target_identity(openli_sctp_worker_t *sctp,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;
    int r;

    found = lookup_sigtran_target_intercept(sctp, provmsg, &sipid);
    if (!found) {
        if (sipid.username) free(sipid.username);
        if (sipid.realm) free(sipid.realm);
        return -1;
    }
    // bit of a misnomer, but the end result is the same
    r = add_new_sip_target_to_list(found, &sipid);
    if (r == 1 && sctp->workerid == 0) {
        logger(LOG_INFO,
                "OpenLI: collector SCTP workers have received a new target identity for LIID %s.", found->common.liid);
    }
    return r;
}

static int remove_sigtran_target_identity(openli_sctp_worker_t *sctp,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;

    found = lookup_sigtran_target_intercept(sctp, provmsg, &sipid);
    if (!found) {
        if (sipid.username) free(sipid.username);
        if (sipid.realm) free(sipid.realm);
        return -1;
    }
    // bit of a misnomer, but the end result is the same
    disable_sip_target_from_list(found, &sipid);
    if (sctp->workerid == 0) {
        logger(LOG_INFO,
                "OpenLI: collector SCTP workers have disabled a target identity for LIID %s.", found->common.liid);
    }

    if (sipid.username) free(sipid.username);
    if (sipid.realm) free(sipid.realm);

    return 0;
}

static int sctp_worker_handle_provisioner_message(openli_sctp_worker_t *sctp,
        openli_export_recv_t *msg) {
    int ret = 0;

    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            disable_unconfirmed_voip_intercepts(&(sctp->voipintercepts),
                    NULL, NULL, NULL, NULL);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_voip_intercepts_as_unconfirmed(&(sctp->voipintercepts));
            break;
        case OPENLI_PROTO_START_VOIPINTERCEPT:
            ret = add_new_sigtran_intercept(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_VOIPINTERCEPT:
            ret = halt_sigtran_intercept(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_VOIPINTERCEPT:
            ret = modify_sigtran_intercept(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_ANNOUNCE_SIP_TARGET:
            ret = add_sigtran_target_identity(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_WITHDRAW_SIP_TARGET:
            ret = remove_sigtran_target_identity(sctp, &(msg->data.provmsg));
            break;
        default:
            logger(LOG_INFO,
                    "OpenLI: SCTP worker thread %d received unexpected message type from provisioner: %u",
                    sctp->workerid, msg->data.provmsg.msgtype);
            ret = -1;
    }

    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }

    return ret;
}

static int sctp_worker_process_sync_thread_message(openli_sctp_worker_t *sctp) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(sctp->zmq_ii_sock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in SCTP thread %d: %s",
                    sctp->workerid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            sctp->haltinfo = msg->data.haltinfo;
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_PROVISIONER_MESSAGE) {
            if (sctp_worker_handle_provisioner_message(sctp, msg) < 0) {
                free(msg);
                return -1;
            }
        }

        free(msg);
    } while (x > 0);

    return 1;

}

#define SAVE_INVOKE \
    tx = lookup_gsm_transaction(sctp, otid, globaltitle, gtlen, tv.tv_sec, 1); \
    invoke = get_available_invoke_slot(tx, invokeid); \
    if (!invoke && tx->active_invoke_slots == 0xFF) { \
        logger(LOG_INFO, "OpenLI: WARNING: Ran out of invoke open slots for transaction ID %u in SCTP worker %d. Transaction events may be missed.", \
                otid, sctp->workerid); \
    } else if (invoke) { \
        invoke->map_opcode = opcode; \
        invoke->content = NULL; \
        invoke->content_len = 0; \
        memset(invoke->saved_imsi, 0, sizeof(invoke->saved_imsi)); \
        memset(invoke->sender_msisdn, 0, sizeof(invoke->sender_msisdn)); \
        memset(invoke->receiving_msisdn, 0, sizeof(invoke->receiving_msisdn)); \
        invoke->sender_msisdn_len = 0; \
        invoke->receiving_msisdn_len = 0; \
    }

#define RECALL_INVOKE \
    tx = lookup_gsm_transaction(sctp, dtid, globaltitle, gtlen, 0, 0); \
    if (tx) { \
        invoke = find_existing_invoke_id(tx, invokeid, 1); \
    }

static gsm_invoke_saved_t *record_mo_sms_tpdu(openli_sctp_worker_t *sctp,
        uint8_t *tpdu, uint32_t tpdulen, uint32_t otid, uint8_t *globaltitle,
        uint8_t gtlen, struct timeval tv, uint8_t invokeid, uint8_t opcode,
        uint8_t *orig_msisdn, uint8_t orig_msisdn_len) {

    gsm_transaction_t *tx = NULL;
    gsm_invoke_saved_t *invoke = NULL;
    uint8_t *ptr = tpdu;
    uint8_t length;
    uint8_t saved_flags;

    saved_flags = (*ptr);

    // We need to do a little decoding to get the TP-DA (i.e. the SMS
    // recipient)
    ptr += 2;

    // the length field is given in BCD digits (i.e. 4 bits per digit), plus
    // we have to account for the numbering plan byte that precedes the
    // MSISDN digits themselves
    length = 1 + (*ptr / 2) + (((*ptr) % 2) ? 1 : 0);

    SAVE_INVOKE
    if (!invoke) return NULL;

    // now save the entire PDU as it is into a TX entry so that we can
    // emit it later on once we have the confirmation that it was forwarded
    // (or not)
    invoke->tpdu_flags = saved_flags;
    memcpy(invoke->receiving_msisdn, ptr + 1, length);
    invoke->receiving_msisdn_len = length;

    invoke->content = malloc(tpdulen);
    memcpy(invoke->content, tpdu, tpdulen);
    invoke->content_len = tpdulen;

    if (orig_msisdn_len > 0) {
        memcpy(invoke->sender_msisdn, orig_msisdn, orig_msisdn_len);
        invoke->sender_msisdn_len = orig_msisdn_len;
    }
    return invoke;
}

static void record_mt_sms_tpdu(openli_sctp_worker_t *sctp, uint8_t *tpdu,
        uint32_t tpdulen, uint32_t otid, uint8_t *globaltitle, uint8_t gtlen,
        struct timeval tv, uint8_t invokeid, uint8_t opcode,
        uint8_t *dest_msisdn, uint8_t dest_msisdn_len, uint8_t *imsi) {

    gsm_transaction_t *tx = NULL;
    gsm_invoke_saved_t *invoke = NULL;
    uint8_t *ptr = tpdu;
    uint8_t length;
    uint8_t saved_flags;

    saved_flags = (*ptr);

    // We need to do a little decoding to get the TP-OA (i.e. the SMS
    // sender)
    ptr++;

    // the length field is given in BCD digits (i.e. 4 bits per digit), plus
    // we have to account for the numbering plan byte that precedes the
    // MSISDN digits themselves
    length = 1 + (*ptr / 2) + (((*ptr) % 2) ? 1 : 0);

    SAVE_INVOKE
    if (!invoke) return;

    // now save the entire PDU as it is into a TX entry so that we can
    // emit it later on once we have the confirmation that it was forwarded
    // (or not)
    invoke->tpdu_flags = saved_flags;
    memcpy(invoke->sender_msisdn, ptr + 1, length);
    invoke->sender_msisdn_len = length;

    invoke->content = malloc(tpdulen);
    memcpy(invoke->content, tpdu, tpdulen);
    invoke->content_len = tpdulen;

    if (dest_msisdn_len > 0) {
        memcpy(invoke->receiving_msisdn, dest_msisdn, dest_msisdn_len);
        invoke->receiving_msisdn_len = dest_msisdn_len;
    } else {
        invoke->receiving_msisdn_len = 0;
    }

    memcpy(invoke->saved_imsi, imsi, 8);
}

static void parse_gsm_mobile_application(openli_sctp_worker_t *sctp,
        wandder_decoder_t *dec, uint32_t otid, uint32_t dtid, uint8_t tcaptype,
        struct call_parties *parties, struct timeval tv) {

    uint8_t invokeid, opcode, class;
    uint32_t length, ident, component_type;
    uint8_t *itemptr;
    gsm_transaction_t *tx = NULL;
    gsm_invoke_saved_t *invoke = NULL;
    uint8_t *globaltitle = NULL;
    uint8_t gtlen = 0;

    component_type = wandder_get_identifier(dec);
    if (component_type == 0xFFFFFFFF) {
        goto endgsm;
    }

    GSM_NEXT_DECODE(dec);
    if (length == 1 && class == WANDDER_CLASS_UNIVERSAL_PRIMITIVE &&
            ident == WANDDER_TAG_INTEGER) {
        invokeid = *itemptr;
    } else {
        invokeid = 0xFF;
    }

    if (component_type == 1) {
        // INVOKE
        // We need to use the caller for GT, not the callee
        globaltitle = parties->calling;
        gtlen = parties->calling_len;

        // opcode
        GSM_NEXT_DECODE(dec);
        if (class == WANDDER_CLASS_CONTEXT_PRIMITIVE && ident == 0) {
            // this is the optional linkedID field, skip it
            GSM_NEXT_DECODE(dec);
        }

        if (length != 1 || ident != WANDDER_TAG_INTEGER ||
                class != WANDDER_CLASS_UNIVERSAL_PRIMITIVE) {
            return;
        }
        opcode = *itemptr;
        if (opcode == 45) {
            // sendRoutingInfoForSM

            // sequence
            if (wandder_decode_next(dec) <= 0) return;

            GSM_NEXT_DECODE(dec);
            if (ident == 0) {
                // MSISDN
                SAVE_INVOKE
                if (!invoke) return;

                if (length > sizeof(invoke->receiving_msisdn)) {
                    length = sizeof(invoke->receiving_msisdn);
                }
                if (invoke) {
                    memcpy(invoke->receiving_msisdn, itemptr, length);
                    invoke->receiving_msisdn_len = length;
                }
            }
        } else if (opcode == 44) {
            // forwardSM
            uint8_t imsi[8];
            uint8_t *rec_msisdn = NULL;
            uint8_t rec_msisdn_len = 0;
            gsm_identity_record_t *rec = NULL;

            // sequence
            if (wandder_decode_next(dec) <= 0) return;

            GSM_NEXT_DECODE(dec);
            if (ident == 0) {
                // sm-RP-DA
                memset(imsi, 0, 8);
                if (length > 8) {
                    length = 8;
                }
                memcpy(imsi, itemptr, length);
                rec = lookup_gsm_identity_map(sctp, imsi, length);
                if (rec != NULL) {
                    rec_msisdn = rec->msisdn;
                    rec_msisdn_len = rec->msisdn_len;
                }
            } else {
                return;
            }

            GSM_NEXT_DECODE(dec);
            while (ident != WANDDER_TAG_OCTETSTRING ||
                    class != WANDDER_CLASS_UNIVERSAL_PRIMITIVE) {
                GSM_NEXT_DECODE(dec);
            }
            record_mt_sms_tpdu(sctp, itemptr, length, otid, globaltitle,
                    gtlen, tv, invokeid, opcode, rec_msisdn, rec_msisdn_len,
                    imsi);

        } else if (opcode == 46) {
            uint8_t orig_msisdn[16];
            uint8_t orig_msisdn_len = 0;

            // mo-forwardSM

            // sequence
            if (wandder_decode_next(dec) <= 0) return;

            // sm-RP-DA
            GSM_NEXT_DECODE(dec);

            // sm-RP-OA
            GSM_NEXT_DECODE(dec);
            if (ident == 2) {
                orig_msisdn_len = length;
                memcpy(orig_msisdn, itemptr, orig_msisdn_len);
            }

            GSM_NEXT_DECODE(dec);
            while (ident != WANDDER_TAG_OCTETSTRING ||
                    class != WANDDER_CLASS_UNIVERSAL_PRIMITIVE) {
                GSM_NEXT_DECODE(dec);
            }

            invoke = record_mo_sms_tpdu(sctp, itemptr, length, otid,
                    globaltitle, gtlen, tv, invokeid, opcode, orig_msisdn,
                    orig_msisdn_len);
            if (!invoke) {
                return;
            }

            GSM_NEXT_DECODE(dec);
            if (ident == WANDDER_TAG_OCTETSTRING) {
                // IMSI of the sender
                if (length > sizeof(invoke->saved_imsi)) {
                    length = sizeof(invoke->saved_imsi);
                }
                memcpy(invoke->saved_imsi, itemptr, length);
            }
        }

    } else if (component_type == 2) {
        // returnResultLast
        globaltitle = parties->called;
        gtlen = parties->called_len;
        RECALL_INVOKE
        if (!invoke) goto endgsm;
        opcode = invoke->map_opcode;

        if (wandder_decode_next(dec) > 0) {
            // result sequence is present
            // skip past opcode
            GSM_NEXT_DECODE(dec);

            if (length != 1 || ident != WANDDER_TAG_INTEGER ||
                    class != WANDDER_CLASS_UNIVERSAL_PRIMITIVE) {
                return;
            }
        }

        if (opcode == 45) {
            // sendRoutingInfoForSM

            // parameter sequence
            if (wandder_decode_next(dec) <= 0) return;
            GSM_NEXT_DECODE(dec);
            if (ident == 4) {
                uint8_t imsi[12];
                // IMSI
                if (invoke) {
                    memset(imsi, 0, 12);
                    if (length > 12) {
                        length = 12;
                    }
                    memcpy(imsi, itemptr, length);

                    // add to identity cache
                    update_gsm_identity_map(sctp, imsi, length,
                            invoke->receiving_msisdn,
                            invoke->receiving_msisdn_len);

                }
            }
        } else if (opcode == 44 || opcode == 46) {
            // forwardSM or mo-forwardSM
            // message was sent successfully, so generate the IRI if either
            // party matches an intercept target
            sctp_intercept_sms_ifrequired(sctp, invoke,
                    OPENLI_GSMSMS_TRANSFER_SUCCESS, &(tx->tx_key),
                    &tv);
        }

    } else if (component_type == 3 || component_type == 4) {
        /* returnError, or reject -- both are functionally the same from
         * our perspective. A reject may not have a usable invoke ID to
         * match against the original request, but we can hopefully find the
         * transaction */
        globaltitle = parties->called;
        gtlen = parties->called_len;
        RECALL_INVOKE
        if (!invoke) goto endgsm;
        opcode = invoke->map_opcode;

        if (opcode == 44 || opcode == 46) {
            // forwardSM or mo-forwardSM
            // message failed to send, but we still can generate an IRI if
            // either party matches an intercept target
            sctp_intercept_sms_ifrequired(sctp, invoke,
                    OPENLI_GSMSMS_TRANSFER_FAIL, &(tx->tx_key), &tv);
        }

    }

endgsm:
    if (tx && (tcaptype == 0x64 || component_type == 2 || component_type == 3 ||
            component_type == 4)) {
        // transaction is (effectively) over, we can free the transaction state
        HASH_DELETE(hh, sctp->active_transactions, tx);
        free_gsm_transaction(tx);
    }

}

static void process_sccp_content(openli_sctp_worker_t *sctp,
        openli_sccp_content_t *sccp) {

    uint8_t *tcap, tcaptype;
    uint16_t tcap_len;
    uint32_t otid, dtid;
    wandder_decoder_t *dec = NULL;
    struct call_parties parties;

    memset(&parties, 0, sizeof(parties));
    tcap = parse_sccp_for_tcap_tids(sccp->content, sccp->contentlen,
            &tcap_len, &otid, &dtid, &tcaptype, &parties, &dec);
    if (tcaptype == 0x67) {
        // Abort
        gsm_transaction_t *tx = lookup_gsm_transaction(sctp, dtid,
                parties.called, parties.called_len, 0, 0);
        if (tx) {
            HASH_DELETE(hh, sctp->active_transactions, tx);
            free_gsm_transaction(tx);
        }
    } else if (tcap != NULL) {
        parse_gsm_mobile_application(sctp, dec, otid, dtid, tcaptype, &parties,
                sccp->timestamp);
    }

    if (dec) free_wandder_decoder(dec);
}

static int sctp_worker_process_packet(openli_sctp_worker_t *sctp) {
    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(sctp->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving packet in SCTP worker thread %d: %s",
                    sctp->workerid, strerror(errno));
            return -1;
        }

        if (recvd.type != OPENLI_UPDATE_SCCP) {
            logger(LOG_INFO,
                    "OpenLI: SCTP worker thread %d received unexpected update type %u",
                    sctp->workerid, recvd.type);
            break;
        }

        process_sccp_content(sctp, &(recvd.data.sccp));
        if (recvd.data.sccp.content) {
            free(recvd.data.sccp.content);
        }

    } while (rc > 0);

    return 0;
}

void sctp_worker_main(openli_sctp_worker_t *sctp) {

    zmq_pollitem_t *topoll;
    sync_epoll_t purgetimer;
    struct itimerspec its;
    int x;
    uint32_t purgetriggers = 0;

    logger(LOG_INFO, "OpenLI: starting SCTP worker thread %d", sctp->workerid);
    topoll = calloc(3, sizeof(zmq_pollitem_t));

    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    topoll[0].socket = sctp->zmq_ii_sock;
    topoll[0].events = ZMQ_POLLIN;
    topoll[0].revents = 0;

    topoll[1].socket = sctp->zmq_colthread_recvsock;
    topoll[1].events = ZMQ_POLLIN;
    topoll[1].revents = 0;

    topoll[2].socket = NULL;
    topoll[2].fd = purgetimer.fd;
    topoll[2].events = ZMQ_POLLIN;
    topoll[2].revents = 0;

    while (1) {
        if ((x = zmq_poll(topoll, 3, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO,
                    "OpenLI: error while polling in SCTP worker thread %d: %s",
                    sctp->workerid, strerror(errno));
            break;
        }

        if (x == 0) {
            continue;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            x = sctp_worker_process_sync_thread_message(sctp);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            x = sctp_worker_process_packet(sctp);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }

        if (topoll[2].revents & ZMQ_POLLIN) {
            topoll[2].revents = 0;
            close(topoll[2].fd);

            // clear transactions that have not been active for 10 seconds
            expire_old_transactions(sctp);

            // once per hour, clear IMSI mappings that have not been seen
            // for a day
            if (purgetriggers > 360) {
                if (sctp->workerid == 0) {
                    expire_gsm_identity_map(sctp);
                }
                purgetriggers = 0;
            }

            purgetriggers ++;
            purgetimer.fdtype = 0;
            purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(purgetimer.fd, 0, &its, NULL);
            topoll[2].fd = purgetimer.fd;
        }
    }
    free(topoll);

}


static void clear_transaction_map(openli_sctp_worker_t *sctp) {

    gsm_transaction_t *tx, *tmp;

    HASH_ITER(hh, sctp->active_transactions, tx, tmp) {
        HASH_DELETE(hh, sctp->active_transactions, tx);
        free_gsm_transaction(tx);
    }
}

void *sctp_thread_begin(void *arg) {
    openli_sctp_worker_t *sctp = (openli_sctp_worker_t *)arg;
    int x;
    openli_state_update_t recvd;

    sctp->zmq_pubsocks = calloc(sctp->tracker_threads, sizeof(void *));
    init_zmq_socket_array(sctp->zmq_pubsocks, sctp->tracker_threads,
            "inproc://openlipub", sctp->zmq_ctxt, -1);

    sctp->zmq_packet_return =
            init_zmq_packet_return_publish(sctp->zmq_ctxt, "SCTP",
                    sctp->workerid);

    sctp->zmq_ii_sock = init_zmq_ii_consumer(sctp->zmq_ctxt, "SCTP",
            sctp->workerid);
    if (sctp->zmq_ii_sock == NULL) {
        goto haltsctpworker;
    }

    sctp->zmq_colthread_recvsock =
            init_zmq_colthread_recv_consumer(sctp->zmq_ctxt, "SCTP",
                    sctp->workerid);
    if (sctp->zmq_colthread_recvsock == NULL) {
        goto haltsctpworker;
    }

    sctp_worker_main(sctp);

    do {
        x = zmq_recv(sctp->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(RECVD_PKT);
        }
    } while (x > 0);

haltsctpworker:
    logger(LOG_INFO, "OpenLI: halting SCTP processing thread %d",
            sctp->workerid);

    if (sctp->zmq_packet_return) {
        zmq_close(sctp->zmq_packet_return);
    }
    if (sctp->zmq_ii_sock) {
        zmq_close(sctp->zmq_ii_sock);
    }
    if (sctp->zmq_colthread_recvsock) {
        zmq_close(sctp->zmq_colthread_recvsock);
    }
    free_all_voipintercepts(&(sctp->voipintercepts));
    clear_zmq_socket_array(sctp->zmq_pubsocks, sctp->tracker_threads);
    free((char *)sctp->worker_threadname);
    clear_transaction_map(sctp);

    if (sctp->haltinfo) {
        pthread_mutex_lock(&(sctp->haltinfo->mutex));
        sctp->haltinfo->halted ++;
        pthread_cond_signal(&(sctp->haltinfo->cond));
        pthread_mutex_unlock(&(sctp->haltinfo->mutex));
    }


    pthread_exit(NULL);
}
