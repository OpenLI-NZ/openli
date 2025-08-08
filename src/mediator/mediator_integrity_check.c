/*
 *
 * Copyright (c) 2025 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by Searchlight Ltd.
 * For further information please see https://searchlight.nz/
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

#include <uthash.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "agency.h"
#include "coll_recv_thread.h"
#include "liidmapping.h"
#include "mediator_rmq.h"
#include "etsiencoding.h"

int update_agency_digest_config_map(agency_digest_config_t **map,
        liagency_t *lea) {

    agency_digest_config_t *found = NULL;

    HASH_FIND(hh, *map, lea->agencyid, strlen(lea->agencyid), found);

    if (found) {
        free_liagency(found->config);
        found->config = lea;
        found->disabled = 0;

        /* For now, I'll just let any current timers expire rather
         * than trying to adjust them to suit the new config. After that,
         * any future timers will be based off the new options (although
         * realistically, the likelihood of having to modify an existing
         * agencies integrity check config is very very small).
         */
         return 0;
    }

    found = calloc(1, sizeof(agency_digest_config_t));
    found->agencyid = strdup(lea->agencyid);
    found->config = lea;
    found->disabled = 0;

    HASH_ADD_KEYPTR(hh, *map, found->agencyid, strlen(found->agencyid),
            found);

    return 1;
}

void free_agency_digest_config(agency_digest_config_t *dig) {

    if (dig->agencyid) {
        free(dig->agencyid);
    }
    if (dig->config) {
        free_liagency(dig->config);
    }

    free(dig);
}

void remove_agency_digest_config(agency_digest_config_t **map,
        char *agencyid) {

    agency_digest_config_t *found;

    HASH_FIND(hh, *map, agencyid, strlen(agencyid), found);
    if (!found) {
        return;
    }

    /* Just disable it because there may be references to 'found' stored
     * in other objects and we don't want to break those
     */
    found->disabled = 1;

}

static integrity_check_state_t *lookup_integrity_check_state(
        integrity_check_state_t **map, char *liid,
        openli_proto_msgtype_t msgtype, wandder_etsispec_t *decoder) {

    /** map key is LIID, CIN and msgtype, separated by space characeters.
     *  For performance reasons, CIN and msgtype are encoded in binary format
     *  so we don't have to call snprintf on every intercept record.
     */
    uint32_t cin;
    integrity_check_state_t *found = NULL;
    char key[64];
    char *ptr = key;

    memset(ptr, 0, 64);

    memcpy(key, liid, strlen(liid));
    ptr += strlen(liid);
    *ptr = ' ';
    ptr ++;
    *ptr = (uint8_t)msgtype;
    ptr ++;
    *ptr = ' ';
    ptr ++;

    cin = wandder_etsili_get_cin(decoder);
    if (cin == 0) {
        return NULL;
    }

    memcpy(ptr, &cin, sizeof(uint32_t));

    HASH_FIND(hh, *map, key, strlen(key), found);
    if (!found) {
        found = calloc(1, sizeof(integrity_check_state_t));
        found->key = strdup(key);
        found->agency = NULL;
        found->cin = cin;
        found->msgtype = msgtype;
        found->liid = strdup(liid);
        found->hashed_seqnos = calloc(32, sizeof(int64_t));
        found->signing_seqnos = calloc(16, sizeof(int64_t));
        found->seqno_array_size = 32;
        found->seqno_next_index = 0;
        found->signing_seqno_array_size = 16;
        found->signing_seqno_next_index = 0;
        found->self_seqno_hash = 1;
        found->self_seqno_sign = 1;
        found->awaiting_final_signature = 0;
        found->sign_jobs = NULL;
        HASH_ADD_KEYPTR(hh, *map, found->key, strlen(found->key), found);
    }

    return found;
}

static inline void reset_hash_context(integrity_check_state_t *found) {

    if (found->hash_ctx == NULL) {
        found->hash_ctx = EVP_MD_CTX_new();
    }

    switch(found->agency->config->digest_hash_method) {
        case OPENLI_DIGEST_HASH_ALGO_SHA256:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha256(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA512:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha512(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA1:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha1(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA384:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha384(), NULL);
            break;
    }
}

static inline void reset_sign_hash_context(integrity_check_state_t *found) {
    if (found->signature_ctx == NULL) {
        found->signature_ctx = EVP_MD_CTX_new();
    }

    switch(found->agency->config->digest_sign_method) {
        case OPENLI_DIGEST_HASH_ALGO_SHA256:
            EVP_DigestInit_ex(found->signature_ctx, EVP_sha256(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA512:
            EVP_DigestInit_ex(found->signature_ctx, EVP_sha512(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA1:
            EVP_DigestInit_ex(found->signature_ctx, EVP_sha1(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA384:
            EVP_DigestInit_ex(found->signature_ctx, EVP_sha384(), NULL);
            break;
    }
}


static inline void printable_integrity_key(integrity_check_state_t *ics,
        char *buf, size_t buflen) {

    snprintf(buf, buflen, "%s-%s-%u", ics->liid,
            ics->msgtype == OPENLI_PROTO_ETSI_IRI ? "IRI" : "CC",
            ics->cin);

}

static inline void populate_integrity_check_pshdr_data(
        wandder_etsipshdr_data_t *hdrdata, integrity_check_state_t *ics,
        uint32_t mediatorid, char *operatorid, char *netelemid) {

    hdrdata->liid = ics->liid;
    hdrdata->liid_len = strlen(ics->liid);
    if (ics->agency->config->agencycc &&
            strlen(ics->agency->config->agencycc) == 2) {
        hdrdata->authcc = ics->agency->config->agencycc;
        hdrdata->delivcc = ics->agency->config->agencycc;
    } else {
        hdrdata->authcc = "--";
        hdrdata->delivcc = "--";
    }

    hdrdata->authcc_len = strlen(hdrdata->authcc);
    hdrdata->delivcc_len = strlen(hdrdata->delivcc);

    if (operatorid) {
        hdrdata->operatorid = operatorid;
    } else {
        hdrdata->operatorid = "unspecified";
    }
    hdrdata->operatorid_len = strlen(hdrdata->operatorid);

    if (strcmp(hdrdata->authcc, "NL") == 0) {
        snprintf(netelemid, 16, "%u", mediatorid);
    } else {
        snprintf(netelemid, 16, "med-%u", mediatorid);
    }
    hdrdata->networkelemid = netelemid;
    hdrdata->networkelemid_len = strlen(netelemid);

    hdrdata->intpointid = NULL;
    hdrdata->intpointid_len = 0;
}

static inline void update_signature_hash(integrity_check_state_t *found,
        wandder_etsispec_t *etsidecoder, wandder_encoded_result_t *ic_pdu) {

    uint8_t *icbody = NULL;
    uint32_t icbodylen = 0;

    wandder_attach_etsili_buffer(etsidecoder, ic_pdu->encoded, ic_pdu->len, 0);

    icbody = wandder_etsili_get_integrity_check_contents(etsidecoder,
            etsidecoder->dec, &icbodylen);

    if (icbody && icbodylen > 0) {
        EVP_DigestUpdate(found->signature_ctx, icbody, icbodylen);
        if (found->hashes_since_last_signrec == 0 &&
                found->agency->config->digest_sign_hashlimit > 1 &&
                found->agency->config->digest_sign_timeout > 0) {

            if (start_mediator_timer(found->sign_timer,
                        found->agency->config->digest_sign_timeout) < 0) {
                /* what can we do here? */
            }
        }
        if (found->signing_seqno_next_index ==
                found->signing_seqno_array_size) {
            found->signing_seqnos = realloc(found->signing_seqnos,
                    (found->signing_seqno_array_size + 16) * sizeof(int64_t));
            found->signing_seqno_array_size += 16;
        }
        found->signing_seqnos[found->signing_seqno_next_index] =
                found->self_seqno_hash;
        found->signing_seqno_next_index ++;
        found->hashes_since_last_signrec += 1;
    }
}


static wandder_encoded_result_t *generate_integrity_check_hash_pdu(
        integrity_check_state_t *ics, uint32_t mediatorid, char *operatorid,
        wandder_encoder_t *encoder, wandder_etsispec_t *etsidecoder) {

    wandder_encoded_result_t *ic_pdu = NULL;
    uint8_t hashresult[EVP_MAX_MD_SIZE];
    unsigned int hashlen;
    wandder_etsipshdr_data_t hdrdata;
    char netelemid[128];

    EVP_DigestFinal_ex(ics->hash_ctx, hashresult, &hashlen);
    populate_integrity_check_pshdr_data(&hdrdata, ics, mediatorid,
            operatorid, netelemid);

    reset_wandder_encoder(encoder);

    ic_pdu = encode_etsi_integrity_check(encoder, &hdrdata,
            ics->self_seqno_hash,
            ics->agency->config->digest_hash_method, INTEGRITY_CHECK_SEND_HASH,
            ics->msgtype, hashresult, hashlen, ics->hashed_seqnos,
            ics->seqno_next_index);

    if (ic_pdu != NULL) {
        /* update the signed hash using the contents of the IntegrityCheck
         * PDU
         */
        update_signature_hash(ics, etsidecoder, ic_pdu);

        // don't increment until AFTER update_signature_hash()
        ics->self_seqno_hash ++;
    }

    ics->seqno_next_index = 0;
    reset_hash_context(ics);
    return ic_pdu;
}

uint8_t update_integrity_check_state(integrity_check_state_t **map,
        col_known_liid_t *known, uint8_t *msgbody, uint16_t msglen,
        openli_proto_msgtype_t msgtype, int epoll_fd,
        wandder_etsispec_t *decoder, integrity_check_state_t **chain) {

    //char keydump[128];
    integrity_check_state_t *found;
    int64_t seqno;
    uint8_t action = INTEGRITY_CHECK_NO_ACTION;

    if (msgtype != OPENLI_PROTO_ETSI_IRI && msgtype != OPENLI_PROTO_ETSI_CC) {
        *chain = NULL;
        return action;
    }

    wandder_attach_etsili_buffer(decoder, msgbody, msglen, false);

    found = lookup_integrity_check_state(map, known->liid, msgtype, decoder);
    seqno = wandder_etsili_get_sequence_number(decoder);

    //printable_integrity_key(found, keydump, 128);  // TODO remove
    if (found->agency == NULL) {
        /* this is a new stream */
        found->agency = known->digest_config;
        found->hash_ctx = NULL;
        found->signature_ctx = NULL;

        reset_hash_context(found);
        reset_sign_hash_context(found);

        /* do not start the timers until we've seen at least one PDU */
        found->hash_timer = create_mediator_timer(epoll_fd, found,
                MED_EPOLL_INTEGRITY_HASH_TIMER, 0);
        found->sign_timer = create_mediator_timer(epoll_fd, found,
                MED_EPOLL_INTEGRITY_SIGN_TIMER, 0);

        found->pdus_since_last_hashrec = 0;
        found->hashes_since_last_signrec = 0;
    } else {
        found->agency = known->digest_config;
    }

    EVP_DigestUpdate(found->hash_ctx, msgbody, msglen);

    if (found->seqno_next_index == found->seqno_array_size) {
        found->hashed_seqnos = realloc(found->hashed_seqnos,
                (found->seqno_array_size + 32) * sizeof(int64_t));
        found->seqno_array_size += 32;
    }
    found->hashed_seqnos[found->seqno_next_index] = seqno;
    found->seqno_next_index ++;

    if (found->pdus_since_last_hashrec == 0 &&
            found->agency->config->digest_hash_pdulimit > 1 &&
            found->agency->config->digest_hash_timeout > 0) {
        if (start_mediator_timer(found->hash_timer,
                    found->agency->config->digest_hash_timeout) < 0) {
            /* what can we do here? */
        }
    }
    found->pdus_since_last_hashrec += 1;

    if (found->pdus_since_last_hashrec >=
            found->agency->config->digest_hash_pdulimit &&
            found->agency->config->digest_hash_pdulimit != 0) {
        halt_mediator_timer(found->hash_timer);
        action = INTEGRITY_CHECK_SEND_HASH;

    }
    *chain = found;
    return action;

}

uint8_t send_integrity_check_hash_pdu(coll_recv_t *col,
        integrity_check_state_t *ics) {

    wandder_encoded_result_t *encres;
    char *operatorid = NULL;
    uint32_t medid;
    col_known_liid_t *found;
    int r = 0;
    uint8_t ret = INTEGRITY_CHECK_NO_ACTION;

    if (ics == NULL) {
        return INTEGRITY_CHECK_NO_ACTION;
    }

    if (ics->pdus_since_last_hashrec == 0) {
        return INTEGRITY_CHECK_NO_ACTION;
    }

    HASH_FIND(hh, col->known_liids, ics->liid, strlen(ics->liid), found);
    if (!found) {
        return INTEGRITY_CHECK_NO_ACTION;
    }

    if (!found->declared_int_rmq) {
        /* we don't have an RMQ to put this IC PDU into, so for now we'll
         * just have to skip it */
        ics->pdus_since_last_hashrec = 0;
        return INTEGRITY_CHECK_NO_ACTION;
    }

    /* Generate a hash digest record and push it into the appropriate
     * RMQ for the LIID
     */

    lock_med_collector_config(col->parentconfig);
    if (col->parentconfig->operatorid) {
        operatorid = strdup(col->parentconfig->operatorid);
    }
    medid = col->parentconfig->parent_mediatorid;
    unlock_med_collector_config(col->parentconfig);

    encres = generate_integrity_check_hash_pdu(ics, medid, operatorid,
            col->etsiencoder, col->etsidecoder);
    if (ics->msgtype == OPENLI_PROTO_ETSI_CC) {
        r = publish_cc_on_mediator_liid_RMQ_queue(col->amqp_producer_state,
                encres->encoded, encres->len, found->liid,
                found->queuenames[1], &(col->rmq_blocked));
    } else if (ics->msgtype == OPENLI_PROTO_ETSI_IRI) {
        r = publish_iri_on_mediator_liid_RMQ_queue(col->amqp_producer_state,
                encres->encoded, encres->len, found->liid,
                found->queuenames[0], &(col->rmq_blocked));
    }

    if (r < 0) {
        amqp_destroy_connection(col->amqp_producer_state);
        col->amqp_producer_state = NULL;
    }
    if (operatorid) {
        free(operatorid);
    }
    wandder_release_encoded_result(col->etsiencoder, encres);
    ics->pdus_since_last_hashrec = 0;

    // don't restart the timer until we've seen at least one hashable PDU
    halt_mediator_timer(ics->hash_timer);

    if (ics->hashes_since_last_signrec >=
            ics->agency->config->digest_sign_hashlimit &&
            ics->agency->config->digest_sign_hashlimit > 0) {
        ret = INTEGRITY_CHECK_REQUEST_SIGN;
    }

    return ret;
}

static void push_signing_request(coll_recv_t *col, integrity_check_state_t *ics,
        ics_sign_request_t *job) {

    col_thread_msg_t msg;
    struct ics_sign_request_message *body;

    body = calloc(1, sizeof(struct ics_sign_request_message));
    body->ics_key = strdup(ics->key);
    body->seqno = job->seqno;
    body->digest = calloc(job->digest_len + 1, sizeof(unsigned char));
    memcpy(body->digest, job->digest, job->digest_len);
    body->digest_len = job->digest_len;

    memset(&msg, 0, sizeof(msg));
    msg.type = MED_COLL_INTEGRITY_SIGN_REQUEST;
    msg.arg = (uint64_t)(body);

    libtrace_message_queue_put(&(col->out_main), &msg);

    job->attempts ++;
    start_mediator_timer(job->reply_timer, 30);
}

#define MAX_ICS_SIGN_REQUEST_ATTEMPTS 10

void integrity_sign_reply_timer_callback(coll_recv_t *col,
        med_epoll_ev_t *mev) {

    ics_sign_request_t *job;

    if (mev == NULL) {
        return;
    }
    halt_mediator_timer(mev);
    job = (ics_sign_request_t *)(mev->state);

    if (job->attempts == 5 || (
            job->attempts > MAX_ICS_SIGN_REQUEST_ATTEMPTS &&
            HASH_CNT(hh, job->chain->sign_jobs) > 5)) {
        logger(LOG_INFO, "OpenLI mediator: giving up on signing request %ld for ICS chain %s:%u:%u after %u attempts",
                job->seqno, job->chain->liid, job->chain->cin,
                job->chain->msgtype, job->attempts);
        free(job->digest);
        free(job->signing_seqnos);
        destroy_mediator_timer(job->reply_timer);

        HASH_DELETE(hh, job->chain->sign_jobs, job);
        free(job);
        return;
    }

    push_signing_request(col, job->chain, job);

}


int send_integrity_check_signing_request(coll_recv_t *col,
        integrity_check_state_t *ics) {

    ics_sign_request_t *job = NULL;

    HASH_FIND(hh, ics->sign_jobs, &(ics->self_seqno_sign),
            sizeof(ics->self_seqno_sign), job);
    if (job) {
        /* this is bad, because this should not happen... */
        logger(LOG_INFO, "OpenLI mediator: sequence number %ld is already in use for an outstanding signing request for %s:%u:%u?",
                ics->self_seqno_sign, ics->liid, ics->cin, ics->msgtype);
        return -1;
    }

    job = calloc(1, sizeof(ics_sign_request_t));
    job->chain = ics;
    job->attempts = 0;
    job->seqno = ics->self_seqno_sign;
    job->signing_seqnos = ics->signing_seqnos;
    job->signing_seqno_array_size = ics->signing_seqno_next_index;
    job->reply_timer = NULL;
    job->digest = calloc(EVP_MAX_MD_SIZE + 1, sizeof(unsigned char));
    job->digest_len = 0;
    job->reply_timer = create_mediator_timer(col->epoll_fd, job,
            MED_EPOLL_INTEGRITY_SIGN_REQUEST_TIMER, 0);

    HASH_ADD_KEYPTR(hh, ics->sign_jobs, &(job->seqno), sizeof(job->seqno), job);

    ics->self_seqno_sign ++;
    ics->signing_seqnos = calloc(16, sizeof(int64_t));
    ics->signing_seqno_array_size = 16;
    ics->signing_seqno_next_index = 0;

    EVP_DigestFinal_ex(ics->signature_ctx, job->digest, &(job->digest_len));
    push_signing_request(col, ics, job);

    /* TODO here
     *
     * EVP_DigestFinal_ex on the current hash.
     * Generate a signing request and push it back to the provisioner.
     * Save whatever state we are going to need to generate a PDU if/when
     * we get a response.
     * Set up a timer to expire this request if the provisioner never
     * replies for some reason.
     * reset_sign_hash_context()
     */


    reset_sign_hash_context(ics);

    return 0;
}

int integrity_hash_timer_callback(coll_recv_t *col, med_epoll_ev_t *mev) {

    integrity_check_state_t *ics;

    if (mev == NULL) {
        return -1;
    }

    ics = (integrity_check_state_t *)(mev->state);

    if (send_integrity_check_hash_pdu(col, ics) ==
            INTEGRITY_CHECK_REQUEST_SIGN) {
        return send_integrity_check_signing_request(col, ics);
    }

    return 0;
}

int integrity_sign_timer_callback(coll_recv_t *col, med_epoll_ev_t *mev) {

    integrity_check_state_t *ics;

    if (mev == NULL) {
        return -1;
    }

    ics = (integrity_check_state_t *)(mev->state);

    halt_mediator_timer(ics->sign_timer);
    return send_integrity_check_signing_request(col, ics);

}

void destroy_integrity_sign_job(ics_sign_request_t *job) {
    if (!job) return;

    if (job->signing_seqnos) {
        free(job->signing_seqnos);
    }
    if (job->reply_timer) {
        destroy_mediator_timer(job->reply_timer);
    }
    if (job->digest) {
        free(job->digest);
        job->digest = NULL;
        job->digest_len = 0;
    }
    free(job);
}

void free_integrity_check_state(integrity_check_state_t *integ) {
    ics_sign_request_t *job, *tmp;
    if (integ == NULL) {
        return;
    }
    HASH_ITER(hh, integ->sign_jobs, job, tmp) {
        HASH_DELETE(hh, integ->sign_jobs, job);
        destroy_integrity_sign_job(job);
    }
    if (integ->key) free(integ->key);
    if (integ->liid) free(integ->liid);
    if (integ->hash_ctx) EVP_MD_CTX_free(integ->hash_ctx);
    if (integ->signature_ctx) EVP_MD_CTX_free(integ->signature_ctx);
    if (integ->hash_timer) destroy_mediator_timer(integ->hash_timer);
    if (integ->sign_timer) destroy_mediator_timer(integ->sign_timer);
    if (integ->hashed_seqnos) free(integ->hashed_seqnos);
    if (integ->signing_seqnos) free(integ->signing_seqnos);

    free(integ);
}

void handle_liid_withdrawal_within_integrity_check_state(
        integrity_check_state_t **state, char *liid,
        coll_recv_t *col) {

    integrity_check_state_t *ics, *tmp;

    HASH_ITER(hh, *state, ics, tmp) {
        if (strcmp(liid, ics->liid) == 0) {
            HASH_DELETE(hh, *state, ics);
            if (ics->hash_timer) {
                destroy_mediator_timer(ics->hash_timer);
                ics->hash_timer = NULL;
            }
            if (ics->sign_timer) {
                destroy_mediator_timer(ics->sign_timer);
                ics->sign_timer = NULL;
            }
            /* have to produce a final hash record for any unhashed PDUs */
            send_integrity_check_hash_pdu(col, ics);

            /* TODO have to produce a final signature for any unsigned hashes */


            /* If we need a final signature, we can't free this ICS instance
             * yet because we will need it to encode the message once the
             * signed response gets back to us from the provisioner.
             *
             */
        }
    }

}

void handle_lea_withdrawal_within_integrity_check_state(
        integrity_check_state_t **state, char *agencyid) {

    integrity_check_state_t *ics, *tmp;

    HASH_ITER(hh, *state, ics, tmp) {
        if (strcmp(agencyid, ics->agency->agencyid) == 0) {
            HASH_DELETE(hh, *state, ics);
            free_integrity_check_state(ics);
        }
    }
}
