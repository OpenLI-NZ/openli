/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
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
#include "etsiencoding/etsiencoding.h"
#include "collector_base.h"
#include "collector_integrity_check.h"


int update_liid_to_agency_map(liid_to_agency_mapping_t **map,
        char *liid, char *agencyid) {

    liid_to_agency_mapping_t *found = NULL;

    if (!liid || !agencyid) {
        return -1;
    }

    HASH_FIND(hh, *map, liid, strlen(liid), found);

    if (found) {
        if (found->agencyid) {
            if (strcmp(found->agencyid, agencyid) == 0) {
                return 0;
            }
            free(found->agencyid);
        }
        found->agencyid = strdup(agencyid);
    } else {
        found = calloc(1, sizeof(liid_to_agency_mapping_t));
        found->liid = strdup(liid);
        found->agencyid = strdup(agencyid);

        HASH_ADD_KEYPTR(hh, *map, found->liid, strlen(found->liid), found);
    }
    return 1;
}

void remove_liid_to_agency_map_entry(liid_to_agency_mapping_t **map,
        char *liid) {

    liid_to_agency_mapping_t *found = NULL;
    if (!liid) {
        return;
    }

    HASH_FIND(hh, *map, liid, strlen(liid), found);
    if (!found) {
        return;
    }

    HASH_DELETE(hh, *map, found);
    if (found->liid) {
        free(found->liid);
    }
    if (found->agencyid) {
        free(found->agencyid);
    }
    free(found);
}

void purge_liid_to_agency_map(liid_to_agency_mapping_t **map) {
    liid_to_agency_mapping_t *lam, *tmp;

    HASH_ITER(hh, *map, lam, tmp) {
        HASH_DELETE(hh, *map, lam);
        if (lam->liid) free(lam->liid);
        if (lam->agencyid) free(lam->agencyid);
        free(lam);
    }
}

void clear_digest_key_map(digest_map_key_t **map) {
    digest_map_key_t *k, *tmp;

    HASH_ITER(hh, *map, k, tmp) {
        if (k->keystring) {
            free((void *)k->keystring);
        }
        HASH_DELETE(hh, *map, k);
        free(k);
    }
}

int update_agency_digest_config_map(agency_digest_config_t **map,
        char *agencyid, liagency_digest_config_t *digest) {

    agency_digest_config_t *found = NULL;

    HASH_FIND(hh, *map, agencyid, strlen(agencyid), found);

    if (found) {
        free(found->config);
        found->config = digest;
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
    found->agencyid = strdup(agencyid);
    found->config = digest;
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
        free(dig->config);
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

static inline void reset_hash_context(integrity_check_state_t *found) {

    if (found->hash_ctx == NULL) {
        found->hash_ctx = EVP_MD_CTX_new();
    }

    switch(found->agency->hash_method) {
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

    switch(found->agency->sign_method) {
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

    snprintf(buf, buflen, "%s-%s-%u", ics->liid_key,
            ics->msgtype == OPENLI_PROTO_ETSI_IRI ? "IRI" : "CC",
            ics->cin);

}

static inline void populate_integrity_check_pshdr_data(
        wandder_etsipshdr_data_t *hdrdata, integrity_check_state_t *ics,
        char *netelemid, char *operatorid) {

    hdrdata->liid = ics->liid_key;
    hdrdata->liid_len = strlen(ics->liid_key);
    hdrdata->liid_format = ics->liid_format;
    hdrdata->authcc = ics->authcc;
    hdrdata->delivcc = ics->delivcc;
    hdrdata->authcc_len = strlen(hdrdata->authcc);
    hdrdata->delivcc_len = strlen(hdrdata->delivcc);

    if (operatorid) {
        hdrdata->operatorid = operatorid;
    } else {
        hdrdata->operatorid = "unspecified";
    }
    hdrdata->operatorid_len = strlen(hdrdata->operatorid);

    if (netelemid) {
        hdrdata->networkelemid = netelemid;
    } else {
        hdrdata->networkelemid = "unspecified";
    }
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
                found->agency->sign_hashlimit > 1 &&
                found->agency->sign_timeout > 0) {

            if (start_openli_timer(found->sign_timer,
                        found->agency->sign_timeout) < 0) {
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

uint8_t update_integrity_check_state(integrity_check_state_t **map,
        encoder_liid_state_t *known, uint8_t *msgbody, uint16_t msglen,
        openli_proto_msgtype_t msgtype, openli_encoding_job_t *job,
        int epoll_fd, integrity_check_state_t **chain) {

    //char keydump[128];
    integrity_check_state_t *found;
    uint32_t seqno = job->seqno;
    uint8_t action = INTEGRITY_CHECK_NO_ACTION;
    uint32_t cin = (uint32_t)job->cin;
    digest_map_key_t *dmk;
    uint64_t dmk_kval = 0;


    if (msgtype != OPENLI_PROTO_ETSI_IRI && msgtype != OPENLI_PROTO_ETSI_CC) {
        *chain = NULL;
        return action;
    }

    /* save the key string in a local map so we don't need to call
     * snprintf() for every single intercept record
     */
    dmk_kval = cin | (((uint64_t)msgtype) << 32);
    HASH_FIND(hh, known->digest_cin_keys, &dmk_kval, sizeof(dmk_kval), dmk);
    if (!dmk) {
        char key[128];
        dmk = calloc(1, sizeof(digest_map_key_t));
        dmk->key_cin = dmk_kval;
        snprintf(key, 128, "%s %u %u", known->liid_key, msgtype, cin);
        dmk->keystring = strdup(key);

        HASH_ADD_KEYPTR(hh, known->digest_cin_keys, &(dmk->key_cin),
                sizeof(dmk->key_cin), dmk);
    }

    /** map key is LIID, CIN and msgtype, separated by space characters. */
    HASH_FIND(hh, *map, dmk->keystring, strlen(dmk->keystring), found);
    if (!found) {
        char cin_string[1024];
        snprintf(cin_string, 1024, "%s-%u", known->liid_key, cin);

        found = calloc(1, sizeof(integrity_check_state_t));
        found->key = strdup(dmk->keystring);
        found->cinstr = strdup(cin_string);
        found->agency = NULL;
        found->cin = cin;
        found->msgtype = msgtype;
        found->liid_key = strdup(known->liid_key);
        found->authcc = strdup(known->authcc);
        found->delivcc = strdup(known->delivcc);
        found->hashed_seqnos = calloc(32, sizeof(int64_t));
        found->signing_seqnos = calloc(16, sizeof(int64_t));
        found->seqno_array_size = 32;
        found->seqno_next_index = 0;
        found->signing_seqno_array_size = 16;
        found->signing_seqno_next_index = 0;
        found->self_seqno_hash = 1;
        found->self_seqno_sign = 1;
        found->awaiting_final_signature = 0;
        found->encryptmethod = OPENLI_PAYLOAD_ENCRYPTION_NONE;
        found->encryptkey = NULL;
        found->encryptkey_len = 0;
        HASH_ADD_KEYPTR(hh, *map, found->key, strlen(found->key), found);
    }

    if (found->agency == NULL) {
        /* this is a new stream */
        found->agency = &(known->digest_config);
        found->hash_ctx = NULL;
        found->signature_ctx = NULL;

        reset_hash_context(found);
        reset_sign_hash_context(found);

        /* do not start the timers until we've seen at least one PDU */
        found->hash_timer = create_openli_timer(epoll_fd, found,
                OPENLI_EPOLL_INTEGRITY_HASH_TIMER, 0);
        found->sign_timer = create_openli_timer(epoll_fd, found,
                OPENLI_EPOLL_INTEGRITY_SIGN_TIMER, 0);

        found->pdus_since_last_hashrec = 0;
        found->hashes_since_last_signrec = 0;
    } else {
        found->agency = &(known->digest_config);
    }

    if (job && job->origreq) {
        found->destmediator = job->origreq->destid;
    }

    if (job) {
        found->encryptmethod = job->encryptmethod;

        if (job->encryptkey == NULL) {
            if (found->encryptkey) free(found->encryptkey);
            found->encryptkey = NULL;
        } else {
            if (found->encryptkey != NULL && memcmp(found->encryptkey,
                    job->encryptkey, job->encryptkey_len) != 0) {
                free(found->encryptkey);
                found->encryptkey = NULL;
            }
            if (found->encryptkey == NULL) {
                found->encryptkey = malloc(job->encryptkey_len);
                memcpy(found->encryptkey, job->encryptkey,
                        job->encryptkey_len);
            }
        }
        found->encryptkey_len = job->encryptkey_len;
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
            found->agency->hash_pdulimit > 1 &&
            found->agency->hash_timeout > 0) {
        if (start_openli_timer(found->hash_timer,
                    found->agency->hash_timeout) < 0) {
            /* what can we do here? */
        }
    }
    found->pdus_since_last_hashrec += 1;

    if (found->pdus_since_last_hashrec >=
            found->agency->hash_pdulimit &&
            found->agency->hash_pdulimit != 0) {
        halt_openli_timer(found->hash_timer);
        action = INTEGRITY_CHECK_SEND_HASH;
    }
    *chain = found;
    return action;

}

int generate_integrity_check_signature_pdu(openli_encoded_result_t *res,
        integrity_check_state_t *ics, char *netelemid, char *operatorid,
        wandder_encoder_t *encoder, EVP_PKEY *signingkey,
        wandder_etsispec_t *etsidecoder,
        EVP_CIPHER_CTX *evp_ctx, encrypt_encode_state_t *encryptstate) {

    wandder_encoded_result_t *ic_pdu = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE + 1];
    unsigned char *signature;
    unsigned int digestlen = 0;
    size_t signlen = 0;
    wandder_etsipshdr_data_t hdrdata;
    uint16_t liidlen, l;
    EVP_PKEY_CTX *sign_ctx = NULL;
    char err_msg[256];
    unsigned long errcode;

    sign_ctx = EVP_PKEY_CTX_new(signingkey, NULL);
    if (!sign_ctx) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO,
                "OpenLI collector: failed to create signing context for integrity check signatures: %s", err_msg);
        return -1;
    }

    if (EVP_PKEY_sign_init(sign_ctx) <= 0) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO,
                "OpenLI collector: failed to initialize integrity check signature: %s", err_msg);
        return -1;
    }

    EVP_DigestFinal_ex(ics->signature_ctx, digest, &digestlen);

    if (EVP_PKEY_sign(sign_ctx, NULL, &(signlen), digest, digestlen) <= 0) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO,
                "OpenLI collector: failed to derive length for integrity check signature: %s", err_msg);
        EVP_PKEY_CTX_free(sign_ctx);
        return -1;
    }

    signature = OPENSSL_malloc(signlen);
    if (!signature) {
        logger(LOG_INFO,
                "OpenLI collector: failed to allocate memory to store integrity check signature");
        EVP_PKEY_CTX_free(sign_ctx);
        return -1;
    }

    if (EVP_PKEY_sign(sign_ctx, signature, &(signlen), digest,
            digestlen) <= 0) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO,
                "OpenLI collector: failed to generate integrity check signature from digest: %s", err_msg);
        OPENSSL_free(signature);
        EVP_PKEY_CTX_free(sign_ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(sign_ctx);
    populate_integrity_check_pshdr_data(&hdrdata, ics, netelemid,
            operatorid);
    reset_wandder_encoder(encoder);
    ic_pdu = encode_etsi_integrity_check(encoder, &hdrdata, ics->cin,
            ics->self_seqno_sign, ics->agency->hash_method,
            INTEGRITY_CHECK_REQUEST_SIGN,
            ics->msgtype, signature, signlen, ics->signing_seqnos,
            ics->signing_seqno_next_index,
            ics->agency->time_fmt);

    if (ic_pdu == NULL) {
        OPENSSL_free(signature);
        return -1;
    }

    /* If we're meant to be encrypted, generate the encrypted version of the
     * IC PDU now.
     *
     * There are probably faster ways to do this, but it is simpler to just
     * regenerate the entire PDU from scratch
     */
    if (ics->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        wandder_release_encoded_result(encoder, ic_pdu);
        reset_wandder_encoder(encoder);

        ic_pdu = encode_encrypted_etsi_integrity_check(encoder, etsidecoder,
                &hdrdata, encryptstate, evp_ctx, ics->encryptmethod,
                ics->encryptkey, ics->encryptkey_len, ics->cin,
                ics->self_seqno_sign, ics->agency->sign_method,
                INTEGRITY_CHECK_REQUEST_SIGN, ics->msgtype, signature,
                signlen, ics->signing_seqnos, ics->signing_seqno_next_index,
                ics->agency->time_fmt);
        if (ic_pdu == NULL) {
            return -1;
        }
    }
    ics->self_seqno_sign ++;
    reset_sign_hash_context(ics);
    ics->signing_seqno_next_index = 0;

    liidlen = strlen(ics->liid_key);
    l = htons(liidlen);

    res->msgbody = calloc(1, sizeof(wandder_encoded_result_t));
    res->msgbody->encoder = NULL;
    res->preamblen = liidlen + 2;
    res->msgbody->encoded = malloc(res->preamblen + ic_pdu->len);

    memcpy(res->msgbody->encoded, &l, sizeof(uint16_t));
    memcpy(res->msgbody->encoded + sizeof(uint16_t), ics->liid_key, liidlen);
    memcpy(res->msgbody->encoded + sizeof(uint16_t) + liidlen,
            ic_pdu->encoded, ic_pdu->len);

    res->msgbody->len = ic_pdu->len + sizeof(uint16_t) + liidlen;
    res->msgbody->alloced = res->msgbody->len;
    res->msgbody->next = NULL;
    res->ipcontents = NULL;
    res->ipclen = 0;
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len);
    res->header.intercepttype = htons(ics->msgtype);
    res->header.internalid = 0;

    OPENSSL_free(signature);
    wandder_release_encoded_result(encoder, ic_pdu);
    return 0;
}

int generate_integrity_check_hash_pdu(openli_encoded_result_t *res,
        integrity_check_state_t *ics, char *netelemid, char *operatorid,
        wandder_encoder_t *encoder, wandder_etsispec_t *etsidecoder,
        EVP_CIPHER_CTX *evp_ctx, encrypt_encode_state_t *encryptstate) {

    wandder_encoded_result_t *ic_pdu = NULL;
    uint8_t hashresult[EVP_MAX_MD_SIZE];
    unsigned int hashlen;
    wandder_etsipshdr_data_t hdrdata;
    uint16_t liidlen, l;

    EVP_DigestFinal_ex(ics->hash_ctx, hashresult, &hashlen);
    populate_integrity_check_pshdr_data(&hdrdata, ics, netelemid,
            operatorid);

    reset_wandder_encoder(encoder);

    ic_pdu = encode_etsi_integrity_check(encoder, &hdrdata, ics->cin,
            ics->self_seqno_hash,
            ics->agency->hash_method, INTEGRITY_CHECK_SEND_HASH,
            ics->msgtype, hashresult, hashlen, ics->hashed_seqnos,
            ics->seqno_next_index, ics->agency->time_fmt);

    if (ic_pdu == NULL) {
        return -1;
    }

    /* update the signed hash using the contents of the IntegrityCheck
     * PDU
     */
    update_signature_hash(ics, etsidecoder, ic_pdu);

    /* If we're meant to be encrypted, generate the encrypted version of the
     * IC PDU now.
     *
     * There are probably faster ways to do this, but it is simpler to just
     * regenerate the entire PDU from scratch
     */
    if (ics->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        wandder_release_encoded_result(encoder, ic_pdu);
        reset_wandder_encoder(encoder);

        ic_pdu = encode_encrypted_etsi_integrity_check(encoder, etsidecoder,
                &hdrdata, encryptstate, evp_ctx, ics->encryptmethod,
                ics->encryptkey, ics->encryptkey_len, ics->cin,
                ics->self_seqno_hash, ics->agency->hash_method,
                INTEGRITY_CHECK_SEND_HASH, ics->msgtype, hashresult, hashlen,
                ics->hashed_seqnos, ics->seqno_next_index,
                ics->agency->time_fmt);
        if (ic_pdu == NULL) {
            return -1;
        }
    }

    // don't increment until AFTER update_signature_hash()
    ics->self_seqno_hash ++;

    ics->seqno_next_index = 0;
    reset_hash_context(ics);

    liidlen = strlen(ics->liid_key);
    l = htons(liidlen);

    res->msgbody = calloc(1, sizeof(wandder_encoded_result_t));
    res->msgbody->encoder = NULL;
    res->preamblen = liidlen + 2;
    res->msgbody->encoded = malloc(res->preamblen + ic_pdu->len);

    memcpy(res->msgbody->encoded, &l, sizeof(uint16_t));
    memcpy(res->msgbody->encoded + sizeof(uint16_t), ics->liid_key, liidlen);
    memcpy(res->msgbody->encoded + sizeof(uint16_t) + liidlen,
            ic_pdu->encoded, ic_pdu->len);

    res->msgbody->len = ic_pdu->len + sizeof(uint16_t) + liidlen;
    res->msgbody->alloced = res->msgbody->len;
    res->msgbody->next = NULL;
    res->ipcontents = NULL;
    res->ipclen = 0;
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len);
    res->header.intercepttype = htons(ics->msgtype);
    res->header.internalid = 0;

    wandder_release_encoded_result(encoder, ic_pdu);

    return 0;
}

void free_integrity_check_state(integrity_check_state_t *integ) {
    if (integ == NULL) {
        return;
    }

    if (integ->key) free(integ->key);
    if (integ->liid_key) free(integ->liid_key);
    if (integ->authcc) free(integ->authcc);
    if (integ->delivcc) free(integ->delivcc);
    if (integ->cinstr) free(integ->cinstr);
    if (integ->hash_ctx) EVP_MD_CTX_free(integ->hash_ctx);
    if (integ->signature_ctx) EVP_MD_CTX_free(integ->signature_ctx);
    if (integ->hash_timer) destroy_openli_timer(integ->hash_timer);
    if (integ->sign_timer) destroy_openli_timer(integ->sign_timer);
    if (integ->hashed_seqnos) free(integ->hashed_seqnos);
    if (integ->signing_seqnos) free(integ->signing_seqnos);
    if (integ->encryptkey) free(integ->encryptkey);

    free(integ);
}

