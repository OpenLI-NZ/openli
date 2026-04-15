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

#include <unistd.h>
#include <assert.h>
#include <sys/eventfd.h>

#include "util.h"
#include "ipiri.h"
#include "ipmmcc.h"
#include "ipcc.h"
#include "ipmmiri.h"
#include "umtsiri.h"
#include "epsiri.h"
#include "emailiri.h"
#include "epscc.h"
#include "collector_base.h"
#include "logger.h"
#include "etsili_core.h"
#include "encoder_worker.h"
#include "intercept.h"
#include "collector_integrity_check.h"

static void destroy_known_liid(encoder_liid_state_t *known) {

    if (known->liid_key) {
        free(known->liid_key);
    }
    if (known->authcc) {
        free(known->authcc);
    }
    if (known->delivcc) {
        free(known->delivcc);
    }
    if (known->operatorid) {
        free(known->operatorid);
    }
    etsili_destroy_encrypted_templates(
            known->encrypt_cc.saved_encryption_templates);
    etsili_destroy_encrypted_templates(
            known->encrypt_iri.saved_encryption_templates);
    clear_digest_key_map(&(known->digest_cin_keys));
    free(known);
}

static void destroy_encoding_job(openli_encoding_job_t *job,
        uint8_t free_request) {

    if (!job) {
        return;
    }
    if (job->cinstr) {
        free(job->cinstr);
    }
    if (job->liid) {
        free(job->liid);
    }
    if (job->authcc) {
        free(job->authcc);
    }
    if (job->delivcc) {
        free(job->delivcc);
    }
    if (job->encryptkey) {
        free(job->encryptkey);
    }
    if (job->operatorid) {
        free(job->operatorid);
    }
    if (job->origreq && free_request) {
        free_published_message(job->origreq);
    }
}

static int init_worker(openli_encoder_t *enc) {
    int zero = 0, rto = 10;
    int hwm = 1000;
    int i, zmq_fd;
    char sockname[128];
    size_t fdlen;

    enc->epoll_fd = epoll_create1(0);

    enc->encoder = init_wandder_encoder();
    enc->freegenerics = create_etsili_generic_freelist(0);
    enc->halted = 0;

    enc->evp_ctx = EVP_CIPHER_CTX_new();
    enc->etsidecoder = wandder_create_etsili_decoder();

    enc->zmq_recvjob = zmq_socket(enc->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 128, "inproc://openliseqpush-%d", enc->workerid);
    if (zmq_setsockopt(enc->zmq_recvjob, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO, "OpenLI: error configuring connection to zmq pull socket");
        return -1;
    }

    if (zmq_setsockopt(enc->zmq_recvjob, ZMQ_RCVTIMEO, &rto,
                sizeof(rto)) != 0) {
        logger(LOG_INFO, "OpenLI: error configuring connection to zmq pull socket");
        return -1;
    }
    if (zmq_connect(enc->zmq_recvjob, sockname) != 0) {
        logger(LOG_INFO, "OpenLI: error connecting to zmq pull socket");
        return -1;
    }

    fdlen = sizeof(zmq_fd);
    zmq_getsockopt(enc->zmq_recvjob, ZMQ_FD, &zmq_fd, &fdlen);
    enc->zmq_job_ev = create_openli_fdevent(enc->epoll_fd, (void *)enc,
            OPENLI_EPOLL_ENCODING_JOB, zmq_fd, EPOLLIN | EPOLLET);

    enc->yield_fd = eventfd(0, EFD_NONBLOCK);
    enc->zmq_yield_ev = create_openli_fdevent(enc->epoll_fd, (void *)enc,
            OPENLI_EPOLL_ZMQ_YIELD, enc->yield_fd, EPOLLIN | EPOLLET);


    enc->zmq_pushresults = calloc(enc->forwarders, sizeof(void *));
    for (i = 0; i < enc->forwarders; i++) {
        snprintf(sockname, 128, "inproc://openlirespush-%d", i);
        enc->zmq_pushresults[i] = zmq_socket(enc->zmq_ctxt, ZMQ_PUSH);
        if (zmq_setsockopt(enc->zmq_pushresults[i], ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
            logger(LOG_INFO,
                    "OpenLI: error configuring connection to exporter push socket %s: %s",
                    sockname, strerror(errno));
            zmq_close(enc->zmq_pushresults[i]);
            enc->zmq_pushresults[i] = NULL;
            continue;
        }
        if (zmq_setsockopt(enc->zmq_pushresults[i], ZMQ_SNDHWM, &hwm,
                sizeof(hwm)) != 0) {
            logger(LOG_INFO,
                    "OpenLI: error configuring connection to exporter push socket %s: %s",
                    sockname, strerror(errno));
            zmq_close(enc->zmq_pushresults[i]);
            enc->zmq_pushresults[i] = NULL;
            continue;
        }
        if (zmq_connect(enc->zmq_pushresults[i], sockname) != 0) {
            logger(LOG_INFO,
                    "OpenLI: error connecting to exporter result socket%s: %s",
                    sockname, strerror(errno));
            zmq_close(enc->zmq_pushresults[i]);
            enc->zmq_pushresults[i] = NULL;
            continue;
        }
    }

    enc->zmq_control_ev = create_openli_fdevent(enc->epoll_fd, (void *)enc,
            OPENLI_EPOLL_ENCODING_CONTROL, enc->control_pipe[0], EPOLLIN);

    return 0;

}

static void free_mobileiri_parameters(etsili_generic_t *params) {

    etsili_generic_t *oldp, *tmp;

    HASH_ITER(hh, params, oldp, tmp) {
        HASH_DELETE(hh, params, oldp);
        release_etsili_generic(oldp);
    }

}

void destroy_encoder_worker(openli_encoder_t *enc) {
    int x;
    openli_encoding_job_t job;
    uint32_t drained = 0;
    encoder_liid_state_t *known, *tmp;
    integrity_check_state_t *integ, *integtmp;

    destroy_all_saved_encoding_templates(enc->saved_intercept_templates);

    clear_global_templates(&(enc->saved_global_templates));

    HASH_ITER(hh, enc->known_liids, known, tmp) {
        HASH_DELETE(hh, enc->known_liids, known);
        destroy_known_liid(known);
    }

    HASH_ITER(hh, enc->integrity_state, integ, integtmp) {
        HASH_DELETE(hh, enc->integrity_state, integ);
        free_integrity_check_state(integ);
    }

    if (enc->encoder) {
        free_wandder_encoder(enc->encoder);
    }

    if (enc->etsidecoder) {
        wandder_free_etsili_decoder(enc->etsidecoder);
    }

    if (enc->freegenerics) {
        free_etsili_generics(enc->freegenerics);
    }

    do {
        x = zmq_recv(enc->zmq_recvjob, &job, sizeof(openli_encoding_job_t), 0);
        if (x < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        }
        destroy_encoding_job(&job, 1);
        drained ++;

    } while (x > 0);
    zmq_close(enc->zmq_recvjob);

    remove_openli_fdevent(enc->zmq_job_ev);
    // this should close control_pipe[0]?
    remove_openli_fdevent(enc->zmq_control_ev);
    remove_openli_fdevent(enc->zmq_yield_ev);

    free(enc->zmq_pushresults);

    if (enc->evp_ctx) {
        EVP_CIPHER_CTX_free(enc->evp_ctx);
    }

    close(enc->control_pipe[1]);
    close(enc->epoll_fd);
}

static int _send_integrity_check_pdu(openli_encoder_t *enc,
        integrity_check_state_t *ics, uint8_t is_hash) {

    openli_encoded_result_t res;
    char *operatorid = NULL;
    char *netelemid = NULL;
    encoder_liid_state_t *found = NULL;
    EVP_PKEY *signingkey = NULL;
    encrypt_encode_state_t *encryptstate;

    memset(&res, 0, sizeof(res));

    HASH_FIND(hh, enc->known_liids, ics->liid_key, strlen(ics->liid_key),
            found);
    if (!found) {
        return 0;
    }

    pthread_rwlock_rdlock(enc->shared_mutex);
    if (found->operatorid) {
        operatorid = strdup(found->operatorid);
    } else if (enc->shared->operatorid) {
        operatorid = strdup(enc->shared->operatorid);
    }
    if (enc->shared->networkelemid) {
        netelemid = strdup(enc->shared->networkelemid);
    }
    pthread_rwlock_unlock(enc->shared_mutex);

    if (ics->msgtype == OPENLI_PROTO_ETSI_IRI) {
        encryptstate = &(found->encrypt_iri);
    } else {
        encryptstate = &(found->encrypt_cc);
    }

    if (is_hash) {
        if (generate_integrity_check_hash_pdu(&res, ics, netelemid, operatorid,
                enc->encoder, enc->etsidecoder, enc->evp_ctx,
                encryptstate) < 0) {
            free_encoded_result(&res);
            if (operatorid) free(operatorid);
            if (netelemid) free(netelemid);
            return -1;
        }
        res.seqno = ics->self_seqno_hash - 1;
    } else {
        pthread_rwlock_rdlock(enc->shared_mutex);
        if (!enc->shared->digestsigningkey) {
            logger(LOG_INFO,
                    "OpenLI collector: unable to generate integrity check signatures because we do not know the signing key!");
            pthread_rwlock_unlock(enc->shared_mutex);
            goto endzone;
        }

        signingkey = enc->shared->digestsigningkey;
        EVP_PKEY_up_ref(signingkey);
        pthread_rwlock_unlock(enc->shared_mutex);

        if (generate_integrity_check_signature_pdu(&res, ics, netelemid,
                operatorid, enc->encoder, signingkey, enc->etsidecoder,
                enc->evp_ctx, encryptstate) < 0) {
            free_encoded_result(&res);
            EVP_PKEY_free(signingkey);
            if (operatorid) free(operatorid);
            if (netelemid) free(netelemid);
            return -1;
        }
        EVP_PKEY_free(signingkey);
        res.seqno = ics->self_seqno_sign - 1;
    }

    res.liid = strdup(ics->liid_key);
    res.restype = ics->msgtype;
    res.encodedby = enc->workerid;
    res.cinstr = strdup(ics->cinstr);
    res.destid = ics->destmediator;

    zmq_send(enc->zmq_pushresults[found->fwd_index], &res, sizeof(res), 0);

endzone:
    if (operatorid) free(operatorid);
    if (netelemid) free(netelemid);
    return 1;
}

static int send_integrity_check_sign_pdu(openli_encoder_t *enc,
        integrity_check_state_t *ics) {

    int ret = 0;

    halt_openli_timer(ics->sign_timer);
    if (ics->hashes_since_last_signrec == 0) {
        return 0;
    }

    ret = _send_integrity_check_pdu(enc, ics, 0);
    if (ret > 0) {
        ics->hashes_since_last_signrec = 0;
    }
    return ret;
}

static int send_integrity_check_hash_pdu(openli_encoder_t *enc,
        integrity_check_state_t *ics) {
    int ret = 0;

    halt_openli_timer(ics->hash_timer);
    if (ics->pdus_since_last_hashrec == 0) {
        return ret;
    }

    ret = _send_integrity_check_pdu(enc, ics, 1);

    if (ret <= 0) {
        return ret;
    }
    ics->pdus_since_last_hashrec = 0;

    if (ics->hashes_since_last_signrec >= ics->agency->sign_hashlimit &&
            ics->agency->sign_hashlimit > 0) {
        // send signed hashes
        ret = send_integrity_check_sign_pdu(enc, ics);
    }
    return ret;
}

static inline int finalize_encoded_result(openli_encoded_result_t *res,
        openli_encoding_job_t *job, openli_encoder_t *enc,
        encoder_liid_state_t *known, uint8_t type) {

    uint8_t integrity_res = INTEGRITY_CHECK_NO_ACTION;
    integrity_check_state_t *chain = NULL;

    res->cinstr = strdup(job->cinstr);
    res->liid = strdup(job->liid);
    res->seqno = job->seqno;
    res->destid = job->origreq->destid;
    res->encodedby = enc->workerid;
    res->restype = type;

    // update digest state
    if (known && !known->digest_config_disabled &&
            known->digest_config.required) {
        integrity_res = update_integrity_check_state(&(enc->integrity_state),
                known, res->msgbody->encoded + res->preamblen,
                res->msgbody->len - res->preamblen,
                ntohs(res->header.intercepttype), job, enc->epoll_fd,
                &chain);
    }

    if (type == OPENLI_EXPORT_LAST_SEGMENT_FLAG ||
            type == OPENLI_EXPORT_FIRST_SEGMENT_FLAG) {
        // Otherwise we run the risk of double freeing this later on
        // XXX we could duplicate it if we absolutely needed it, but
        // we shouldn't need it
        res->origreq = NULL;
    } else {
        res->origreq = job->origreq;
        job->origreq = NULL;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (encrypt_payload_container_aes_192_cbc(enc->evp_ctx,
                enc->etsidecoder, res->msgbody->encoded + res->preamblen,
                res->msgbody->len - res->preamblen, job->encryptkey,
                job->encryptkey_len) == NULL) {
            return -1;
        }
    }

    if (integrity_res == INTEGRITY_CHECK_SEND_HASH) {
        return send_integrity_check_hash_pdu(enc, chain);
    }

    return 0;
}

#define AGENCY_MAPPING_CHECK_FREQ (5)

static void check_agency_digest_config(openli_encoder_t *enc,
        encoder_liid_state_t *found) {

    liid_to_agency_mapping_t *agmap;
    agency_digest_config_t *agdigest;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    if (tv.tv_sec - found->last_agency_check < AGENCY_MAPPING_CHECK_FREQ) {
        return;
    }

    found->last_agency_check = tv.tv_sec;

    pthread_rwlock_rdlock(enc->liid_agency_mutex);
    HASH_FIND(hh, enc->liid_agencies->map, found->liid_key,
            strlen(found->liid_key), agmap);

    if (!agmap) {
        if (found->no_agency_map_warning == 0) {
            logger(LOG_INFO, "OpenLI Collector: encoder worker %d does not have a usable agency mapping for LIID %s, cannot produce integrity checks for this LIID",
                    enc->workerid, found->liid_key);
            found->no_agency_map_warning = 1;
        }
        found->digest_config_disabled = 1;
        memset(&found->digest_config, 0, sizeof(found->digest_config));
        pthread_rwlock_unlock(enc->liid_agency_mutex);
        return;
    }

    pthread_rwlock_rdlock(enc->digest_config_mutex);
    HASH_FIND(hh, enc->digest_config->map, agmap->agencyid,
            strlen(agmap->agencyid), agdigest);

    if (!agdigest) {
        if (found->no_agency_map_warning == 0 &&
                strcmp(agmap->agencyid, "pcapdisk") != 0) {
            logger(LOG_INFO, "OpenLI Collector: encoder worker %d does not have digest configuration for agency %s, cannot produce integrity checks for LIID %s",
                    enc->workerid, agmap->agencyid, found->liid_key);
            found->no_agency_map_warning = 1;
        }
        found->digest_config_disabled = 1;
        memset(&found->digest_config, 0, sizeof(found->digest_config));
        pthread_rwlock_unlock(enc->digest_config_mutex);
        pthread_rwlock_unlock(enc->liid_agency_mutex);
        return;
    }

    if (agdigest->disabled) {
        found->digest_config_disabled = 1;
        memset(&found->digest_config, 0, sizeof(found->digest_config));
    } else {
        found->digest_config_disabled = 0;
        memcpy(&found->digest_config, agdigest->config,
                sizeof(liagency_digest_config_t));
    }
    if (found->operatorid) {
        free(found->operatorid);
    }
    if (agdigest->operatorid) {
        found->operatorid = strdup(agdigest->operatorid);
    } else {
        found->operatorid = NULL;
    }

    pthread_rwlock_unlock(enc->digest_config_mutex);
    pthread_rwlock_unlock(enc->liid_agency_mutex);
}

static encoder_liid_state_t *create_new_known_liid(openli_encoder_t *enc,
        char *liid, char *authcc, char *delivcc, char *operatorid) {

    encoder_liid_state_t *found;

    found = calloc(1, sizeof(encoder_liid_state_t));
    found->liid_key = strdup(liid);
    found->authcc = strdup(authcc);
    if (delivcc) {
        found->delivcc = strdup(delivcc);
    }
    found->no_agency_map_warning = 0;
    found->last_agency_check = 0;
    memset(&found->digest_config, 0, sizeof(found->digest_config));
    found->digest_cin_keys = NULL;
    found->digest_config_disabled = 1;
    if (operatorid) {
        found->operatorid = strdup(operatorid);
    }

    found->fwd_index = hash_liid(liid) % enc->forwarders;

    HASH_ADD_KEYPTR(hh, enc->known_liids, found->liid_key,
            strlen(found->liid_key), found);
    return found;
}

static int encode_rawip(openli_encoder_t *enc, openli_encoding_job_t *job,
        openli_encoded_result_t *res, uint16_t rawtype) {

    uint16_t liidlen, l;

    liidlen = strlen(job->liid);
    l = htons(liidlen);

    memset(res, 0, sizeof(openli_encoded_result_t));

    res->msgbody = calloc(1, sizeof(wandder_encoded_result_t));
    res->msgbody->encoder = NULL;
    res->msgbody->encoded = malloc(liidlen + sizeof(uint16_t));

    memcpy(res->msgbody->encoded, &l, sizeof(uint16_t));
    memcpy(res->msgbody->encoded + sizeof(uint16_t), job->liid, liidlen);

    res->msgbody->len = job->origreq->data.rawip.ipclen +
            (liidlen + sizeof(uint16_t));
    res->msgbody->alloced = liidlen + sizeof(uint16_t);
    res->msgbody->next = NULL;

    res->ipcontents = job->origreq->data.rawip.ipcontent;
    res->ipclen = job->origreq->data.rawip.ipclen;
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len);
    res->header.intercepttype = htons(rawtype);
    res->header.internalid = 0;

    finalize_encoded_result(res, job, enc, NULL, job->origreq->type);

    return 0;
}

static int encode_templated_ipiri(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    /* Doesn't really make sense to template the IPIRI payload itself, since
     * the content is quite variable and IPIRIs should be generated
     * relatively infrequently.
     */

    wandder_encoded_result_t *body = NULL;
    openli_ipiri_job_t *ipirijob;
    etsili_iri_type_t iritype;
    etsili_generic_t *params = NULL;

    ipirijob = (openli_ipiri_job_t *)&(job->origreq->data.ipiri);

    /* in ipiri.c */
    prepare_ipiri_parameters(enc->freegenerics, ipirijob, &iritype, &params);

    reset_wandder_encoder(enc->encoder);
    body = encode_ipiri_body(enc->encoder, job->preencoded, iritype, &params);

    if (body == NULL || body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI IPIRI body");
        if (body) {
            wandder_release_encoded_result(enc->encoder, body);
            free_ipiri_parameters(params);
        }
        return -1;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_iri,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            free_ipiri_parameters(params);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job->origreq->type, job->liid) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            free_ipiri_parameters(params);
            return -1;
        }
    }

    wandder_release_encoded_result(enc->encoder, body);
    free_ipiri_parameters(params);

    /* Success */
    return 1;
}

static int encode_templated_emailiri(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    wandder_encoded_result_t *body = NULL;
    openli_emailiri_job_t *irijob =
            (openli_emailiri_job_t *)&(job->origreq->data.emailiri);

    /* create custom params from job "contents" */
    prepare_emailiri_parameters(enc->freegenerics, irijob,
            &(irijob->customparams));

    reset_wandder_encoder(enc->encoder);
    body = encode_emailiri_body(enc->encoder, job->preencoded, irijob->iritype,
            &(irijob->customparams));
    if (body == NULL || body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI Email IRI body");
        if (body) {
            wandder_release_encoded_result(enc->encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_iri,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job->origreq->type, job->liid) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(enc->encoder, body);
    free_emailiri_parameters(irijob->customparams);

    /* Success */
    return 1;
}

static inline void create_mobile_operator_identifier(openli_encoder_t *enc,
        openli_mobiri_job_t *irijob, int elem_id) {


    etsili_generic_t *np = NULL;
    char opid[6];
    int opidlen;

    pthread_rwlock_rdlock(enc->shared_mutex);
    opidlen = enc->shared->operatorid_len;

    /* TODO maybe we could find a way to reuse this instead of creating
     * every time?
     */
    if (opidlen > 5) {
        opidlen = 5;
    }

    memcpy(opid, enc->shared->operatorid, opidlen);
    opid[opidlen] = '\0';
    pthread_rwlock_unlock(enc->shared_mutex);

    np = create_etsili_generic(enc->freegenerics, elem_id, opidlen,
            (uint8_t *)opid);
    HASH_ADD_KEYPTR(hh, irijob->customparams,
            &(np->itemnum), sizeof(np->itemnum), np);

}

static int encode_templated_segflag(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res, uint8_t is_first) {

    wandder_encoded_result_t *body = NULL;

    reset_wandder_encoder(enc->encoder);

    body = encode_etsi_segment_flag_body(enc->encoder, job->preencoded,
            is_first);

    if (body == NULL ||  body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI TRI Segment Flag body");
        if (body) {
            wandder_release_encoded_result(enc->encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_cc,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job->origreq->type, job->liid) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(enc->encoder, body);
    /* Success */
    return 1;

}

static int encode_templated_epscc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    wandder_encoded_result_t *body = NULL;
    openli_mobcc_job_t *epsccjob;

    epsccjob = (openli_mobcc_job_t *)&(job->origreq->data.mobcc);

    /* Templating is going to be difficult because of the timestamp and
     * sequence number fields in the ULIC header
     */
    reset_wandder_encoder(enc->encoder);

    body = encode_epscc_body(enc->encoder, job->preencoded, job->liid,
            job->cin, epsccjob->gtpseqno, epsccjob->dir, job->origreq->ts,
            epsccjob->icetype, epsccjob->ipclen, job->liid_format);

    if (body == NULL ||  body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI EPSCC body");
        if (body) {
            wandder_release_encoded_result(enc->encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_cc,
                res, hdr_tplate,
                body->encoded, body->len, epsccjob->ipcontent,
                epsccjob->ipclen, job) < 0) {

            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, epsccjob->ipcontent, epsccjob->ipclen,
                job->origreq->type, job->liid) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(enc->encoder, body);
    /* Success */
    return 1;

}


static int encode_templated_epsiri(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    wandder_encoded_result_t *body = NULL;
    openli_mobiri_job_t *irijob =
            (openli_mobiri_job_t *)&(job->origreq->data.mobiri);

    create_mobile_operator_identifier(enc, irijob,
            EPSIRI_CONTENTS_OPERATOR_IDENTIFIER);

    /* Not worth trying to template the body of EPS IRIs -- way too
     * many variables in here that may or may not change on a semi-regular
     * basis.
     */
    reset_wandder_encoder(enc->encoder);

    body = encode_epsiri_body(enc->encoder, job->preencoded, irijob->iritype,
            irijob->customparams);

    if (body == NULL || body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI EPSIRI body");
        if (body) {
            wandder_release_encoded_result(enc->encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_iri,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {

            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job->origreq->type, job->liid) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(enc->encoder, body);
    free_mobileiri_parameters(irijob->customparams);
    /* Success */
    return 1;
}

static int encode_templated_umtsiri(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    wandder_encoded_result_t *body = NULL;
    openli_mobiri_job_t *irijob =
            (openli_mobiri_job_t *)&(job->origreq->data.mobiri);

    create_mobile_operator_identifier(enc, irijob,
            UMTSIRI_CONTENTS_OPERATOR_IDENTIFIER);
    /* Not worth trying to template the body of UMTS IRIs -- way too
     * many variables in here that may or may not change on a semi-regular
     * basis.
     */
    reset_wandder_encoder(enc->encoder);

    /* Assuming SIP here for now, other protocols can be supported later */
    body = encode_umtsiri_body(enc->encoder, job->preencoded, irijob->iritype,
            irijob->customparams);


    if (body == NULL || body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI UMTSIRI body");
        if (body) {
            wandder_release_encoded_result(enc->encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_iri,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {

            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job->origreq->type, job->liid) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(enc->encoder, body);
    free_mobileiri_parameters(irijob->customparams);
    /* Success */
    return 1;
}

static int encode_templated_umtscc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate, openli_encoded_result_t *res) {

    uint32_t key = 0;
    encoded_global_template_t *umtscc_tplate = NULL;
    openli_ipcc_job_t *ccjob;
    uint8_t is_new = 0;

    ccjob = (openli_ipcc_job_t *)&(job->origreq->data.ipcc);

    if (ccjob->dir == ETSI_DIR_FROM_TARGET) {
        key = (TEMPLATE_TYPE_UMTSCC_DIRFROM << 16) + ccjob->ipclen;
    } else if (ccjob->dir == ETSI_DIR_TO_TARGET) {
        key = (TEMPLATE_TYPE_UMTSCC_DIRTO << 16) + ccjob->ipclen;
    } else {
        key = (TEMPLATE_TYPE_UMTSCC_DIROTHER << 16) + ccjob->ipclen;
    }

    umtscc_tplate = lookup_global_template(&(enc->saved_global_templates),
            key, &is_new);

    if (is_new) {
        if (etsili_create_umtscc_template(enc->encoder, job->preencoded,
                ccjob->dir, ccjob->ipclen, umtscc_tplate) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to create UMTSCC template?");
            return -1;
        }
    }
    /* We have very specific templates for each observed packet size, so
     * this will not require updating */

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_cc,
                res, hdr_tplate,
                umtscc_tplate->cc_content.cc_wrap,
                umtscc_tplate->cc_content.cc_wrap_len,
                (uint8_t *)ccjob->ipcontent, ccjob->ipclen, job) < 0) {
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate,
                umtscc_tplate->cc_content.cc_wrap,
                umtscc_tplate->cc_content.cc_wrap_len,
                (uint8_t *)ccjob->ipcontent, ccjob->ipclen,
                job->origreq->type, job->liid) < 0) {
            return -1;
        }
    }

    /* Success */
    return 1;

}


static int encode_templated_emailcc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    uint32_t key = 0;
    encoded_global_template_t *emailcc_tplate = NULL;
    openli_emailcc_job_t *emailccjob;
    uint8_t is_new = 0;

    emailccjob = (openli_emailcc_job_t *)&(job->origreq->data.emailcc);

    if (emailccjob->format == ETSILI_EMAIL_CC_FORMAT_IP &&
            emailccjob->dir == ETSI_DIR_FROM_TARGET) {
        key = (TEMPLATE_TYPE_EMAILCC_IP_DIRFROM << 16) +
                emailccjob->cc_content_len;
    } else if (emailccjob->format == ETSILI_EMAIL_CC_FORMAT_APP &&
            emailccjob->dir == ETSI_DIR_FROM_TARGET) {
        key = (TEMPLATE_TYPE_EMAILCC_APP_DIRFROM << 16) +
                emailccjob->cc_content_len;
    } else if (emailccjob->format == ETSILI_EMAIL_CC_FORMAT_IP &&
            emailccjob->dir == ETSI_DIR_TO_TARGET) {
        key = (TEMPLATE_TYPE_EMAILCC_IP_DIRTO << 16) +
                emailccjob->cc_content_len;
    } else if (emailccjob->format == ETSILI_EMAIL_CC_FORMAT_APP &&
            emailccjob->dir == ETSI_DIR_TO_TARGET) {
        key = (TEMPLATE_TYPE_EMAILCC_APP_DIRTO << 16) +
                emailccjob->cc_content_len;
    } else if (emailccjob->format == ETSILI_EMAIL_CC_FORMAT_IP &&
            emailccjob->dir == ETSI_DIR_INDETERMINATE) {
        key = (TEMPLATE_TYPE_EMAILCC_IP_DIROTHER << 16) +
                emailccjob->cc_content_len;
    } else if (emailccjob->format == ETSILI_EMAIL_CC_FORMAT_APP &&
            emailccjob->dir == ETSI_DIR_INDETERMINATE) {
        key = (TEMPLATE_TYPE_EMAILCC_APP_DIROTHER << 16) +
                emailccjob->cc_content_len;
    } else {
        logger(LOG_INFO, "Unexpected format + direction for EmailCC: %u %u",
                emailccjob->format, emailccjob->dir);
        return -1;
    }

    emailcc_tplate = lookup_global_template(&(enc->saved_global_templates),
            key, &is_new);

    if (is_new) {
        if (etsili_create_emailcc_template(enc->encoder, job->preencoded,
                emailccjob->format, emailccjob->dir,
                emailccjob->cc_content_len, emailcc_tplate) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to create EmailCC template?");
            return -1;
        }
    }
    /* We have very specific templates for each observed packet size, so
     * this will not require updating */
    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_cc,
                res, hdr_tplate,
                emailcc_tplate->cc_content.cc_wrap,
                emailcc_tplate->cc_content.cc_wrap_len,
                (uint8_t *)emailccjob->cc_content,
                emailccjob->cc_content_len, job) < 0) {
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate,
                emailcc_tplate->cc_content.cc_wrap,
                emailcc_tplate->cc_content.cc_wrap_len,
                (uint8_t *)emailccjob->cc_content,
                emailccjob->cc_content_len, job->origreq->type,
                job->liid) < 0) {
            return -1;
        }
    }

    return 1;
}

static int encode_templated_ipcc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoder_liid_state_t *known,
        encoded_header_template_t *hdr_tplate, openli_encoded_result_t *res) {

    uint32_t key = 0;
    encoded_global_template_t *ipcc_tplate = NULL;
    openli_ipcc_job_t *ipccjob;
    uint8_t is_new = 0;

    ipccjob = (openli_ipcc_job_t *)&(job->origreq->data.ipcc);

    if (ipccjob->dir == ETSI_DIR_FROM_TARGET) {
        key = (TEMPLATE_TYPE_IPCC_DIRFROM << 16) + ipccjob->ipclen;
    } else if (ipccjob->dir == ETSI_DIR_TO_TARGET) {
        key = (TEMPLATE_TYPE_IPCC_DIRTO << 16) + ipccjob->ipclen;
    } else {
        key = (TEMPLATE_TYPE_IPCC_DIROTHER << 16) + ipccjob->ipclen;
    }

    ipcc_tplate = lookup_global_template(&(enc->saved_global_templates),
            key, &is_new);

    if (is_new) {
        if (etsili_create_ipcc_template(enc->encoder, job->preencoded,
                ipccjob->dir, ipccjob->ipclen, ipcc_tplate) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to create IPCC template?");
            return -1;
        }
    }
    /* We have very specific templates for each observed packet size, so
     * this will not require updating */
    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(enc->encoder, &known->encrypt_cc,
                res, hdr_tplate,
                ipcc_tplate->cc_content.cc_wrap,
                ipcc_tplate->cc_content.cc_wrap_len,
                (uint8_t *)ipccjob->ipcontent,
                ipccjob->ipclen, job) < 0) {
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate,
                ipcc_tplate->cc_content.cc_wrap,
                ipcc_tplate->cc_content.cc_wrap_len,
                (uint8_t *)ipccjob->ipcontent,
                ipccjob->ipclen, job->origreq->type, job->liid) < 0) {
            return -1;
        }
    }

    /* Success */
    return 1;

}

static int encode_etsi(openli_encoder_t *enc, openli_encoding_job_t *job,
        encoder_liid_state_t *known, openli_encoded_result_t *resarray,
        size_t *next) {

    int ret = -1;
    int enccount = 1;
    char keystr[1000];
    PWord_t pval;
    saved_encoding_templates_t *t_set = NULL;
    encoded_header_template_t *hdr_tplate = NULL;
    struct timeval *tsptr = NULL;
    openli_encoded_result_t *res = &(resarray[(*next)]);

    snprintf(keystr, 1000, "%s-%s-%u", job->liid, job->cinstr,
            job->timefmt);
    JSLI(pval, enc->saved_intercept_templates, (const uint8_t *)keystr);
    if ((*pval)) {
        t_set = (saved_encoding_templates_t *)(*pval);
    } else {
        t_set = calloc(1, sizeof(saved_encoding_templates_t));
        t_set->key = strdup(keystr);
        (*pval) = (Word_t)t_set;
    }
    if (job->origreq->type == OPENLI_EXPORT_FIRST_SEGMENT_FLAG ||
            job->origreq->type == OPENLI_EXPORT_LAST_SEGMENT_FLAG) {
        tsptr = NULL;
    } else {
        tsptr = &(job->origreq->ts);
    }

    hdr_tplate = encode_templated_psheader(enc->encoder, &(t_set->headers),
            job->preencoded, job->seqno, tsptr, job->cin,
            job->cept_version, job->timefmt);

    switch (job->origreq->type) {
        case OPENLI_EXPORT_IPCC:
            /* IPCC "header" can be templated */
            ret = encode_templated_ipcc(enc, job, known, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_IPMMCC:
            ret = encode_templated_ipmmcc(enc->encoder, &known->encrypt_cc,
                    job, hdr_tplate, res, &(enc->saved_global_templates));
            break;
        case OPENLI_EXPORT_UMTSCC:
            ret = encode_templated_umtscc(enc, job, known, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_IPIRI:
            ret = encode_templated_ipiri(enc, job, known, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_IPMMIRI:
            ret = encode_templated_ipmmiri(enc->encoder, &known->encrypt_iri,
                    job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_UMTSIRI:
            ret = encode_templated_umtsiri(enc, job, known, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_EPSIRI:
            ret = encode_templated_epsiri(enc, job, known, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_EMAILIRI:
            ret = encode_templated_emailiri(enc, job, known, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_EMAILCC: {
            openli_emailcc_job_t *emailccjob;
            emailccjob = (openli_emailcc_job_t *)&(job->origreq->data.emailcc);

            if (emailccjob->segflag == OPENLI_EXPORT_FIRST_SEGMENT_FLAG) {
                ret = encode_templated_segflag(enc, job, known, hdr_tplate,
                        res, 1);
                if (ret < 0) {
                    return ret;
                }
                finalize_encoded_result(res, job, enc, known,
                        OPENLI_EXPORT_FIRST_SEGMENT_FLAG);
                (*next)++;
                res = &(resarray[*next]);
                enccount = 2;
            }
            ret = encode_templated_emailcc(enc, job, known, hdr_tplate, res);
            if (ret < 0) {
                return ret;
            }
            if (emailccjob->segflag == OPENLI_EXPORT_LAST_SEGMENT_FLAG) {
                finalize_encoded_result(res, job, enc, known,
                        job->origreq->type);
                (*next)++;
                res = &(resarray[*next]);
                ret = encode_templated_segflag(enc, job, known, hdr_tplate,
                        res, 0);
                finalize_encoded_result(res, job, enc, known,
                        OPENLI_EXPORT_LAST_SEGMENT_FLAG);
                // can fall through in every other case EXCEPT the one where
                // we need to ensure the last segment TRI has the right
                // 'restype' set.
                return 2;
            }
            break;
        }
        case OPENLI_EXPORT_EPSCC:
            ret = encode_templated_epscc(enc, job, known, hdr_tplate, res);
            break;
        default:
            ret = 0;
    }

    finalize_encoded_result(res, job, enc, known, job->origreq->type);

    if (ret < 0) {
        return ret;
    }
    return enccount;
}

static int process_job(openli_encoder_t *enc, void *socket) {
    int x, i;
    int encoded_total = 0;
    size_t next;
    uint8_t fullbatch = 0;
    encoder_liid_state_t *found = NULL;

    openli_encoding_job_t job;

    for (i = 0; i < enc->forwarders; i++) {
        if (enc->result_array[i] == NULL) {
            /* +1 to leave room for a segmentFlag TRI if required */
            enc->result_array[i] = calloc(MAX_ENCODED_RESULT_BATCH + 1,
                    sizeof(openli_encoded_result_t));
        }
        enc->result_batch[i] = 0;
    }

    while (!fullbatch) {
        openli_encoded_result_t *result = NULL;

        memset(&job, 0, sizeof(openli_encoding_job_t));
        x = zmq_recv(socket, &job, sizeof(openli_encoding_job_t), 0);
        if (x < 0 && (errno != EAGAIN && errno != EINTR)) {
            logger(LOG_INFO,
                    "OpenLI: error reading job in encoder worker %d",
                    enc->workerid);
            encoded_total = -1;
            break;
        } else if (x < 0) {
            break;
        } else if (x == 0) {
            encoded_total = 0;
            break;
        }

        if (job.liid == NULL) {
            goto encodejoberror;
        }

        HASH_FIND(hh, enc->known_liids, job.liid, strlen(job.liid), found);

        if (job.origreq == NULL) {
            /* This is a message to tell us that the intercept is no
             * longer active. Remove integrity check state as well */
            if (found) {
                integrity_check_state_t *ics, *tmp;
                HASH_DELETE(hh, enc->known_liids, found);
                // remove all integrity state chains for this LIID
                HASH_ITER(hh, enc->integrity_state, ics, tmp) {
                    if (strcmp(job.liid, ics->liid_key) != 0) {
                        continue;
                    }
                    HASH_DELETE(hh, enc->integrity_state, ics);
                    /* make sure we send final hashes and signatures */
                    send_integrity_check_hash_pdu(enc, ics);
                    send_integrity_check_sign_pdu(enc, ics);
                    free_integrity_check_state(ics);
                }
                destroy_known_liid(found);
            }
            destroy_encoding_job(&job, 0);
            continue;
        }

        if (!found) {
            found = create_new_known_liid(enc, job.liid, job.authcc,
                    job.delivcc, job.operatorid);
        }

        check_agency_digest_config(enc, found);

        result = enc->result_array[found->fwd_index];
        next = enc->result_batch[found->fwd_index];

        if (job.origreq->type == OPENLI_EXPORT_RAW_SYNC) {
            encode_rawip(enc, &job, &(result[next]), OPENLI_PROTO_RAWIP_SYNC);
            x = 1;
        } else if (job.origreq->type == OPENLI_EXPORT_RAW_CC) {
            encode_rawip(enc, &job, &(result[next]), OPENLI_PROTO_RAWIP_CC);
            x = 1;
        } else if (job.origreq->type == OPENLI_EXPORT_RAW_IRI) {
            encode_rawip(enc, &job, &(result[next]), OPENLI_PROTO_RAWIP_IRI);
            x = 1;
        } else {
            if ((x = encode_etsi(enc, &job, found, result, &next)) <= 0) {
                /* What do we do in the event of an error? */
                if (x < 0) {
                    logger(LOG_INFO,
                            "OpenLI: encoder worker had an error when encoding %d record",
                            job.origreq->type);
                }
encodejoberror:
                destroy_encoding_job(&job, 1);
                continue;
            }
        }

        encoded_total += x;
        enc->result_batch[found->fwd_index] = next + 1;

        if (enc->result_batch[found->fwd_index] >= MAX_ENCODED_RESULT_BATCH) {
            fullbatch = 1;

        }
        destroy_encoding_job(&job, 0);
    }

    /* If we have multiple forwarding threads, we will need to
     * assign individual results to the forwarder based on its LIID --
     * this will also require multiple result[] arrays (one per forwarder)
     * for message batching.
     */
    for (i = 0; i < enc->forwarders; i++) {
        if (enc->result_batch[i] == 0 || encoded_total <= 0) {
            continue;
        }

        if (zmq_send(enc->zmq_pushresults[i], enc->result_array[i],
                    enc->result_batch[i] * sizeof(openli_encoded_result_t),
                    0) < 0) {
            logger(LOG_INFO, "OpenLI: error while pushing encoded result to forwarding thread %d (worker=%d)", i, enc->workerid);
            encoded_total = 1;
            break;
        }
    }

    if (fullbatch) {
        /* More messages are possibly available. Since the ZMQ epoll event
         * is edge-triggered, the ZMQ fd itself won't fire again in epoll to
         * remind us that we left some jobs unread. Instead we write something
         * into the yield fd to trigger the ZMQ_YIELD event -- our main loop
         * then knows that it should resume reading from the ZMQ even if ZMQ
         * itself has not triggered an event.
         */
        uint64_t u = 1;
        if (write(enc->yield_fd, &u, sizeof(u)) <= 0) {
            return -1;
        }
    }

    return encoded_total;
}

static int integrity_hash_timer_callback(openli_encoder_t *enc,
        openli_epoll_ev_t *mev) {

    integrity_check_state_t *ics;

    if (mev == NULL) {
        return -1;
    }

    ics = (integrity_check_state_t *)(mev->state);
    if (ics == NULL) {
        return 0;
    }

    return send_integrity_check_hash_pdu(enc, ics);
}

static int integrity_sign_timer_callback(openli_encoder_t *enc,
        openli_epoll_ev_t *mev) {

    integrity_check_state_t *ics;

    if (mev == NULL) {
        return -1;
    }

    ics = (integrity_check_state_t *)(mev->state);
    if (ics == NULL) {
        return 0;
    }

    return send_integrity_check_sign_pdu(enc, ics);
}

static int handle_epoll_event(openli_encoder_t *enc, struct epoll_event *ev) {

    openli_epoll_ev_t *mev = (openli_epoll_ev_t *)(ev->data.ptr);
    int ret = 0;

    switch(mev->fdtype) {
        case OPENLI_EPOLL_ENCODING_CONTROL:
            // Time to halt the worker
            return -1;
        case OPENLI_EPOLL_ZMQ_YIELD:
        case OPENLI_EPOLL_ENCODING_JOB:
            ret = process_job(enc, enc->zmq_recvjob);
            break;
        case OPENLI_EPOLL_INTEGRITY_HASH_TIMER:
            ret = integrity_hash_timer_callback(enc, mev);
            break;
        case OPENLI_EPOLL_INTEGRITY_SIGN_TIMER:
            ret = integrity_sign_timer_callback(enc, mev);
            break;
        default:
            logger(LOG_INFO, "OpenLI collector: invalid epoll event type %d seen in encoder worker %d", mev->fdtype, enc->workerid);
            ret = -1;
    }

    return ret;
}


static inline void poll_nextjob(openli_encoder_t *enc) {
    int x, nfds, i;
    struct epoll_event evs[256];
    uint32_t zmq_events;
    size_t size = sizeof(zmq_events);

    while (!enc->halted) {
        nfds = epoll_wait(enc->epoll_fd, evs, 256, 100);
        if (nfds < 0) {
            if (errno == EINTR) {
                sched_yield();
                continue;
            }
            logger(LOG_INFO, "OpenLI collector: error while waiting for epoll events in encoder worker %d: %s", enc->workerid, strerror(errno));
            break;
        }
        for (i = 0; i < nfds; i++) {
            x = handle_epoll_event(enc, &(evs[i]));
            if (x < 0) {
                enc->halted = 1;
                break;
            }
        }

        if (nfds == 0) {
            zmq_getsockopt(enc->zmq_recvjob, ZMQ_EVENTS, &zmq_events, &size);
            if (zmq_events & ZMQ_POLLIN) {
                process_job(enc, enc->zmq_recvjob);
            }
        }
    }
    enc->halted = 1;
}


void *run_encoder_worker(void *encstate) {
    openli_encoder_t *enc = (openli_encoder_t *)encstate;
    int i;
    sigset_t mask, verify;

    sigfillset(&mask);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);

    pthread_sigmask(SIG_SETMASK, NULL, &verify);
    if (!sigismember(&verify, SIGINT)) {
        logger(LOG_INFO, "Mask FAILED to stick immediately after setting!");
    }

    if (init_worker(enc) == -1) {
        logger(LOG_INFO,
                "OpenLI: encoder worker thread %d failed to initialise",
                enc->workerid);
        pthread_exit(NULL);
    }

    while (!enc->halted) {
        poll_nextjob(enc);
    }
    for (i = 0; i < enc->forwarders; i++) {
        if (enc->zmq_pushresults[i]) {
            openli_encoded_result_t final;

            memset(&final, 0, sizeof(final));
            zmq_send(enc->zmq_pushresults[i], &final, sizeof(final), 0);
            zmq_close(enc->zmq_pushresults[i]);
        }
        if (enc->result_array[i]) {
            free(enc->result_array[i]);
        }
    }
    if (enc->result_array) {
        free(enc->result_array);
    }
    if (enc->result_batch) {
        free(enc->result_batch);
    }
    logger(LOG_INFO, "OpenLI: halting encoding worker %d", enc->workerid);
    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
