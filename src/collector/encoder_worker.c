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

static int init_worker(openli_encoder_t *enc) {
    int zero = 0, rto = 10;
    int hwm = 1000;
    int i;
    char sockname[128];

    enc->encoder = init_wandder_encoder();
    enc->freegenerics = create_etsili_generic_freelist(0);
    enc->halted = 0;

    enc->zmq_recvjobs = calloc(enc->seqtrackers, sizeof(void *));
    for (i = 0; i < enc->seqtrackers; i++) {
        enc->zmq_recvjobs[i] = zmq_socket(enc->zmq_ctxt, ZMQ_PULL);
        snprintf(sockname, 128, "inproc://openliseqpush-%d", i);
        if (zmq_setsockopt(enc->zmq_recvjobs[i], ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
            logger(LOG_INFO, "OpenLI: error configuring connection to zmq pull socket");
            return -1;
        }

        if (zmq_setsockopt(enc->zmq_recvjobs[i], ZMQ_RCVTIMEO, &rto,
                sizeof(rto)) != 0) {
            logger(LOG_INFO, "OpenLI: error configuring connection to zmq pull socket");
            return -1;
        }
        if (zmq_connect(enc->zmq_recvjobs[i], sockname) != 0) {
            logger(LOG_INFO, "OpenLI: error connecting to zmq pull socket");
            return -1;
        }

    }

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

    enc->zmq_control = zmq_socket(enc->zmq_ctxt, ZMQ_SUB);
    if (zmq_connect(enc->zmq_control, "inproc://openliencodercontrol") != 0) {
        logger(LOG_INFO, "OpenLI: error connecting to exporter control socket");
        return -1;
    }

    if (zmq_setsockopt(enc->zmq_control, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: error configuring connection to exporter control socket");
        return -1;
    }

    if (zmq_setsockopt(enc->zmq_control, ZMQ_SUBSCRIBE, "", 0) != 0) {
        logger(LOG_INFO, "OpenLI: error configuring subscription to exporter control socket");
        return -1;
    }

    enc->topoll = calloc(enc->seqtrackers + 1, sizeof(zmq_pollitem_t));

    enc->topoll[0].socket = enc->zmq_control;
    enc->topoll[0].fd = 0;
    enc->topoll[0].events = ZMQ_POLLIN;

    for (i = 0; i < enc->seqtrackers; i++) {
        enc->topoll[i + 1].socket = enc->zmq_recvjobs[i];
        enc->topoll[i + 1].fd = 0;
        enc->topoll[i + 1].events = ZMQ_POLLIN;
    }

    return 0;

}

static void free_encoded_header_templates(Pvoid_t headers) {
    PWord_t pval;
    Word_t index = 0;

    JLF(pval, headers, index);
    while (pval) {
        encoded_header_template_t *tplate;

        tplate = (encoded_header_template_t *)(*pval);
        if (tplate->header) {
            free(tplate->header);
        }
        free(tplate);
        JLN(pval, headers, index);
    }
}

static void free_mobileiri_parameters(etsili_generic_t *params) {

    etsili_generic_t *oldp, *tmp;

    HASH_ITER(hh, params, oldp, tmp) {
        HASH_DELETE(hh, params, oldp);
        release_etsili_generic(oldp);
    }

}

void destroy_encoder_worker(openli_encoder_t *enc) {
    int x, i, rcint;
    openli_encoding_job_t job;
    uint32_t drained = 0;
    PWord_t pval;
    uint8_t index[1000];
    Word_t rcw, indexint;

    index[0] = '\0';

    JSLF(pval, enc->saved_intercept_templates, index);
    while (pval) {
        saved_encoding_templates_t *t_set;

        t_set = (saved_encoding_templates_t *)(*pval);
        if (t_set->key) {
            free(t_set->key);
        }
        free_encoded_header_templates(t_set->headers);
        JLFA(rcint, t_set->headers);

        assert(t_set->ccpayloads == NULL);
        assert(t_set->iripayloads == NULL);
        free(t_set);

        JSLN(pval, enc->saved_intercept_templates, index);
    }
    JSLFA(rcw, enc->saved_intercept_templates);

    indexint = 0;
    JLF(pval, enc->saved_global_templates, indexint);
    while (pval) {
        encoded_global_template_t *t;

        t = (encoded_global_template_t *)(*pval);
        if (t->cc_content.cc_wrap) {
            free(t->cc_content.cc_wrap);
        }
        free(t);
        JLN(pval, enc->saved_global_templates, indexint);
    }
    JLFA(rcint, enc->saved_global_templates);

    etsili_destroy_encrypted_templates(enc->encrypt.saved_encryption_templates);
    if (enc->encoder) {
        free_wandder_encoder(enc->encoder);
    }

    if (enc->freegenerics) {
        free_etsili_generics(enc->freegenerics);
    }

    for (i = 0; i < enc->seqtrackers; i++) {
        do {
            x = zmq_recv(enc->zmq_recvjobs[i], &job,
                    sizeof(openli_encoding_job_t), 0);
            if (x < 0) {
                if (errno == EAGAIN) {
                    continue;
                }
                break;
            }
            if (job.origreq) {
                free_published_message(job.origreq);
            }
            if (job.liid) {
                free(job.liid);
            }
            if (job.cinstr) {
                free(job.cinstr);
            }
            if (job.encryptkey) {
                free(job.encryptkey);
            }
            drained ++;

        } while (x > 0);
        zmq_close(enc->zmq_recvjobs[i]);
    }

    if (enc->encrypt.evp_ctx) {
        EVP_CIPHER_CTX_free(enc->encrypt.evp_ctx);
    }

    if (enc->zmq_control) {
        zmq_close(enc->zmq_control);
    }

    for (i = 0; i < enc->forwarders; i++) {
        if (enc->zmq_pushresults[i]) {
            openli_encoded_result_t final;

            memset(&final, 0, sizeof(final));
            zmq_send(enc->zmq_pushresults[i], &final, sizeof(final), 0);
            zmq_close(enc->zmq_pushresults[i]);
        }
    }
    free(enc->zmq_recvjobs);
    free(enc->zmq_pushresults);
    free(enc->topoll);

}

static int encode_rawip(openli_encoding_job_t *job,
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

    return 0;
}

static int encode_templated_ipiri(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
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

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            free_ipiri_parameters(params);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job) < 0) {
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

static inline encoded_global_template_t *lookup_global_template(
        openli_encoder_t *enc, uint32_t key, uint8_t *is_new) {

    PWord_t pval;
    encoded_global_template_t *ipcc_tplate = NULL;

    JLG(pval, enc->saved_global_templates, key);
    if (pval == NULL) {
        ipcc_tplate = calloc(1, sizeof(encoded_global_template_t));
        ipcc_tplate->key = key;
        ipcc_tplate->cctype = (key >> 16);
        JLI(pval, enc->saved_global_templates, key);
        *pval = (Word_t)ipcc_tplate;
        *is_new = 1;
    } else {
        ipcc_tplate = (encoded_global_template_t *)(*pval);
        *is_new = 0;
    }

    return ipcc_tplate;
}

static int encode_templated_ipmmcc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    uint32_t key = 0;
    encoded_global_template_t *ipmmcc_tplate = NULL;
    openli_ipcc_job_t *mmccjob;
    uint8_t is_new = 0;

    mmccjob = (openli_ipcc_job_t *)&(job->origreq->data.ipcc);

    /* We only handle IP frames and RTP protocol for IPMM so far... */

    if (mmccjob->dir == ETSI_DIR_FROM_TARGET) {
        key = (TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_RTP << 16) + mmccjob->ipclen;
    } else if (mmccjob->dir == ETSI_DIR_TO_TARGET) {
        key = (TEMPLATE_TYPE_IPMMCC_DIRTO_IP_RTP << 16) + mmccjob->ipclen;
    } else {
        key = (TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_RTP << 16) + mmccjob->ipclen;
    }

    ipmmcc_tplate = lookup_global_template(enc, key, &is_new);

    if (is_new) {
        if (etsili_create_ipmmcc_template(enc->encoder, job->preencoded,
                mmccjob->dir, mmccjob->ipcontent, mmccjob->ipclen,
                ipmmcc_tplate) < 0) {
            return -1;
        }
    } else {
        /* Overwrite the existing MMCCContents field */
        if (etsili_update_ipmmcc_template(ipmmcc_tplate, mmccjob->ipcontent,
                mmccjob->ipclen) < 0) {
            return -1;
        }
    }

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
                res, hdr_tplate,
                ipmmcc_tplate->cc_content.cc_wrap,
                ipmmcc_tplate->cc_content.cc_wrap_len,
                NULL, 0, job) < 0) {
            return -1;
        }

    } else {
        if (create_etsi_encoded_result(res, hdr_tplate,
                ipmmcc_tplate->cc_content.cc_wrap,
                ipmmcc_tplate->cc_content.cc_wrap_len, NULL, 0, job) < 0) {
            return -1;
        }
    }

    /* Success */
    return 1;
}

static int encode_templated_emailiri(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
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

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job) < 0) {
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

static int encode_templated_epscc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
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
            epsccjob->icetype, epsccjob->ipclen);

    if (body == NULL ||  body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI EPSCC body");
        if (body) {
            wandder_release_encoded_result(enc->encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
                res, hdr_tplate,
                body->encoded, body->len, epsccjob->ipcontent,
                epsccjob->ipclen, job) < 0) {

            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, epsccjob->ipcontent, epsccjob->ipclen, job) < 0) {
            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(enc->encoder, body);
    /* Success */
    return 1;

}


static int encode_templated_epsiri(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
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

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {

            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job) < 0) {
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
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
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

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
                res, hdr_tplate,
                body->encoded, body->len, NULL, 0, job) < 0) {

            wandder_release_encoded_result(enc->encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0, job) < 0) {
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
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

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

    umtscc_tplate = lookup_global_template(enc, key, &is_new);

    if (is_new) {
        if (etsili_create_umtscc_template(enc->encoder, job->preencoded,
                ccjob->dir, ccjob->ipclen, umtscc_tplate) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to create UMTSCC template?");
            return -1;
        }
    }
    /* We have very specific templates for each observed packet size, so
     * this will not require updating */

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
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
                (uint8_t *)ccjob->ipcontent, ccjob->ipclen, job) < 0) {
            return -1;
        }
    }

    /* Success */
    return 1;

}


static int encode_templated_emailcc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
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

    emailcc_tplate = lookup_global_template(enc, key, &is_new);

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
    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
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
                emailccjob->cc_content_len, job) < 0) {
            return -1;
        }
    }

    /* Success */
    return 1;
}

static int encode_templated_ipcc(openli_encoder_t *enc,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

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

    ipcc_tplate = lookup_global_template(enc, key, &is_new);

    if (is_new) {
        if (etsili_create_ipcc_template(enc->encoder, job->preencoded,
                ipccjob->dir, ipccjob->ipclen, ipcc_tplate) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to create IPCC template?");
            return -1;
        }
    }
    /* We have very specific templates for each observed packet size, so
     * this will not require updating */
    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_encrypted_message_body(enc->encoder, &enc->encrypt,
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
                ipccjob->ipclen, job) < 0) {
            return -1;
        }
    }

    /* Success */
    return 1;

}

static encoded_header_template_t *encode_templated_psheader(
        wandder_encoder_t *encoder, saved_encoding_templates_t *t_set,
        openli_encoding_job_t *job) {

    uint8_t seqlen, tvsec_len, tvusec_len;
    uint32_t key = 0;
    PWord_t pval;
    encoded_header_template_t *tplate = NULL;

    if (job->origreq->ts.tv_sec == 0) {
        gettimeofday(&(job->origreq->ts), NULL);
    }

    seqlen = DERIVE_INTEGER_LENGTH(job->seqno);
    tvsec_len = DERIVE_INTEGER_LENGTH(job->origreq->ts.tv_sec);
    tvusec_len = DERIVE_INTEGER_LENGTH(job->origreq->ts.tv_usec);

    key = (job->cept_version << 24) + (seqlen << 16) +
            (tvsec_len << 8) + tvusec_len;

    JLI(pval, t_set->headers, key);
    if (*pval == 0) {
        tplate = calloc(1, sizeof(encoded_header_template_t));

        if (etsili_create_header_template(encoder, job->preencoded,
                (int64_t)job->cin, (int64_t)job->seqno, &(job->origreq->ts),
                tplate) < 0) {
            free(tplate);
            return NULL;
        }

        *pval = (Word_t)tplate;

    } else {
        tplate = (encoded_header_template_t *)(*pval);

        if (etsili_update_header_template(tplate, (int64_t)job->seqno,
                &(job->origreq->ts)) < 0) {
            return NULL;
        }
    }

    return tplate;
}

static int encode_etsi(openli_encoder_t *enc, openli_encoding_job_t *job,
        openli_encoded_result_t *res) {

    int ret = -1;
    char keystr[1000];
    PWord_t pval;
    saved_encoding_templates_t *t_set = NULL;
    encoded_header_template_t *hdr_tplate = NULL;

    snprintf(keystr, 1000, "%s-%s", job->liid, job->cinstr);
    JSLI(pval, enc->saved_intercept_templates, (const uint8_t *)keystr);
    if ((*pval)) {
        t_set = (saved_encoding_templates_t *)(*pval);
    } else {
        t_set = calloc(1, sizeof(saved_encoding_templates_t));
        t_set->key = strdup(keystr);
        (*pval) = (Word_t)t_set;
    }

    hdr_tplate = encode_templated_psheader(enc->encoder, t_set, job);

    switch (job->origreq->type) {
        case OPENLI_EXPORT_IPCC:
            /* IPCC "header" can be templated */
            ret = encode_templated_ipcc(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_IPMMCC:
            ret = encode_templated_ipmmcc(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_UMTSCC:
            ret = encode_templated_umtscc(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_IPIRI:
            ret = encode_templated_ipiri(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_IPMMIRI:
            ret = encode_templated_ipmmiri(enc->encoder, &enc->encrypt,
                    job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_UMTSIRI:
            ret = encode_templated_umtsiri(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_EPSIRI:
            ret = encode_templated_epsiri(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_EMAILIRI:
            ret = encode_templated_emailiri(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_EMAILCC:
            ret = encode_templated_emailcc(enc, job, hdr_tplate, res);
            break;
        case OPENLI_EXPORT_EPSCC:
            ret = encode_templated_epscc(enc, job, hdr_tplate, res);
            break;
        default:
            ret = 0;
    }

    return ret;
}

static int process_job(openli_encoder_t *enc, void *socket) {
    int x, i;
    int encoded_total = 0;
    size_t index, next;
    uint8_t fullbatch = 0;

    openli_encoding_job_t job;
    openli_encoded_result_t **result_array;
    size_t *result_batch;

    result_array = calloc(enc->forwarders, sizeof(openli_encoded_result_t *));
    result_batch = calloc(enc->forwarders, sizeof(size_t));

    for (i = 0; i < enc->forwarders; i++) {
        result_array[i] = calloc(MAX_ENCODED_RESULT_BATCH,
                sizeof(openli_encoded_result_t));
        result_batch[i] = 0;
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

        index = hash_liid(job.liid) % enc->forwarders;
        assert(enc->forwarders > 0 && index < (size_t)enc->forwarders);

        result = result_array[index];
        next = result_batch[index];

        if (job.origreq->type == OPENLI_EXPORT_RAW_SYNC) {
            encode_rawip(&job, &(result[next]), OPENLI_PROTO_RAWIP_SYNC);
        } else if (job.origreq->type == OPENLI_EXPORT_RAW_CC) {
            encode_rawip(&job, &(result[next]), OPENLI_PROTO_RAWIP_CC);
        } else if (job.origreq->type == OPENLI_EXPORT_RAW_IRI) {
            encode_rawip(&job, &(result[next]), OPENLI_PROTO_RAWIP_IRI);
        } else {

            if ((x = encode_etsi(enc, &job, &(result[next]))) <= 0) {
                /* What do we do in the event of an error? */
                if (x < 0) {
                    logger(LOG_INFO,
                            "OpenLI: encoder worker had an error when encoding %d record",
                            job.origreq->type);
                }
encodejoberror:
                if (job.cinstr) {
                    free(job.cinstr);
                }
                if (job.liid) {
                    free(job.liid);
                }
                if (job.encryptkey) {
                    free(job.encryptkey);
                }
                if (job.origreq) {
                    free_published_message(job.origreq);
                }
                continue;
            }
        }

        result[next].cinstr = job.cinstr;
        result[next].liid = job.liid;
        result[next].seqno = job.seqno;
        result[next].destid = job.origreq->destid;
        result[next].origreq = job.origreq;
        result[next].encodedby = enc->workerid;

        if (job.encryptkey) {
            free(job.encryptkey);
        }
        encoded_total ++;
        result_batch[index] ++;

        if (result_batch[index] >= MAX_ENCODED_RESULT_BATCH) {
            fullbatch = 1;
        }
    }

    /* TODO if we have multiple forwarding threads, we will need to
     * assign individual results to the forwarder based on its LIID --
     * this will also require multiple result[] arrays (one per forwarder)
     * for message batching.
     */
    for (i = 0; i < enc->forwarders; i++) {
        if (result_batch[i] == 0 || encoded_total <= 0) {
            free(result_array[i]);
            continue;
        }

        if (zmq_send(enc->zmq_pushresults[i], result_array[i],
                    result_batch[i] * sizeof(openli_encoded_result_t), 0) < 0) {
            logger(LOG_INFO, "OpenLI: error while pushing encoded result to forwarding thread %d (worker=%d)", i, enc->workerid);
            encoded_total = 1;
            break;
        }
        free(result_array[i]);
    }
    free(result_array);
    free(result_batch);

    return encoded_total;
}

static inline void poll_nextjob(openli_encoder_t *enc) {
    int x, i;
    int tmpbuf;

    x = zmq_recv(enc->zmq_control, &tmpbuf, sizeof(tmpbuf), ZMQ_DONTWAIT);

    if (x < 0 && errno != EAGAIN) {
        logger(LOG_INFO,
                "OpenLI: error reading ctrl msg in encoder worker %d",
                enc->workerid);
    }

    if (x >= 0) {
        enc->halted = 1;
        return;
    }

    /* TODO better error checking / handling for multiple seqtrackers */
    for (i = 0; i < enc->seqtrackers; i++) {
        x = process_job(enc, enc->topoll[i+1].socket);
    }

    return;
}

void *run_encoder_worker(void *encstate) {
    openli_encoder_t *enc = (openli_encoder_t *)encstate;

    if (init_worker(enc) == -1) {
        logger(LOG_INFO,
                "OpenLI: encoder worker thread %d failed to initialise",
                enc->workerid);
        pthread_exit(NULL);
    }

    while (!enc->halted) {
        poll_nextjob(enc);
    }
    logger(LOG_INFO, "OpenLI: halting encoding worker %d", enc->workerid);
    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
