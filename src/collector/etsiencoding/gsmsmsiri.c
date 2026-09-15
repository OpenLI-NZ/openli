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

#include <libwandder_etsili.h>
#include "etsiencoding.h"
#include "logger.h"
#include "intercept.h"
#include "etsili_core.h"

static wandder_encoded_result_t *encode_gsmsms_iri_body(
        wandder_encoder_t *encoder, wandder_encode_job_t *precomputed,
        openli_gsmsms_iri_job_t *job, struct timeval *tv) {

    wandder_encode_job_t *jobarray[10];
    uint32_t iriversion = 8;
    uint32_t gprstarget = 3;
    uint32_t enumval;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]); // Payload
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]); // IRIPayload
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_IRITYPE_REPORT]); // IRIType
    jobarray[4] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);  // IRIContents
    jobarray[5] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_4]); // UMTSIRI
    jobarray[6] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]); //IRI-Parameters
    jobarray[7] = &(precomputed[OPENLI_PREENCODE_UMTSIRIOID]); // hi2DomainId
    jobarray[8] = &(precomputed[OPENLI_PREENCODE_LIID]); // LIID
    jobarray[9] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_3]); // timeStamp


    wandder_encode_next_preencoded(encoder, jobarray, 10);

    /* timeStamp "body" */
    wandder_encode_next(encoder, WANDDER_TAG_UTCTIME,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, tv, sizeof(struct timeval));
    END_ENCODED_SEQUENCE(encoder, 1);

    /* initiator */
    enumval = job->initiator;
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &enumval, sizeof(enumval));

    /* party information (just the target) */
    ENC_CSEQUENCE(encoder, 9);
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &gprstarget, sizeof(gprstarget));
    ENC_CSEQUENCE(encoder, 1);

    /* party information -- IMSI */
    if (memcmp(job->target_imsi, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, job->target_imsi, 8);
    }

    if (job->target_msisdn_len > 0) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, job->target_msisdn,
                job->target_msisdn_len);
    }

    END_ENCODED_SEQUENCE(encoder, 2);

    ENC_CSEQUENCE(encoder, 14);         // SMS-report
    ENC_CSEQUENCE(encoder, 3);         // SMS-contents
    enumval = job->sms_initiator;
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &enumval, sizeof(enumval));

    enumval = job->transfer_status;
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &enumval, sizeof(enumval));

    if (job->tpdu && job->tpdu_len > 0) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, job->tpdu,
                (job->tpdu_len > 270) ? 270 : job->tpdu_len);
    }

    END_ENCODED_SEQUENCE(encoder, 2);

    // gprsEvent
    enumval = 11;           // SMS
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 20, &enumval, sizeof(enumval));

    // IRI version
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 23, &iriversion,
            sizeof(iriversion));

    END_ENCODED_SEQUENCE(encoder, 6);
    return wandder_encode_finish(encoder);
}

int encode_templated_gsmsmsiri(wandder_encoder_t *encoder,
        encrypt_encode_state_t *encrypt,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    wandder_encoded_result_t *body = NULL;
    openli_gsmsms_iri_job_t *smsjob =
            (openli_gsmsms_iri_job_t *)&(job->origreq->data.gsmsms);

    reset_wandder_encoder(encoder);
    body = encode_gsmsms_iri_body(encoder, job->preencoded, smsjob,
            &job->origreq->ts);

    // everything from here down could be a boiler-plate function
    if (body == NULL || body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI GSM-SMS IRI body");
        if (body) {
            wandder_release_encoded_result(encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(encoder, encrypt, res, hdr_tplate,
                body->encoded, body->len,
                NULL, 0, job) < 0) {
            wandder_release_encoded_result(encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0,
                job->origreq->type, job->liid) < 0) {
            wandder_release_encoded_result(encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(encoder, body);

    /* Success */
    return 1;
}

