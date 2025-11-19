/*
 *
 * Copyright (c) 2025 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by SearchLight Ltd.
 * For further information please see https://searchlight.nz
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
#include <assert.h>
#include <libwandder_etsili.h>
#include "intercept.h"
#include "etsili_core.h"
#include "etsiencoding.h"
#include "logger.h"
#include "util.h"

uint8_t etsi_hi1operationoid[8] = {0x00, 0x04, 0x00, 0x02, 0x02, 0x00, 0x01,
        0x06};

static inline void encode_hi1_notification_body(wandder_encoder_t *encoder,
        hi1_notify_data_t *not_data, char *shortopid) {

    struct timeval tv;

    /* We're not likely to be doing too many of these, so we can
     * get away without having to rely on pre-computing encoded fields
     * and all that extra optimization that we do for IRIs and CCs.
     */

    ENC_CSEQUENCE(encoder, 2);          // Payload

    ENC_CSEQUENCE(encoder, 3);          // HI1-Operation

    if (not_data->notify_type >= HI1_LI_ACTIVATED &&
            not_data->notify_type <= HI1_LI_MODIFIED) {
        ENC_CSEQUENCE(encoder, not_data->notify_type);   // Notification
        wandder_encode_next(encoder, WANDDER_TAG_OID,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0,
                etsi_hi1operationoid, sizeof(etsi_hi1operationoid));

        // encoding will differ based on whether LIID is binary or ASCII
        if (not_data->liid_format == OPENLI_LIID_FORMAT_BINARY_OCTETS) {
            uint8_t liidbuf[OPENLI_LIID_MAXSIZE];
            size_t liidsize = 0;
            liidsize = openli_convert_hexstring_to_binary(not_data->liid,
                    liidbuf, OPENLI_LIID_MAXSIZE);
            if (liidsize > 0) {
                wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, liidbuf, liidsize);

            } else {
                wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, "unknown",
                        strlen("unknown"));
            }
        } else {
            wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                    WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, not_data->liid,
                    strlen(not_data->liid));
        }

        ENC_CSEQUENCE(encoder, 2);      // CommunicationIdentifier (HI2)

        ENC_CSEQUENCE(encoder, 1);      // Network-Identifier
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, shortopid,
                strlen(shortopid));

        /* No network element ID required for this HI1 record (?) */

        wandder_encode_endseq(encoder); // End Network-Identifier
        wandder_encode_endseq(encoder);     // End CommunicationIdentifier (HI2)

        ENC_CSEQUENCE(encoder, 3);      // Timestamp
        tv.tv_sec = not_data->ts_sec;
        tv.tv_usec = not_data->ts_usec;

        wandder_encode_next(encoder, WANDDER_TAG_UTCTIME,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &tv,
                sizeof(tv));
        wandder_encode_endseq(encoder); // End Timestamp

        /* target-Information? */
        if (not_data->target_info) {
            wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                    WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, not_data->target_info,
                    strlen(not_data->target_info));
        }
        wandder_encode_endseq(encoder); // End Notification
    }

    /* TODO add support for alarm notifications */

    wandder_encode_endseq(encoder);     // End HI1-Operation
    wandder_encode_endseq(encoder);     // End Payload
    //wandder_encode_endseq(encoder);     // End Outermost Sequence
}

openli_encoded_result_t *encode_etsi_hi1_notification(
        wandder_encoder_t *encoder, hi1_notify_data_t *not_data,
        char *operatorid, char *shortopid,
        openli_timestamp_encoding_fmt_t timefmt,
        encrypt_encode_state_t *encryptstate,
        payload_encryption_method_t encryptmethod, uint8_t *encryptkey,
        uint32_t enckeylen) {

    struct timeval tv;
    wandder_etsipshdr_data_t hdrdata;
    encoded_header_template_t hdr_tplate;
    wandder_encoded_result_t *res;
    uint8_t *buf;
    uint8_t *notbody;
    uint32_t enclen = 0, notbody_len = 0;
    openli_encoded_result_t *encoded;
    EVP_CIPHER_CTX *evp_ctx;

    /* This is a bit clunky because I'm trying to re-use as much of the
     * existing encryption and encoding code as possible, which is
     * written more with the "collector wraps, mediator encrypts" pattern
     * in mind -- whereas here we are wrapping and then immediately
     * encrypting.
     */

    hdrdata.liid = not_data->liid;
    hdrdata.liid_len = strlen(not_data->liid);
    hdrdata.authcc = not_data->authcc;
    hdrdata.authcc_len = strlen(not_data->authcc);
    hdrdata.delivcc = not_data->delivcc;
    hdrdata.delivcc_len = strlen(not_data->delivcc);
    hdrdata.operatorid = operatorid;
    hdrdata.operatorid_len = strlen(operatorid);
    hdrdata.networkelemid = NULL;
    hdrdata.networkelemid_len = 0;
    hdrdata.intpointid = NULL;
    hdrdata.intpointid_len = 0;
    hdrdata.liid_format = not_data->liid_format;

    encoded = calloc(1, sizeof(openli_encoded_result_t));

    gettimeofday(&tv, NULL);

    reset_wandder_encoder(encoder);
    encode_etsili_pshdr(encoder, &hdrdata, 0, (int64_t)not_data->seqno, &tv,
            timefmt);
    res = wandder_encode_finish(encoder);

    // don't need the other template pointers because we're not re-using it
    hdr_tplate.header = malloc(res->len);
    hdr_tplate.header_len = res->len;
    memcpy(hdr_tplate.header, res->encoded, res->len);
    wandder_release_encoded_result(encoder, res);

    reset_wandder_encoder(encoder);
    encode_hi1_notification_body(encoder, not_data, shortopid);
    res = wandder_encode_finish(encoder);
    if (encryptmethod > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        uint32_t noencrypt = 1;
        uint32_t encpayloadtype = 8;

        notbody = malloc(res->len);
        memcpy(notbody, res->encoded, res->len);
        notbody_len = res->len;
        wandder_release_encoded_result(encoder, res);

        buf = wrap_etsili_preencryption(encryptstate, encryptmethod,
                hdr_tplate.header_len, notbody, notbody_len, NULL, 0,
                &enclen);
        reset_wandder_encoder(encoder);
        ENC_CSEQUENCE(encoder, 2);
        ENC_CSEQUENCE(encoder, 4);
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &noencrypt,
                sizeof(noencrypt));
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, buf, enclen);
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &encpayloadtype,
                sizeof(encpayloadtype));
        END_ENCODED_SEQUENCE(encoder, 2);

        res = wandder_encode_finish(encoder);
        free(buf);
        free(notbody);
    }

    buf = malloc(res->len);
    memcpy(buf, res->encoded, res->len);
    enclen = res->len;

    wandder_release_encoded_result(encoder, res);

    if (create_etsi_encoded_result(encoded, &hdr_tplate, buf, enclen, NULL,
            0, 0, NULL) < 0) {
        goto failstate;
    }

    if (encryptmethod == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        /* use existing methods to replace the wrapped unencrypted
         * payload generated above with the encrypted version
         */
        wandder_etsispec_t *etsidecoder;
        assert(enckeylen && encryptkey);

        // XXX it's probably OK to just create a new ctx here because we
        // won't be generating too many of these messages, but we could also
        // consider having a shared ctx for the whole thread if necessary.
        evp_ctx = EVP_CIPHER_CTX_new();

        etsidecoder = wandder_create_etsili_decoder();
        if (encrypt_payload_container_aes_192_cbc(evp_ctx, etsidecoder,
                encoded->msgbody->encoded, enclen,
                encryptkey, enckeylen) == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: error while attempting to encrypt HI1 notification for LIID %s in agency thread", not_data->liid);
            goto failstate;
        }

        wandder_free_etsili_decoder(etsidecoder);
        EVP_CIPHER_CTX_free(evp_ctx);
    }

    free(buf);
    free(hdr_tplate.header);
    return encoded;

failstate:
    if (encoded) {
        if (encoded->msgbody) {
            if (encoded->msgbody->encoded) {
                free(encoded->msgbody->encoded);
            }
            free(encoded->msgbody);
        }
        if (encoded->liid) {
            free(encoded->liid);
        }
        if (encoded->cinstr) {
            free(encoded->cinstr);
        }
        free(encoded);
    }
    if (buf) {
        free(buf);
    }
    free(hdr_tplate.header);
    return NULL;
}
