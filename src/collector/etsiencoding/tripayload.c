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

#include <libwandder_etsili.h>
#include <libwandder.h>
#include "intercept.h"
#include "etsili_core.h"
#include "etsiencoding.h"
#include "logger.h"

static int _encode_etsi_integrity_check_payload(
        wandder_encoder_t *encoder, openli_integrity_hash_method_t hashmethod,
        uint32_t checktype, openli_proto_msgtype_t msgtype,
        uint8_t *checkval, unsigned int checkvallen,
        int64_t *inclseqnos, size_t numseqnos) {

    uint32_t datatype_val = 0;
    size_t i;
    uint32_t hashalgo = 0;

    ENC_CSEQUENCE(encoder, 2);          // Payload
    ENC_CSEQUENCE(encoder, 2);          // TRIPayload
    ENC_CSEQUENCE(encoder, 0);          // integrityCheck
    ENC_CSEQUENCE(encoder, 0);          // includedSequenceNumbers

    for (i = 0; i < numseqnos; i++) {
        wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
                WANDDER_CLASS_UNIVERSAL_PRIMITIVE,
                WANDDER_TAG_INTEGER, &(inclseqnos[i]), sizeof(int64_t));
    }
    END_ENCODED_SEQUENCE(encoder, 1);    // End includedSequenceNumbers

    if (msgtype == OPENLI_PROTO_ETSI_IRI) {
        datatype_val = 1;
    } else if (msgtype == OPENLI_PROTO_ETSI_CC) {
        datatype_val = 2;
    } else {
        return -1;
    }

    hashalgo = (uint32_t)hashmethod;

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &checktype, sizeof(checktype));
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &datatype_val,
            sizeof(datatype_val));

    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, checkval, checkvallen);

    if (hashalgo != 0) {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &hashalgo,
                sizeof(hashalgo));
    }

    END_ENCODED_SEQUENCE(encoder, 3); // End Payload, TRIPayload, integrityCheck
    return 0;
}

wandder_encoded_result_t *encode_encrypted_etsi_integrity_check(
        wandder_encoder_t *encoder, wandder_etsispec_t *etsidecoder,
        wandder_etsipshdr_data_t *hdrdata,
        encrypt_encode_state_t *encryptstate, EVP_CIPHER_CTX *evp_ctx,
        payload_encryption_method_t encryptmethod, uint8_t *encryptkey,
        size_t encryptkey_len, int64_t cin,
        int64_t self_seqno, openli_integrity_hash_method_t hashmethod,
        uint32_t checktype, openli_proto_msgtype_t msgtype,
        uint8_t *checkval, unsigned int checkvallen,
        int64_t *inclseqnos, size_t numseqnos,
        openli_timestamp_encoding_fmt_t timefmt) {


    struct timeval tv;
    uint32_t enclen, noenc, tri;
    uint8_t *buf, *ptr, *combined;
    uint8_t len_space_req;
    uint32_t contentsize, combinedlen;
    int i;

    wandder_encoded_result_t *content, *header, *wrapped;
    wandder_encoded_result_t *final;

    reset_wandder_encoder(encoder);
    if (_encode_etsi_integrity_check_payload(encoder, hashmethod, checktype,
            msgtype, checkval, checkvallen, inclseqnos, numseqnos) < 0) {
        return NULL;
    }
    content = wandder_encode_finish(encoder);

    buf = wrap_etsili_preencryption(encryptstate, encryptmethod,
            0, content->encoded, content->len, NULL, 0,
            &enclen);
    if (buf == NULL || enclen == 0) {
        return NULL;
    }

    wandder_release_encoded_result(encoder, content);

    reset_wandder_encoder(encoder);
    noenc = OPENLI_PAYLOAD_ENCRYPTION_NONE;
    ENC_CSEQUENCE(encoder, 2);
    ENC_CSEQUENCE(encoder, 4);
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &noenc, sizeof(noenc));
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, buf, enclen);

    tri = 8;    // ETSI TS 102 232-1 for encrypted payload type
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &tri, sizeof(tri));
    END_ENCODED_SEQUENCE(encoder, 2);
    wrapped = wandder_encode_finish(encoder);

    reset_wandder_encoder(encoder);
    gettimeofday(&tv, NULL);
    encode_etsili_pshdr(encoder, hdrdata, cin, self_seqno, &tv, timefmt);

    header = wandder_encode_finish(encoder);

    free(buf);
    /* Hack together an encoded result from the requisite components */
    combined = malloc(wrapped->len + header->len + 16);
    ptr = combined;

    contentsize = wrapped->len + header->len;
    len_space_req = DERIVE_INTEGER_LENGTH(contentsize);
    *ptr = (uint8_t)((WANDDER_CLASS_UNIVERSAL_CONSTRUCT << 5) |
            WANDDER_TAG_SEQUENCE);
    ptr ++;

    if (len_space_req == 1) {
        *ptr = (uint8_t)(contentsize);
        ptr ++;
    } else {
        *ptr = len_space_req | 0x80;
        ptr ++;

        for (i = len_space_req - 1; i >= 0; i--) {
            *(ptr + i) = (contentsize & 0xff);
            contentsize = contentsize >> 8;
        }
        ptr += len_space_req;
    }

    memcpy(ptr, header->encoded, header->len);
    ptr += header->len;
    memcpy(ptr, wrapped->encoded, wrapped->len);
    ptr += wrapped->len;

    combinedlen = ptr - combined;
    wandder_release_encoded_result(encoder, header);
    wandder_release_encoded_result(encoder, wrapped);

    encryptstate->byte_counter += combinedlen;

    final = calloc(1, sizeof(wandder_encoded_result_t));
    final->encoder = encoder;
    final->alloced = combinedlen;
    final->len = combinedlen;
    final->next = NULL;

    if (encryptmethod == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        if (encrypt_payload_container_aes_192_cbc(evp_ctx,
                etsidecoder, combined, (uint16_t)combinedlen,
                encryptkey, encryptkey_len) == NULL) {
            free(final);
            free(combined);
            return NULL;
        }
        final->encoded = combined;
    } else {
        free(final);
        free(combined);
        return NULL;
    }

    return final;
}

wandder_encoded_result_t *encode_etsi_integrity_check(
        wandder_encoder_t *encoder, wandder_etsipshdr_data_t *hdrdata,
        int64_t cin,
        int64_t self_seqno, openli_integrity_hash_method_t hashmethod,
        uint32_t checktype, openli_proto_msgtype_t msgtype,
        uint8_t *checkval, unsigned int checkvallen,
        int64_t *inclseqnos, size_t numseqnos,
        openli_timestamp_encoding_fmt_t timefmt) {


    struct timeval tv;

    gettimeofday(&tv, NULL);
    ENC_USEQUENCE(encoder);
    encode_etsili_pshdr(encoder, hdrdata, cin, self_seqno, &tv, timefmt);
    if (_encode_etsi_integrity_check_payload(encoder, hashmethod, checktype,
            msgtype, checkval, checkvallen, inclseqnos, numseqnos) < 0) {
        return NULL;
    }

    END_ENCODED_SEQUENCE(encoder, 1); // End outer PS-PDU
    return wandder_encode_finish(encoder);
}

wandder_encoded_result_t *encode_etsi_keepalive(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t seqno,
        openli_timestamp_encoding_fmt_t timefmt) {

    struct timeval tv;

    gettimeofday(&tv, NULL);
    ENC_USEQUENCE(encoder);
    encode_etsili_pshdr(encoder, hdrdata, 0, seqno, &tv, timefmt);
    ENC_CSEQUENCE(encoder, 2);          // Payload
    ENC_CSEQUENCE(encoder, 2);          // TRIPayload
    wandder_encode_next(encoder, WANDDER_TAG_NULL,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, NULL, 0);
    wandder_encode_endseq(encoder);     // End TRIPayload
    wandder_encode_endseq(encoder);     // End Payload
    wandder_encode_endseq(encoder);     // End Outermost Sequence

    return wandder_encode_finish(encoder);
}

wandder_encoded_result_t *encode_etsi_segment_flag_body(
        wandder_encoder_t *encoder, wandder_encode_job_t *precomputed,
        uint8_t is_first) {

    wandder_encode_job_t *jobarray[2];

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]); // Payload
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]); // TRIPayload
    wandder_encode_next_preencoded(encoder, jobarray, 2);

    if (is_first) {
        wandder_encode_next(encoder, WANDDER_TAG_NULL,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, NULL, 0);
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_NULL,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, NULL, 0);
    }
    END_ENCODED_SEQUENCE(encoder, 3);
    return wandder_encode_finish(encoder);
}
