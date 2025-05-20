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

wandder_encoded_result_t *encode_etsi_integrity_check(
        wandder_encoder_t *encoder, wandder_etsipshdr_data_t *hdrdata,
        int64_t self_seqno, openli_integrity_hash_method_t hashmethod,
        uint32_t datatype, openli_proto_msgtype_t msgtype,
        uint8_t *checkval, unsigned int checkvallen,
        int64_t *inclseqnos, size_t numseqnos) {


    struct timeval tv;
    uint32_t checktype = 0;
    size_t i;
    uint32_t hashalgo = 0;

    gettimeofday(&tv, NULL);
    encode_etsili_pshdr(encoder, hdrdata, 0, self_seqno, &tv);
    ENC_CSEQUENCE(encoder, 2);          // Payload
    ENC_CSEQUENCE(encoder, 2);          // TRIPayload
    ENC_CSEQUENCE(encoder, 0);          // integrityCheck
    ENC_CSEQUENCE(encoder, 0);          // includedSequenceNumbers
    ENC_USEQUENCE(encoder);             // start sequence

    for (i = 0; i < numseqnos; i++) {
        wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
                WANDDER_CLASS_UNIVERSAL_PRIMITIVE,
                WANDDER_TAG_INTEGER, &(inclseqnos[i]), sizeof(int64_t));
    }
    END_ENCODED_SEQUENCE(encoder, 2);   // End universal sequence
                                        // End includedSequenceNumbers

    if (msgtype == OPENLI_PROTO_ETSI_IRI) {
        checktype = 1;
    } else if (msgtype == OPENLI_PROTO_ETSI_CC) {
        checktype = 2;
    } else {
        return NULL;
    }

    hashalgo = (uint32_t)hashmethod;

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &checktype, sizeof(checktype));
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &datatype, sizeof(datatype));

    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, checkval, checkvallen);

    if (hashalgo != 0) {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &hashalgo,
                sizeof(hashalgo));
    }

    END_ENCODED_SEQUENCE(encoder, 4); // End Payload + outer PS-PDU
    return wandder_encode_finish(encoder);
}

wandder_encoded_result_t *encode_etsi_keepalive(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t seqno) {

    struct timeval tv;

    gettimeofday(&tv, NULL);
    encode_etsili_pshdr(encoder, hdrdata, 0, seqno, &tv);
    ENC_CSEQUENCE(encoder, 2);          // Payload
    ENC_CSEQUENCE(encoder, 2);          // TRIPayload
    wandder_encode_next(encoder, WANDDER_TAG_NULL,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, NULL, 0);
    wandder_encode_endseq(encoder);     // End TRIPayload
    wandder_encode_endseq(encoder);     // End Payload
    wandder_encode_endseq(encoder);     // End Outermost Sequence

    return wandder_encode_finish(encoder);
}
