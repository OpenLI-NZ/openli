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
#include "intercept.h"
#include "etsili_core.h"
#include "etsiencoding.h"
#include "logger.h"

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

        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, not_data->liid,
                strlen(not_data->liid));

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
    wandder_encode_endseq(encoder);     // End Outermost Sequence
}

wandder_encoded_result_t *encode_etsi_hi1_notification(
        wandder_encoder_t *encoder, hi1_notify_data_t *not_data,
        char *operatorid, char *shortopid,
        openli_timestamp_encoding_fmt_t timefmt) {

    struct timeval tv;
    wandder_etsipshdr_data_t hdrdata;

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

    gettimeofday(&tv, NULL);
    encode_etsili_pshdr(encoder, &hdrdata, 0, (int64_t)not_data->seqno, &tv,
            timefmt);
    encode_hi1_notification_body(encoder, not_data, shortopid);
    return wandder_encode_finish(encoder);
}
