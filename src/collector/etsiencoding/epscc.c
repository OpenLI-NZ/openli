/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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
#include "epscc.h"

openli_export_recv_t *create_epscc_job(char *liid, uint32_t cin,
        uint32_t destid, uint8_t dir, uint8_t *ipcontent, uint32_t ipclen,
        uint8_t icetype, uint16_t gtpseqno) {

    openli_export_recv_t *msg = NULL;

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }

    msg->type = OPENLI_EXPORT_EPSCC;
    msg->destid = destid;
    gettimeofday(&(msg->ts), NULL);

    msg->data.mobcc.liid = strdup(liid);
    msg->data.mobcc.cin = cin;
    msg->data.mobcc.dir = dir;
    msg->data.mobcc.ipcontent = calloc(ipclen, sizeof(uint8_t));
    memcpy(msg->data.mobcc.ipcontent, ipcontent, ipclen);
    msg->data.mobcc.ipclen = ipclen;
    msg->data.mobcc.icetype = icetype;
    msg->data.mobcc.gtpseqno = gtpseqno;

    return msg;
}

wandder_encoded_result_t *encode_epscc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, const char *liid, uint32_t cin,
        uint16_t gtpseqno, uint8_t dir, struct timeval tv, uint8_t icetype,
        uint32_t ipclen) {

    wandder_encode_job_t *jobarray[8];
    char correlation[32];
    uint32_t seqno = gtpseqno;
    uint32_t tpdudir;
    uint32_t ice32 = icetype;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    if (dir == ETSI_DIR_FROM_TARGET) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
    } else if (dir == ETSI_DIR_TO_TARGET) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
    } else {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
    }
    jobarray[4] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]); // ccContents
    jobarray[5] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_17]); // EPSCC-PDU
    jobarray[6] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]); // ULIC-header
    jobarray[7] = &(precomputed[OPENLI_PREENCODE_EPSCCOID]);    // hi3DomainID
    wandder_encode_next_preencoded(encoder, jobarray, 8);

    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, (void *)liid, strlen(liid));

    snprintf(correlation, 32, "%u", cin);
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, correlation,
            strlen(correlation));

    ENC_CSEQUENCE(encoder, 4);
    wandder_encode_next(encoder, WANDDER_TAG_UTCTIME,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &tv, sizeof(tv));
    wandder_encode_endseq(encoder);

    // sequenceNumber
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, &seqno, sizeof(seqno));

    // tpdu-direction
    if (dir == ETSI_DIR_FROM_TARGET) {
        tpdudir = 1;
    } else if (dir == ETSI_DIR_TO_TARGET) {
        tpdudir = 2;
    } else {
        tpdudir = 3;
    }
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, &(tpdudir), sizeof(tpdudir));

    // national parameters go here (7)

    // ice-type
    if (icetype != 0) {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 8, &(ice32), sizeof(ice32));
    }

    END_ENCODED_SEQUENCE(encoder, 1);

    // payload
    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, NULL, ipclen);
    END_ENCODED_SEQUENCE(encoder, 6);
    return wandder_encode_finish(encoder);
}
