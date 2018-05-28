/*
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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
#include <sys/time.h>
#include <inttypes.h>
#include <libwandder_etsili.h>
#include "etsili_core.h"

uint8_t etsi_ipccoid[4] = {0x05, 0x03, 0x0a, 0x02};
uint8_t etsi_ipmmccoid[4] = {0x05, 0x05, 0x06, 0x02};
uint8_t etsi_ipmmirioid[4] = {0x05, 0x05, 0x06, 0x01};

static inline void encode_tri_body(wandder_encoder_t *encoder) {
    ENC_CSEQUENCE(encoder, 2);          // Payload
    ENC_CSEQUENCE(encoder, 2);          // TRIPayload
    wandder_encode_next(encoder, WANDDER_TAG_NULL,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, NULL, 0);
    wandder_encode_endseq(encoder);     // End TRIPayload
    wandder_encode_endseq(encoder);     // End Payload
    wandder_encode_endseq(encoder);     // End Outermost Sequence
}


static inline void encode_ipcc_body(wandder_encoder_t *encoder,
        void *ipcontent, uint32_t iplen, uint8_t dir) {

    uint32_t dir32 = dir;

    ENC_CSEQUENCE(encoder, 2);
    ENC_CSEQUENCE(encoder, 1);
    ENC_USEQUENCE(encoder);
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
            sizeof(uint32_t));
    ENC_CSEQUENCE(encoder, 2);
    ENC_CSEQUENCE(encoder, 2);

    wandder_encode_next(encoder, WANDDER_TAG_RELATIVEOID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, etsi_ipccoid,
            sizeof(etsi_ipccoid));
    ENC_CSEQUENCE(encoder, 1);
    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontent, iplen);


    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);    // ends outermost sequence

}

static inline void encode_ipmmiri_body(wandder_encoder_t *encoder,
        etsili_iri_type_t iritype, void *ipcontent, uint32_t iplen) {

    ENC_CSEQUENCE(encoder, 2);      // Payload
    ENC_CSEQUENCE(encoder, 0);      // IRIPayload
    ENC_USEQUENCE(encoder);         // IRIPayload sequence
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
            sizeof(iritype));
    ENC_CSEQUENCE(encoder, 2);      // IRIContents
    ENC_CSEQUENCE(encoder, 11);     // IPMMIRI
    wandder_encode_next(encoder, WANDDER_TAG_RELATIVEOID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, etsi_ipmmirioid,
            sizeof(etsi_ipmmirioid));
    ENC_CSEQUENCE(encoder, 1);      // IPMMIRIContents
    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontent, iplen);

    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);    // ends outermost sequence

}

static inline void encode_ipmmcc_body(wandder_encoder_t *encoder,
        void *ipcontent, uint32_t iplen, uint8_t dir) {

    uint32_t frametype, mmccproto, dir32;

    dir32 = dir;
    frametype = 0;      //  ipFrame
    mmccproto = 0;      //  RTP  -- consider others in future?

    ENC_CSEQUENCE(encoder, 2);      // Payload
    ENC_CSEQUENCE(encoder, 1);      // CCPayload
    ENC_USEQUENCE(encoder);         // CCpayload sequence
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
            sizeof(uint32_t));
    ENC_CSEQUENCE(encoder, 2);      // CCContents
    ENC_CSEQUENCE(encoder, 12);     // IPMMCC
    wandder_encode_next(encoder, WANDDER_TAG_RELATIVEOID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, etsi_ipmmccoid,
            sizeof(etsi_ipmmccoid));
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, ipcontent, iplen);
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &frametype,
            sizeof(uint32_t));

    /* do we need streamIdentifier?? */

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &mmccproto,
            sizeof(uint32_t));

    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
    wandder_encode_endseq(encoder);
}


static inline void encode_etsili_pshdr(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    uint32_t tvclass = 1;       // timeOfInterception

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */

    ENC_USEQUENCE(encoder);             // starts outermost sequence

    ENC_CSEQUENCE(encoder, 1);
    wandder_encode_next(encoder, WANDDER_TAG_OID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0,
            (uint8_t *)WANDDER_ETSILI_PSDOMAINID,
            sizeof(WANDDER_ETSILI_PSDOMAINID));
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, hdrdata->liid,
            hdrdata->liid_len);
    wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, hdrdata->authcc,
            hdrdata->authcc_len);

    ENC_CSEQUENCE(encoder, 3);

    ENC_CSEQUENCE(encoder, 0);
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, hdrdata->operatorid,
            hdrdata->operatorid_len);

    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, hdrdata->networkelemid,
            hdrdata->networkelemid_len);
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
            sizeof(int64_t));
    wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, hdrdata->delivcc,
            hdrdata->delivcc_len);
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
            sizeof(int64_t));
    wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, tv,
            sizeof(struct timeval));

    if (hdrdata->intpointid) {
        wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, hdrdata->intpointid,
                hdrdata->intpointid_len);
    }

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 8, &tvclass, sizeof(tvclass));
    wandder_encode_endseq(encoder);

}

wandder_encoded_result_t *encode_etsi_ipcc(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir) {


    encode_etsili_pshdr(encoder, hdrdata, cin, seqno, tv);
    encode_ipcc_body(encoder, ipcontents, iplen, dir);
    return wandder_encode_finish(encoder);

}

wandder_encoded_result_t *encode_etsi_ipmmcc(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir) {

    encode_etsili_pshdr(encoder, hdrdata, cin, seqno, tv);
    encode_ipmmcc_body(encoder, ipcontents, iplen, dir);
    return wandder_encode_finish(encoder);

}

wandder_encoded_result_t *encode_etsi_ipmmiri(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t cin, int64_t seqno,
        etsili_iri_type_t iritype, struct timeval *tv, void *ipcontents,
        uint32_t iplen) {

    encode_etsili_pshdr(encoder, hdrdata, cin, seqno, tv);
    encode_ipmmiri_body(encoder, iritype, ipcontents, iplen);
    return wandder_encode_finish(encoder);
}

wandder_encoded_result_t *encode_etsi_keepalive(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t seqno) {

    struct timeval tv;

    gettimeofday(&tv, NULL);
    encode_etsili_pshdr(encoder, hdrdata, 0, seqno, &tv);
    encode_tri_body(encoder);

    return wandder_encode_finish(encoder);
}


etsili_generic_t *create_etsili_generic(etsili_generic_t **freelist,
        uint8_t itemnum, uint16_t itemlen, uint8_t *itemvalptr) {

    etsili_generic_t *gen;

    if (*freelist) {
        gen = *freelist;
        *freelist = (*freelist)->nextfree;
    } else {
        gen = (etsili_generic_t *)malloc(sizeof(etsili_generic_t));
    }

    gen->itemnum = itemnum;
    gen->itemlen = itemlen;
    gen->itemptr = itemvalptr;
    gen->nextfree = NULL;
    return gen;
}

void release_etsili_generic(etsili_generic_t **freelist, etsili_generic_t *gen) {

    if (*freelist) {
        gen->nextfree = *freelist;
        *freelist = gen;
    } else {
        gen->nextfree = NULL;
        *freelist = gen;
    }

}

void free_etsili_generics(etsili_generic_t *freelist) {
    etsili_generic_t *gen, *tmp;

    gen = freelist;
    while (gen) {
        tmp = gen;
        gen = gen->nextfree;
        free(tmp);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
