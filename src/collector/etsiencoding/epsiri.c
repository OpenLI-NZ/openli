/*
 *
 * Copyright (c) 2024 SearchLight NZ
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
#include "location.h"
#include "epsiri.h"

wandder_encoded_result_t *encode_epsiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        etsili_iri_type_t iritype, etsili_generic_t *params) {

    wandder_encode_job_t *jobarray[6];
    etsili_generic_t *p, *savedtime;
    uint8_t lookup;
    uint32_t iriversion = 8;
    uint32_t gprstarget = 3;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);
    wandder_encode_next_preencoded(encoder, jobarray, 3);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
            sizeof(iritype));

    /* timeStamp -- as generalized time */
    lookup = EPSIRI_CONTENTS_EVENT_TIME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1,
                p->itemptr, p->itemlen);
        savedtime = p;
    } else {
        savedtime = NULL;
        logger(LOG_INFO,
                "OpenLI: warning, no timestamp available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    }

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_15]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);

    /* IRI-Parameters start here */

    /* Object identifier (0) */
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_EPSIRIOID]);

    /* LIID (1) -- fortunately the identifier matches the one
     * used in the PSHeader, so we can use our preencoded
     * version */

    jobarray[4] = &(precomputed[OPENLI_PREENCODE_LIID]);

    /* timeStamp again (3) -- different format, use UTCTime */
    jobarray[5] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_3]);
    wandder_encode_next_preencoded(encoder, jobarray, 6);

    if (savedtime) {
        wandder_encode_next(encoder, WANDDER_TAG_UTCTIME,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1,
                savedtime->itemptr, savedtime->itemlen);
    }
    END_ENCODED_SEQUENCE(encoder, 1);

    /* initiator (4) */
    lookup = EPSIRI_CONTENTS_INITIATOR;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        logger(LOG_INFO,
                "OpenLI: warning, no initiator available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 4,
                p->itemptr, p->itemlen);
    }

    /* skip locationOfTheTarget (8) because we're going to encode it later
     * on inside ePS-GTPV2-specificParameters as a ULI info element */

        /* party information (9) -- nested */
    ENC_CSEQUENCE(encoder, 9);
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &gprstarget, sizeof(gprstarget));
    ENC_CSEQUENCE(encoder, 1);

    lookup = EPSIRI_CONTENTS_IMEI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no IMEI available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    }

    lookup = EPSIRI_CONTENTS_IMSI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no IMSI available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    }


    lookup = EPSIRI_CONTENTS_MSISDN;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no MSISDN available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    }

    END_ENCODED_SEQUENCE(encoder, 1);

    /* servicesDataInformation (pdpAddress, APN etc) */
    ENC_CSEQUENCE(encoder, 4);       // services-data-information
    ENC_CSEQUENCE(encoder, 1);       // gprs-parameters


    lookup = EPSIRI_CONTENTS_PDP_ADDRESS;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        ENC_CSEQUENCE(encoder, 1);       // pdp-address
        ENC_CSEQUENCE(encoder, 1);       // datanodeaddress
        encode_ipaddress(encoder, (etsili_ipaddress_t *)(p->itemptr));
        END_ENCODED_SEQUENCE(encoder, 2);
    }

    lookup = EPSIRI_CONTENTS_APNAME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, p->itemptr, p->itemlen);
    }

    lookup = EPSIRI_CONTENTS_PDPTYPE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, p->itemptr, p->itemlen);
    }

    END_ENCODED_SEQUENCE(encoder, 3);

    /* gprs correlation number (18) */
    lookup = EPSIRI_CONTENTS_GPRS_CORRELATION;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        logger(LOG_INFO,
                "OpenLI: warning, no GPRS correlation number available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    } else {
        char space[24];
        snprintf(space, 24, "%lu", *((uint64_t *)(p->itemptr)));

        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 18, space, strlen(space));
    }

    /* EPS event (20) */
    lookup = EPSIRI_CONTENTS_EVENT_TYPE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        logger(LOG_INFO,
                "OpenLI: warning, no EPS event type available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 20, p->itemptr, p->itemlen);
    }

    /* ggsnAddress (25) -- also appears in networkIdentifier, but why not... */
    ENC_CSEQUENCE(encoder, 25);
    lookup = EPSIRI_CONTENTS_GGSN_IPADDRESS;

    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        ENC_CSEQUENCE(encoder, 1);
        ENC_CSEQUENCE(encoder, 5);
        encode_ipaddress(encoder, (etsili_ipaddress_t *)(p->itemptr));
        END_ENCODED_SEQUENCE(encoder, 2);
    }
    END_ENCODED_SEQUENCE(encoder, 1);

    /* networkIdentifier (26) -- nested */
    ENC_CSEQUENCE(encoder, 26);

    lookup = EPSIRI_CONTENTS_OPERATOR_IDENTIFIER;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no operator identifier available for building EPS IRI");
        logger(LOG_INFO, "OpenLI: EPS IRI record may be invalid...");
    }

    lookup = EPSIRI_CONTENTS_GGSN_IPADDRESS;

    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        ENC_CSEQUENCE(encoder, 1);
        ENC_CSEQUENCE(encoder, 5);
        encode_ipaddress(encoder, (etsili_ipaddress_t *)(p->itemptr));
        END_ENCODED_SEQUENCE(encoder, 2);
    }
    END_ENCODED_SEQUENCE(encoder, 1);

    /* eps-GTPV2-specificParameters (36) */
    ENC_CSEQUENCE(encoder, 36);


    END_ENCODED_SEQUENCE(encoder, 7);
    return wandder_encode_finish(encoder);
}
