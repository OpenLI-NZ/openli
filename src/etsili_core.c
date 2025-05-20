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
#include <assert.h>
#include <sys/time.h>
#include <inttypes.h>
#include <libtrace.h>
#include <libwandder_etsili.h>
#include "etsili_core.h"
#include "collector/ipiri.h"
#include "collector/umtsiri.h"
#include "collector/emailiri.h"
#include "logger.h"

uint8_t etsi_emailirioid[4] = {0x05, 0x02, 0x0f, 0x01};
uint8_t etsi_emailccoid[4] = {0x05, 0x02, 0x0f, 0x02};

void encode_umtscc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, void *ipcontent, uint32_t iplen,
        uint8_t dir) {

    uint32_t dir32 = dir;

    wandder_encode_job_t *jobarray[8];
    int nextjob = 0;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    if (dir == 0) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
        nextjob = 4;
    } else if (dir == 1) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
        nextjob = 4;
    } else if (dir == 2) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
        nextjob = 4;
    } else {
        wandder_encode_next_preencoded(encoder, jobarray, 3);
        nextjob = 0;
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
                sizeof(uint32_t));
    }

    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    nextjob ++;

    wandder_encode_next_preencoded(encoder, jobarray, nextjob);
    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, ipcontent, iplen);
    END_ENCODED_SEQUENCE(encoder, 4);
}

static inline void encode_emailcc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, void *content, uint32_t len,
        uint8_t format, uint8_t dir) {

    wandder_encode_job_t *jobarray[7];
    uint32_t format32 = format;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    if (dir == 0) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
    } else if (dir == 1) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
    } else {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
    }
    jobarray[4] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[5] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[6] = &(precomputed[OPENLI_PREENCODE_EMAILCCOID]);
    wandder_encode_next_preencoded(encoder, jobarray, 7);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &format32, sizeof(format32));
    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, content, len);
    END_ENCODED_SEQUENCE(encoder, 5);

}

static inline void encode_ipcc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, void *ipcontent, uint32_t iplen,
        uint8_t dir) {

    uint32_t dir32 = dir;
    wandder_encode_job_t *jobarray[8];
    int nextjob = 0;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    if (dir == 0) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
        nextjob = 4;
    } else if (dir == 1) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
        nextjob = 4;
    } else if (dir == 2) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
        nextjob = 4;
    } else {
        wandder_encode_next_preencoded(encoder, jobarray, 3);
        nextjob = 0;
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
                sizeof(uint32_t));
    }

    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_IPCCOID]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    nextjob ++;

    wandder_encode_next_preencoded(encoder, jobarray, nextjob);

    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontent, iplen);

    END_ENCODED_SEQUENCE(encoder, 7);

}

static inline void encode_ipiri_id(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, ipiri_id_t *iriid) {

    if (iriid->type == IPIRI_ID_PRINTABLE) {
        wandder_encode_next(encoder, WANDDER_TAG_UTF8STR,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, iriid->content.printable,
                strlen(iriid->content.printable));
    } else if (iriid->type == IPIRI_ID_MAC) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, iriid->content.mac, 6);
    } else if (iriid->type == IPIRI_ID_IPADDR) {
        ENC_CSEQUENCE(encoder, 2);
        encode_ipaddress(encoder, precomputed, iriid->content.ip);
        END_ENCODED_SEQUENCE(encoder, 1);
    }

    wandder_encode_endseq(encoder);
}

static inline void encode_email_recipients(wandder_encoder_t *encoder,
        etsili_email_recipients_t *recipients) {

    size_t i;

    for (i = 0; i < recipients->count; i++) {
        wandder_encode_next(encoder, WANDDER_TAG_UTF8STR,
                WANDDER_CLASS_UNIVERSAL_PRIMITIVE, WANDDER_TAG_UTF8STR,
                recipients->addresses[i],
                strlen(recipients->addresses[i]));
    }
}

static inline void encode_other_targets(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, etsili_other_targets_t *others) {

    int i;

    ENC_CSEQUENCE(encoder, 0);
    for (i = 0; i < others->count; i++) {
        encode_ipaddress(encoder, precomputed, &(others->targets[i]));
    }
    END_ENCODED_SEQUENCE(encoder, 1);

}

static int sort_etsili_generic(etsili_generic_t *a, etsili_generic_t *b) {

    if (a->itemnum < b->itemnum) {
        return -1;
    }
    if (a->itemnum > b->itemnum) {
        return 1;
    }
    return 0;
}

wandder_encoded_result_t *encode_umtsiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        etsili_iri_type_t iritype, etsili_generic_t *params) {

    wandder_encode_job_t *jobarray[7];
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
    lookup = UMTSIRI_CONTENTS_EVENT_TIME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1,
                p->itemptr, p->itemlen);
        savedtime = p;
    } else {
        savedtime = NULL;
        logger(LOG_INFO,
                "OpenLI: warning, no timestamp available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    }

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_4]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);

    /* IRI-Parameters start here */

    /* Object identifier (0) */
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_UMTSIRIOID]);

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
    lookup = UMTSIRI_CONTENTS_INITIATOR;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        logger(LOG_INFO,
                "OpenLI: warning, no initiator available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 4,
                p->itemptr, p->itemlen);
    }

    /* location, if available (8) -- nested */

    ENC_CSEQUENCE(encoder, 8);
    lookup = UMTSIRI_CONTENTS_CGI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, p->itemptr, p->itemlen);
    }

    lookup = UMTSIRI_CONTENTS_SAI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 7, p->itemptr, p->itemlen);
    }

    lookup = UMTSIRI_CONTENTS_TAI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 9, p->itemptr, p->itemlen);
    }

    lookup = UMTSIRI_CONTENTS_ECGI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 10, p->itemptr, p->itemlen);
    }

    ENC_CSEQUENCE(encoder, 13);
    ENC_CSEQUENCE(encoder, 0);

    lookup = UMTSIRI_CONTENTS_LOCATION_TIME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_UTCTIME,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0,
                p->itemptr, p->itemlen);
    }
    END_ENCODED_SEQUENCE(encoder, 3);

    /* party information (9) -- nested */
    ENC_CSEQUENCE(encoder, 9);
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &gprstarget, sizeof(gprstarget));
    ENC_CSEQUENCE(encoder, 1);

    lookup = UMTSIRI_CONTENTS_IMEI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no IMEI available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    }

    lookup = UMTSIRI_CONTENTS_IMSI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no IMSI available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    }

    lookup = UMTSIRI_CONTENTS_MSISDN;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no MSISDN available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    }

    END_ENCODED_SEQUENCE(encoder, 1);

    /* servicesDataInformation (pdpAddress, APN etc) */
    ENC_CSEQUENCE(encoder, 4);       // services-data-information
    ENC_CSEQUENCE(encoder, 1);       // gprs-parameters

    lookup = UMTSIRI_CONTENTS_PDP_ADDRESS;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        ENC_CSEQUENCE(encoder, 1);       // pdp-address
        ENC_CSEQUENCE(encoder, 1);       // datanodeaddress
        encode_ipaddress(encoder, precomputed,
			(etsili_ipaddress_t *)(p->itemptr));
        END_ENCODED_SEQUENCE(encoder, 2);
    }

    /* TODO figure out if we need to include the "length" field in our
     * encoding.
     */
    lookup = UMTSIRI_CONTENTS_APNAME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, p->itemptr, p->itemlen);
    }

    lookup = UMTSIRI_CONTENTS_PDPTYPE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, p->itemptr, p->itemlen);
    }


    END_ENCODED_SEQUENCE(encoder, 3);

    /* gprs correlation number (18) */
    lookup = UMTSIRI_CONTENTS_GPRS_CORRELATION;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        logger(LOG_INFO,
                "OpenLI: warning, no GPRS correlation number available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    } else {
        char space[24];
        snprintf(space, 24, "%lu", *((uint64_t *)(p->itemptr)));

        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 18, space, strlen(space));
    }

    /* gprs event (20) */
    lookup = UMTSIRI_CONTENTS_EVENT_TYPE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        logger(LOG_INFO,
                "OpenLI: warning, no GPRS event type available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 20, p->itemptr, p->itemlen);
    }


    /* gprs operation error code (22)  -- optional */
    lookup = UMTSIRI_CONTENTS_GPRS_ERROR_CODE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 22, p->itemptr, p->itemlen);
    }

    /* IRI version (23) */
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 23, &iriversion, sizeof(iriversion));

    /* networkIdentifier (26) -- nested */
    ENC_CSEQUENCE(encoder, 26);

    lookup = UMTSIRI_CONTENTS_OPERATOR_IDENTIFIER;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, p->itemptr, p->itemlen);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no operator identifier available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    }

    lookup = UMTSIRI_CONTENTS_GGSN_IPADDRESS;

    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        ENC_CSEQUENCE(encoder, 1);
        ENC_CSEQUENCE(encoder, 5);
        encode_ipaddress(encoder, precomputed,
			(etsili_ipaddress_t *)(p->itemptr));
        END_ENCODED_SEQUENCE(encoder, 2);
    } else {
        logger(LOG_INFO,
                "OpenLI: warning, no network element identifier available for constructing UMTS IRI");
        logger(LOG_INFO, "OpenLI: UMTS IRI record may be invalid...");
    }

    END_ENCODED_SEQUENCE(encoder, 7);
    return wandder_encode_finish(encoder);
}


wandder_encoded_result_t *encode_emailiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        etsili_iri_type_t iritype, etsili_generic_t **params) {

    etsili_generic_t *p, *tmp;
    wandder_encode_job_t *jobarray[4];

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);
    wandder_encode_next_preencoded(encoder, jobarray, 3);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
            sizeof(iritype));

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_EMAILIRIOID]);
    wandder_encode_next_preencoded(encoder, jobarray, 3);

    HASH_SRT(hh, *params, sort_etsili_generic);

    HASH_ITER(hh, *params, p, tmp) {
        switch(p->itemnum) {
            case EMAILIRI_CONTENTS_EVENT_TYPE:
            case EMAILIRI_CONTENTS_PROTOCOL_ID:
            case EMAILIRI_CONTENTS_STATUS:
            case EMAILIRI_CONTENTS_SENDER_VALIDITY:
                wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;
            case EMAILIRI_CONTENTS_CLIENT_ADDRESS:
            case EMAILIRI_CONTENTS_SERVER_ADDRESS:
                ENC_CSEQUENCE(encoder, p->itemnum);
                encode_ipaddress(encoder, precomputed,
				(etsili_ipaddress_t *)(p->itemptr));
                END_ENCODED_SEQUENCE(encoder, 1);
                break;
            case EMAILIRI_CONTENTS_CLIENT_PORT:
            case EMAILIRI_CONTENTS_SERVER_PORT:
            case EMAILIRI_CONTENTS_SERVER_OCTETS_SENT:
            case EMAILIRI_CONTENTS_CLIENT_OCTETS_SENT:
            case EMAILIRI_CONTENTS_TOTAL_RECIPIENTS:
                wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;
            case EMAILIRI_CONTENTS_SENDER:
                wandder_encode_next(encoder, WANDDER_TAG_UTF8STR,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;
            case EMAILIRI_CONTENTS_MESSAGE_ID:
            case EMAILIRI_CONTENTS_NATIONAL_PARAMETER:
                wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;
            case EMAILIRI_CONTENTS_RECIPIENTS:
                ENC_CSEQUENCE(encoder, p->itemnum);
                encode_email_recipients(encoder,
                        (etsili_email_recipients_t *)(p->itemptr));
                END_ENCODED_SEQUENCE(encoder, 1);
                break;

            case EMAILIRI_CONTENTS_NATIONAL_ASN1_PARAMETERS:
            case EMAILIRI_CONTENTS_AAA_INFORMATION:
                /* TODO? */
                break;
        }
    }
    END_ENCODED_SEQUENCE(encoder, 5);
    return wandder_encode_finish(encoder);
}

wandder_encoded_result_t *encode_ipiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        etsili_iri_type_t iritype, etsili_generic_t **params) {

    etsili_generic_t *p, *tmp;
    wandder_encode_job_t *jobarray[4];

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);
    wandder_encode_next_preencoded(encoder, jobarray, 3);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
            sizeof(iritype));

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_IPIRIOID]);
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    wandder_encode_next_preencoded(encoder, jobarray, 4);

    /* Sort the parameter list by item ID, since we have to provide the
     * IRI contents in order.
     */
    HASH_SRT(hh, *params, sort_etsili_generic);

    HASH_ITER(hh, *params, p, tmp) {
        switch(p->itemnum) {
            case IPIRI_CONTENTS_ACCESS_EVENT_TYPE:
            case IPIRI_CONTENTS_INTERNET_ACCESS_TYPE:
            case IPIRI_CONTENTS_IPVERSION:
            case IPIRI_CONTENTS_ENDREASON:
            case IPIRI_CONTENTS_AUTHENTICATION_TYPE:
                wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;

            case IPIRI_CONTENTS_TARGET_USERNAME:
            case IPIRI_CONTENTS_RAW_AAA_DATA:
                wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;

            case IPIRI_CONTENTS_TARGET_IPADDRESS:
            case IPIRI_CONTENTS_POP_IPADDRESS:
            case IPIRI_CONTENTS_ADDITIONAL_IPADDRESS:
                ENC_CSEQUENCE(encoder, p->itemnum);
                encode_ipaddress(encoder, precomputed,
				(etsili_ipaddress_t *)(p->itemptr));
                END_ENCODED_SEQUENCE(encoder, 1);
                break;

            case IPIRI_CONTENTS_POP_IDENTIFIER:
                ENC_CSEQUENCE(encoder, p->itemnum);
                encode_ipiri_id(encoder, precomputed,
				(ipiri_id_t *)(p->itemptr));
                break;

            case IPIRI_CONTENTS_NATIONAL_IPIRI_PARAMETERS:
                /* TODO NationalIPIRIParameters */
                break;

            case IPIRI_CONTENTS_OTHER_TARGET_IDENTIFIERS:
                ENC_CSEQUENCE(encoder, p->itemnum);
                encode_other_targets(encoder, precomputed,
                        (etsili_other_targets_t *)(p->itemptr));
                END_ENCODED_SEQUENCE(encoder, 1);
                break;

            case IPIRI_CONTENTS_POP_PORTNUMBER:
            case IPIRI_CONTENTS_OCTETS_RECEIVED:
            case IPIRI_CONTENTS_OCTETS_TRANSMITTED:
                wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;

            case IPIRI_CONTENTS_STARTTIME:
            case IPIRI_CONTENTS_ENDTIME:
            case IPIRI_CONTENTS_EXPECTED_ENDTIME:
                if (p->itemlen == sizeof(struct timeval)) {
                    wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
                            WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                            p->itemptr, p->itemlen);
                }
                break;

            case IPIRI_CONTENTS_TARGET_NETWORKID:
            case IPIRI_CONTENTS_TARGET_CPEID:
            case IPIRI_CONTENTS_TARGET_LOCATION:
            case IPIRI_CONTENTS_CALLBACK_NUMBER:
            case IPIRI_CONTENTS_POP_PHONENUMBER:
                /* TODO enforce max string lens */
                wandder_encode_next(encoder, WANDDER_TAG_UTF8STR,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
                break;

        }
    }

    END_ENCODED_SEQUENCE(encoder, 6);
    return wandder_encode_finish(encoder);
}

void encode_ipmmcc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        void *ipcontent, uint32_t iplen, uint8_t dir,
        uint32_t frametype, uint32_t mmccproto) {

    wandder_encode_job_t *jobarray[7];
    int nextjob = 0;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    if (dir == 0) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
        nextjob = 4;
    } else if (dir == 1) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
        nextjob = 4;
    } else if (dir == 2) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
        nextjob = 4;
    } else {
        uint32_t dir32 = dir;
        wandder_encode_next_preencoded(encoder, jobarray, 3);
        nextjob = 0;
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
                sizeof(uint32_t));
    }

    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_12]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_IPMMCCOID]);
    nextjob ++;

    wandder_encode_next_preencoded(encoder, jobarray, nextjob);
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, ipcontent, iplen);

    /* Consider pre-encoding common frame types and protocols */
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &frametype,
            sizeof(uint32_t));

    /* do we need streamIdentifier?? */

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &mmccproto,
            sizeof(uint32_t));

    END_ENCODED_SEQUENCE(encoder, 5);
}

static inline void encode_etsili_pshdr_pc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */

    wandder_encode_job_t *jobarray[8];

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_PSDOMAINID]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_LIID]);
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_AUTHCC]);
    jobarray[4] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_3]);
    jobarray[5] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);
    jobarray[6] = &(precomputed[OPENLI_PREENCODE_OPERATORID]);
    jobarray[7] = &(precomputed[OPENLI_PREENCODE_NETWORKELEMID]);

    wandder_encode_next_preencoded(encoder, jobarray, 8);
    END_ENCODED_SEQUENCE(encoder, 1)

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
            sizeof(int64_t));

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_DELIVCC]);
    wandder_encode_next_preencoded(encoder, jobarray, 1);

    END_ENCODED_SEQUENCE(encoder, 1)

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
            sizeof(int64_t));

    if (precomputed[OPENLI_PREENCODE_INTPOINTID].valspace) {
        jobarray[0] = &(precomputed[OPENLI_PREENCODE_INTPOINTID]);
        jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_7]);
        wandder_encode_next_preencoded(encoder, jobarray, 2);
    } else {
        jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_7]);
        wandder_encode_next_preencoded(encoder, jobarray, 1);
    }

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
            sizeof(tv->tv_sec));
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
            sizeof(tv->tv_usec));
    END_ENCODED_SEQUENCE(encoder, 1)

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_TVCLASS]);
    wandder_encode_next_preencoded(encoder, jobarray, 1);
    END_ENCODED_SEQUENCE(encoder, 1)

}

etsili_generic_freelist_t *create_etsili_generic_freelist(uint8_t needmutex) {
    etsili_generic_freelist_t *flist;

    flist = (etsili_generic_freelist_t *)calloc(1,
            sizeof(etsili_generic_freelist_t));

    pthread_mutex_init(&(flist->mutex), NULL);
    flist->first = NULL;
    flist->needmutex = needmutex;
    return flist;
}

etsili_generic_t *create_etsili_generic(etsili_generic_freelist_t *freelist,
        uint8_t itemnum, uint16_t itemlen, uint8_t *itemvalptr) {

    etsili_generic_t *gen = NULL;

    if (!freelist->needmutex ||
            pthread_mutex_trylock(&(freelist->mutex)) == 0) {
        if (freelist->first) {
            gen = freelist->first;
            freelist->first = gen->nextfree;
        }

        if (freelist->needmutex) {
            pthread_mutex_unlock(&(freelist->mutex));
        }
    }

    if (gen == NULL) {
        gen = (etsili_generic_t *)malloc(sizeof(etsili_generic_t));
        gen->itemptr = (uint8_t *)malloc(64);
        gen->alloced = 64;
    }

    if (itemlen > gen->alloced) {
        gen->itemptr = (uint8_t *)realloc(gen->itemptr, itemlen);
        gen->alloced = itemlen;
    } else if (itemlen < 64 && gen->alloced > 64) {
        gen->itemptr = (uint8_t *)realloc(gen->itemptr, 64);
        gen->alloced = 64;
    }


    gen->itemnum = itemnum;
    gen->itemlen = itemlen;
    memcpy(gen->itemptr, itemvalptr, itemlen);
    gen->nextfree = NULL;
    gen->owner = freelist;
    return gen;
}

void release_etsili_generic(etsili_generic_t *gen) {

    etsili_generic_freelist_t *freelist = gen->owner;

    if (!freelist->needmutex ||
            pthread_mutex_trylock(&(freelist->mutex)) == 0) {

        gen->nextfree = freelist->first;
        freelist->first = gen;
        if (freelist->needmutex) {
            pthread_mutex_unlock(&(freelist->mutex));
        }
    } else {
        free(gen->itemptr);
        free(gen);
    }

}

void free_etsili_generics(etsili_generic_freelist_t *freelist) {
    etsili_generic_t *gen, *tmp;

    /* XXX make sure this is called *after* the encoding thread exit */
    pthread_mutex_lock(&(freelist->mutex));
    gen = freelist->first;
    while (gen) {
        tmp = gen;
        gen = gen->nextfree;
        free(tmp->itemptr);
        free(tmp);
    }
    pthread_mutex_unlock(&(freelist->mutex));
    pthread_mutex_destroy(&(freelist->mutex));
    free(freelist);
}

void etsili_create_ipaddress_v6(uint8_t *addrnum,
        uint8_t slashbits, uint8_t assigned, etsili_ipaddress_t *ip) {

    ip->iptype = ETSILI_IPADDRESS_VERSION_6;
    ip->assignment = assigned;
    ip->v6prefixlen = slashbits;
    ip->v4subnetmask = 0;

    ip->valtype = ETSILI_IPADDRESS_REP_BINARY;
    ip->ipvalue = calloc(16, sizeof(uint8_t));
    memcpy(ip->ipvalue, addrnum, 16);
}

void etsili_create_ipaddress_v4(uint32_t *addrnum,
        uint8_t slashbits, uint8_t assigned, etsili_ipaddress_t *ip) {

    ip->iptype = ETSILI_IPADDRESS_VERSION_4;
    ip->assignment = assigned;
    ip->v4subnetmask = 0xffffffff;
    ip->v6prefixlen = 0;

    if (slashbits < 32) {
        ip->v4subnetmask = htonl(~((1 << (32 - slashbits)) - 1));
    }

    ip->valtype = ETSILI_IPADDRESS_REP_BINARY;
    ip->ipvalue = calloc(4, sizeof(uint8_t));
    memcpy(ip->ipvalue, addrnum, 4);
}

void etsili_preencode_static_fields(
        wandder_encode_job_t *pendarray, etsili_intercept_details_t *details) {

    wandder_encode_job_t *p;
    int tvclass = 1;
    uint32_t dirin = 0, dirout = 1, dirunk = 2;
    uint32_t noencrypt = 1, aes_192_cbc = 3;
    uint32_t iptype_4 = 0, iptype_6 = 1;
    uint32_t ipassign_static = 1, ipassign_dynamic = 2, ipassign_unk = 3;
    uint32_t ippfx_64 = 64, ippfx_48 = 48, ippfx_32 = 32;

    memset(pendarray, 0, sizeof(wandder_encode_job_t) * OPENLI_PREENCODE_LAST);

    p = &(pendarray[OPENLI_PREENCODE_USEQUENCE]);
    p->identclass = WANDDER_CLASS_UNIVERSAL_CONSTRUCT;
    p->identifier = WANDDER_TAG_SEQUENCE;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_0]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_1]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_2]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 2;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_3]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 3;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_4]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 4;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_7]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 7;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_11]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 11;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_12]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 12;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_15]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 15;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_17]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 17;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_PSDOMAINID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_OID;
    wandder_encode_preencoded_value(p, (uint8_t *)WANDDER_ETSILI_PSDOMAINID,
            sizeof(WANDDER_ETSILI_PSDOMAINID));

    p = &(pendarray[OPENLI_PREENCODE_LIID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->liid, strlen(details->liid));

    p = &(pendarray[OPENLI_PREENCODE_AUTHCC]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 2;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->authcc, strlen(details->authcc));

    p = &(pendarray[OPENLI_PREENCODE_OPERATORID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->operatorid, strlen(details->operatorid));

    p = &(pendarray[OPENLI_PREENCODE_NETWORKELEMID]);
    if (details->networkelemid) {
        p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
        p->identifier = 1;
        p->encodeas = WANDDER_TAG_OCTETSTRING;
        wandder_encode_preencoded_value(p, details->networkelemid, strlen(details->networkelemid));
    } else {
        p->valspace = NULL;
        p->vallen = 0;
    }

    p = &(pendarray[OPENLI_PREENCODE_DELIVCC]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 2;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->delivcc, strlen(details->delivcc));

    p = &(pendarray[OPENLI_PREENCODE_INTPOINTID]);
    if (details->intpointid) {
        p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
        p->identifier = 6;
        p->encodeas = WANDDER_TAG_OCTETSTRING;
        wandder_encode_preencoded_value(p, details->intpointid, strlen(details->intpointid));
    } else {
        p->valspace = NULL;
        p->vallen = 0;
    }

    p = &(pendarray[OPENLI_PREENCODE_TVCLASS]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 8;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &tvclass, sizeof(tvclass));

    p = &(pendarray[OPENLI_PREENCODE_IPMMIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, (uint8_t *)wandder_etsi_ipmmirioid,
            sizeof(wandder_etsi_ipmmirioid));

    p = &(pendarray[OPENLI_PREENCODE_IPCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, (uint8_t *)wandder_etsi_ipccoid,
            sizeof(wandder_etsi_ipccoid));

    p = &(pendarray[OPENLI_PREENCODE_IPIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, (uint8_t *)wandder_etsi_ipirioid,
            sizeof(wandder_etsi_ipirioid));

    p = &(pendarray[OPENLI_PREENCODE_EMAILIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, (uint8_t *)etsi_emailirioid,
            sizeof(etsi_emailirioid));

    p = &(pendarray[OPENLI_PREENCODE_EMAILCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, (uint8_t *)etsi_emailccoid,
            sizeof(etsi_emailccoid));

    p = &(pendarray[OPENLI_PREENCODE_UMTSIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_OID;
    wandder_encode_preencoded_value(p, (uint8_t *)wandder_etsi_umtsirioid,
            sizeof(wandder_etsi_umtsirioid));

    p = &(pendarray[OPENLI_PREENCODE_EPSIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_OID;
    wandder_encode_preencoded_value(p, (uint8_t *)wandder_etsi_epsirioid,
            sizeof(wandder_etsi_epsirioid));

    p = &(pendarray[OPENLI_PREENCODE_EPSCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_OID;
    wandder_encode_preencoded_value(p, (uint8_t *)wandder_etsi_epsccoid,
            sizeof(wandder_etsi_epsccoid));

    p = &(pendarray[OPENLI_PREENCODE_IPMMCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, (uint8_t *)wandder_etsi_ipmmccoid,
            sizeof(wandder_etsi_ipmmccoid));

    p = &(pendarray[OPENLI_PREENCODE_DIRFROM]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &dirin, sizeof(dirin));

    p = &(pendarray[OPENLI_PREENCODE_DIRTO]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &dirout, sizeof(dirout));

    p = &(pendarray[OPENLI_PREENCODE_DIRUNKNOWN]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &dirunk, sizeof(dirunk));

    p = &(pendarray[OPENLI_PREENCODE_NO_ENCRYPTION]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &noencrypt, sizeof(noencrypt));

    p = &(pendarray[OPENLI_PREENCODE_AES_192_CBC]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &aes_192_cbc, sizeof(aes_192_cbc));

    p = &(pendarray[OPENLI_PREENCODE_IPTYPE_IPV4]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &iptype_4, sizeof(iptype_4));

    p = &(pendarray[OPENLI_PREENCODE_IPTYPE_IPV6]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &iptype_6, sizeof(iptype_6));

    p = &(pendarray[OPENLI_PREENCODE_IPASSIGN_STATIC]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 3;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &ipassign_static,
		    sizeof(ipassign_static));

    p = &(pendarray[OPENLI_PREENCODE_IPASSIGN_DYNAMIC]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 3;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &ipassign_dynamic,
		    sizeof(ipassign_dynamic));

    p = &(pendarray[OPENLI_PREENCODE_IPASSIGN_UNKNOWN]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 3;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &ipassign_unk, sizeof(ipassign_unk));

    p = &(pendarray[OPENLI_PREENCODE_IPV6_PREFIX_64]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 4;
    p->encodeas = WANDDER_TAG_INTEGER;
    wandder_encode_preencoded_value(p, &ippfx_64, sizeof(ippfx_64));

    p = &(pendarray[OPENLI_PREENCODE_IPV6_PREFIX_48]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 4;
    p->encodeas = WANDDER_TAG_INTEGER;
    wandder_encode_preencoded_value(p, &ippfx_48, sizeof(ippfx_48));

    p = &(pendarray[OPENLI_PREENCODE_IPV4_NETMASK_32]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 5;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, &ippfx_32, sizeof(ippfx_32));

}

void etsili_clear_preencoded_fields(wandder_encode_job_t *pendarray) {

    preencode_index_t i;

    for (i = 0; i < OPENLI_PREENCODE_LAST; i++) {
        if (pendarray[i].encodedspace) {
            free(pendarray[i].encodedspace);
        }
        if (pendarray[i].valspace) {
            free(pendarray[i].valspace);
        }
    }
}

void etsili_copy_preencoded(wandder_encode_job_t *dest,
        wandder_encode_job_t *src) {

    preencode_index_t i;

    for (i = 0; i < OPENLI_PREENCODE_LAST; i++) {
        memcpy(&(dest[i]), &(src[i]), sizeof(wandder_encode_job_t));

        /* Don't technically need to copy this, but other wandder functions
         * currently assume valspace is freeable memory so will do so for now
         * just to avoid issues.
         */
        dest[i].valspace = malloc(src[i].valalloced);
        memcpy(dest[i].valspace, src[i].valspace, src[i].vallen);

        dest[i].encodedspace = malloc(src[i].encodedlen);
        memcpy(dest[i].encodedspace, src[i].encodedspace, src[i].encodedlen);
    }
}

int etsili_create_header_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, encoded_header_template_t *tplate) {

    wandder_encoded_result_t *encres;
    wandder_decoder_t *dec;
    uint16_t level;


    if (tplate == NULL) {
        logger(LOG_INFO, "OpenLI: called etsili_create_header_template with NULL template?");
        return -1;
    }

    if (encoder == NULL) {
        logger(LOG_INFO, "OpenLI: called etsili_create_header_template with NULL encoder?");
        return -1;
    }

    reset_wandder_encoder(encoder);

    /* Create an encoded header */
    encode_etsili_pshdr_pc(encoder, precomputed, cin, seqno, tv);
    encres = wandder_encode_finish(encoder);

    if (encres == NULL || encres->len == 0 || encres->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI PS header for template");
        if (encres) {
            wandder_release_encoded_result(encoder, encres);
        }
        return -1;
    }

    /* Copy the encoded header to the template */
    tplate->header = malloc(encres->len);
    memcpy(tplate->header, encres->encoded, encres->len);
    tplate->header_len = encres->len;

    /* Release the encoded result -- the caller will use the templated copy */
    wandder_release_encoded_result(encoder, encres);

    /* Use a decoder to find the locations of the sequence number, timestamp
     * seconds and timestamp microseconds
     */
    dec = init_wandder_decoder(NULL, tplate->header, tplate->header_len, 0);
    if (dec == NULL) {
        logger(LOG_INFO, "OpenLI: unable to create decoder for templated ETSI PS header");
        return -1;
    }

    if (wandder_decode_next(dec) <= 0) {
        logger(LOG_INFO, "OpenLI: cannot decode templated ETSI PS header");
        free_wandder_decoder(dec);
        return -1;
    }

    if (wandder_decode_sequence_until(dec, 4) == 1) {
        tplate->seqno_ptr = wandder_get_itemptr(dec);
        tplate->seqno_size = wandder_get_itemlen(dec);
    } else {
        logger(LOG_INFO, "OpenLI: cannot find sequence number in templated ETSI PS header");
        free_wandder_decoder(dec);
        return -1;
    }

    level = wandder_get_level(dec);

    while (1) {
        int r;
        if ((r = wandder_decode_next(dec)) < 0) {
            logger(LOG_INFO, "OpenLI: cannot continue decode templated ETSI PS header");
            free_wandder_decoder(dec);
            return -1;
        }

        if (r == 0) {
            break;
        }

        if (wandder_get_level(dec) < level) {
            break;
        }
        if (wandder_get_level(dec) > level) {
            continue;
        }

        if (wandder_get_identifier(dec) != 7) {
            continue;
        }

        /* Must be at start of microSecondsTimestamp sequence */
        if (wandder_decode_next(dec) <= 0) {
            logger(LOG_INFO, "OpenLI: cannot decode timestamp section of templated ETSI PS header");
            free_wandder_decoder(dec);
            return -1;
        }

        tplate->tssec_ptr = wandder_get_itemptr(dec);
        tplate->tssec_size = wandder_get_itemlen(dec);

        if (wandder_decode_next(dec) <= 0) {
            logger(LOG_INFO, "OpenLI: cannot decode timestamp section of templated ETSI PS header");
            free_wandder_decoder(dec);
            return -1;
        }

        tplate->tsusec_ptr = wandder_get_itemptr(dec);
        tplate->tsusec_size = wandder_get_itemlen(dec);
        break;
    }

    /* Return success */
    free_wandder_decoder(dec);
    return 0;

}

int etsili_update_header_template(encoded_header_template_t *tplate,
        int64_t seqno, struct timeval *tv) {
    int i;
    time_t tvsec = tv->tv_sec;
    time_t tvusec = tv->tv_usec;

    /* Assume that we've been provided the right template with sufficient
     * space to fit the sequence number and timestamps -- ideally we would
     * validate this, but the point of the template is to save CPU cycles
     * not waste them on double-checking something that we should get
     * right anyway...
     */

    for (i = tplate->seqno_size - 1; i >= 0; i--) {
        *(tplate->seqno_ptr + i) = (seqno & 0xff);
        seqno = seqno >> 8;
    }

    for (i = tplate->tssec_size - 1; i >= 0; i--) {
        *(tplate->tssec_ptr + i) = (tvsec & 0xff);
        tvsec = tvsec >> 8;
    }

    for (i = tplate->tsusec_size - 1; i >= 0; i--) {
        *(tplate->tsusec_ptr + i) = (tvusec & 0xff);
        tvusec = tvusec >> 8;
    }

    return 0;
}

enum {
    CC_TEMPLATE_TYPE_IPCC,
    CC_TEMPLATE_TYPE_UMTSCC,
    CC_TEMPLATE_TYPE_EMAILCC,
};

static int etsili_create_generic_cc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, uint8_t dir, uint16_t ipclen,
        encoded_global_template_t *tplate, int templatetype) {

    wandder_encoded_result_t *encres;
    const char *funcname;

    if (templatetype == CC_TEMPLATE_TYPE_IPCC) {
        funcname = "etsili_create_ipcc_template";
    } else if (templatetype == CC_TEMPLATE_TYPE_UMTSCC) {
        funcname = "etsili_create_umtscc_template";
    } else {
        funcname = "etsili_create_generic_cc_template";
    }

    if (tplate == NULL) {
        logger(LOG_INFO, "OpenLI: called %s with NULL template?", funcname);
        return -1;
    }

    if (encoder == NULL) {
        logger(LOG_INFO, "OpenLI: called %s with NULL encoder?", funcname);
        return -1;
    }

    reset_wandder_encoder(encoder);

    if (templatetype == CC_TEMPLATE_TYPE_IPCC) {
        /* Create an encoded IPCC body -- NULL should be OK for the IPcontents,
         * since it won't be touched by libwandder (we copy it in ourselves
         * manually later on).  */
        encode_ipcc_body(encoder, precomputed, NULL, ipclen, dir);
    } else if (templatetype == CC_TEMPLATE_TYPE_UMTSCC) {
        encode_umtscc_body(encoder, precomputed, NULL, ipclen, dir);
    } else {
        logger(LOG_INFO, "OpenLI: unexpected CC template type: %d",
                templatetype);
        return -1;
    }
    encres = wandder_encode_finish(encoder);

    if (encres == NULL || encres->len == 0 || encres->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI CC body in %s",
                funcname);
        if (encres) {
            wandder_release_encoded_result(encoder, encres);
        }
        return -1;
    }

    /* Copy the encoded header to the template */
    tplate->cc_content.cc_wrap = malloc(encres->len);
    memcpy(tplate->cc_content.cc_wrap, encres->encoded, encres->len);
    tplate->cc_content.cc_wrap_len = encres->len;
    tplate->cc_content.content_size = ipclen;
    tplate->cc_content.content_ptr = NULL;

    /* Release the encoded result -- the caller will use the templated copy */
    wandder_release_encoded_result(encoder, encres);
    return 0;
}

int etsili_create_umtscc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, uint8_t dir, uint16_t ipclen,
        encoded_global_template_t *tplate) {

    return etsili_create_generic_cc_template(encoder, precomputed, dir,
            ipclen, tplate, CC_TEMPLATE_TYPE_UMTSCC);
}

int etsili_create_emailcc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, uint8_t format, uint8_t dir,
        uint16_t contentlen, encoded_global_template_t *tplate) {

    wandder_encoded_result_t *encres;
    const char *funcname = "etsili_create_emailcc_template";

    if (tplate == NULL) {
        logger(LOG_INFO, "OpenLI: called %s with NULL template?", funcname);
        return -1;
    }

    if (encoder == NULL) {
        logger(LOG_INFO, "OpenLI: called %s with NULL encoder?", funcname);
        return -1;
    }

    reset_wandder_encoder(encoder);

    encode_emailcc_body(encoder, precomputed, NULL, contentlen, format, dir);
    encres = wandder_encode_finish(encoder);

    if (encres == NULL || encres->len == 0 || encres->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI CC body in %s",
                funcname);
        if (encres) {
            wandder_release_encoded_result(encoder, encres);
        }
        return -1;
    }

    /* Copy the encoded header to the template */
    tplate->cc_content.cc_wrap = malloc(encres->len);
    memcpy(tplate->cc_content.cc_wrap, encres->encoded, encres->len);
    tplate->cc_content.cc_wrap_len = encres->len;
    tplate->cc_content.content_size = contentlen;
    tplate->cc_content.content_ptr = NULL;

    /* Release the encoded result -- the caller will use the templated copy */
    wandder_release_encoded_result(encoder, encres);
    return 0;
}

int etsili_create_ipcc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, uint8_t dir, uint16_t ipclen,
        encoded_global_template_t *tplate) {

    return etsili_create_generic_cc_template(encoder, precomputed, dir,
            ipclen, tplate, CC_TEMPLATE_TYPE_IPCC);

}

inline uint8_t DERIVE_INTEGER_LENGTH(uint64_t x) {
    if (x < 128) return 1;
    if (x < 32768) return 2;
    if (x < 8388608) return 3;
    if (x < 2147483648) return 4;
    return 5;
}

int calculate_pspdu_length(uint32_t contentsize) {
    uint8_t len_space_req = DERIVE_INTEGER_LENGTH(contentsize);

    if (len_space_req == 1) {
        return contentsize + 2;
    }
    return len_space_req + 2 + contentsize;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
