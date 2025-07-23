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
#include "location.h"

static void encode_ipmmiri_location_eps(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipmmiri_job_t *job) {

    wandder_encode_job_t *jobarray[4];
    char encoded_uli[256];
    int encoded_uli_len = 0;
    int space = 256;

    if (encode_user_location_information(encoded_uli, space, &encoded_uli_len,
            job->locations, job->location_cnt, job->location_types) < 0) {
        return;
    }

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]); //targetLocation
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]); //epsLocation

    wandder_encode_next_preencoded(encoder, jobarray, 2);


    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, encoded_uli, encoded_uli_len);

    END_ENCODED_SEQUENCE(encoder, 2);

}

static void encode_ipmmiri_location(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipmmiri_job_t *job) {

    switch(job->location_encoding) {
        case OPENLI_LOC_ENCODING_UMTS_HI2:
            logger(LOG_INFO,
                    "OpenLI: location encoding using UMTS HI2 is currently not supported");
            return;
            break;
        case OPENLI_LOC_ENCODING_EPS:
            encode_ipmmiri_location_eps(encoder, precomputed, job);
            break;
        case OPENLI_LOC_ENCODING_WLAN:
            logger(LOG_INFO,
                    "OpenLI: location encoding using WLAN location attributes is currently not supported");
            return;
            break;
        case OPENLI_LOC_ENCODING_ETSI_671_HI2:
            logger(LOG_INFO,
                    "OpenLI: location encoding using ETSI HI2 operations is currently not supported");
            return;
            break;
        case OPENLI_LOC_ENCODING_3GPP_33128:
            logger(LOG_INFO,
                    "OpenLI: location encoding using TS 33.128 is currently not supported");
            return;
            break;
        default:
            logger(LOG_INFO, "OpenLI: unexpected location encoding method: %u",
                    job->location_encoding);
            return;
    }




}

static inline void encode_ipmmiri_body_common(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, etsili_iri_type_t iritype) {

    wandder_encode_job_t *jobarray[4];

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]); // Payload
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]); // IRIPayload
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    wandder_encode_next_preencoded(encoder, jobarray, 3);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
            sizeof(iritype));

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);  // IRIContents
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_11]); // IPMMIRI
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_IPMMIRIOID]);   // IPMMIRI OID
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);  // IRIContents

    wandder_encode_next_preencoded(encoder, jobarray, 4);
}

static wandder_encoded_result_t *encode_sipiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipmmiri_job_t *job) {

    etsili_ipaddress_t encipsrc, encipdst;
    wandder_encode_job_t *jobarray[2];

    if (job->ipfamily == AF_INET) {
        encipsrc.iptype = ETSILI_IPADDRESS_VERSION_4;
        encipsrc.assignment = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;
        encipsrc.v6prefixlen = 0;
        encipsrc.v4subnetmask = 0xffffffff;
        encipsrc.valtype = ETSILI_IPADDRESS_REP_BINARY;
        encipsrc.ipvalue = calloc(1, sizeof(uint32_t));
        memcpy(encipsrc.ipvalue, job->ipsrc, sizeof(uint32_t));

        encipdst = encipsrc;
        encipdst.ipvalue = calloc(1, sizeof(uint32_t));
        memcpy(encipdst.ipvalue, job->ipdest, sizeof(uint32_t));
    } else if (job->ipfamily == AF_INET6) {
        encipsrc.iptype = ETSILI_IPADDRESS_VERSION_6;
        encipsrc.assignment = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;
        encipsrc.v6prefixlen = 0;
        encipsrc.v4subnetmask = 0;
        encipsrc.valtype = ETSILI_IPADDRESS_REP_BINARY;

        encipsrc.ipvalue = calloc(16, sizeof(uint8_t));
        memcpy(encipsrc.ipvalue, job->ipsrc, 16);

        encipdst = encipsrc;
        encipdst.ipvalue = calloc(16, sizeof(uint8_t));
        memcpy(encipdst.ipvalue, job->ipdest, 16);
    } else {
        return NULL;
    }
    encode_ipmmiri_body_common(encoder, precomputed, job->iritype);
    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]); // SIPMessage
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]); // Src IP
    wandder_encode_next_preencoded(encoder, jobarray, 2);
    encode_ipaddress(encoder, precomputed, &encipsrc);
    END_ENCODED_SEQUENCE(encoder, 1);

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]); // Dest IP
    wandder_encode_next_preencoded(encoder, jobarray, 1);
    encode_ipaddress(encoder, precomputed, &encipdst);
    END_ENCODED_SEQUENCE(encoder, 1);

    /* SIP content */
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, job->content, job->contentlen);

    END_ENCODED_SEQUENCE(encoder, 2);

    if (job->location_cnt > 0) {
        encode_ipmmiri_location(encoder, precomputed, job);
    }

    END_ENCODED_SEQUENCE(encoder, 5);

    return wandder_encode_finish(encoder);
}


int encode_templated_ipmmiri(wandder_encoder_t *encoder,
        encrypt_encode_state_t *encrypt,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res) {

    wandder_encoded_result_t *body = NULL;
    openli_ipmmiri_job_t *irijob =
            (openli_ipmmiri_job_t *)&(job->origreq->data.ipmmiri);

    /* We could consider templating the body portion of IPMMIRIs if we
     * really need the performance -- we'd need to create templates for each
     * SIP message size + IP version + IRI type, with saved pointers to the SIP
     * content, IRI type, source IP address and dest IP address.
     *
     * The addition of location information for mobile via IMS complicates
     * things further...
     */

    reset_wandder_encoder(encoder);

    /* Assuming SIP here for now, other protocols can be supported later */
    body = encode_sipiri_body(encoder, job->preencoded, irijob);


    if (body == NULL || body->len == 0 || body->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI SIP IPMMIRI body");
        if (body) {
            wandder_release_encoded_result(encoder, body);
        }
        return -1;
    }

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(encoder, encrypt, res, hdr_tplate,
                body->encoded, body->len,
                NULL, 0, job) < 0) {
            wandder_release_encoded_result(encoder, body);
            return -1;
        }
    } else {
        if (create_etsi_encoded_result(res, hdr_tplate, body->encoded,
                body->len, NULL, 0,
                //(uint8_t *)(irijob->content), irijob->contentlen,
                job) < 0) {
            wandder_release_encoded_result(encoder, body);
            return -1;
        }
    }

    wandder_release_encoded_result(encoder, body);

    /* Success */
    return 1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
