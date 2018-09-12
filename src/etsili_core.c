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
#include <assert.h>
#include <sys/time.h>
#include <inttypes.h>
#include <libtrace.h>
#include <libwandder_etsili.h>
#include "etsili_core.h"
#include "collector/ipiri.h"

uint8_t etsi_ipccoid[4] = {0x05, 0x03, 0x0a, 0x02};
uint8_t etsi_ipirioid[4] = {0x05, 0x03, 0x0a, 0x01};
uint8_t etsi_ipmmccoid[4] = {0x05, 0x05, 0x06, 0x02};
uint8_t etsi_ipmmirioid[4] = {0x05, 0x05, 0x06, 0x01};

#define END_ENCODED_SEQUENCE(enc) \
        wandder_encode_endseq(enc);

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
        wandder_encode_job_t *precomputed, void *ipcontent, uint32_t iplen,
        uint8_t dir) {

    uint32_t dir32 = dir;

    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_USEQUENCE]));

    if (dir == 0) {
        wandder_encode_next_preencoded(encoder,
                &(precomputed[OPENLI_PREENCODE_DIRFROM]));
    } else if (dir == 1) {
        wandder_encode_next_preencoded(encoder,
                &(precomputed[OPENLI_PREENCODE_DIRTO]));
    } else if (dir == 2) {
        wandder_encode_next_preencoded(encoder,
                &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]));
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
                sizeof(uint32_t));
    }
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_IPCCOID]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]));
    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontent, iplen);

    END_ENCODED_SEQUENCE(encoder);
    END_ENCODED_SEQUENCE(encoder);
    END_ENCODED_SEQUENCE(encoder);
    END_ENCODED_SEQUENCE(encoder);
    END_ENCODED_SEQUENCE(encoder);
    END_ENCODED_SEQUENCE(encoder);
    END_ENCODED_SEQUENCE(encoder);

}

static inline void encode_ipaddress(wandder_encoder_t *encoder,
        etsili_ipaddress_t *addr) {

    uint32_t addrlen = 4;
    uint32_t iptype = addr->iptype;
    uint32_t assign = addr->assignment;
    uint32_t prefbits = addr->v6prefixlen;

    if (addr->iptype == ETSILI_IPADDRESS_VERSION_6) {
        addrlen = 16;
    }

    // iP-Type
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(iptype), sizeof(iptype));

    ENC_CSEQUENCE(encoder, 2);      // iP-value
    if (addr->valtype == ETSILI_IPADDRESS_REP_BINARY) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, addr->ipvalue, addrlen);
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_IA5,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, addr->ipvalue,
            strlen((char *)(addr->ipvalue)));
    }

    wandder_encode_endseq(encoder);     // ends iP-value

    // iP-assignment
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, &(assign), sizeof(assign));

    // iPv6PrefixLength
    if (addr->v6prefixlen > 0) {
        wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(prefbits), sizeof(prefbits));
    }

    // iPv4SubnetMask
    if (addr->v4subnetmask > 0) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, &(addr->v4subnetmask),
            sizeof(addr->v4subnetmask));
    }

    wandder_encode_endseq(encoder);    // ends IPAddress sequence
}

static inline void encode_ipmmiri_body_common(wandder_encoder_t *encoder,
        etsili_iri_type_t iritype) {

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

}

static inline void encode_ipmmiri_body_common_end(wandder_encoder_t *encoder) {

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

    encode_ipmmiri_body_common(encoder, iritype);
    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontent, iplen);
    encode_ipmmiri_body_common_end(encoder);

}

static inline void encode_sipiri_body(wandder_encoder_t *encoder,
        etsili_iri_type_t iritype, uint8_t *ipsrc, uint8_t *ipdest,
        int ipfamily, void *sipcontent, uint32_t siplen) {

    etsili_ipaddress_t encipsrc, encipdst;

    if (ipfamily == AF_INET) {
        encipsrc.iptype = ETSILI_IPADDRESS_VERSION_4;
        encipsrc.assignment = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;
        encipsrc.v6prefixlen = 0;
        encipsrc.v4subnetmask = 0xffffffff;
        encipsrc.valtype = ETSILI_IPADDRESS_REP_BINARY;
        encipsrc.ipvalue = ipsrc;

        encipdst = encipsrc;
        encipdst.ipvalue = ipdest;
    } else if (ipfamily == AF_INET6) {
        encipsrc.iptype = ETSILI_IPADDRESS_VERSION_6;
        encipsrc.assignment = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;
        encipsrc.v6prefixlen = 0;
        encipsrc.v4subnetmask = 0;
        encipsrc.valtype = ETSILI_IPADDRESS_REP_BINARY;

        encipsrc.ipvalue = ipsrc;

        encipdst = encipsrc;
        encipdst.ipvalue = ipdest;
    } else {
        wandder_encode_endseq(encoder);    // ends outermost sequence
        return;
    }

    encode_ipmmiri_body_common(encoder, iritype);
    ENC_CSEQUENCE(encoder, 1);      // SIPMessage
    ENC_CSEQUENCE(encoder, 0);
    encode_ipaddress(encoder, &encipsrc);
    ENC_CSEQUENCE(encoder, 1);
    encode_ipaddress(encoder, &encipdst);
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, sipcontent, siplen);
    wandder_encode_endseq(encoder); // end SIPMessage
    encode_ipmmiri_body_common_end(encoder);
}

static inline void encode_ipiri_id(wandder_encoder_t *encoder,
        ipiri_id_t *iriid) {

    if (iriid->type == IPIRI_ID_PRINTABLE) {
        wandder_encode_next(encoder, WANDDER_TAG_UTF8STR,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, iriid->content.printable,
                strlen(iriid->content.printable));
    } else if (iriid->type == IPIRI_ID_MAC) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, iriid->content.mac, 6);
    } else if (iriid->type == IPIRI_ID_IPADDR) {
        ENC_CSEQUENCE(encoder, 2);
        encode_ipaddress(encoder, iriid->content.ip);
    }

    wandder_encode_endseq(encoder);
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


static inline void encode_ipiri_body(wandder_encoder_t *encoder,
        etsili_iri_type_t iritype, etsili_generic_t *params) {

    etsili_generic_t *p, *tmp;

    ENC_CSEQUENCE(encoder, 2);      // Payload
    ENC_CSEQUENCE(encoder, 0);      // IRIPayload
    ENC_USEQUENCE(encoder);         // IRIPayload sequence
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
            sizeof(iritype));
    ENC_CSEQUENCE(encoder, 2);      // IRIContents
    ENC_CSEQUENCE(encoder, 2);      // IPIRI
    wandder_encode_next(encoder, WANDDER_TAG_RELATIVEOID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, etsi_ipirioid,
            sizeof(etsi_ipmmirioid));
    ENC_CSEQUENCE(encoder, 1);      // IPIRIContents

    /* Sort the parameter list by item ID, since we have to provide the
     * IRI contents in order.
     */
    HASH_SRT(hh, params, sort_etsili_generic);

    HASH_ITER(hh, params, p, tmp) {
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
                encode_ipaddress(encoder, (etsili_ipaddress_t *)(p->itemptr));
                break;

            case IPIRI_CONTENTS_POP_IDENTIFIER:
                ENC_CSEQUENCE(encoder, p->itemnum);
                encode_ipiri_id(encoder, (ipiri_id_t *)(p->itemptr));
                break;

            case IPIRI_CONTENTS_NATIONAL_IPIRI_PARAMETERS:
                /* TODO NationalIPIRIParameters */
                break;

            case IPIRI_CONTENTS_OTHER_TARGET_IDENTIFIERS:
                /* TODO */
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
                if (p->itemlen != sizeof(struct timeval)) {
                    return;
                }
                wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE, p->itemnum,
                        p->itemptr, p->itemlen);
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

static inline void encode_etsili_pshdr_pc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */

    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_USEQUENCE]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_PSDOMAINID]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_LIID]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_AUTHCC]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_3]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_OPERATORID]));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_NETWORKELEMID]));

    END_ENCODED_SEQUENCE(encoder)

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
            sizeof(int64_t));
    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_DELIVCC]));

    END_ENCODED_SEQUENCE(encoder)

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
            sizeof(int64_t));

    if (precomputed[OPENLI_PREENCODE_INTPOINTID].valspace) {
        wandder_encode_next_preencoded(encoder,
                &(precomputed[OPENLI_PREENCODE_INTPOINTID]));
    }

    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_CSEQUENCE_7]));
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
            sizeof(tv->tv_sec));
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
            sizeof(tv->tv_usec));
    END_ENCODED_SEQUENCE(encoder)

    wandder_encode_next_preencoded(encoder,
            &(precomputed[OPENLI_PREENCODE_TVCLASS]));
    END_ENCODED_SEQUENCE(encoder)

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
    /*
    wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, tv,
            sizeof(struct timeval));
    */

    if (hdrdata->intpointid) {
        wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, hdrdata->intpointid,
                hdrdata->intpointid_len);
    }

    ENC_CSEQUENCE(encoder, 7);
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
            sizeof(tv->tv_sec));
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
            sizeof(tv->tv_usec));
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 8, &tvclass, sizeof(tvclass));
    wandder_encode_endseq(encoder);

}

wandder_encoded_result_t *encode_etsi_ipcc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir) {


    encode_etsili_pshdr_pc(encoder, precomputed, cin, seqno, tv);
    encode_ipcc_body(encoder, precomputed, ipcontents, iplen, dir);
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

wandder_encoded_result_t *encode_etsi_ipiri(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t cin, int64_t seqno,
        etsili_iri_type_t iritype, struct timeval *tv,
        etsili_generic_t *params) {

    encode_etsili_pshdr(encoder, hdrdata, cin, seqno, tv);
    encode_ipiri_body(encoder, iritype, params);
    return wandder_encode_finish(encoder);

}

wandder_encoded_result_t *encode_etsi_sipiri(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t cin, int64_t seqno,
        etsili_iri_type_t iritype, struct timeval *tv, uint8_t *ipsrc,
        uint8_t *ipdest, int ipfamily, void *sipcontents, uint32_t siplen) {

    encode_etsili_pshdr(encoder, hdrdata, cin, seqno, tv);
    encode_sipiri_body(encoder, iritype, ipsrc, ipdest, ipfamily, sipcontents,
            siplen);
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
        free(tmp->itemptr);
        free(tmp);
    }
}

void etsili_create_ipaddress_v6(uint8_t *addrnum,
        uint8_t slashbits, uint8_t assigned, etsili_ipaddress_t *ip) {

    ip->iptype = ETSILI_IPADDRESS_VERSION_6;
    ip->assignment = assigned;
    ip->v6prefixlen = slashbits;
    ip->v4subnetmask = 0;

    ip->valtype = ETSILI_IPADDRESS_REP_BINARY;
    ip->ipvalue = addrnum;
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
    ip->ipvalue = (uint8_t *)addrnum;
}

void etsili_preencode_static_fields(
        wandder_encode_job_t *pendarray, etsili_intercept_details_t *details) {

    wandder_encode_job_t *p;
    int tvclass = 1;
    uint32_t dirin = 0, dirout = 1, dirunk = 2;

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
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->networkelemid, strlen(details->networkelemid));

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
    wandder_encode_preencoded_value(p, etsi_ipmmirioid, sizeof(etsi_ipmmirioid));

    p = &(pendarray[OPENLI_PREENCODE_IPCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, etsi_ipccoid, sizeof(etsi_ipccoid));

    p = &(pendarray[OPENLI_PREENCODE_IPIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, etsi_ipirioid, sizeof(etsi_ipirioid));

    p = &(pendarray[OPENLI_PREENCODE_IPMMCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, etsi_ipmmccoid, sizeof(etsi_ipmmccoid));

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

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
