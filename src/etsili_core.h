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
#ifndef OPENLI_ETSILI_CORE_H_
#define OPENLI_ETSILI_CORE_H_

#include <stdlib.h>
#include <inttypes.h>
#include <libwandder.h>
#include <uthash.h>

#define ENC_USEQUENCE(enc) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_UNIVERSAL_CONSTRUCT, WANDDER_TAG_SEQUENCE, NULL, 0)

#define ENC_CSEQUENCE(enc, x) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_CONTEXT_CONSTRUCT, x, NULL, 0)

#define ETSI_DIR_FROM_TARGET 0
#define ETSI_DIR_TO_TARGET 1
#define ETSI_DIR_INDETERMINATE 2

typedef struct etsili_generic etsili_generic_t;
typedef struct etsili_generic_freelist etsili_generic_freelist_t;

struct etsili_generic {
    uint8_t itemnum;
    uint16_t itemlen;
    uint8_t *itemptr;
    uint16_t alloced;

    UT_hash_handle hh;
    etsili_generic_t *nextfree;
    etsili_generic_freelist_t *owner;
};

struct etsili_generic_freelist {
    etsili_generic_t *first;
    pthread_mutex_t mutex;
    uint8_t needmutex;
};

typedef struct etsili_intercept_details {
    char *liid;
    char *authcc;
    char *delivcc;
    char *intpointid;
    char *operatorid;
    char *networkelemid;
} etsili_intercept_details_t;

typedef struct etsili_ipaddress {
    uint8_t iptype;
    uint8_t assignment;
    uint8_t v6prefixlen;
    uint32_t v4subnetmask;

    uint8_t valtype;
    uint8_t *ipvalue;
} etsili_ipaddress_t;

typedef enum {
    ETSILI_IRI_BEGIN = 1,
    ETSILI_IRI_END = 2,
    ETSILI_IRI_CONTINUE = 3,
    ETSILI_IRI_REPORT = 4
} etsili_iri_type_t;

enum {
    ETSILI_IPADDRESS_VERSION_4 = 0,
    ETSILI_IPADDRESS_VERSION_6 = 1,
};

enum {
    ETSILI_IPADDRESS_REP_BINARY = 1,
    ETSILI_IPADDRESS_REP_TEXT = 2,
};

enum {
    ETSILI_IPADDRESS_ASSIGNED_STATIC = 1,
    ETSILI_IPADDRESS_ASSIGNED_DYNAMIC = 2,
    ETSILI_IPADDRESS_ASSIGNED_UNKNOWN = 3,
};

#define ETSILI_IPV4_SUBNET_UNKNOWN 255
#define ETSILI_IPV6_SUBNET_UNKNOWN 128

typedef enum {
    OPENLI_PREENCODE_USEQUENCE,
    OPENLI_PREENCODE_CSEQUENCE_0,
    OPENLI_PREENCODE_CSEQUENCE_1,
    OPENLI_PREENCODE_CSEQUENCE_2,
    OPENLI_PREENCODE_CSEQUENCE_3,
    OPENLI_PREENCODE_CSEQUENCE_7,	/* Microsecond timestamp */
    OPENLI_PREENCODE_CSEQUENCE_11,  /* IPMMIRI */
    OPENLI_PREENCODE_CSEQUENCE_12,  /* IPMMCC */
    OPENLI_PREENCODE_PSDOMAINID,
    OPENLI_PREENCODE_LIID,
    OPENLI_PREENCODE_AUTHCC,
    OPENLI_PREENCODE_OPERATORID,
    OPENLI_PREENCODE_NETWORKELEMID,
    OPENLI_PREENCODE_DELIVCC,
    OPENLI_PREENCODE_INTPOINTID,
    OPENLI_PREENCODE_TVCLASS,
    OPENLI_PREENCODE_IPMMIRIOID,
    OPENLI_PREENCODE_IPCCOID,
    OPENLI_PREENCODE_IPIRIOID,
    OPENLI_PREENCODE_IPMMCCOID,
    OPENLI_PREENCODE_DIRFROM,
    OPENLI_PREENCODE_DIRTO,
    OPENLI_PREENCODE_DIRUNKNOWN,
    OPENLI_PREENCODE_LAST

} preencode_index_t;


typedef struct wandder_etsipshdr_data {

    char *liid;
    int liid_len;
    char *authcc;
    int authcc_len;
    char *operatorid;
    int operatorid_len;
    char *networkelemid;
    int networkelemid_len;
    char *delivcc;
    int delivcc_len;
    char *intpointid;
    int intpointid_len;

} wandder_etsipshdr_data_t;

wandder_encoded_result_t *encode_etsi_ipcc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir);

wandder_encoded_result_t *encode_etsi_ipmmcc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir);

wandder_encoded_result_t *encode_etsi_ipmmiri(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        etsili_iri_type_t iritype, struct timeval *tv, void *ipcontents,
        uint32_t iplen);

wandder_encoded_result_t *encode_etsi_ipiri(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        etsili_iri_type_t iritype, struct timeval *tv,
        etsili_generic_t *params);

wandder_encoded_result_t *encode_etsi_sipiri(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        etsili_iri_type_t iritype, struct timeval *tv, uint8_t *ipsrc,
        uint8_t *ipdest, int ipfamily, void *sipcontents, uint32_t siplen);

wandder_encoded_result_t *encode_etsi_keepalive(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t seqno);


etsili_generic_freelist_t *create_etsili_generic_freelist(uint8_t needmutex);
etsili_generic_t *create_etsili_generic(etsili_generic_freelist_t *freelist,
        uint8_t itemnum, uint16_t itemlen, uint8_t *itemvalptr);
void release_etsili_generic(etsili_generic_t *gen);
void free_etsili_generics(etsili_generic_freelist_t *freelist);

void etsili_create_ipaddress_v4(uint32_t *addrnum, uint8_t slashbits,
        uint8_t assigned, etsili_ipaddress_t *ip);
void etsili_create_ipaddress_v6(uint8_t *addrnum,
        uint8_t slashbits, uint8_t assigned, etsili_ipaddress_t *ip);

void etsili_preencode_static_fields(wandder_encode_job_t *pendarray,
        etsili_intercept_details_t *details);
void etsili_clear_preencoded_fields(wandder_encode_job_t *pendarray);
void etsili_copy_preencoded(wandder_encode_job_t *dest,
        wandder_encode_job_t *src);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
