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
#ifndef OPENLI_ETSILI_CORE_H_
#define OPENLI_ETSILI_CORE_H_

#include <stdlib.h>
#include <inttypes.h>
#include <libwandder.h>
#include <uthash.h>

#include "intercept.h"

#define ENC_USEQUENCE(enc) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_UNIVERSAL_CONSTRUCT, WANDDER_TAG_SEQUENCE, NULL, 0)

#define ENC_CSEQUENCE(enc, x) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_CONTEXT_CONSTRUCT, x, NULL, 0)

#define END_ENCODED_SEQUENCE(enc, x) \
        wandder_encode_endseq_repeat(enc, x);

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

typedef struct etsili_email_iri {
    uint32_t eventtype;
    struct sockaddr_storage *serveraddr;
    struct sockaddr_storage *clientaddr;
    uint32_t server_octets;
    uint32_t client_octets;
    uint32_t protocol;
    uint32_t recipient_count;
    char *sender;
    char **recipients;
    uint32_t status;
    char *messageid;
    uint32_t sender_validity;
} etsili_email_iri_content_t;

typedef struct etsili_other_targets {

    uint8_t count;
    uint8_t alloced;
    etsili_ipaddress_t *targets;
} etsili_other_targets_t;

typedef struct etsili_email_recipients {
    uint32_t count;
    char **addresses;
} etsili_email_recipients_t;

typedef enum {
    ETSILI_IRI_NONE = 0,
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
    ETSILI_EMAIL_STATUS_UNKNOWN = 1,
    ETSILI_EMAIL_STATUS_FAILED = 2,
    ETSILI_EMAIL_STATUS_SUCCESS = 3
};

enum {
    ETSILI_EMAIL_CC_FORMAT_IP = 1,
    ETSILI_EMAIL_CC_FORMAT_APP = 2,
};

enum {
    ETSILI_EMAIL_EVENT_SEND = 1,
    ETSILI_EMAIL_EVENT_RECEIVE = 2,
    ETSILI_EMAIL_EVENT_DOWNLOAD = 3,
    ETSILI_EMAIL_EVENT_LOGON_ATTEMPT = 4,
    ETSILI_EMAIL_EVENT_LOGON = 5,
    ETSILI_EMAIL_EVENT_LOGON_FAILURE = 6,
    ETSILI_EMAIL_EVENT_LOGOFF = 7,
    ETSILI_EMAIL_EVENT_PARTIAL_DOWNLOAD = 8,
    ETSILI_EMAIL_EVENT_UPLOAD = 9,
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
    OPENLI_PREENCODE_CSEQUENCE_4,   /* UMTSIRI */
    OPENLI_PREENCODE_CSEQUENCE_7,	/* Microsecond timestamp */
    OPENLI_PREENCODE_CSEQUENCE_11,  /* IPMMIRI */
    OPENLI_PREENCODE_CSEQUENCE_12,  /* IPMMCC */
    OPENLI_PREENCODE_CSEQUENCE_15,  /* EPSIRI */
    OPENLI_PREENCODE_CSEQUENCE_17,  /* EPSCC-PDU */
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
    OPENLI_PREENCODE_UMTSIRIOID,
    OPENLI_PREENCODE_EPSIRIOID,
    OPENLI_PREENCODE_EMAILIRIOID,
    OPENLI_PREENCODE_EMAILCCOID,
    OPENLI_PREENCODE_IPMMCCOID,
    OPENLI_PREENCODE_DIRFROM,
    OPENLI_PREENCODE_DIRTO,
    OPENLI_PREENCODE_DIRUNKNOWN,
    OPENLI_PREENCODE_NO_ENCRYPTION,
    OPENLI_PREENCODE_AES_192_CBC,
    OPENLI_PREENCODE_EPSCCOID,
    OPENLI_PREENCODE_IPTYPE_IPV4,
    OPENLI_PREENCODE_IPTYPE_IPV6,
    OPENLI_PREENCODE_IPASSIGN_STATIC,
    OPENLI_PREENCODE_IPASSIGN_DYNAMIC,
    OPENLI_PREENCODE_IPASSIGN_UNKNOWN,
    OPENLI_PREENCODE_IPV6_PREFIX_64,
    OPENLI_PREENCODE_IPV6_PREFIX_48,
    OPENLI_PREENCODE_IPV4_NETMASK_32,
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

typedef struct encoded_header_template {
    uint32_t key;
    uint8_t *header;
    uint16_t header_len;
    uint8_t seqno_size;
    uint8_t tssec_size;
    uint8_t tsusec_size;
    uint8_t *seqno_ptr;
    uint8_t *tssec_ptr;
    uint8_t *tsusec_ptr;

} encoded_header_template_t;

typedef struct encoded_cc_template {
    uint8_t *content_ptr;
    uint16_t content_size;

    uint8_t *cc_wrap;
    uint16_t cc_wrap_len;

} encoded_cc_template_t;

typedef struct encoded_global_template {
    uint32_t key;
    uint8_t cctype;

    encoded_cc_template_t cc_content;
} encoded_global_template_t;

uint8_t DERIVE_INTEGER_LENGTH(uint64_t x);

int calculate_pspdu_length(uint32_t contentsize);

wandder_encoded_result_t *encode_ipiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, etsili_iri_type_t iritype,
        etsili_generic_t **params);

wandder_encoded_result_t *encode_umtsiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        etsili_iri_type_t iritype, etsili_generic_t *params);

wandder_encoded_result_t *encode_epsiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        etsili_iri_type_t iritype, etsili_generic_t *params);

wandder_encoded_result_t *encode_emailiri_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        etsili_iri_type_t iritype, etsili_generic_t **params);

wandder_encoded_result_t *encode_etsi_keepalive(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t seqno);


wandder_encoded_result_t *encode_etsi_hi1_notification(
        wandder_encoder_t *encoder, hi1_notify_data_t *not_data,
        char *operatorid, char *shortopid);

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


int etsili_create_umtscc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, uint8_t dir, uint16_t ipclen,
        encoded_global_template_t *tplate);
int etsili_create_header_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, encoded_header_template_t *tplate);
int etsili_update_header_template(encoded_header_template_t *tplate,
        int64_t seqno, struct timeval *tv);
int etsili_create_ipcc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, uint8_t dir, uint16_t ipclen,
        encoded_global_template_t *tplate);
int etsili_create_emailcc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, uint8_t format, uint8_t dir,
        uint16_t ipclen, encoded_global_template_t *tplate);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
