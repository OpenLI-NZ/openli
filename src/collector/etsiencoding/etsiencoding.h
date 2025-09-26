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

#ifndef OPENLI_ETSIENCODING_H_
#define OPENLI_ETSIENCODING_H_

#include <stdlib.h>
#include <inttypes.h>
#include <libwandder.h>
#include <uthash.h>
#include <libwandder_etsili.h>
#include <openssl/evp.h>


#include "intercept.h"
#include "etsili_core.h"
#include "export_buffer.h"

/* 16 byte block size for AES, and 16 bytes for the IV
 *
 * size = ((input_size + block_size - 1) / block_size) * block_size
 */
#define AES_OUTPUT_SIZE(inpsize) \
    (((inpsize + 16 - 1) / 16) * 16)

typedef struct encoded_encrypt_template {
    uint32_t key;
    uint32_t totallen;
    uint32_t payloadlen;
    uint8_t *start;
    uint8_t *payload;
    uint8_t *payload_type;
} encoded_encrypt_template_t;

enum {
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_UNKNOWN = 1,
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART2 = 2,
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART3 = 3,
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART4 = 4,
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART5 = 5,
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART6 = 6,
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART7 = 7,
    OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART1 = 8
};

enum {
    TEMPLATE_TYPE_IPCC_DIRFROM,
    TEMPLATE_TYPE_IPCC_DIRTO,
    TEMPLATE_TYPE_IPCC_DIROTHER,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIRTO_IP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_RTP,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_MSRP,
    TEMPLATE_TYPE_IPMMCC_DIRTO_IP_MSRP,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_MSRP,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_UDPTL,
    TEMPLATE_TYPE_IPMMCC_DIRTO_IP_UDPTL,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_UDPTL,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_UDP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIRTO_UDP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_UDP_RTP,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_UDP_UDPTL,
    TEMPLATE_TYPE_IPMMCC_DIRTO_UDP_UDPTL,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_UDP_UDPTL,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_TCP_MSRP,
    TEMPLATE_TYPE_IPMMCC_DIRTO_TCP_MSRP,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_TCP_MSRP,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_RTP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIRTO_RTP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_RTP_RTP,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_MSRP_MSRP,
    TEMPLATE_TYPE_IPMMCC_DIRTO_MSRP_MSRP,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_MSRP_MSRP,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_UDPTL_UDPTL,
    TEMPLATE_TYPE_IPMMCC_DIRTO_UDPTL_UDPTL,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_UDPTL_UDPTL,

    TEMPLATE_TYPE_UMTSCC_DIRFROM,
    TEMPLATE_TYPE_UMTSCC_DIRTO,
    TEMPLATE_TYPE_UMTSCC_DIROTHER,

    TEMPLATE_TYPE_EMAILCC_IP_DIRTO,
    TEMPLATE_TYPE_EMAILCC_APP_DIRTO,
    TEMPLATE_TYPE_EMAILCC_IP_DIRFROM,
    TEMPLATE_TYPE_EMAILCC_APP_DIRFROM,
    TEMPLATE_TYPE_EMAILCC_IP_DIROTHER,
    TEMPLATE_TYPE_EMAILCC_APP_DIROTHER,

    TEMPLATE_TYPE_EPSCC_DIRFROM,
    TEMPLATE_TYPE_EPSCC_DIRTO,
    TEMPLATE_TYPE_EPSCC_DIROTHER,
};


typedef struct encrypt_encode_state {
    uint32_t byte_counter;
    uint32_t byte_startts;
    EVP_CIPHER_CTX *evp_ctx;
    Pvoid_t saved_encryption_templates;
} encrypt_encode_state_t;

typedef struct encoder_job {
    wandder_encode_job_t *preencoded;
    uint32_t seqno;
    int64_t cin;
    char *cinstr;
    openli_export_recv_t *origreq;
    char *liid;
    uint8_t cept_version;
    payload_encryption_method_t encryptmethod;
    uint8_t *encryptkey;
} PACKED openli_encoding_job_t;

void encode_ipaddress(wandder_encoder_t *encoder,
		wandder_encode_job_t *precomputed, etsili_ipaddress_t *addr);

int create_encrypted_message_body(wandder_encoder_t *encoder,
                encrypt_encode_state_t *encrypt,
                openli_encoded_result_t *res,
                encoded_header_template_t *hdr_tplate,
                uint8_t *payloadbody, uint16_t bodylen,
                uint8_t *ipcontents, uint16_t ipclen,
                openli_encoding_job_t *job);

int create_etsi_encoded_result(openli_encoded_result_t *res,
        encoded_header_template_t *hdr_tplate,
        uint8_t *body_content, uint16_t bodylen,
        uint8_t *trailing, uint16_t traillen,
        openli_encoding_job_t *job);

void etsili_destroy_encrypted_templates(Pvoid_t templates);

int encode_templated_ipmmiri(wandder_encoder_t *encoder,
        encrypt_encode_state_t *encrypt,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res);

int encode_templated_ipmmcc(wandder_encoder_t *encoder,
        encrypt_encode_state_t *encrypt,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res, Pvoid_t *saved_templates);

encoded_global_template_t *lookup_global_template(Pvoid_t *saved_templates,
        uint32_t key, uint8_t *is_new);
void clear_global_templates(Pvoid_t *saved_templates);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
