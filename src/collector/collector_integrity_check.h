/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by Searchlight Ltd.
 * For further information please see https://searchlight.nz/
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

#ifndef OPENLI_COLLECTOR_INTEGRITY_H_
#define OPENLI_COLLECTOR_INTEGRITY_H_

#include "collector_base.h"
#include "agency.h"

enum {
    INTEGRITY_CHECK_NO_ACTION = 0,
    INTEGRITY_CHECK_SEND_HASH = 1,
    INTEGRITY_CHECK_REQUEST_SIGN = 2,
};

void clear_digest_key_map(digest_map_key_t **map);

void remove_liid_to_agency_map_entry(liid_to_agency_mapping_t **map,
        char *liid);
int update_liid_to_agency_map(liid_to_agency_mapping_t **map,
        char *liid, char *agencyid);
void purge_liid_to_agency_map(liid_to_agency_mapping_t **map);

int update_agency_digest_config_map(agency_digest_config_t **map,
        char *agencyid, liagency_digest_config_t *digest);
void free_agency_digest_config(agency_digest_config_t *dig);
void remove_agency_digest_config(agency_digest_config_t **map,
        char *agencyid);


uint8_t update_integrity_check_state(integrity_check_state_t **map,
        encoder_liid_state_t *known, uint8_t *msgbody, uint16_t msglen,
        openli_proto_msgtype_t msgtype, openli_encoding_job_t *job,
        int epoll_fd, integrity_check_state_t **chain);

int generate_integrity_check_hash_pdu(openli_encoded_result_t *res,
        integrity_check_state_t *ics, char *netelemid, char *operatorid,
        wandder_encoder_t *encoder, wandder_etsispec_t *etsidecoder,
        EVP_CIPHER_CTX *evp_ctx, encrypt_encode_state_t *encryptstate);
int generate_integrity_check_signature_pdu(openli_encoded_result_t *res,
        integrity_check_state_t *ics, char *netelemid, char *operatorid,
        wandder_encoder_t *encoder, EVP_PKEY *signingkey);

void free_integrity_check_state(integrity_check_state_t *integ);

#endif
