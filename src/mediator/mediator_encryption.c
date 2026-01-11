/*
 *
 * Copyright (c) 2025 SearchLight Ltd, New Zealand.
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

#include <uthash.h>
#include <libwandder_etsili.h>

#include "etsiencoding.h"
#include "coll_recv_thread.h"
#include "liidmapping.h"
#include "logger.h"

payload_encryption_method_t check_encryption_requirements(
        mediator_collector_config_t *config, char *liid,
        uint8_t *enckey, size_t *enckeylen) {

    added_liid_t *found = NULL;
    payload_encryption_method_t method = OPENLI_PAYLOAD_ENCRYPTION_NONE;

    memset(enckey, 0, OPENLI_MAX_ENCRYPTKEY_LEN);

    pthread_mutex_lock(&(config->mutex));
    HASH_FIND(hh, config->liid_to_agency_map, liid, strlen(liid), found);
    if (found && found->encryptkey_len > 0) {
        memcpy(enckey, found->encryptkey, found->encryptkey_len);
    }
    if (found) {
        method = found->encrypt;
        *enckeylen = found->encryptkey_len;
    }
    pthread_mutex_unlock(&(config->mutex));

    return method;
}
