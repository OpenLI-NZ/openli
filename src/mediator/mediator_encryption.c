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

uint8_t *encrypt_payload_container_aes_192_cbc(EVP_CIPHER_CTX *ctx,
        wandder_etsispec_t *etsidecoder, uint8_t *fullrec, uint16_t reclen,
        char *enckey) {


    uint8_t *dest = NULL;
    uint8_t *buf = NULL;
    uint32_t buflen = 0;
    int64_t seqno = 0;
    uint8_t *container;
    uint32_t container_len = 0;
    uint8_t *enctypeptr = NULL;

    if (!enckey) {
        return NULL;
    }
    if (!ctx) {
        return NULL;
    }

    wandder_attach_etsili_buffer(etsidecoder, fullrec, reclen, 0);

    seqno = wandder_etsili_get_sequence_number(etsidecoder);

    container = wandder_etsili_get_encryption_container(etsidecoder,
            etsidecoder->dec, &container_len);
    if (!container || container_len == 0) {
        return NULL;
    }

    wandder_decode_next(etsidecoder->dec);      // encryptionType
    enctypeptr = wandder_get_itemptr(etsidecoder->dec);
    *enctypeptr = OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC;

    wandder_decode_next(etsidecoder->dec);      // encryptedPayload
    buflen = wandder_get_itemlen(etsidecoder->dec);
    buf = malloc(buflen);
    dest = wandder_get_itemptr(etsidecoder->dec);

    if (encrypt_aes_192_cbc(ctx, dest,
            buflen, buf, buflen, (uint32_t)seqno, enckey) < 0) {
        free(buf);
        return NULL;
    }

    memcpy(dest, buf, buflen);
    free(buf);

    return dest;

}


payload_encryption_method_t check_encryption_requirements(
        mediator_collector_config_t *config, char *liid,
        char **enckey) {

    added_liid_t *found = NULL;
    payload_encryption_method_t method = OPENLI_PAYLOAD_ENCRYPTION_NONE;

    pthread_mutex_lock(&(config->mutex));
    HASH_FIND(hh, config->liid_to_agency_map, liid, strlen(liid), found);
    if (found && found->encryptkey) {
        (*enckey) = strdup(found->encryptkey);
    } else {
        *enckey = NULL;
    }
    if (found) {
        method = found->encrypt;
    }
    pthread_mutex_unlock(&(config->mutex));

    return method;
}
