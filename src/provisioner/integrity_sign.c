/*
 * Copyright (c) 2025 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by SearchLight Ltd. For more information,
 * see https://searchlight.nz
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

#include <stdio.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "logger.h"
#include "provisioner.h"

int load_integrity_signing_privatekey(provision_state_t *state) {

    FILE *fp;

    if (state->integrity_sign_private_key) {
        EVP_PKEY_free(state->integrity_sign_private_key);
    }

    state->integrity_sign_private_key = NULL;
    if (!state->integrity_sign_private_key_location) {
        return 0;
    }

    fp = fopen(state->integrity_sign_private_key_location, "r");
    if (!fp) {
        logger(LOG_INFO, "OpenLI provisioner: failed to open private key for signing integrity checks at '%s': %s",
                state->integrity_sign_private_key_location, strerror(errno));
        return -1;
    }

    state->integrity_sign_private_key = PEM_read_PrivateKey(fp, NULL, NULL,
            NULL);
    if (state->integrity_sign_private_key == NULL) {
        unsigned long errcode = ERR_get_error();
        char err_msg[256];

        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO,
                "OpenLI provisioner: failed to read private key from %s: %s",
                state->integrity_sign_private_key_location, err_msg);
        fclose(fp);
        return -1;
    }
    logger(LOG_INFO,
            "OpenLI provisioner: successfully loaded integrity signing key from %s",
            state->integrity_sign_private_key_location);

    fclose(fp);
    return 1;

}
