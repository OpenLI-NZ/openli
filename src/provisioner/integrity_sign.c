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
#include "netcomms.h"

int prov_handle_ics_signing_request(provision_state_t *state,
        uint8_t *msgbody, uint16_t msglen, prov_sock_state_t *cs,
        prov_epoll_ev_t *pev) {

    struct ics_sign_request_message req;
    struct ics_sign_response_message resp;
    int ret = 0;
    char err_msg[256];
    unsigned long errcode;
    size_t signlen = 0;

    memset(&resp, 0, sizeof(struct ics_sign_response_message));

    if (decode_ics_signing_request(msgbody, msglen, &req) < 0) {
        return -1;
    }

    if (state->sign_ctx == NULL) {
        goto tidyup;
    }

    if (EVP_PKEY_sign_init(state->sign_ctx) <= 0) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO, "OpenLI provisioner: failed to initialize integrity check signature: %s",
                err_msg);
        goto tidyup;
    }

    if (EVP_PKEY_sign(state->sign_ctx, NULL, &(signlen), req.digest,
            req.digest_len) <= 0) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO, "OpenLI provisioner: failed to derive length for integrity check signature: %s",
                err_msg);
        goto tidyup;
    }

    resp.signature = OPENSSL_malloc(signlen);
    if (!resp.signature) {
        logger(LOG_INFO, "OpenLI provisioner: failed to allocate memory to store integrity check signature");
        goto tidyup;
    }

    if (EVP_PKEY_sign(state->sign_ctx, resp.signature, &(signlen),
            req.digest, req.digest_len) <= 0) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO, "OpenLI provisioner: failed to generate integrity check signature from digest: %s",
                err_msg);
        goto tidyup;
    }

    /* create and send a response with the signature in it */
    resp.ics_key = req.ics_key;
    resp.sign_len = (uint32_t)signlen;
    resp.requestedby = req.requestedby;
    resp.requestedby_fwd = req.requestedby_fwd;
    resp.seqno = req.seqno;

    if (push_ics_signing_response_onto_net_buffer(cs->outgoing, &resp) < 0) {
        if (cs->log_allowed) {
            logger(LOG_INFO, "OpenLI provisioner: error pushing integrity check signature response onto buffer for writing to mediator %s", cs->ipaddr);
        }
        ret = -1;
    }
    req.ics_key = NULL;
    req.requestedby = NULL;

    if (enable_epoll_write(state, pev) == -1) {
        logger(LOG_INFO, "OpenLI provisioner: unable to re-enable epoll write event to send integrity check signature response to mediator: %s", strerror(errno));

    }


tidyup:
    if (resp.signature) {
        OPENSSL_free(resp.signature);
    }
    if (req.digest) {
        free(req.digest);
    }
    if (req.ics_key) {
        free(req.ics_key);
    }
    if (req.requestedby) {
        free(req.requestedby);
    }

    return ret;

}

int load_integrity_signing_privatekey(provision_state_t *state) {

    FILE *fp;
    char err_msg[256];
    unsigned long errcode;

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
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO,
                "OpenLI provisioner: failed to read private key from %s: %s",
                state->integrity_sign_private_key_location, err_msg);
        fclose(fp);
        return -1;
    }

    if (state->sign_ctx) {
        EVP_PKEY_CTX_free(state->sign_ctx);
    }
    state->sign_ctx = EVP_PKEY_CTX_new(state->integrity_sign_private_key, NULL);
    if (!state->sign_ctx) {
        errcode = ERR_get_error();
        ERR_error_string_n(errcode, err_msg, sizeof(err_msg));

        logger(LOG_INFO,
                "OpenLI provisioner: failed to create signing context for integrity check signatures: %s", err_msg);
        fclose(fp);
        return -1;
    }

    logger(LOG_INFO,
            "OpenLI provisioner: successfully loaded integrity signing key from %s",
            state->integrity_sign_private_key_location);

    fclose(fp);
    return 1;

}
