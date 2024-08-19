/*
 *
 * Copyright (c) 2024 SearchLight NZ
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
#include "epscc.h"

openli_export_recv_t *create_epscc_job(char *liid, uint32_t cin,
        uint32_t destid, uint8_t dir, uint8_t *ipcontent, uint32_t ipclen,
        uint8_t icetype) {

    openli_export_recv_t *msg = NULL;

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }

    msg->type = OPENLI_EXPORT_EPSCC;
    msg->destid = destid;
    gettimeofday(&(msg->ts), NULL);

    msg->data.mobcc.liid = strdup(liid);
    msg->data.mobcc.cin = cin;
    msg->data.mobcc.dir = dir;
    msg->data.mobcc.ipcontent = calloc(ipclen, sizeof(uint8_t));
    memcpy(msg->data.mobcc.ipcontent, ipcontent, ipclen);
    msg->data.mobcc.ipclen = ipclen;
    msg->data.mobcc.icetype = icetype;

    return msg;
}

wandder_encoded_result_t *encode_epscc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed UNUSED, uint32_t cin UNUSED,
        uint32_t seqno UNUSED, uint8_t dir UNUSED, struct timeval tv UNUSED,
        uint8_t icetype UNUSED) {

    return wandder_encode_finish(encoder);
}
