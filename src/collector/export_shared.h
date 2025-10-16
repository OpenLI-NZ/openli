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

#ifndef OPENLI_EXPORT_SHARED_H_
#define OPENLI_EXPORT_SHARED_H_

#include "config.h"
#include <uthash.h>
#include <libwandder.h>

#include "etsili_core.h"
#include "intercept.h"

typedef struct exporter_intercept_msg {
    char *liid;
    int liid_len;
    char *authcc;
    int authcc_len;
    char *delivcc;
    int delivcc_len;

    payload_encryption_method_t encryptmethod;
    openli_timestamp_encoding_fmt_t timefmt;
    openli_liid_format_t liid_format;
} exporter_intercept_msg_t;

typedef struct cin_seqno {
    uint32_t cin;
    uint32_t cc_seqno;
    uint32_t iri_seqno;
    char *cin_string;
    UT_hash_handle hh;
} cin_seqno_t;

typedef struct intercept_state {
    exporter_intercept_msg_t details;
    cin_seqno_t *cinsequencing;
    UT_hash_handle hh;
    wandder_encode_job_t *preencoded;
    uint8_t version;
} exporter_intercept_state_t;
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
