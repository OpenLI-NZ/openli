/*
 *
 * Copyright (c) 2024,2025 SearchLight Ltd, New Zealand.
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

#include <Judy.h>

#include "etsili_core.h"
#include "logger.h"

void free_encoded_header_templates(Pvoid_t *headers) {
    PWord_t pval;
    Word_t index = 0;
    int rcint;

    JLF(pval, *headers, index);
    while (pval) {
        encoded_header_template_t *tplate;

        tplate = (encoded_header_template_t *)(*pval);
        if (tplate->header) {
            free(tplate->header);
        }
        free(tplate);
        JLN(pval, *headers, index);
    }
    JLFA(rcint, *headers);
}

encoded_header_template_t *encode_templated_psheader(
        wandder_encoder_t *encoder, Pvoid_t *headermap,
        wandder_encode_job_t *preencoded, uint32_t seqno,
        struct timeval *tv, int64_t cin, uint32_t cept_version,
        openli_timestamp_encoding_fmt_t timefmt) {

    uint8_t seqlen, tvsec_len, tvusec_len;
    uint32_t key = 0;
    PWord_t pval;
    encoded_header_template_t *tplate = NULL;

    if (!encoder || !headermap) {
        return NULL;
    }

    if (tv && tv->tv_sec == 0) {
        gettimeofday(tv, NULL);
    }
    seqlen = DERIVE_INTEGER_LENGTH(seqno);
    if (timefmt == OPENLI_ENCODED_TIMESTAMP_MICROSECONDS) {
        if (tv == NULL) {
            tvsec_len = 0;
            tvusec_len = 0;
        } else {
            tvsec_len = DERIVE_INTEGER_LENGTH(tv->tv_sec);
            tvusec_len = DERIVE_INTEGER_LENGTH(tv->tv_usec);
        }

        key = (cept_version << 24) + (seqlen << 16) + (tvsec_len << 8) +
                tvusec_len;
    } else if (timefmt == OPENLI_ENCODED_TIMESTAMP_GENERALIZED) {
        // all libwandder generalized timestamps are encoded with the
        // same length
        key = (cept_version << 24) + (seqlen << 16);
    } else {
        return NULL;
    }

    JLI(pval, *headermap, key);
    if (*pval == 0) {
        tplate = calloc(1, sizeof(encoded_header_template_t));

        if (etsili_create_header_template(encoder, preencoded, cin,
                (int64_t)seqno, tv, tplate, timefmt) < 0) {
            free(tplate);
            return NULL;
        }

        *pval = (Word_t)tplate;

    } else {
        tplate = (encoded_header_template_t *)(*pval);

        if (etsili_update_header_template(tplate, (int64_t)seqno, tv,
                timefmt) < 0) {
            return NULL;
        }
    }

    return tplate;
}


encoded_global_template_t *lookup_global_template(Pvoid_t *saved_templates,
        uint32_t key, uint8_t *is_new) {

    PWord_t pval;
    encoded_global_template_t *tplate = NULL;

    JLG(pval, *saved_templates, key);
    if (pval == NULL) {
        tplate = calloc(1, sizeof(encoded_global_template_t));
        tplate->key = key;
        tplate->cctype = (key >> 16);
        JLI(pval, *saved_templates, key);
        *pval = (Word_t)tplate;
        *is_new = 1;
    } else {
        tplate = (encoded_global_template_t *)(*pval);
        *is_new = 0;
    }

    return tplate;
}

void clear_global_templates(Pvoid_t *saved_templates) {
    Word_t indexint = 0;
    PWord_t pval;
    encoded_global_template_t *t;
    int rcint;

    JLF(pval, *(saved_templates), indexint);
    while (pval) {
        t = (encoded_global_template_t *)(*pval);
        if (t->cc_content.cc_wrap) {
            free(t->cc_content.cc_wrap);
        }
        free(t);
        JLN(pval, *(saved_templates), indexint);
    }
    JLFA(rcint, *saved_templates);
}
