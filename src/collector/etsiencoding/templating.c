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
    Word_t indexint;
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
