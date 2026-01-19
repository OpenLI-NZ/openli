/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
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

#ifndef OPENLI_CONFIGWRITER_COMMON_H_
#define OPENLI_CONFIGWRITER_COMMON_H_

#include <yaml.h>
#include "coreserver.h"

typedef struct yaml_mem_buf {
    uint8_t *buffer;
    size_t alloced;
    size_t used;
} yaml_buffer_t;


#define YAML_EMIT_INTEGER(event, label, strval) \
    if (strval != NULL) {                                               \
        yaml_scalar_event_initialize(&event, NULL,                      \
                (yaml_char_t *)YAML_INT_TAG,                            \
                (yaml_char_t *)label, strlen(label), 1, 0,              \
                YAML_PLAIN_SCALAR_STYLE);                               \
        if (!yaml_emitter_emit(emitter, &event)) return -1;             \
                                                                        \
        yaml_scalar_event_initialize(&event, NULL,                      \
                (yaml_char_t *)YAML_INT_TAG,                            \
                (yaml_char_t *)strval, strlen(strval),                  \
                        1, 0, YAML_PLAIN_SCALAR_STYLE);                 \
        if (!yaml_emitter_emit(emitter, &event)) return -1;             \
    }

#define YAML_EMIT_STRING(event, label, strval) \
    if (strval != NULL) {                                               \
        yaml_scalar_event_initialize(&event, NULL,                      \
                (yaml_char_t *)YAML_STR_TAG,                            \
                (yaml_char_t *)label, strlen(label), 1, 0,              \
                YAML_PLAIN_SCALAR_STYLE);                               \
        if (!yaml_emitter_emit(emitter, &event)) return -1;             \
                                                                        \
        yaml_scalar_event_initialize(&event, NULL,                      \
                (yaml_char_t *)YAML_STR_TAG,                            \
                (yaml_char_t *)strval, strlen(strval),                  \
                        1, 0, YAML_PLAIN_SCALAR_STYLE);                 \
        if (!yaml_emitter_emit(emitter, &event)) return -1;             \
    }

#define YAML_EMIT_BOOLEAN(event, label, boolean) \
    if (boolean) {                                                      \
        YAML_EMIT_STRING(event, label, "yes");                          \
    } else {                                                            \
        YAML_EMIT_STRING(event, label, "no");                           \
    }
#endif

int buffer_yaml_memory(void *data, unsigned char *towrite, size_t size);

int emit_core_server_list(coreserver_t *servers, const char *label,
        yaml_emitter_t *emitter);
