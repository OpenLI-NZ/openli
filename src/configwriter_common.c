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

#include <yaml.h>

#include "configwriter_common.h"
#include "logger.h"

int buffer_yaml_memory(void *data, unsigned char *towrite, size_t size) {

    yaml_buffer_t *buf = (yaml_buffer_t *)data;

    if (size > buf->alloced - buf->used) {
        buf->buffer = realloc(buf->buffer, buf->alloced + 65536);
        if (buf->buffer == NULL) {
            return 0;
        }
        buf->alloced += 65536;
    }

    memcpy(buf->buffer + buf->used, towrite, size);
    buf->used += size;
    buf->buffer[buf->used] = '\0';
    return 1;
}

int emit_core_server_list(coreserver_t *servers, const char *label,
        yaml_emitter_t *emitter) {

    yaml_event_t event;
    coreserver_t *cs, *tmp;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)label, strlen(label), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh, servers, cs, tmp) {
        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        YAML_EMIT_STRING(event, "ip", cs->ipstr);
        if (cs->portstr) {
            YAML_EMIT_STRING(event, "port", cs->portstr);
        }

        if (cs->lower_portstr) {
            YAML_EMIT_STRING(event, "port_lower", cs->lower_portstr);
        }

        if (cs->upper_portstr) {
            YAML_EMIT_STRING(event, "port_upper", cs->upper_portstr);
        }

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

