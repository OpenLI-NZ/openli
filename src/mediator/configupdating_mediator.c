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

#include <json-c/json.h>

#include "logger.h"
#include "mediator.h"

int handle_base_mediator_config_changes(mediator_state_t *state,
        openli_yaml_config_pending_updates_t *pending, char *json,
        int *listenchanged, int *opidchanged) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *listenaddr_json, *listenport_json;
    struct json_object *opid_json, *altopid_json;
    int ret = -1;
    const char *listenaddr = NULL;
    const char *listenport = NULL;
    const char *opid = NULL;
    const char *altopid = NULL;

    listenaddr_json = listenport_json = NULL;
    opid_json = altopid_json = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI mediator: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto basefail;
    }

    if (json_object_object_get_ex(parsed, "operatorid", &opid_json) &&
            json_object_is_type(opid_json, json_type_string)) {
        opid = json_object_get_string(opid_json);
        if (opid) {
            if (state->operatorid) {
                free(state->operatorid);
            }
            state->operatorid = strdup((char *)opid);
            if (strlen(state->operatorid) > 16) {
                state->operatorid[16] = '\0';
                logger(LOG_INFO, "OpenLI: warning, 'operatorid' received from provisioner was longer than 16 characters -- truncated to %s", state->operatorid);
            }
            UPDATE_SCALAR_CONFIG(pending, "operatorid", state->operatorid,
                    true, true);
            *opidchanged = 1;
        }
    }

    if (json_object_object_get_ex(parsed, "altoperatorid", &altopid_json) &&
            json_object_is_type(altopid_json, json_type_string)) {
        altopid = json_object_get_string(altopid_json);
        if (altopid) {
            if (state->shortoperatorid) {
                free(state->shortoperatorid);
            }
            state->shortoperatorid = strdup((char *)altopid);
            if (strlen(state->shortoperatorid) > 5) {
                state->shortoperatorid[5] = '\0';
                logger(LOG_INFO, "OpenLI: warning, 'altoperatorid' received from provisioner was longer than 5 characters -- truncated to %s", state->shortoperatorid);
            }
            UPDATE_SCALAR_CONFIG(pending, "altoperatorid",
                    state->shortoperatorid, true, true);
            *opidchanged = 1;
        }
    }

    if (json_object_object_get_ex(parsed, "listenaddr", &listenaddr_json) &&
            json_object_is_type(listenaddr_json, json_type_string)) {
        listenaddr = json_object_get_string(listenaddr_json);
        if (listenaddr) {
            if (state->listenaddr) {
                free(state->listenaddr);
            }
            state->listenaddr = strdup((char *)listenaddr);
            UPDATE_SCALAR_CONFIG(pending, "listenaddr", state->listenaddr,
                    true, true);
            *listenchanged = 1;
        }
    }
    if (json_object_object_get_ex(parsed, "listenport", &listenport_json) &&
            json_object_is_type(listenport_json, json_type_string)) {
        listenport = json_object_get_string(listenport_json);
        if (listenport) {
            if (state->listenport) {
                free(state->listenport);
            }
            state->listenport = strdup((char *)listenport);
            UPDATE_SCALAR_CONFIG(pending, "listenport", state->listenport,
                    true, true);
            *listenchanged = 1;
        }
    }
    ret = 0;

basefail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}
