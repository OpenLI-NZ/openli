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
#include "collector.h"


int handle_sip_config_changes(collector_sip_config_t *sipconfig, char *json) {
    struct json_tokener *tknr;
    struct json_object *ignore_sdpo, *trust_from, *disable_redirect;
    struct json_object *sipdebugfile;
    struct json_object *parsed = NULL;
    int ret = -1;
    const char *debugfile = NULL;

    ignore_sdpo = trust_from = disable_redirect = sipdebugfile = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));
    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto sipconffail;
    }

    if (json_object_object_get_ex(parsed, "sipallowfromident", &trust_from)
            && json_object_is_type(trust_from, json_type_boolean)) {
        sipconfig->trust_sip_from = json_object_get_boolean(trust_from);
    }
    if (json_object_object_get_ex(parsed, "sipdisableredirect",
                &disable_redirect) && json_object_is_type(disable_redirect,
                        json_type_boolean)) {
        sipconfig->disable_sip_redirect =
                json_object_get_boolean(disable_redirect);
    }
    if (json_object_object_get_ex(parsed, "sipignoresdpo", &ignore_sdpo)
            && json_object_is_type(ignore_sdpo, json_type_boolean)) {
        sipconfig->ignore_sdpo_matches =
                json_object_get_boolean(ignore_sdpo);
    }

    if (json_object_object_get_ex(parsed, "sipdebugfile", &sipdebugfile) &&
            json_object_is_type(sipdebugfile, json_type_string)) {
        debugfile = json_object_get_string(sipdebugfile);
        if (debugfile) {
            if (sipconfig->sipdebugfile) {
                free(sipconfig->sipdebugfile);
            }
            sipconfig->sipdebugfile = strdup((char *)debugfile);
        }
        free((char *)debugfile);
    }
    ret = 0;

sipconffail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}
