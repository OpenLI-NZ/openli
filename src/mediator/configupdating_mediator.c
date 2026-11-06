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
    } else if (opid && state->shortoperatorid == NULL) {
        state->shortoperatorid = strdup((char *)opid);
        if (strlen(state->shortoperatorid) > 5) {
            state->shortoperatorid[5] = '\0';
        }
        UPDATE_SCALAR_CONFIG(pending, "altoperatorid",
                state->shortoperatorid, true, true);
        *opidchanged = 1;
    }

    if (json_object_object_get_ex(parsed, "listenaddr", &listenaddr_json) &&
            json_object_is_type(listenaddr_json, json_type_string)) {
        listenaddr = json_object_get_string(listenaddr_json);
        if (listenaddr && (!state->listenaddr ||
                strcmp(state->listenaddr, listenaddr) != 0)) {
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
            (json_object_is_type(listenport_json, json_type_string) ||
             json_object_is_type(listenport_json, json_type_int))) {
        listenport = json_object_get_string(listenport_json);
        if (listenport && (!state->listenport ||
                strcmp(state->listenport, listenport) != 0)) {
            if (state->listenport) {
                free(state->listenport);
            }
            state->listenport = strdup((char *)listenport);
            UPDATE_SCALAR_CONFIG(pending, "listenport", state->listenport,
                    false, true);
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

int handle_rmq_mediator_config_changes(mediator_state_t *state,
        openli_yaml_config_pending_updates_t *pending, char *json,
        int *rmqchanged) {

    int ret = -1;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *hbfreq_json = NULL;
    const char *rmqfreq = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI mediator: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto rmqfail;
    }

    if (json_object_object_get_ex(parsed, "RMQheartbeatfreq", &hbfreq_json) &&
            (json_object_is_type(hbfreq_json, json_type_string) ||
             json_object_is_type(hbfreq_json, json_type_int))) {
        rmqfreq = json_object_get_string(hbfreq_json);
        if (rmqfreq) {
            char *endptr = NULL;
            long freqint;
            errno = 0;

            freqint = strtol(rmqfreq, &endptr, 10);
            if (endptr == rmqfreq) {
                logger(LOG_INFO, "OpenLI mediator: invalid value for RMQheartbeatfreq option in update sent by provisioner: %s", rmqfreq);
                goto rmqfail;
            }

            if (freqint < 0) {
                logger(LOG_INFO, "OpenLI mediator: invalid value for RMQheartbeatfreq option in update sent by provisioner, must be >= 0: %ld", freqint);
                goto rmqfail;
            }

            if (freqint != state->RMQ_conf.heartbeatFreq) {
                state->RMQ_conf.heartbeatFreq = freqint;
                *endptr = '\0';
                UPDATE_SCALAR_CONFIG(pending, "RMQheartbeatfreq", rmqfreq,
                        false, true);
                *rmqchanged = 1;
            }
        }
    }

    ret = 0;
rmqfail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}

int handle_tls_mediator_config_changes(mediator_state_t *state,
        openli_yaml_config_pending_updates_t *pending, char *json,
        int *tlschanged) {
    int ret = -1;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *groups_json, *enabled_json;
    const char *tlsgroups = NULL;
    bool enabled;

    groups_json = enabled_json = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI mediator: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto tlsfail;
    }

    if (json_object_object_get_ex(parsed, "tlsgroups", &groups_json)) {
        if (json_object_is_type(groups_json, json_type_string)) {
            tlsgroups = json_object_get_string(groups_json);
            if (tlsgroups[0] == '\0' || strcasecmp(tlsgroups, "default") == 0) {
                tlsgroups = NULL;
            }
        } else if (json_object_is_type(groups_json, json_type_null)) {
            tlsgroups = NULL;
        }

        if ((state->sslconf.tlsgroups == NULL && tlsgroups != NULL) ||
            (state->sslconf.tlsgroups != NULL && tlsgroups == NULL) ||
            (state->sslconf.tlsgroups && tlsgroups &&
                    strcmp(state->sslconf.tlsgroups, tlsgroups) != 0)) {

            if (state->sslconf.tlsgroups) {
                free(state->sslconf.tlsgroups);
                state->sslconf.tlsgroups = NULL;
            }

            if (tlsgroups) {
                state->sslconf.tlsgroups = strdup((char *)tlsgroups);
                UPDATE_SCALAR_CONFIG(pending, "tlsgroups",
                        state->sslconf.tlsgroups, true, true);
            } else {
                UPDATE_SCALAR_CONFIG(pending, "tlsgroups", "", true, true);
            }
            *tlschanged = 1;
        }
    }

    if (json_object_object_get_ex(parsed, "etsitls", &enabled_json) &&
            json_object_is_type(enabled_json, json_type_boolean)) {
        enabled = json_object_get_boolean(enabled_json);
        if (state->etsitls != (uint8_t)enabled) {
            *tlschanged = 1;
            state->etsitls = (enabled ? 1 : 0);
            UPDATE_SCALAR_CONFIG(pending, "etsitls",
                    GENERATE_CONFIG_BOOLEAN(state->etsitls), false, true);
        }
    }

    ret = 0;

tlsfail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;


}

int handle_pcap_mediator_config_changes(mediator_state_t *state,
        openli_yaml_config_pending_updates_t *pending, char *json,
        int *pcapchanged) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *pcaptemplate_json, *compress_json;
    struct json_object *rotatefreq_json;
    int ret = -1;
    const char *pcaptemplate = NULL;
    const char *pcapcompress = NULL;
    const char *pcaprotatefreq = NULL;

    pcaptemplate_json = compress_json = rotatefreq_json = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI mediator: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto pcapfail;
    }

    if (json_object_object_get_ex(parsed, "pcapfilename", &pcaptemplate_json)
            && json_object_is_type(pcaptemplate_json, json_type_string)) {
        pcaptemplate = json_object_get_string(pcaptemplate_json);
        if (pcaptemplate) {
            if (state->pcaptemplate) {
                free(state->pcaptemplate);
            }
            state->pcaptemplate = strdup((char *)pcaptemplate);
            UPDATE_SCALAR_CONFIG(pending, "pcapfilename", state->pcaptemplate,
                    true, true);
            *pcapchanged = 1;
        }
    }

    if (json_object_object_get_ex(parsed, "pcapcompress", &compress_json) &&
            (json_object_is_type(compress_json, json_type_string) ||
             json_object_is_type(compress_json, json_type_int))) {
        pcapcompress = json_object_get_string(compress_json);
        if (pcapcompress) {
            char *endptr = NULL;
            long compress_int;
            errno = 0;

            compress_int = strtol(pcapcompress, &endptr, 10);
            if (endptr == pcapcompress) {
                logger(LOG_INFO, "OpenLI mediator: invalid value for pcapcompress option in update sent by provisioner: %s", pcapcompress);
                goto pcapfail;
            }

            if (compress_int < 0 || compress_int > 9) {
                logger(LOG_INFO, "OpenLI mediator: invalid value for pcapcompress option in update sent by provisioner (must be between 0 and 9 inclusive): %ld", compress_int);
                goto pcapfail;
            }

            state->pcapcompress = (uint8_t)compress_int;
            *endptr = '\0';
            UPDATE_SCALAR_CONFIG(pending, "pcapcompress", pcapcompress,
                    false, true);
            *pcapchanged = 1;
        }
    }

    if (json_object_object_get_ex(parsed, "pcaprotatefreq", &rotatefreq_json) &&
            (json_object_is_type(rotatefreq_json, json_type_string) ||
             json_object_is_type(rotatefreq_json, json_type_int))) {
        pcaprotatefreq = json_object_get_string(rotatefreq_json);
        if (pcaprotatefreq) {
            char *endptr = NULL;
            long freqint;
            errno = 0;

            freqint = strtol(pcaprotatefreq, &endptr, 10);
            if (endptr == pcaprotatefreq) {
                logger(LOG_INFO, "OpenLI mediator: invalid value for pcaprotatefreq option in update sent by provisioner: %s", pcaprotatefreq);
                goto pcapfail;
            }

            if (freqint <= 0) {
                logger(LOG_INFO, "OpenLI mediator: invalid value for pcaprotatefreq option in update sent by provisioner, must be > 0: %ld", freqint);
                goto pcapfail;
            }

            state->pcaprotatefreq = (uint32_t)freqint;
            *endptr = '\0';
            UPDATE_SCALAR_CONFIG(pending, "pcaprotatefreq", pcaprotatefreq,
                    false, true);
            *pcapchanged = 1;
        }
    }

    ret = 0;

pcapfail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;

}
