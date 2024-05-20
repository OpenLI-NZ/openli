/*
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "logger.h"
#include "agency.h"
#include "coreserver.h"
#include "provisioner.h"
#include "intercept.h"

static const char *access_type_to_string(internet_access_method_t method) {

    switch(method) {
        case INTERNET_ACCESS_TYPE_XDSL:
            return "xdsl";
        case INTERNET_ACCESS_TYPE_FIBER:
            return "fiber";
        case INTERNET_ACCESS_TYPE_CABLEMODEM:
            return "cable";
        case INTERNET_ACCESS_TYPE_LAN:
            return "lan";
        case INTERNET_ACCESS_TYPE_WIRELESS_LAN:
            return "wifi";
        case INTERNET_ACCESS_TYPE_DIALUP:
            return "dialup";
        case INTERNET_ACCESS_TYPE_WIMAX:
            return "wimax";
        case INTERNET_ACCESS_TYPE_SATELLITE:
            return "satellite";
        case INTERNET_ACCESS_TYPE_WIRELESS_OTHER:
            return "wifi-other";
        case INTERNET_ACCESS_TYPE_MOBILE:
            return "mobile";
        case INTERNET_ACCESS_TYPE_UNDEFINED:
            break;
    }
    return "undefined";

}

static int emit_default_radius_usernames(default_radius_user_t *radusers,
        yaml_emitter_t *emitter) {

    yaml_event_t event;
    default_radius_user_t *user, *tmp;

    if (HASH_CNT(hh, radusers) == 0) {
        return 0;
    }

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"defaultradiususers",
            strlen("defaultradiususers"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh, radusers, user, tmp) {

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)user->name, user->namelen, 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

    }
    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_core_server_list(coreserver_t *servers, const char *label,
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

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"ip", strlen("ip"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)cs->ipstr, strlen(cs->ipstr), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"port", strlen("port"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)cs->portstr, strlen(cs->portstr), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_agencies(prov_agency_t *agencies, yaml_emitter_t *emitter) {
    yaml_event_t event;
    prov_agency_t *ag, *tmp;
    char buffer[64];

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"agencies", strlen("agencies"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh, agencies, ag, tmp) {

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"hi3address", strlen("hi3address"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)ag->ag->hi3_ipstr, strlen(ag->ag->hi3_ipstr),
                1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"hi3port", strlen("hi3port"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)ag->ag->hi3_portstr,
                strlen(ag->ag->hi3_portstr), 1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"hi2address", strlen("hi2address"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)ag->ag->hi2_ipstr, strlen(ag->ag->hi2_ipstr),
                1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"hi2port", strlen("hi2port"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)ag->ag->hi2_portstr, strlen(ag->ag->hi2_portstr), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"agencyid", strlen("agencyid"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)ag->ag->agencyid, strlen(ag->ag->agencyid), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"keepalivefreq", strlen("keepalivefreq"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        snprintf(buffer, 64, "%u", ag->ag->keepalivefreq);
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)buffer, strlen(buffer), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"keepalivewait", strlen("keepalivewait"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        snprintf(buffer, 64, "%u", ag->ag->keepalivewait);
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)buffer, strlen(buffer), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    return 0;
}

static int emit_static_ipranges(static_ipranges_t *ranges,
        yaml_emitter_t *emitter) {

    static_ipranges_t *ipr, *tmp;
    char buffer[64];
    yaml_event_t event;

    HASH_ITER(hh, ranges, ipr, tmp) {

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"iprange", strlen("iprange"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)ipr->rangestr, strlen(ipr->rangestr), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        snprintf(buffer, 64, "%u", ipr->cin);

        yaml_scalar_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"sessionid", strlen("sessionid"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)buffer, strlen(buffer), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }
    return 0;

}

static int emit_voip_targets(libtrace_list_t *targets, yaml_emitter_t *emitter)
{
    openli_sip_identity_t *sipid;
    libtrace_list_node_t *n;
    yaml_event_t event;

    n = targets->head;

    while (n) {
        sipid = *((openli_sip_identity_t **) (n->data));

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"username", strlen("username"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)sipid->username, strlen(sipid->username), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (sipid->realm) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"realm", strlen("realm"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)sipid->realm, strlen(sipid->realm), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        n = n->next;
    }
    return 0;
}

static int emit_intercept_common(intercept_common_t *intcom,
        yaml_emitter_t *emitter) {

    char buffer[64];
    yaml_event_t event;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"liid", strlen("liid"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)intcom->liid, strlen(intcom->liid), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"authcountrycode", strlen("authcountrycode"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)intcom->authcc, strlen(intcom->authcc), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"deliverycountrycode",
            strlen("deliverycountrycode"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)intcom->delivcc, strlen(intcom->delivcc), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"agencyid", strlen("agencyid"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)intcom->targetagency, strlen(intcom->targetagency),
            1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    snprintf(buffer, 64, "%u", intcom->destid);

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"mediator", strlen("mediator"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)buffer, strlen(buffer), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    snprintf(buffer, 64, "%lu", intcom->tostart_time);

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"starttime", strlen("starttime"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)buffer, strlen(buffer), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    snprintf(buffer, 64, "%lu", intcom->toend_time);

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"endtime", strlen("endtime"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)buffer, strlen(buffer), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;


    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"payloadencryption", strlen("payloadencryption"),
            1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    if (intcom->encrypt == OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"none", strlen("none"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    } else if (intcom->encrypt == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"aes-192-cbc", strlen("aes-192-cbc"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    } else {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"none", strlen("none"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    }
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    if (intcom->encryptkey && strlen(intcom->encryptkey) > 0) {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"encryptionkey", strlen("encryptionkey"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)intcom->encryptkey,
                strlen(intcom->encryptkey), 1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"outputhandovers", strlen("outputhandovers"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    if (intcom->tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"irionly", strlen("irionly"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    } else if (intcom->tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"cconly", strlen("cconly"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    } else {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"all", strlen("all"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    }
    if (!yaml_emitter_emit(emitter, &event)) return -1;


    return 0;
}

static int emit_email_targets(emailintercept_t *mailint,
        yaml_emitter_t *emitter) {

    email_target_t *tgt, *tmp;
    yaml_event_t event;

    HASH_ITER(hh, mailint->targets, tgt, tmp) {

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"address", strlen("address"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)tgt->address, strlen(tgt->address), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }
    return 0;
}

static int emit_voipintercepts(voipintercept_t *vints, yaml_emitter_t *emitter) 
{
    yaml_event_t event;
    voipintercept_t *v, *tmp;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"voipintercepts", strlen("voipintercepts"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh_liid, vints, v, tmp) {

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (emit_intercept_common(&(v->common), emitter) < 0) {
            return -1;
        }

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"siptargets", strlen("siptargets"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_sequence_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (emit_voip_targets(v->targets, emitter) < 0) {
            return -1;
        }

        yaml_sequence_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_ipintercepts(ipintercept_t *ipints, yaml_emitter_t *emitter) {
    yaml_event_t event;
    ipintercept_t *ipint, *tmp;
    char buffer[64];
    const char *accesstype;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"ipintercepts", strlen("ipintercepts"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh_liid, ipints, ipint, tmp) {

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (emit_intercept_common(&(ipint->common), emitter) < 0) {
            return -1;
        }

        if (ipint->username == NULL) {
            logger(LOG_INFO, "cannot emit intercept %s without a username!",
                    ipint->common.liid);
            continue;
        }

        yaml_scalar_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"user", strlen("user"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)ipint->username, strlen(ipint->username), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (ipint->accesstype != INTERNET_ACCESS_TYPE_UNDEFINED) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"accesstype", strlen("accesstype"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            accesstype = access_type_to_string(ipint->accesstype);
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)accesstype, strlen(accesstype), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

        if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {

            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"vendmirrorid", strlen("vendmirrorid"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            snprintf(buffer, 64, "0x%08x", ipint->vendmirrorid);
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)buffer, strlen(buffer), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

        if (ipint->statics != NULL) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"staticips", strlen("staticips"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            yaml_sequence_start_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            if (emit_static_ipranges(ipint->statics, emitter) < 0) {
                return -1;
            }

            yaml_sequence_end_event_initialize(&event);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

        if (ipint->mobileident != OPENLI_MOBILE_IDENTIFIER_NOT_SPECIFIED) {
            const char *mobtype = NULL;

            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"mobileident", strlen("mobileident"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
            mobtype = get_mobile_identifier_string(ipint->mobileident);

            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)mobtype, strlen(mobtype), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

        if (ipint->options & (1<<OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID) &&
                !(ipint->options & (1<<OPENLI_IPINT_OPTION_RADIUS_IDENT_USER)))
        {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"radiusident", strlen("radiusident"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"csid", strlen("csid"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        } else
        if (ipint->options & (1<<OPENLI_IPINT_OPTION_RADIUS_IDENT_USER) &&
                !(ipint->options & (1<<OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID)))
        {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"radiusident", strlen("radiusident"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"user", strlen("user"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }


        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    return 0;
}

static int emit_emailintercepts(emailintercept_t *mailints,
        yaml_emitter_t *emitter) {
    yaml_event_t event;
    emailintercept_t *mail, *tmp;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"emailintercepts", strlen("emailintercepts"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh_liid, mailints, mail, tmp) {

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (emit_intercept_common(&(mail->common), emitter) < 0) {
            return -1;
        }

        if (mail->delivercompressed !=
                OPENLI_EMAILINT_DELIVER_COMPRESSED_DEFAULT) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"delivercompressed",
                    strlen("delivercompressed"),
                    1, 0, YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            if (mail->delivercompressed ==
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS) {

                yaml_scalar_event_initialize(&event, NULL,
                        (yaml_char_t *)YAML_STR_TAG,
                        (yaml_char_t *)"as-is", strlen("as-is"), 1, 0,
                        YAML_PLAIN_SCALAR_STYLE);
            } else if (mail->delivercompressed ==
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED) {

                yaml_scalar_event_initialize(&event, NULL,
                        (yaml_char_t *)YAML_STR_TAG,
                        (yaml_char_t *)"decompressed",
                        strlen("decompressed"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
            } else {
                yaml_scalar_event_initialize(&event, NULL,
                        (yaml_char_t *)YAML_STR_TAG,
                        (yaml_char_t *)"default", strlen("default"), 1, 0,
                        YAML_PLAIN_SCALAR_STYLE);
            }
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }


        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"targets", strlen("targets"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_sequence_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (emit_email_targets(mail, emitter) < 0) {
            return -1;
        }

        yaml_sequence_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_basic_options(prov_intercept_conf_t *conf,
        yaml_emitter_t *emitter) {

    yaml_event_t event;
    yaml_scalar_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"email-defaultdelivercompressed",
            strlen("email-defaultdelivercompressed"),
            1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    if (conf->default_email_deliver_compress ==
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS) {
        yaml_scalar_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"as-is", strlen("as-is"), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    } else if (conf->default_email_deliver_compress ==
            OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED) {

        yaml_scalar_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"decompressed",
                strlen("decompressed"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
    }
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    return 0;
}

int emit_intercept_config(char *configfile, prov_intercept_conf_t *conf) {

    yaml_emitter_t emitter;
    yaml_event_t event;
    FILE *f, *fout;
    char tmpfile[] = "/tmp/openli-intconf-XXXXXX";
    int tmpfd;
    char buffer[1024 * 32];
    size_t n;

    tmpfd = mkstemp(tmpfile);

    f = fdopen(tmpfd, "w");
    if (ferror(f)) {
        logger(LOG_INFO, "OpenLI: unable to open config file '%s' to write updated intercept config: %s", tmpfile, strerror(errno));
        return -1;
    }

    /* TODO write warning comments that manual edits will not persist
     * unless a HUP is triggered prior to any REST API calls (except
     * GET) */

    yaml_emitter_initialize(&emitter);
    yaml_emitter_set_output_file(&emitter, f);

    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_mapping_start_event_initialize(&event, NULL,
            (unsigned char *)YAML_DEFAULT_MAPPING_TAG, 1,
            YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    if (emit_basic_options(conf, &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->sipservers, "sipservers", &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->radiusservers, "radiusservers",
            &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->gtpservers, "gtpservers",
            &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->smtpservers, "smtpservers",
            &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->imapservers, "imapservers",
            &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->pop3servers, "pop3servers",
            &emitter) < 0) {
        goto error;
    }

    if (emit_default_radius_usernames(conf->defradusers, &emitter) < 0) {
        goto error;
    }

    if (emit_agencies(conf->leas, &emitter) < 0) {
        goto error;
    }

    if (emit_voipintercepts(conf->voipintercepts, &emitter) < 0) {
        goto error;
    }

    if (emit_ipintercepts(conf->ipintercepts, &emitter) < 0) {
        goto error;
    }

    if (emit_emailintercepts(conf->emailintercepts, &emitter) < 0) {
        goto error;
    }

    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_end_event_initialize(&event, 0);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_emitter_delete(&emitter);
    if (f) {
        fclose(f);
    }

    /* copy temp file contents back into the original */
    f = fopen(tmpfile, "r");
    fout = fopen(configfile, "w");

    while ((n = fread(buffer, sizeof(char), sizeof(buffer), f)) > 0) {
        if (fwrite(buffer, sizeof(char), n, fout) != n) {
            logger(LOG_INFO,
                    "OpenLI: error writing new intercept config file: %s",
                    strerror(errno));
            return -1;
        }
    }
    if (!feof(f)) {
        logger(LOG_INFO,
                "OpenLI: error reading temporary intercept config file: %s",
                strerror(errno));
        return -1;
    }

    fclose(fout);
    fclose(f);
    unlink(tmpfile);

    return 0;

error:
    logger(LOG_INFO, "OpenLI: error while emitting intercept config: %s",
            emitter.problem);
    yaml_emitter_delete(&emitter);
    if (f) {
        fclose(f);
    }
    return -1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
