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

#include <yaml.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "logger.h"
#include "agency.h"
#include "coreserver.h"
#include "provisioner.h"
#include "intercept.h"
#include "configparser_common.h"
#include "configwriter_common.h"

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

static const char *agency_integrity_hash_method_to_string(
        openli_integrity_hash_method_t method) {

    switch(method) {
        case OPENLI_DIGEST_HASH_ALGO_SHA1:
            return "sha-1";
        case OPENLI_DIGEST_HASH_ALGO_SHA256:
            return "sha-256";
        case OPENLI_DIGEST_HASH_ALGO_SHA384:
            return "sha-384";
        case OPENLI_DIGEST_HASH_ALGO_SHA512:
            return "sha-512";
    }
    return "undefined";
}

static inline int emit_encryption_key(yaml_emitter_t *emitter,
        uint8_t *key, size_t keylen) {

    /* Emit encryption key as 0x + hex, using the binary key length */
    yaml_event_t event;

    if (keylen == 0) {
        return 0;
    }

    /* field name */
    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"encryptionkey", (int)strlen("encryptionkey"),
            1, 0, YAML_PLAIN_SCALAR_STYLE);
    yaml_emitter_emit(emitter, &event);

    /* value: 0x + 2 hex chars per byte */
    char hexbuf[2 + OPENLI_MAX_ENCRYPTKEY_LEN * 2 + 1];
    size_t n = keylen;
    char *p = hexbuf;
    static const char hexd[] = "0123456789abcdef";
    *p++ = '0'; *p++ = 'x';
    for (size_t i = 0; i < n; ++i) {
        *p++ = hexd[key[i] >> 4];
        *p++ = hexd[key[i] & 0x0F];
    }
    *p = '\0';

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)hexbuf, (int)(2 + n * 2),
            1, 0, YAML_PLAIN_SCALAR_STYLE);
    yaml_emitter_emit(emitter, &event);
    return 1;
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

static inline int emit_u32_scalar(yaml_emitter_t *emitter, const char *key,
        uint32_t *toemit) {

    yaml_event_t event;
    char buffer[64];

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)key, strlen(key), 1, 0, YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    snprintf(buffer, 64, "%u", *toemit);

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)buffer, strlen(buffer), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_agency_integrity_config(yaml_emitter_t *emitter,
        liagency_t *ag) {

    yaml_event_t event;
    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"integrity", strlen("integrity"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    const char *hashmethod;
    const char *signmethod;

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_mapping_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"enabled", strlen("enabled"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;


    if (ag->digest_required) {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"yes", strlen("yes"),
                1, 0, YAML_PLAIN_SCALAR_STYLE);
    } else {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"no", strlen("no"),
                1, 0, YAML_PLAIN_SCALAR_STYLE);
    }

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"hashmethod", strlen("hashmethod"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    hashmethod = agency_integrity_hash_method_to_string(ag->digest_hash_method);

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)hashmethod, strlen(hashmethod),
            1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"signedhashmethod", strlen("signedhashmethod"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    signmethod = agency_integrity_hash_method_to_string(ag->digest_sign_method);
    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)signmethod, strlen(signmethod),
            1, 0, YAML_PLAIN_SCALAR_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;


    if (emit_u32_scalar(emitter, "hashtimeout", &(ag->digest_hash_timeout))
            < 0) return -1;
    if (emit_u32_scalar(emitter, "datapducount", &(ag->digest_hash_pdulimit))
            < 0) return -1;
    if (emit_u32_scalar(emitter, "signtimeout", &(ag->digest_sign_timeout))
            < 0) return -1;
    if (emit_u32_scalar(emitter, "hashpducount", &(ag->digest_sign_hashlimit))
            < 0) return -1;

    yaml_mapping_end_event_initialize(&event);
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

        if (ag->ag->agencycc) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"agencycountrycode",
                    strlen("agencycountrycode"), 1, 0, YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)ag->ag->agencycc,
                    strlen(ag->ag->agencycc), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

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

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"connectretrywait", strlen("connectretrywait"),
                1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        snprintf(buffer, 64, "%u", ag->ag->handover_retry);
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)buffer, strlen(buffer), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (ag->ag->resend_window_kbs != 0) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"resendwindow", strlen("resendwindow"),
                    1, 0, YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            snprintf(buffer, 64, "%u", ag->ag->resend_window_kbs);
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)buffer, strlen(buffer), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"timestampformat", strlen("timestampformat"),
                1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (ag->ag->time_fmt == OPENLI_ENCODED_TIMESTAMP_GENERALIZED) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"generalized", strlen("generalized"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
        } else if (ag->ag->time_fmt == OPENLI_ENCODED_TIMESTAMP_MICROSECONDS) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"microseconds", strlen("microseconds"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
        } else {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"microseconds", strlen("microseconds"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
        }
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (ag->ag->encrypt != OPENLI_PAYLOAD_ENCRYPTION_NOT_SPECIFIED) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"payloadencryption",
                    strlen("payloadencryption"),
                    1, 0, YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            if (ag->ag->encrypt == OPENLI_PAYLOAD_ENCRYPTION_NONE) {
                yaml_scalar_event_initialize(&event, NULL,
                        (yaml_char_t *)YAML_STR_TAG,
                        (yaml_char_t *)"none", strlen("none"), 1, 0,
                        YAML_PLAIN_SCALAR_STYLE);
            } else if (ag->ag->encrypt ==
                    OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
                yaml_scalar_event_initialize(&event, NULL,
                        (yaml_char_t *)YAML_STR_TAG,
                        (yaml_char_t *)"aes-192-cbc", strlen("aes-192-cbc"),
                        1, 0, YAML_PLAIN_SCALAR_STYLE);
            } else {
                yaml_scalar_event_initialize(&event, NULL,
                        (yaml_char_t *)YAML_STR_TAG,
                        (yaml_char_t *)"none", strlen("none"), 1, 0,
                        YAML_PLAIN_SCALAR_STYLE);
            }
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }

        if (emit_encryption_key(emitter, ag->ag->encryptkey,
                ag->ag->encryptkey_len) < 0) {
            return -1;
        }

        if (emit_agency_integrity_config(emitter, ag->ag) < 0) {
            return -1;
        }

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    return 0;
}

static int emit_intercept_udpsinks(intercept_udp_sink_t *sinks,
        yaml_emitter_t *emitter) {
    intercept_udp_sink_t *sink, *tmp;
    yaml_event_t event;
    const char *dirstring;
    const char *encapstring;
    char buffer[256];

    HASH_ITER(hh, sinks, sink, tmp) {

        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        YAML_EMIT_STRING(event, "collectorid", sink->collectorid);
        YAML_EMIT_STRING(event, "listenaddr", sink->listenaddr);
        YAML_EMIT_STRING(event, "listenport", sink->listenport);

        if (sink->cin != 0xFFFFFFFF) {
            snprintf(buffer, 64, "%u", sink->cin);
            YAML_EMIT_STRING(event, "sessionid", buffer);
        }

        dirstring = get_etsi_direction_string(sink->direction);
        encapstring = get_udp_encap_format_string(sink->encapfmt);

        YAML_EMIT_STRING(event, "direction", dirstring);
        YAML_EMIT_STRING(event, "encapsulation", encapstring);
        YAML_EMIT_STRING(event, "sourcehost", sink->sourcehost);
        YAML_EMIT_STRING(event, "sourceport", sink->sourceport);

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }
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

    if (intcom->liid_format == OPENLI_LIID_FORMAT_BINARY_OCTETS) {
        snprintf(buffer, 64, "0x%s", intcom->liid);
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)buffer, strlen(buffer), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    } else {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)intcom->liid, strlen(intcom->liid), 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
    }
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



    if (!intcom->encrypt_inherited &&
            intcom->encrypt != OPENLI_PAYLOAD_ENCRYPTION_NOT_SPECIFIED) {
        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)"payloadencryption", strlen("payloadencryption"),
                1, 0, YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        if (intcom->encrypt == OPENLI_PAYLOAD_ENCRYPTION_NONE) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"none", strlen("none"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
        } else if (intcom->encrypt == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"aes-192-cbc", strlen("aes-192-cbc"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
        } else {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"none", strlen("none"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
        }
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }

    if (!intcom->encrypt_inherited) {
        if (emit_encryption_key(emitter, intcom->encryptkey,
                intcom->encryptkey_len) < 0) {
            return -1;
        }
    }

    if (intcom->xid_count != 0) {
        size_t i;
        yaml_scalar_event_initialize(&event, NULL, NULL,
                (yaml_char_t *)"xids", strlen("xids"), 1, 1,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        yaml_sequence_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        for (i = 0; i < intcom->xid_count; i++) {
            if (uuid_is_null(intcom->xids[i])) {
                continue;
            }
            uuid_unparse(intcom->xids[i], buffer);
            yaml_scalar_event_initialize(&event, NULL,
                    NULL,
                    (yaml_char_t *)buffer, strlen(buffer), 1, 1,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;
        }
        yaml_sequence_end_event_initialize(&event);
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


        if (ipint->udp_sinks) {
            yaml_scalar_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_STR_TAG,
                    (yaml_char_t *)"udpsinks", strlen("udpsinks"), 1, 0,
                    YAML_PLAIN_SCALAR_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            yaml_sequence_start_event_initialize(&event, NULL,
                    (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
            if (!yaml_emitter_emit(emitter, &event)) return -1;

            if (emit_intercept_udpsinks(ipint->udp_sinks, emitter) < 0) {
                return -1;
            }

            yaml_sequence_end_event_initialize(&event);
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

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_SALT_SIZE 8

size_t encrypt_aes_yaml(yaml_buffer_t *buf, unsigned char *key,
        unsigned char *iv, uint8_t *out) {

    EVP_CIPHER_CTX *ctx;
    int len, cipherlen;
    char msg[256];
    unsigned long errcode;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        logger(LOG_INFO, "OpenLI: EVP_CIPHER_CTX_new() failed");
        return 0;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        logger(LOG_INFO, "OpenLI: EVP_EncryptInit_ex() failed");
        return 0;
    }

    if (EVP_EncryptUpdate(ctx, out, &len, buf->buffer, buf->used) != 1) {
        logger(LOG_INFO, "OpenLI: EVP_EncryptUpdate() failed");
        return 0;
    }
    cipherlen = len;
    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) {
        errcode = ERR_get_error();
        if (errcode) {
            ERR_error_string_n(errcode, msg, sizeof(msg));
        } else {
            snprintf(msg, 256, "No SSL error");
        }
        logger(LOG_INFO, "OpenLI: EVP_EncryptFinal_ex() failed: %s", msg);

        return 0;
    }
    cipherlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return cipherlen;

}

uint8_t *encrypt_intercept_config(yaml_buffer_t *buf, const char *encpassfile,
        size_t *enclen) {

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE], salt[AES_SALT_SIZE];
    uint8_t pass[1024];
    size_t passlen;
    uint8_t *output;
    uint8_t tmp[AES_KEY_SIZE + AES_BLOCK_SIZE];

    RAND_bytes(salt, AES_SALT_SIZE);
    RAND_bytes(iv, AES_BLOCK_SIZE);

    passlen = read_encryption_password_file(encpassfile, pass);
    if (passlen == 0) {
        return NULL;
    }

    if (PKCS5_PBKDF2_HMAC((char *)pass, passlen, salt, AES_SALT_SIZE,
                AES_ENCRYPT_ITERATIONS, EVP_sha256(),
                AES_BLOCK_SIZE + AES_KEY_SIZE, tmp) == 0) {
        return NULL;
    }

    memcpy(key, tmp, AES_KEY_SIZE);
    memcpy(iv, tmp + AES_KEY_SIZE, AES_BLOCK_SIZE);

    output = calloc(1, buf->used + AES_BLOCK_SIZE + 8 + AES_SALT_SIZE);
    memcpy(output, "Salted__", 8);
    memcpy(output + 8, salt, AES_SALT_SIZE);

    *enclen = encrypt_aes_yaml(buf, key, iv, output + 8 + AES_SALT_SIZE);
    if (*enclen == 0) {
        free(output);
        return NULL;
    }
    *enclen = *enclen + 8 + AES_SALT_SIZE;
    return output;
}

int emit_intercept_config(char *configfile, const char *encpassfile,
        prov_intercept_conf_t *conf) {

    yaml_buffer_t buf;
    yaml_emitter_t emitter;
    yaml_event_t event;
    FILE *fout;
    uint8_t *finalconfig;
    uint8_t *ciphered = NULL;
    size_t configlen;
    int ret = 0;

    buf.buffer = calloc(1, 65536);
    buf.alloced = 65536;
    buf.used = 0;

    /* TODO write warning comments that manual edits will not persist
     * unless a HUP is triggered prior to any REST API calls (except
     * GET) */

    yaml_emitter_initialize(&emitter);
    yaml_emitter_set_output(&emitter, buffer_yaml_memory, (void *)&buf);

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

    /* do we need to encrypt? */
    if (encpassfile == NULL) {
        finalconfig = buf.buffer;
        configlen = buf.used;
    } else {
        ciphered = encrypt_intercept_config(&buf, encpassfile, &configlen);
        if (ciphered == NULL) {
            logger(LOG_INFO,
                    "OpenLI: unable to encrypt intercept configuration");

            if (conf->was_encrypted) {
                ret = -1;
                goto endemit;
            }
            /* fall back to unencrypted, since that was what we started with
             * anyway and it is better for us to update the config file with
             * the changes
             */
            logger(LOG_INFO,
                    "OpenLI: falling back to writing unencrypted intercept configuration");
            finalconfig = buf.buffer;
            configlen = buf.used;
        } else {
            finalconfig = ciphered;
        }
    }

    /* copy encoded config back into the original file */
    fout = fopen(configfile, "w");
    if (!fout) {
        logger(LOG_INFO,
                "OpenLI: cannot open new intercept config file for writing: %s",
                strerror(errno));
        ret = -1;
        goto endemit;
    }

    if (fwrite(finalconfig, 1, configlen, fout) != configlen) {
        logger(LOG_INFO,
                "OpenLI: error while writing new intercept config file: %s",
                strerror(errno));
        ret = -1;
    }

    fclose(fout);

endemit:
    if (ciphered) {
        free(ciphered);
    }
    if (buf.buffer) {
        free(buf.buffer);
    }
    return ret;

error:
    logger(LOG_INFO, "OpenLI: error while emitting intercept config: %s",
            emitter.problem);
    yaml_emitter_delete(&emitter);
    return -1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
