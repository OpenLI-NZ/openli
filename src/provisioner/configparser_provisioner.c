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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <libtrace/message_queue.h>
#include <libtrace_parallel.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "configparser_common.h"
#include "configparser_provisioner.h"


uint64_t nextid = 0;

static void add_single_xid(char *srcvalue, intercept_common_t *common) {

    uuid_t parsed;
    if (uuid_parse(srcvalue, parsed) < 0) {
        logger(LOG_INFO,
                "OpenLI: invalid UUID provided as 'xid' in intercept config: %s",
                (char *)srcvalue);
        return;
    }

    common->xid_count ++;
    common->xids = realloc(common->xids, common->xid_count * sizeof(uuid_t));
    uuid_copy(common->xids[common->xid_count - 1], parsed);

}

static void parse_and_set_liid(intercept_common_t *common,
        const char *liidval) {

    if (!liidval) return;

    // Case 1: begins with 0x, so treat as binary octets
    if (strlen(liidval) > 2 && liidval[0] == '0' &&
            (liidval[1] == 'x' || liidval[1] == 'X')) {

        common->liid = strdup(liidval + 2);
        common->liid_len = strlen(common->liid);
        common->liid_format = OPENLI_LIID_FORMAT_BINARY_OCTETS;
    } else {
        common->liid = strdup(liidval);
        common->liid_len = strlen(common->liid);
        common->liid_format = OPENLI_LIID_FORMAT_ASCII;
    }
}

static void parse_xid_list(intercept_common_t *common, yaml_document_t *doc,
        yaml_node_t *xidlist) {

    yaml_node_item_t *item;
    for (item = xidlist->data.sequence.items.start;
            item != xidlist->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);

        if (node->type == YAML_SCALAR_NODE) {
            add_single_xid((char *)(node->data.scalar.value), common);
        }
    }
}


static void parse_email_targets(email_target_t **targets, yaml_document_t *doc,
        yaml_node_t *tgtconf) {

    yaml_node_item_t *item;

    for (item = tgtconf->data.sequence.items.start;
            item != tgtconf->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        email_target_t *newtgt, *found;

        newtgt = (email_target_t *)calloc(1, sizeof(email_target_t));
        newtgt->awaitingconfirm = 1;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;
            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "address") == 0) {
                SET_CONFIG_STRING_OPTION(newtgt->address, value);
            } else if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "targetID") == 0) {
                SET_CONFIG_STRING_OPTION(newtgt->address, value);
            }
        }

        if (!newtgt->address) {
            logger(LOG_INFO,
                    "OpenLI: a Email target requires an address or targetID, skipping.");
            free(newtgt);
            continue;
        }

        HASH_FIND(hh, *targets, newtgt->address, strlen(newtgt->address),
                    found);
        if (found) {
            free(newtgt->address);
            free(newtgt);
            continue;
        }

        HASH_ADD_KEYPTR(hh, *targets, newtgt->address, strlen(newtgt->address),
                newtgt);
    }

}

static void parse_sip_targets(libtrace_list_t *targets, yaml_document_t *doc,
        yaml_node_t *tgtconf) {

    yaml_node_item_t *item;

    for (item = tgtconf->data.sequence.items.start;
            item != tgtconf->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        openli_sip_identity_t *newtgt;

        newtgt = (openli_sip_identity_t *)calloc(1,
                sizeof(openli_sip_identity_t));
        newtgt->awaitingconfirm = 1;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;
            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "username") == 0) {
                SET_CONFIG_STRING_OPTION(newtgt->username, value);
                newtgt->username_len = strlen(newtgt->username);

                    continue;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "realm") == 0) {
                SET_CONFIG_STRING_OPTION(newtgt->realm, value);
                newtgt->realm_len = strlen(newtgt->realm);
            }
        }

        if (newtgt->username) {
            if (newtgt->username_len == 1 && newtgt->username[0] == '*' &&
                    newtgt->realm == NULL) {
                logger(LOG_INFO,
                        "OpenLI: a SIP target of '*' requires a realm, skipping.");
                free(newtgt->username);
                free(newtgt);
            } else {
                libtrace_list_push_back(targets, &newtgt);
            }
        } else {
            logger(LOG_INFO,
                    "OpenLI: a SIP target requires a username, skipping.");
            if (newtgt->realm) {
                free(newtgt->realm);
            }
            free(newtgt);
        }
    }

}

static int parse_defradusers_list(prov_intercept_conf_t *state,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {

        yaml_node_t *node = yaml_document_get_node(doc, *item);
        default_radius_user_t *defuser, *found;

        if (node->type != YAML_SCALAR_NODE) {
            continue;
        }
        defuser = (default_radius_user_t *)calloc(1,
                sizeof(default_radius_user_t));

        defuser->name = strdup((char *)node->data.scalar.value);
        defuser->namelen = strlen(defuser->name);
        defuser->awaitingconfirm = 1;

        HASH_FIND(hh, state->defradusers, defuser->name, defuser->namelen,
                found);
        if (found) {
            logger(LOG_INFO,
                    "OpenLI: warning -- '%s' should only appear once in the default RADIUS username config.",
                    defuser->name);
            free(defuser->name);
            free(defuser);
            continue;
        }

        HASH_ADD_KEYPTR(hh, state->defradusers, defuser->name,
                defuser->namelen, defuser);
    }

    return 0;
}


static int parse_and_set_encryption_key(uint8_t *keyspace, size_t *keylen,
        const char *yaml_value) {
    if (!keyspace || !yaml_value) return -1;

    // Case 1: 0x + 48 hex digits
    if (yaml_value[0] == '0' && (yaml_value[1] == 'x' || yaml_value[1] == 'X')) {
        if (openli_hex_to_bytes_24(yaml_value, keyspace) != 0) {
            logger(LOG_ERR, "OpenLI: encryptionkey must be 0x + 48 hex digits for AES-192.");
            return -1;
        }
        *keylen = OPENLI_AES192_KEY_LEN;
        return 0;
    }

    // Case 2: ASCII string of exactly 24 bytes
    size_t n = strlen(yaml_value);
    if (n == 24) {
        // Optional: enforce printable ASCII only
        for (size_t i = 0; i < n; ++i) {
            unsigned char ch = (unsigned char)yaml_value[i];
            if (ch < 0x20 || ch > 0x7E) {
                logger(LOG_ERR, "OpenLI: encryptionkey ASCII must be 24 printable characters.");
                return -1;
            }
        }
        memcpy(keyspace, yaml_value, 24);
        *keylen = OPENLI_AES192_KEY_LEN;
        return 0;
    }

    logger(LOG_ERR, "OpenLI: encryptionkey must be 0x + 48 hex digits or a 24-byte ASCII string.");
    return -1;
}

static int parse_intercept_udp_sink_config(ipintercept_t *cept,
        yaml_document_t *doc, yaml_node_t *sinkseq) {
    yaml_node_item_t *item;
    intercept_udp_sink_t *sink, *existing;

    for (item = sinkseq->data.sequence.items.start;
            item != sinkseq->data.sequence.items.top; item++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        char buf[1024];

        sink = calloc(1, sizeof(intercept_udp_sink_t));
        sink->direction = ETSI_DIR_INDETERMINATE;
        sink->encapfmt = INTERCEPT_UDP_ENCAP_FORMAT_RAW;
        sink->cin = 0;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "sourcehost") == 0) {
                SET_CONFIG_STRING_OPTION(sink->sourcehost, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "sourceport") == 0) {
                SET_CONFIG_STRING_OPTION(sink->sourceport, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "collectorid") == 0) {
                SET_CONFIG_STRING_OPTION(sink->collectorid, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "listenport") == 0) {
                SET_CONFIG_STRING_OPTION(sink->listenport, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "listenaddr") == 0) {
                SET_CONFIG_STRING_OPTION(sink->listenaddr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "sessionid") == 0) {
                sink->cin = strtoul((char *)value->data.scalar.value, NULL, 10);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "direction") == 0) {
                if (strcasecmp((char *)value->data.scalar.value, "from") == 0) {
                    sink->direction = ETSI_DIR_FROM_TARGET;
                }
                else if (strcasecmp((char *)value->data.scalar.value, "to") == 0) {
                    sink->direction = ETSI_DIR_TO_TARGET;
                }
                else if (strcasecmp((char *)value->data.scalar.value, "both") == 0) {
                    sink->direction = ETSI_DIR_INDETERMINATE;
                } else {
                    logger(LOG_INFO,
                            "OpenLI provisioner: unexpected direction for UDP sink '%s' -- should be one of 'to', 'from' or 'both'",
                            (char *)value->data.scalar.value);
                    goto parsefail;
                }
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "encapsulation") == 0) {
                if (strcasecmp((char *)value->data.scalar.value, "raw") == 0) {
                    sink->encapfmt = INTERCEPT_UDP_ENCAP_FORMAT_RAW;
                }
                else if (strcasecmp((char *)value->data.scalar.value, "jmirror") == 0) {
                    sink->encapfmt = INTERCEPT_UDP_ENCAP_FORMAT_JMIRROR;
                }
                else if (strcasecmp((char *)value->data.scalar.value, "cisco") == 0) {
                    sink->encapfmt = INTERCEPT_UDP_ENCAP_FORMAT_CISCO;
                }
                else if (strcasecmp((char *)value->data.scalar.value, "nokia") == 0 || strcasecmp((char *)value->data.scalar.value, "alu") == 0) {
                    sink->encapfmt = INTERCEPT_UDP_ENCAP_FORMAT_NOKIA;
                } else if (strcasecmp((char *)value->data.scalar.value, "nokia-l3") == 0) {
                    sink->encapfmt = INTERCEPT_UDP_ENCAP_FORMAT_NOKIA_L3;
                } else {
                    logger(LOG_INFO,
                            "OpenLI provisioner: unexpected encapsulation for UDP sink '%s' -- should be one of 'raw', 'cisco', 'jmirror', 'nokia' or 'nokia-l3'",
                            (char *)value->data.scalar.value);
                    goto parsefail;
                }
            }

        }

        if (sink->collectorid == NULL) {
            logger(LOG_INFO, "OpenLI provisioner: UDP sink configuration must include a 'collectorid' field -- ignoring UDP sink");
            goto parsefail;
        }
        if (strchr(sink->collectorid, ',') != NULL) {
            logger(LOG_INFO, "OpenLI provisioner: the 'collectorid' field for a UDP sink configuration must not include a comma character -- ignoring UDP sink");
            goto parsefail;
        }

        if (sink->listenaddr == NULL) {
            logger(LOG_INFO, "OpenLI provisioner: UDP sink configuration must include a 'listenaddr' field -- ignoring UDP sink");
            goto parsefail;
        }

        if (sink->listenport == NULL) {
            logger(LOG_INFO, "OpenLI provisioner: UDP sink configuration must include a 'listenport' field -- ignoring UDP sink");
            goto parsefail;
        }

        snprintf(buf, 1024, "%s,%s,%s", sink->collectorid, sink->listenaddr,
                sink->listenport);
        sink->key = strdup(buf);

        HASH_FIND(hh, cept->udp_sinks, sink->key, strlen(sink->key), existing);
        if (existing) {
            logger(LOG_INFO, "OpenLI provisioner: duplicate UDP sink configuration in ipintercept config -- ignoring");
            goto parsefail;
        }

        sink->enabled = 1;
        sink->awaitingconfirm = 1;
        HASH_ADD_KEYPTR(hh, cept->udp_sinks, sink->key, strlen(sink->key),
                sink);
        continue;

parsefail:
        clean_intercept_udp_sink(sink);
        free(sink);
    }
    return 0;
}

static int add_intercept_static_ips(static_ipranges_t **statics,
        yaml_document_t *doc, yaml_node_t *ipseq) {

    yaml_node_item_t *item;
    static_ipranges_t *newr, *existing;

    for (item = ipseq->data.sequence.items.start;
            item != ipseq->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        newr = (static_ipranges_t *)malloc(sizeof(static_ipranges_t));
        newr->rangestr = NULL;
        newr->liid = NULL;
        newr->awaitingconfirm = 1;
        newr->cin = 1;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "iprange") == 0 &&
                    newr->rangestr == NULL) {
                newr->rangestr =
                        parse_iprange_string((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "sessionid") == 0) {
                newr->cin = strtoul((char *)value->data.scalar.value, NULL, 10);
            }
        }


        if (newr->rangestr) {
            if (newr->cin >= (uint32_t)(pow(2, 31))) {
                logger(LOG_INFO,
                        "OpenLI: CIN %u for static IP range %s is too large.",
                        newr->cin, newr->rangestr);
                newr->cin = newr->cin % (uint32_t)(pow(2, 31));
                logger(LOG_INFO, "OpenLI: replaced CIN with %u.",
                        newr->cin);
            }
            HASH_FIND(hh, *statics, newr->rangestr, strlen(newr->rangestr),
                    existing);
            if (!existing) {
                HASH_ADD_KEYPTR(hh, *statics, newr->rangestr,
                        strlen(newr->rangestr), newr);
            } else {
                free(newr->rangestr);
                newr->rangestr = NULL;
            }
        }

        if (!newr->rangestr) {
            free(newr);
        }
    }
    return 0;
}

static int parse_integrity_check_options(liagency_t *newag,
        yaml_document_t *doc, yaml_node_t *integmap) {

    yaml_node_pair_t *pair;
    for (pair = integmap->data.mapping.pairs.start;
            pair < integmap->data.mapping.pairs.top; pair ++) {
        yaml_node_t *key, *value;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
                !strcasecmp((char *)key->data.scalar.value, "enabled")) {
            newag->digest_required =
                    config_check_onoff((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
                !strcasecmp((char *)key->data.scalar.value, "hashtimeout")) {
            errno = 0;
            newag->digest_hash_timeout = strtoul(
                    (char *)value->data.scalar.value, NULL, 10);
            if (errno) {
                logger(LOG_INFO,
                        "OpenLI provisioner: invalid value detected for integrity->hashtimeout option in agency configuration");
                return -1;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
                !strcasecmp((char *)key->data.scalar.value, "signtimeout")) {
            errno = 0;
            newag->digest_sign_timeout = strtoul(
                    (char *)value->data.scalar.value, NULL, 10);
            if (errno) {
                logger(LOG_INFO,
                        "OpenLI provisioner: invalid value detected for integrity->signtimeout option in agency configuration");
                return -1;
            }
        }
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
                !strcasecmp((char *)key->data.scalar.value, "datapducount")) {
            errno = 0;
            newag->digest_hash_pdulimit = strtoul(
                    (char *)value->data.scalar.value, NULL, 10);
            if (errno) {
                logger(LOG_INFO,
                        "OpenLI provisioner: invalid value detected for integrity->datapducount option in agency configuration");
                return -1;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
                !strcasecmp((char *)key->data.scalar.value, "hashpducount")) {
            errno = 0;
            newag->digest_sign_hashlimit = strtoul(
                    (char *)value->data.scalar.value, NULL, 10);
            if (errno) {
                logger(LOG_INFO,
                        "OpenLI provisioner: invalid value detected for integrity->hashpducount option in agency configuration");
                return -1;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
                !strcasecmp((char *)key->data.scalar.value, "hashmethod")) {
            if (strcasecmp((char *)value->data.scalar.value, "sha-1") == 0) {
                newag->digest_hash_method = OPENLI_DIGEST_HASH_ALGO_SHA1;
            } else if (strcasecmp((char *)value->data.scalar.value,
                    "sha-256") == 0) {
                newag->digest_hash_method = OPENLI_DIGEST_HASH_ALGO_SHA256;
            } else if (strcasecmp((char *)value->data.scalar.value,
                    "sha-384") == 0) {
                newag->digest_hash_method = OPENLI_DIGEST_HASH_ALGO_SHA384;
            } else if (strcasecmp((char *)value->data.scalar.value,
                    "sha-512") == 0) {
                newag->digest_hash_method = OPENLI_DIGEST_HASH_ALGO_SHA512;
            } else {
                logger(LOG_INFO,
                        "OpenLI provisioner: unsupported hashmethod '%s' specified in integrity check configuration for agency",
                        (char *)value->data.scalar.value);
                return -1;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE &&
                !strcasecmp((char *)key->data.scalar.value,
                        "signedhashmethod")) {
            if (strcasecmp((char *)value->data.scalar.value, "sha-1") == 0) {
                newag->digest_sign_method = OPENLI_DIGEST_HASH_ALGO_SHA1;
            } else if (strcasecmp((char *)value->data.scalar.value,
                    "sha-256") == 0) {
                newag->digest_sign_method = OPENLI_DIGEST_HASH_ALGO_SHA256;
            } else if (strcasecmp((char *)value->data.scalar.value,
                    "sha-384") == 0) {
                newag->digest_sign_method = OPENLI_DIGEST_HASH_ALGO_SHA384;
            } else if (strcasecmp((char *)value->data.scalar.value,
                    "sha-512") == 0) {
                newag->digest_sign_method = OPENLI_DIGEST_HASH_ALGO_SHA512;
            } else {
                logger(LOG_INFO,
                        "OpenLI provisioner: unsupported signedhashmethod '%s' specified in integrity check configuration for agency",
                        (char *)value->data.scalar.value);
                return -1;
            }
        }
    }

    return 0;
}


static int parse_agency_list(prov_intercept_conf_t *state, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        liagency_t *newag = (liagency_t *)malloc(sizeof(liagency_t));
        uint8_t integrityok = 1;

        newag->hi2_ipstr = NULL;
        newag->hi2_portstr = NULL;
        newag->hi3_ipstr = NULL;
        newag->hi3_portstr = NULL;
        newag->agencyid = NULL;
        newag->agencycc = NULL;
        newag->keepalivefreq = DEFAULT_AGENCY_KEEPALIVE_FREQ;
        newag->keepalivewait = 0;
        newag->handover_retry = DEFAULT_AGENCY_HANDOVER_RETRY;
        newag->resend_window_kbs = DEFAULT_AGENCY_RESEND_WINDOW;
        newag->time_fmt = DEFAULT_AGENCY_TIMESTAMP_FORMAT;
        newag->digest_hash_method = DEFAULT_DIGEST_HASH_METHOD;
        newag->digest_sign_method = DEFAULT_DIGEST_HASH_METHOD;
        newag->digest_hash_timeout = DEFAULT_DIGEST_HASH_TIMEOUT;
        newag->digest_hash_pdulimit = DEFAULT_DIGEST_HASH_PDULIMIT;
        newag->digest_sign_timeout = DEFAULT_DIGEST_SIGN_TIMEOUT;
        newag->digest_sign_hashlimit = DEFAULT_DIGEST_SIGN_HASHLIMIT;
        newag->digest_required = 0;
        newag->encrypt = OPENLI_PAYLOAD_ENCRYPTION_NONE;
        memset(newag->encryptkey, 0, OPENLI_MAX_ENCRYPTKEY_LEN);
        newag->encryptkey_len = 0;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;
            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_MAPPING_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "integrity") == 0) {
                if (parse_integrity_check_options(newag, doc, value) < 0) {
                    integrityok = 0;
                }
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "hi2address") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi2_ipstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "hi2port") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi2_portstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "hi3address") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi3_ipstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "hi3port") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi3_portstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "agencyid") == 0) {
                SET_CONFIG_STRING_OPTION(newag->agencyid, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "agencycountrycode") == 0) {
                SET_CONFIG_STRING_OPTION(newag->agencycc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "keepalivefreq") == 0) {
                newag->keepalivefreq = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "keepalivewait") == 0) {
                newag->keepalivewait = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "connectretrywait") == 0) {
                uint64_t retry = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
                if (retry > 60000) {
                    logger(LOG_INFO, "connectretrywait has been reduced to the maximum value of 60,000 seconds");
                    retry = 60000;
                }
                newag->handover_retry = retry;
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "resendwindow") == 0) {
                uint64_t window = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
                if (window > 1024 * 1024) {
                    logger(LOG_INFO, "resendwindow has been reduced to the maximum value of 1GB");
                    window = 1024 * 1024;
                }
                newag->resend_window_kbs = window;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "timestampformat") == 0) {
                if (strcasecmp((char *)value->data.scalar.value,
                        "generalized") == 0) {
                    newag->time_fmt = OPENLI_ENCODED_TIMESTAMP_GENERALIZED;
                } else if (strcasecmp((char *)value->data.scalar.value,
                        "microseconds") == 0) {
                    newag->time_fmt = OPENLI_ENCODED_TIMESTAMP_MICROSECONDS;
                }
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "payloadencryption") == 0) {
                if (strcasecmp((char *)value->data.scalar.value, "none") == 0) {
                    newag->encrypt = OPENLI_PAYLOAD_ENCRYPTION_NONE;
                } else if (strcasecmp((char *)value->data.scalar.value,
                        "aes-192-cbc") == 0) {
                    newag->encrypt = OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC;
                }
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "encryptionkey") == 0) {
		        const char *k = (const char *)value->data.scalar.value;
        		parse_and_set_encryption_key(newag->encryptkey,
                        &(newag->encryptkey_len), k);
            }
        }

        if (newag->agencyid == NULL) {
            logger(LOG_INFO,
                    "OpenLI: WARNING configuration error in running intercept config -- agency is missing the 'agencyid' field");
            logger(LOG_INFO,
                    "OpenLI: this agency will be ignored");
            free_liagency(newag);
            continue;
        }

        /* 'pcapdisk' is reserved for the intercepts that need to
         * be written to pcap files instead of live streamed to an
         * ETSI-capable agency. */
        if (strcasecmp(newag->agencyid, "pcapdisk") == 0) {
            logger(LOG_INFO,
                    "OpenLI: 'pcapdisk' is a reserved agencyid, please rename to something else.");
            free_liagency(newag);
            continue;
        }

        if (newag->encryptkey_len == 0 &&
                newag->encrypt > OPENLI_PAYLOAD_ENCRYPTION_NONE) {
            logger(LOG_INFO, "OpenLI: Agency configuration for '%s' asks for encryption but has not provided an encryption key -- encryption will be disabled",
                    newag->agencyid);
            newag->encrypt = OPENLI_PAYLOAD_ENCRYPTION_NONE;
        }

        if (newag->keepalivefreq > 1000000) {
            logger(LOG_INFO, "keepalivefreq cannot be larger than 1,000,000 seconds, reducing keepalivefreq to that value...");
            newag->keepalivefreq = 1000000;
        }

        if (newag->keepalivewait > newag->keepalivefreq) {
            logger(LOG_INFO, "keepalivewait must be less than or equal to keepalivefreq, setting keepalivewait to %u",
                    newag->keepalivefreq);
            newag->keepalivewait = newag->keepalivefreq;
        }

        if (newag->handover_retry == 0) {
            logger(LOG_INFO, "connectretrywait has been increased to the minimum value of 1 second");
            newag->handover_retry = 1;
        }

        if (newag->resend_window_kbs < 1024 && newag->agencycc != NULL &&
                strcmp(newag->agencycc, "NL") == 0) {
            logger(LOG_INFO, "OpenLI: WARNING -- NL agencies require a resendwindow of at least 1024 KB, '%s' is configured with a resendwindow of %u KB",
                    newag->agencyid, newag->resend_window_kbs);
            logger(LOG_INFO, "OpenLI: please consider increasing your agency's resendwindow parameter...");
        }

        if (newag->hi2_ipstr != NULL && newag->hi2_portstr != NULL &&
                newag->hi3_ipstr != NULL && newag->hi3_portstr != NULL &&
                integrityok) {
            prov_agency_t *prov_ag;
            prov_ag = (prov_agency_t *)malloc(sizeof(prov_agency_t));
            prov_ag->ag = newag;
            prov_ag->announcereq = 1;
            HASH_ADD_KEYPTR(hh, state->leas, prov_ag->ag->agencyid,
                    strlen(prov_ag->ag->agencyid), prov_ag);

        } else {
            logger(LOG_INFO, "OpenLI: LEA configuration for %s was incomplete or invalid-- skipping.",
                    newag->agencyid ? newag->agencyid : "unknown agency");
            free_liagency(newag);
        }
    }
    return 0;
}

static void parse_intercept_common_fields(intercept_common_t *common,
        yaml_document_t *doc, yaml_node_t *key, yaml_node_t *value) {

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "liid") == 0) {
        parse_and_set_liid(common, (const char *)(value->data.scalar.value));
    }
    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                "authcountrycode") == 0) {
        SET_CONFIG_STRING_OPTION(common->authcc, value);
        common->authcc_len = strlen(common->authcc);
    }
    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                "deliverycountrycode") == 0) {
        SET_CONFIG_STRING_OPTION(common->delivcc, value);
        common->delivcc_len = strlen(common->delivcc);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "mediator") == 0
            && common->destid == 0) {
        common->destid = strtoul(
                (char *)value->data.scalar.value, NULL, 10);
        if (common->destid == 0) {
            logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'mediator' config option.");
        }
    }
    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "starttime") == 0) {
        common->tostart_time = strtoul(
                (char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "endtime") == 0) {
        common->toend_time = strtoul(
                (char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "agencyid") == 0) {
        SET_CONFIG_STRING_OPTION(common->targetagency, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "payloadencryption") == 0) {
        if (strcasecmp((char *)value->data.scalar.value, "none") == 0) {
            common->encrypt = OPENLI_PAYLOAD_ENCRYPTION_NONE;
        } else if (strcasecmp((char *)value->data.scalar.value, "aes-192-cbc") == 0) {
            common->encrypt = OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC;
        }
    }

	if (key->type == YAML_SCALAR_NODE &&
			value->type == YAML_SCALAR_NODE &&
			strcasecmp((char *)key->data.scalar.value, "encryptionkey") == 0) {

		const char *k = (const char *)value->data.scalar.value;
		parse_and_set_encryption_key(common->encryptkey,
                &(common->encryptkey_len), k);
	}

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "xid") == 0) {
        add_single_xid((char *)value->data.scalar.value, common);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "xids") == 0) {
        parse_xid_list(common, doc, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "outputhandovers") == 0) {

        if (strcasecmp((char *)value->data.scalar.value, "irionly") == 0) {
            common->tomediate = OPENLI_INTERCEPT_OUTPUTS_IRIONLY;
        } else if (strcasecmp((char *)value->data.scalar.value, "cconly") == 0) {
            common->tomediate = OPENLI_INTERCEPT_OUTPUTS_CCONLY;
        } else {
            common->tomediate = OPENLI_INTERCEPT_OUTPUTS_ALL;
        }
    }
}


static inline void init_intercept_common(intercept_common_t *common,
        void *parent, openli_intercept_types_t intercept_type) {
    prov_intercept_data_t *local;

    common->liid = NULL;
    common->liid_format = OPENLI_LIID_FORMAT_ASCII;
    common->liid_len = 0;
    common->authcc = NULL;
    common->authcc_len = 0;
    common->delivcc = NULL;
    common->delivcc_len = 0;
    common->destid = 0;
    common->targetagency = NULL;
    common->tostart_time = 0;
    common->toend_time = 0;
    common->tomediate = OPENLI_INTERCEPT_OUTPUTS_ALL;
    common->encrypt = OPENLI_PAYLOAD_ENCRYPTION_NOT_SPECIFIED;
    common->hi1_seqno = 0;
    common->local = calloc(1, sizeof(prov_intercept_data_t));
    memset(common->encryptkey, 0, OPENLI_MAX_ENCRYPTKEY_LEN);
    common->encryptkey_len = 0;

    common->xids = NULL;
    common->xid_count = 0;
    common->encrypt_inherited = 0;
    common->time_fmt = DEFAULT_AGENCY_TIMESTAMP_FORMAT;

    local = (prov_intercept_data_t *)(common->local);
    local->intercept_type = intercept_type;
    local->intercept_ref = (void *)parent;
}

static int parse_emailintercept_list(emailintercept_t **mailints,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        emailintercept_t *newcept;
        unsigned int tgtcount = 0;

        newcept = (emailintercept_t *)calloc(1, sizeof(emailintercept_t));
        init_intercept_common(&(newcept->common), newcept,
                OPENLI_INTERCEPT_TYPE_EMAIL);
        newcept->awaitingconfirm = 1;
        newcept->targets = NULL;
        newcept->delivercompressed = OPENLI_EMAILINT_DELIVER_COMPRESSED_DEFAULT;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            parse_intercept_common_fields(&(newcept->common), doc, key, value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "targets") == 0) {

                parse_email_targets(&(newcept->targets), doc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                    "delivercompressed") == 0) {
                if (strcasecmp((char *)value->data.scalar.value, "as-is") == 0) {
                    newcept->delivercompressed =
                            OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;
                } else if (strcasecmp((char *)value->data.scalar.value,
                        "decompressed") == 0) {
                    newcept->delivercompressed =
                            OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
                } else if (strcasecmp((char *)value->data.scalar.value,
                        "inflated") == 0) {
                    newcept->delivercompressed =
                            OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
                }
            }
        }

        tgtcount = HASH_CNT(hh, newcept->targets);
		if (newcept->common.encrypt > OPENLI_PAYLOAD_ENCRYPTION_NONE &&
        	    newcept->common.encryptkey_len != OPENLI_AES192_KEY_LEN) {
            if (!newcept->common.liid) {
                newcept->common.liid = strdup("unidentified intercept");
            }
            logger(LOG_INFO, "OpenLI: Email intercept configuration for '%s' asks for encryption but has not provided a valid encryption key -- skipping",
                    newcept->common.liid);
            free_single_emailintercept(newcept);
            continue;
        }

        if (newcept->common.liid != NULL && newcept->common.authcc != NULL &&
                newcept->common.delivcc != NULL &&
                tgtcount > 0 &&
                newcept->common.destid > 0 &&
                newcept->common.targetagency != NULL) {
            HASH_ADD_KEYPTR(hh_liid, *mailints, newcept->common.liid,
                    newcept->common.liid_len, newcept);
        } else {
            logger(LOG_INFO, "OpenLI: Email Intercept configuration was incomplete -- skipping.");
            free_single_emailintercept(newcept);
        }

    }

    return 0;
}

static int parse_voipintercept_list(voipintercept_t **voipints,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        voipintercept_t *newcept;
        yaml_node_pair_t *pair;

        /* Each sequence item is a new intercept */
        newcept = (voipintercept_t *)malloc(sizeof(voipintercept_t));
        newcept->internalid = nextid;
        nextid ++;

        init_intercept_common(&(newcept->common), newcept,
                OPENLI_INTERCEPT_TYPE_VOIP);
        newcept->active_cins = NULL;
        newcept->active_registrations = NULL;
        newcept->cin_callid_map = NULL;
        newcept->cin_sdp_map = NULL;
        newcept->targets = libtrace_list_init(sizeof(openli_sip_identity_t *));
        newcept->active = 1;
        newcept->awaitingconfirm = 1;
        newcept->options = 0;

        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            parse_intercept_common_fields(&(newcept->common), doc, key, value);
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "siptargets") == 0) {

                parse_sip_targets(newcept->targets, doc, value);
            }

        }

		if (newcept->common.encrypt > OPENLI_PAYLOAD_ENCRYPTION_NONE &&
        	    newcept->common.encryptkey_len != OPENLI_AES192_KEY_LEN) {
            if (!newcept->common.liid) {
                newcept->common.liid = strdup("unidentified intercept");
            }
            logger(LOG_INFO, "OpenLI: VoIP intercept configuration for '%s' asks for encryption but has not provided a valid encryption key -- skipping",
                    newcept->common.liid);
            free_single_voipintercept(newcept);
            continue;
        }
        if (newcept->common.liid != NULL && newcept->common.authcc != NULL &&
                newcept->common.delivcc != NULL &&
                (libtrace_list_get_size(newcept->targets) > 0 ||
                    newcept->common.xid_count > 0) &&
                newcept->common.destid > 0 &&
                newcept->common.targetagency != NULL) {
            HASH_ADD_KEYPTR(hh_liid, *voipints, newcept->common.liid,
                    newcept->common.liid_len, newcept);
        } else {
            logger(LOG_INFO, "OpenLI: VOIP Intercept configuration was incomplete -- skipping.");
            free_single_voipintercept(newcept);
        }
    }

    return 0;
}



static int parse_ipintercept_list(ipintercept_t **ipints, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        ipintercept_t *newcept;
        yaml_node_pair_t *pair;
        int radchosen = 0;

        /* Each sequence item is a new intercept */
        newcept = (ipintercept_t *)malloc(sizeof(ipintercept_t));
        init_intercept_common(&(newcept->common), newcept,
                OPENLI_INTERCEPT_TYPE_IP);

        newcept->username = NULL;
        newcept->awaitingconfirm = 1;
        newcept->username_len = 0;
        newcept->vendmirrorid = OPENLI_VENDOR_MIRROR_NONE;
        newcept->udp_sinks = NULL;
        newcept->accesstype = INTERNET_ACCESS_TYPE_UNDEFINED;
        newcept->mobileident = OPENLI_MOBILE_IDENTIFIER_NOT_SPECIFIED;
        newcept->statics = NULL;
        newcept->options = 0;

        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            parse_intercept_common_fields(&(newcept->common), doc, key, value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "staticips") == 0) {
                add_intercept_static_ips(&(newcept->statics), doc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "user") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->username, value);
                newcept->username_len = strlen(newcept->username);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "alushimid") == 0) {
                newcept->vendmirrorid = strtoul(
                        (char *)value->data.scalar.value, NULL, 0);
                newcept->vendmirrorid &= 0x3fffffff;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                    "vendmirrorid") == 0) {
                newcept->vendmirrorid = strtoul(
                        (char *)value->data.scalar.value,
                        NULL, 0);
                newcept->vendmirrorid &= 0x3fffffff;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                    "udpsinks") == 0) {
                parse_intercept_udp_sink_config(newcept, doc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "accesstype") == 0) {
                newcept->accesstype = map_access_type_string(
                        (char *)value->data.scalar.value);
                if (newcept->accesstype == INTERNET_ACCESS_TYPE_UNDEFINED) {
                    logger(LOG_INFO, "OpenLI Warning: %s is not a valid access type for an IP intercept, falling back to 'undefined'",
                            (char *)value->data.scalar.value);
                }
            }


            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "radiusident")
                    == 0) {

                if (strcasecmp((char *)value->data.scalar.value, "csid") == 0) {
                    newcept->options |= (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID);
                    radchosen = 1;
                } else if (strncasecmp((char *)value->data.scalar.value,
                        "user", 4) == 0) {
                    newcept->options |= (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_USER);
                    radchosen = 1;
                }

            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "mobileident")
                    == 0) {
                newcept->mobileident = map_mobile_ident_string(
                        (char *)value->data.scalar.value);
            }
        }

        if (newcept->udp_sinks) {
            if (!newcept->common.liid) {
                newcept->common.liid = strdup("unidentified intercept");
            }
            if (newcept->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
                logger(LOG_INFO, "OpenLI: invalid IP intercept configuration for '%s' -- either udpsinks or vendmirrorid may be set, but not both",
                        newcept->common.liid);
                free_single_ipintercept(newcept);
                continue;
            }

        }

		if (newcept->common.encrypt > OPENLI_PAYLOAD_ENCRYPTION_NONE &&
        	    newcept->common.encryptkey_len != OPENLI_AES192_KEY_LEN) {
            if (!newcept->common.liid) {
                newcept->common.liid = strdup("unidentified intercept");
            }
            logger(LOG_INFO, "OpenLI: IP intercept configuration for '%s' asks for encryption but has not provided a valid encryption key -- skipping",
                    newcept->common.liid);
            free_single_ipintercept(newcept);
            continue;
        }

        if (newcept->common.liid != NULL && newcept->common.authcc != NULL &&
                newcept->common.delivcc != NULL &&
                newcept->username != NULL &&
                newcept->common.destid > 0 &&
                newcept->common.targetagency != NULL) {

            /* Default to matching against both RADIUS username and CSID */
            if (!radchosen) {
                newcept->options |= (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID);
                newcept->options |= (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_USER);
            }

            HASH_ADD_KEYPTR(hh_liid, *ipints, newcept->common.liid,
                    newcept->common.liid_len, newcept);
        } else {
            if (newcept->username == NULL) {
                logger(LOG_INFO, "OpenLI: provisioner configuration error: 'user' must be specified for an IP intercept");
            }
            logger(LOG_INFO, "OpenLI: IP Intercept configuration was incomplete -- skipping.");
            free_single_ipintercept(newcept);
        }
    }

    return 0;
}

static int validate_udp_sink_intercepts(prov_intercept_conf_t *state) {
    ipintercept_t *ipint, *tmp;
    udp_sink_intercept_mapping_t *udp;

    HASH_ITER(hh_liid, state->ipintercepts, ipint, tmp) {
        if (!ipint->udp_sinks) {
            continue;
        }
        intercept_udp_sink_t *sink, *tmpsink;

        HASH_ITER(hh, ipint->udp_sinks, sink, tmpsink) {
            HASH_FIND(hh, state->udp_sink_intercept_mappings, sink->key,
                    strlen(sink->key), udp);
            if (udp) {
                logger(LOG_INFO, "OpenLI: UDP Sink %s is configured for multiple IP intercepts! This is invalid, please ensure that (at most) only 1 IP intercept is associated with a UDP sink. Affected LIIDs: %s, %s",
                        sink->key, ipint->common.liid, udp->liid);
                return -1;
            }

            udp = calloc(1, sizeof(udp_sink_intercept_mapping_t));
            udp->udpsink = strdup(sink->key);
            udp->liid = strdup(ipint->common.liid);
            HASH_ADD_KEYPTR(hh, state->udp_sink_intercept_mappings,
                    udp->udpsink, strlen(udp->udpsink), udp);
        }
    }
    return 1;
}

static int intercept_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {

    prov_intercept_conf_t *state = (prov_intercept_conf_t *)arg;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "ipintercepts") == 0) {
        if (parse_ipintercept_list(&state->ipintercepts, doc, value) == -1) {
            return -1;
        }
        if (validate_udp_sink_intercepts(state) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "voipintercepts") == 0) {
        if (parse_voipintercept_list(&state->voipintercepts, doc,
                    value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "emailintercepts") == 0) {
        if (parse_emailintercept_list(&state->emailintercepts, doc,
                    value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "agencies") == 0) {
        if (parse_agency_list(state, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "defaultradiususers") == 0) {
        if (parse_defradusers_list(state, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "radiusservers") == 0) {
        if (parse_core_server_list(&state->radiusservers,
                OPENLI_CORE_SERVER_RADIUS, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "gtpservers") == 0) {
        if (parse_core_server_list(&state->gtpservers,
                OPENLI_CORE_SERVER_GTP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "sipservers") == 0) {
        if (parse_core_server_list(&state->sipservers,
                OPENLI_CORE_SERVER_SIP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "smtpservers") == 0) {
        if (parse_core_server_list(&state->smtpservers,
                OPENLI_CORE_SERVER_SMTP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "imapservers") == 0) {
        if (parse_core_server_list(&state->imapservers,
                OPENLI_CORE_SERVER_IMAP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "pop3servers") == 0) {
        if (parse_core_server_list(&state->pop3servers,
                OPENLI_CORE_SERVER_POP3, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "email-defaultdelivercompressed") == 0) {
        if (strcasecmp((char *)value->data.scalar.value, "as-is") == 0) {
            state->default_email_deliver_compress =
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;
        } else if (strcasecmp((char *)value->data.scalar.value,
                "decompressed") == 0) {
            state->default_email_deliver_compress =
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
        } else if (strcasecmp((char *)value->data.scalar.value,
                "inflated") == 0) {
            state->default_email_deliver_compress =
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
        } else {
            logger(LOG_INFO, "OpenLI provisioner: invalid value for 'email-defaultdelivercompressed' option: %s", (char *)value->data.scalar.value);
            state->default_email_deliver_compress =
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;
            logger(LOG_INFO, "OpenLI provisioner: using 'as-is' instead.");
        }

    }

    return 0;
}

static int provisioning_parser(void *arg, yaml_document_t *doc UNUSED,
        yaml_node_t *key, yaml_node_t *value) {

    provision_state_t *state = (provision_state_t *)arg;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                "encrypt-intercept-config-file") == 0) {
        state->encrypt_intercept_config = config_check_onoff(
                (char *)(value->data.scalar.value));
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "voip-ignorecomfort") == 0) {
        state->ignorertpcomfort =
                config_check_onoff((char *)(value->data.scalar.value));
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "clientport") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "clientaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "updateport") == 0) {
        SET_CONFIG_STRING_OPTION(state->pushport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "updateaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->pushaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "mediationport") == 0) {
        SET_CONFIG_STRING_OPTION(state->mediateport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "mediationaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->mediateaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "intercept-config-file") == 0) {
        SET_CONFIG_STRING_OPTION(state->interceptconffile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "tlscert") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.certfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "tlskey") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.keyfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "tlsca") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.cacertfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "restauthdb") == 0) {
        SET_CONFIG_STRING_OPTION(state->restauthdbfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "restauthkey") == 0) {
        SET_CONFIG_STRING_OPTION(state->restauthkey, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "clientdbfile") == 0) {
        SET_CONFIG_STRING_OPTION(state->clientdbfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "clientdbkey") == 0) {
        SET_CONFIG_STRING_OPTION(state->clientdbkey, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "integrity-signing-private-key") == 0) {
        SET_CONFIG_STRING_OPTION(state->integrity_sign_private_key_location,
                value);
    }

    return 0;
}

static void apply_agency_config_to_intercepts(prov_intercept_conf_t *conf) {
    prov_agency_t *ag;
    emailintercept_t *em, *emtmp;
    voipintercept_t *vint, *vinttmp;
    ipintercept_t *ipint, *ipinttmp;

    HASH_ITER(hh_liid, conf->ipintercepts, ipint, ipinttmp) {
        HASH_FIND(hh, conf->leas, ipint->common.targetagency,
                strlen(ipint->common.targetagency), ag);
        if (!ag) {
            continue;
        }
        ipint->common.time_fmt = ag->ag->time_fmt;
    }

    HASH_ITER(hh_liid, conf->voipintercepts, vint, vinttmp) {
        HASH_FIND(hh, conf->leas, vint->common.targetagency,
                strlen(vint->common.targetagency), ag);
        if (!ag) {
            continue;
        }
        vint->common.time_fmt = ag->ag->time_fmt;
    }

    HASH_ITER(hh_liid, conf->emailintercepts, em, emtmp) {
        HASH_FIND(hh, conf->leas, em->common.targetagency,
                strlen(em->common.targetagency), ag);
        if (!ag) {
            continue;
        }
        em->common.time_fmt = ag->ag->time_fmt;
    }

}

int parse_intercept_config(char *configfile, prov_intercept_conf_t *conf,
        const char *encpassfile) {
    int result = config_yaml_parser(configfile, conf, intercept_parser, 1,
            encpassfile);

    apply_agency_config_to_intercepts(conf);

    if (result == 0) {
        conf->was_encrypted = 0;
    } else if (result == 1) {
        conf->was_encrypted = 1;
    }
    return result;
}

int parse_provisioning_config(char *configfile, provision_state_t *state) {

    return config_yaml_parser(configfile, state, provisioning_parser, 0, NULL);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
