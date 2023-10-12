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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <libtrace/message_queue.h>
#include <libtrace_parallel.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <math.h>

#include "configparser.h"
#include "logger.h"
#include "agency.h"
#include "coreserver.h"

uint64_t nextid = 0;

#define SET_CONFIG_STRING_OPTION(optname, yamlval) \
    if (optname) { \
        free(optname); \
    } \
    optname = strdup((char *)yamlval->data.scalar.value);


static int check_onoff(char *value) {

    if (strcasecmp(value, "yes") == 0) {
        return 1;
    }

    if (strcasecmp(value, "on") == 0) {
        return 1;
    }

    if (strcasecmp(value, "true") == 0) {
        return 1;
    }

    if (strcasecmp(value, "enabled") == 0) {
        return 1;
    }

    if (strcasecmp(value, "no") == 0) {
        return 0;
    }

    if (strcasecmp(value, "off") == 0) {
        return 0;
    }

    if (strcasecmp(value, "false") == 0) {
        return 0;
    }

    if (strcasecmp(value, "disabled") == 0) {
        return 0;
    }

    return -1;
}

static int parse_input_config(collector_global_t *glob, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        colinput_t *inp;
        yaml_node_pair_t *pair;

        /* Each sequence item is a new input */
        inp = (colinput_t *)malloc(sizeof(colinput_t));
        inp->uri = NULL;
        inp->hashconfigured = 0;
        inp->threadcount = 1;
        inp->trace = NULL;
        inp->pktcbs = NULL;
        inp->running = 0;
        inp->report_drops = 1;
        inp->hasher_apply = OPENLI_HASHER_BIDIR;
        inp->filterstring = NULL;
        inp->filter = NULL;

        /* Mappings describe the parameters for each input */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "uri") == 0) {
                SET_CONFIG_STRING_OPTION(inp->uri, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "filter") == 0) {
                SET_CONFIG_STRING_OPTION(inp->filterstring, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                        "reportdrops") == 0) {
                if (check_onoff((char *)value->data.scalar.value) == 0) {
                    inp->report_drops = 0;
                } else {
                    inp->report_drops = 1;
                }
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "threads") == 0) {
                inp->threadcount = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "hasher") == 0) {
                if (strcasecmp((char *)value->data.scalar.value,
                        "balanced") == 0) {
                    inp->hasher_apply = OPENLI_HASHER_BALANCE;
                } else if (strcasecmp((char *)value->data.scalar.value,
                        "bidirectional") == 0) {
                    inp->hasher_apply = OPENLI_HASHER_BIDIR;
                } else if (strcasecmp((char *)value->data.scalar.value,
                        "radius") == 0) {
                    inp->hasher_apply = OPENLI_HASHER_RADIUS;
                } else {
                    logger(LOG_INFO, "OpenLI: unexpected hasher type '%s' in config, ignoring.", (char *)value->data.scalar.value);
                }
            }
        }
        if (!inp->uri) {
            logger(LOG_INFO, "OpenLI collector: input is missing a URI?");
            continue;
        }
        HASH_ADD_KEYPTR(hh, glob->inputs, inp->uri, strlen(inp->uri), inp);
        glob->total_col_threads += inp->threadcount;
    }

    return 0;
}

static int parse_email_ingest_config(collector_global_t *glob,
        yaml_document_t *doc, yaml_node_t *optmap) {

    yaml_node_pair_t *pair;
    yaml_node_t *key, *value;

    for (pair = optmap->data.mapping.pairs.start;
            pair < optmap->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcmp((char *)key->data.scalar.value, "enabled") == 0) {
            glob->emailconf.enabled =
                    check_onoff((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcmp((char *)key->data.scalar.value, "requiretls") == 0) {
            glob->emailconf.tlsrequired =
                    check_onoff((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcmp((char *)key->data.scalar.value, "authpassword") == 0) {
            glob->emailconf.authrequired = true;
            SET_CONFIG_STRING_OPTION(glob->emailconf.authpassword, value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcmp((char *)key->data.scalar.value, "listenaddress") == 0) {
            SET_CONFIG_STRING_OPTION(glob->emailconf.listenaddr, value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcmp((char *)key->data.scalar.value, "listenport") == 0) {
            SET_CONFIG_STRING_OPTION(glob->emailconf.listenport, value);
        }
    }

    return 0;
}

static int parse_email_timeouts_config(collector_global_t *glob,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE) {
                if (strcasecmp((char *)key->data.scalar.value, "smtp") == 0) {
                    glob->email_timeouts.smtp = strtoul(
                            (char *)value->data.scalar.value, NULL, 10);
                }
                else if (strcasecmp((char *)key->data.scalar.value,
                            "imap") == 0) {
                    glob->email_timeouts.imap = strtoul(
                            (char *)value->data.scalar.value, NULL, 10);
                }
                else if (strcasecmp((char *)key->data.scalar.value,
                            "pop3") == 0) {
                    glob->email_timeouts.pop3 = strtoul(
                            (char *)value->data.scalar.value, NULL, 10);
                } else {
                    logger(LOG_INFO, "OpenLI: unexpected email protocol '%s' in 'emailsessiontimeouts' configuration", (char *)key->data.scalar.value);
                }
            }
        }
    }
    return 0;
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
                    strcmp((char *)key->data.scalar.value, "address") == 0) {
                SET_CONFIG_STRING_OPTION(newtgt->address, value);
            }
        }

        if (!newtgt->address) {
            logger(LOG_INFO,
                    "OpenLI: a Email target requires an address, skipping.");
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
                    strcmp((char *)key->data.scalar.value, "username") == 0) {
                SET_CONFIG_STRING_OPTION(newtgt->username, value);
                newtgt->username_len = strlen(newtgt->username);

                    continue;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "realm") == 0) {
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

static int parse_core_server_list(coreserver_t **servlist, uint8_t cstype,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        coreserver_t *cs;

        cs = (coreserver_t *)calloc(1, sizeof(coreserver_t));

        cs->serverkey = NULL;
        cs->info = NULL;
        cs->ipstr = NULL;
        cs->portstr = NULL;
        cs->servertype = cstype;
        cs->awaitingconfirm = 1;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "ip") == 0) {
                SET_CONFIG_STRING_OPTION(cs->ipstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "port") == 0) {
                SET_CONFIG_STRING_OPTION(cs->portstr, value);
            }
        }

        if (construct_coreserver_key(cs) != NULL) {
            HASH_ADD_KEYPTR(hh, *servlist, cs->serverkey,
                    strlen(cs->serverkey), cs);
        } else {
            logger(LOG_INFO,
                    "OpenLI: %s server configuration was incomplete -- skipping.",
                    coreserver_type_to_string(cstype));
            free_single_coreserver(cs);
        }
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
                    strcmp((char *)key->data.scalar.value, "iprange") == 0 &&
                    newr->rangestr == NULL) {
                newr->rangestr =
                        parse_iprange_string((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "sessionid") == 0) {
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

static int parse_agency_list(prov_intercept_conf_t *state, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        liagency_t *newag = (liagency_t *)malloc(sizeof(liagency_t));

        newag->hi2_ipstr = NULL;
        newag->hi2_portstr = NULL;
        newag->hi3_ipstr = NULL;
        newag->hi3_portstr = NULL;
        newag->agencyid = NULL;
        newag->keepalivefreq = DEFAULT_AGENCY_KEEPALIVE_FREQ;
        newag->keepalivewait = DEFAULT_AGENCY_KEEPALIVE_WAIT;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi2address") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi2_ipstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi2port") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi2_portstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi3address") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi3_ipstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi3port") == 0) {
                SET_CONFIG_STRING_OPTION(newag->hi3_portstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "agencyid") == 0) {
                SET_CONFIG_STRING_OPTION(newag->agencyid, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "keepalivefreq") == 0) {
                newag->keepalivefreq = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "keepalivewait") == 0) {
                newag->keepalivewait = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }
        }

        /* 'pcapdisk' is reserved for the intercepts that need to
         * be written to pcap files instead of live streamed to an
         * ETSI-capable agency. */
        if (strcmp(newag->agencyid, "pcapdisk") == 0) {
            logger(LOG_INFO,
                    "OpenLI: 'pcapdisk' is a reserved agencyid, please rename to something else.");
            free(newag->agencyid);
            newag->agencyid = NULL;
        }

        if (newag->keepalivewait > newag->keepalivefreq) {
            logger(LOG_INFO, "keepalivewait must be less than or equal to keepalivefreq, setting keepalivewait to %u",
                    newag->keepalivefreq);
            newag->keepalivewait = newag->keepalivefreq;
        }

        if (newag->hi2_ipstr != NULL && newag->hi2_portstr != NULL &&
                newag->hi3_ipstr != NULL && newag->hi3_portstr != NULL &&
                newag->agencyid != NULL) {
            prov_agency_t *prov_ag;
            prov_ag = (prov_agency_t *)malloc(sizeof(prov_agency_t));
            prov_ag->ag = newag;
            prov_ag->announcereq = 1;
            HASH_ADD_KEYPTR(hh, state->leas, prov_ag->ag->agencyid,
                    strlen(prov_ag->ag->agencyid), prov_ag);

        } else {
            free(newag);
            logger(LOG_INFO, "OpenLI: LEA configuration was incomplete -- skipping.");
        }
    }
    return 0;
}

static void parse_intercept_common_fields(intercept_common_t *common,
        yaml_node_t *key, yaml_node_t *value) {

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "liid") == 0) {
        SET_CONFIG_STRING_OPTION(common->liid, value);
        common->liid_len = strlen(common->liid);
    }
    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value,
                "authcountrycode") == 0) {
        SET_CONFIG_STRING_OPTION(common->authcc, value);
        common->authcc_len = strlen(common->authcc);
    }
    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value,
                "deliverycountrycode") == 0) {
        SET_CONFIG_STRING_OPTION(common->delivcc, value);
        common->delivcc_len = strlen(common->delivcc);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "mediator") == 0
            && common->destid == 0) {
        common->destid = strtoul(
                (char *)value->data.scalar.value, NULL, 10);
        if (common->destid == 0) {
            logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'mediator' config option.");
        }
    }
    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "starttime") == 0) {
        common->tostart_time = strtoul(
                (char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "endtime") == 0) {
        common->toend_time = strtoul(
                (char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "agencyid") == 0) {
        SET_CONFIG_STRING_OPTION(common->targetagency, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "payloadencryption") == 0) {
        if (strcasecmp((char *)value->data.scalar.value, "none") == 0) {
            common->encrypt = OPENLI_PAYLOAD_ENCRYPTION_NONE;
        } else if (strcasecmp((char *)value->data.scalar.value, "aes-192-cbc") == 0) {
            common->encrypt = OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "encryptionkey") == 0) {
        SET_CONFIG_STRING_OPTION(common->encryptkey, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "outputhandovers") == 0) {

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
    common->liid_len = 0;
    common->authcc = NULL;
    common->authcc_len = 0;
    common->delivcc = NULL;
    common->delivcc_len = 0;
    common->destid = 0;
    common->targetagency = NULL;
    common->encryptkey = NULL;
    common->tostart_time = 0;
    common->toend_time = 0;
    common->tomediate = OPENLI_INTERCEPT_OUTPUTS_ALL;
    common->encrypt = OPENLI_PAYLOAD_ENCRYPTION_NONE;
    common->hi1_seqno = 0;
    common->local = calloc(1, sizeof(prov_intercept_data_t));

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

            parse_intercept_common_fields(&(newcept->common), key, value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcmp((char *)key->data.scalar.value, "targets") == 0) {

                parse_email_targets(&(newcept->targets), doc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                    "delivercompressed") == 0) {
                if (strcmp((char *)value->data.scalar.value, "as-is") == 0) {
                    newcept->delivercompressed =
                            OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;
                } else if (strcmp((char *)value->data.scalar.value,
                        "decompressed") == 0) {
                    newcept->delivercompressed =
                            OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
                } else if (strcmp((char *)value->data.scalar.value,
                        "inflated") == 0) {
                    newcept->delivercompressed =
                            OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
                }
            }
        }

        tgtcount = HASH_CNT(hh, newcept->targets);
        if (newcept->common.encryptkey == NULL &&
                newcept->common.encrypt != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
            if (newcept->common.liid == NULL) {
                newcept->common.liid = strdup("unidentified intercept");
            }
            logger(LOG_INFO, "OpenLI: Email intercept configuration for '%s' asks for encryption but has not provided an encryption key -- skipping",
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

            parse_intercept_common_fields(&(newcept->common), key, value);
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcmp((char *)key->data.scalar.value, "siptargets") == 0) {

                parse_sip_targets(newcept->targets, doc, value);
            }

        }

        if (newcept->common.encryptkey == NULL &&
                newcept->common.encrypt != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
            if (newcept->common.liid == NULL) {
                newcept->common.liid = strdup("unidentified intercept");
            }
            logger(LOG_INFO, "OpenLI: VoIP intercept configuration for '%s' asks for encryption but has not provided an encryption key -- skipping",
                    newcept->common.liid);
            free_single_voipintercept(newcept);
            continue;
        }
        if (newcept->common.liid != NULL && newcept->common.authcc != NULL &&
                newcept->common.delivcc != NULL &&
                libtrace_list_get_size(newcept->targets) > 0 &&
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
        newcept->accesstype = INTERNET_ACCESS_TYPE_UNDEFINED;
        newcept->statics = NULL;
        newcept->options = 0;

        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            parse_intercept_common_fields(&(newcept->common), key, value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "staticips") == 0) {
                add_intercept_static_ips(&(newcept->statics), doc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "user") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->username, value);
                newcept->username_len = strlen(newcept->username);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "alushimid") == 0) {
                newcept->vendmirrorid = strtoul(
                        (char *)value->data.scalar.value, NULL, 0);
                newcept->vendmirrorid &= 0x3fffffff;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                    "vendmirrorid") == 0) {
                newcept->vendmirrorid = strtoul(
                        (char *)value->data.scalar.value,
                        NULL, 0);
                newcept->vendmirrorid &= 0x3fffffff;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "accesstype") == 0) {
                newcept->accesstype = map_access_type_string(
                        (char *)value->data.scalar.value);
                if (newcept->accesstype == INTERNET_ACCESS_TYPE_UNDEFINED) {
                    logger(LOG_INFO, "OpenLI Warning: %s is not a valid access type for an IP intercept, falling back to 'undefined'",
                            (char *)value->data.scalar.value);
                }
            }


            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "radiusident")
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
        }

        if (newcept->common.encryptkey == NULL &&
                newcept->common.encrypt != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
            if (newcept->common.liid == NULL) {
                newcept->common.liid = strdup("unidentified intercept");
            }
            logger(LOG_INFO, "OpenLI: IP intercept configuration for '%s' asks for encryption but has not provided an encryption key -- skipping",
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

static int yaml_parser(char *configfile, void *arg,
        int (*parse_mapping)(void *, yaml_document_t *, yaml_node_t *,
                yaml_node_t *), int createifmissing) {
    FILE *in = NULL;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    int ret = -1;

    in = fopen(configfile, "r");

    if (in == NULL && errno == ENOENT && createifmissing) {
        in = fopen(configfile, "w+");
    }

    if (in == NULL) {
        logger(LOG_INFO, "OpenLI: Failed to open config file: %s",
                strerror(errno));
        return -1;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

    if (!yaml_parser_load(&parser, &document)) {
        logger(LOG_INFO, "OpenLI: Malformed config file");
        goto yamlfail;
    }

    root = yaml_document_get_root_node(&document);
    if (!root) {
        logger(LOG_INFO, "OpenLI: Config file '%s' is empty!", configfile);
        ret = -2;
        goto endconfig;
    }

    if (root->type != YAML_MAPPING_NODE) {
        logger(LOG_INFO, "OpenLI: Top level of config should be a map");
        goto endconfig;
    }
    for (pair = root->data.mapping.pairs.start;
            pair < root->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(&document, pair->key);
        value = yaml_document_get_node(&document, pair->value);

        if (parse_mapping(arg, &document, key, value) == -1) {
            ret = -1;
            break;
        }
        ret = 0;
    }
endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return ret;
}


static int global_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {
    collector_global_t *glob = (collector_global_t *)arg;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "inputs") == 0) {
        if (parse_input_config(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "operatorid") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sharedinfo.operatorid, value);
        glob->sharedinfo.operatorid_len = strlen(glob->sharedinfo.operatorid);

        /* Limited to 16 chars */
        if (glob->sharedinfo.operatorid_len > 16) {
            logger(LOG_INFO, "OpenLI: Operator ID must be 16 characters or less!");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "networkelementid")
            == 0) {
        SET_CONFIG_STRING_OPTION(glob->sharedinfo.networkelemid, value);
        glob->sharedinfo.networkelemid_len = strlen(glob->sharedinfo.networkelemid);

        /* Limited to 16 chars */
        if (glob->sharedinfo.networkelemid_len > 16) {
            logger(LOG_INFO, "OpenLI: Network Element ID must be 16 characters or less!");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "interceptpointid")
            == 0) {
        SET_CONFIG_STRING_OPTION(glob->sharedinfo.intpointid, value);
        glob->sharedinfo.intpointid_len = strlen(glob->sharedinfo.intpointid);

        /* Limited to 8 chars */
        if (glob->sharedinfo.intpointid_len > 8) {
            logger(LOG_INFO, "OpenLI: Intercept Point ID must be 8 characters or less!");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisionerport") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sharedinfo.provisionerport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisioneraddr") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sharedinfo.provisionerip, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "sipdebugfile") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sipdebugfile, value);
    }


    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_MAPPING_NODE &&
            strcmp((char *)key->data.scalar.value, "emailingest") == 0) {
        if (parse_email_ingest_config(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "alumirrors") == 0) {
        if (parse_core_server_list(&glob->alumirrors,
                OPENLI_CORE_SERVER_ALUMIRROR, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "jmirrors") == 0) {
        if (parse_core_server_list(&glob->jmirrors,
                OPENLI_CORE_SERVER_ALUMIRROR, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "ciscomirrors") == 0) {
        if (parse_core_server_list(&glob->ciscomirrors,
                OPENLI_CORE_SERVER_ALUMIRROR, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "seqtrackerthreads") == 0) {
        glob->seqtracker_threads = strtoul((char *) value->data.scalar.value,
                NULL, 10);
        if (glob->seqtracker_threads <= 0) {
            glob->seqtracker_threads = 1;
            logger(LOG_INFO, "OpenLI: must have at least one sequence tracker thread per collector!");
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "encoderthreads") == 0) {
        glob->encoding_threads = strtoul((char *) value->data.scalar.value,
                NULL, 10);
        if (glob->encoding_threads <= 0) {
            glob->encoding_threads = 1;
            logger(LOG_INFO, "OpenLI: must have at least one encoder thread per collector!");
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "forwardingthreads") == 0) {
        glob->forwarding_threads = strtoul((char *) value->data.scalar.value,
                NULL, 10);
        if (glob->forwarding_threads <= 0) {
            glob->forwarding_threads = 1;
            logger(LOG_INFO, "OpenLI: must have at least one forwarding thread per collector!");
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "logstatfrequency") == 0) {
        glob->stat_frequency = strtoul((char *) value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlscert") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sslconf.certfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlskey") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sslconf.keyfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlsca") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sslconf.cacertfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "etsitls") == 0) {
        glob->etsitls = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "sipignoresdpo") == 0) {
        glob->ignore_sdpo_matches = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "encoding") == 0) {

        /* We're back to only having one encoding method now, but
         * allow users to choose "BER" without breaking anything.
         */
        if (strcasecmp((char *)value->data.scalar.value, "BER") == 0) {
            glob->encoding_method = OPENLI_ENCODING_DER;
        } else {
            glob->encoding_method = OPENLI_ENCODING_DER;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "SIPallowfromident") == 0) {

       glob->trust_sip_from = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "maskimapcreds") == 0) {

       glob->mask_imap_creds = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "cisconoradius") == 0) {

       glob->sharedinfo.cisco_noradius =
                check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value,
                    "emailsessiontimeouts") == 0) {
        if (parse_email_timeouts_config(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "defaultemaildomain") == 0) {
        SET_CONFIG_STRING_OPTION(glob->default_email_domain, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQname") == 0) {
        SET_CONFIG_STRING_OPTION(glob->RMQ_conf.name, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQpass") == 0) {
        SET_CONFIG_STRING_OPTION(glob->RMQ_conf.pass, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQhostname") == 0) {
        SET_CONFIG_STRING_OPTION(glob->RMQ_conf.hostname, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQheartbeatfreq") == 0) {
        glob->RMQ_conf.heartbeatFreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQenabled") == 0) {
        glob->RMQ_conf.enabled = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQport") == 0) {
        glob->RMQ_conf.port = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }
    
    return 0;
}


static int mediator_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {

    mediator_state_t *state = (mediator_state_t *)arg;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "listenport") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "listenaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisionerport") == 0) {
        SET_CONFIG_STRING_OPTION(state->provisioner.provport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisioneraddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->provisioner.provaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "pcapdirectory") == 0) {
        SET_CONFIG_STRING_OPTION(state->pcapdirectory, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "pcapfilename") == 0) {
        SET_CONFIG_STRING_OPTION(state->pcaptemplate, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "operatorid") == 0) {
        SET_CONFIG_STRING_OPTION(state->operatorid, value);
        /* 16 chars max allowed for this field (defined in
         * ETSI LI-PS-PDU spec) */
        if (strlen(state->operatorid) > 16) {
            state->operatorid[16] = '\0';
            logger(LOG_INFO, "OpenLI: warning, 'operatorid' must be no longer than 16 characters -- truncated to %s", state->operatorid);
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "altoperatorid") == 0) {
        SET_CONFIG_STRING_OPTION(state->shortoperatorid, value);

        /* 5 chars max allowed for this field (defined in ETSI HI2 spec) */
        if (strlen(state->shortoperatorid) > 5) {
            state->shortoperatorid[5] = '\0';
            logger(LOG_INFO, "OpenLI: warning, 'altoperatorid' must be no longer than 5 characters -- truncated to %s", state->shortoperatorid);
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "mediatorid") == 0) {
        state->mediatorid = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->mediatorid == 0) {
            logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'mediatorid' config option.");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "pcapcompress") == 0) {
        state->pcapcompress = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->pcapcompress > 9) {
            logger(LOG_INFO, "OpenLI: maximum pcap compression level is 9, setting to that instead.");
            state->pcapcompress = 9;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "pcaprotatefreq") == 0) {
        state->pcaprotatefreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->pcaprotatefreq == 0) {
            logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'pcaprotatefreq' config option.");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlscert") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.certfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlskey") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.keyfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlsca") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.cacertfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "etsitls") == 0) {
            state->etsitls = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQname") == 0) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.name, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQpass") == 0) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.pass, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQlocalpass") == 0) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.internalpass, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQhostname") == 0) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.hostname, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQheartbeatfreq") == 0) {
        state->RMQ_conf.heartbeatFreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQenabled") == 0) {
        state->RMQ_conf.enabled = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQSSL") == 0) {
        state->RMQ_conf.SSLenabled = check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "RMQport") == 0) {
        state->RMQ_conf.port = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }

    return 0;

}

static int intercept_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {

    prov_intercept_conf_t *state = (prov_intercept_conf_t *)arg;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "ipintercepts") == 0) {
        if (parse_ipintercept_list(&state->ipintercepts, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "voipintercepts") == 0) {
        if (parse_voipintercept_list(&state->voipintercepts, doc,
                    value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "emailintercepts") == 0) {
        if (parse_emailintercept_list(&state->emailintercepts, doc,
                    value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "agencies") == 0) {
        if (parse_agency_list(state, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "defaultradiususers") == 0) {
        if (parse_defradusers_list(state, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "radiusservers") == 0) {
        if (parse_core_server_list(&state->radiusservers,
                OPENLI_CORE_SERVER_RADIUS, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "gtpservers") == 0) {
        if (parse_core_server_list(&state->gtpservers,
                OPENLI_CORE_SERVER_GTP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "sipservers") == 0) {
        if (parse_core_server_list(&state->sipservers,
                OPENLI_CORE_SERVER_SIP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "smtpservers") == 0) {
        if (parse_core_server_list(&state->smtpservers,
                OPENLI_CORE_SERVER_SMTP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "imapservers") == 0) {
        if (parse_core_server_list(&state->imapservers,
                OPENLI_CORE_SERVER_IMAP, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "pop3servers") == 0) {
        if (parse_core_server_list(&state->pop3servers,
                OPENLI_CORE_SERVER_POP3, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value,
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

static int provisioning_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {

    provision_state_t *state = (provision_state_t *)arg;


    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "voip-ignorecomfort") == 0) {
        state->ignorertpcomfort =
                check_onoff((char *)(value->data.scalar.value));
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "clientport") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "clientaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "updateport") == 0) {
        SET_CONFIG_STRING_OPTION(state->pushport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "updateaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->pushaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "mediationport") == 0) {
        SET_CONFIG_STRING_OPTION(state->mediateport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "mediationaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->mediateaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "intercept-config-file") == 0) {
        SET_CONFIG_STRING_OPTION(state->interceptconffile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlscert") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.certfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlskey") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.keyfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "tlsca") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.cacertfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "restauthdb") == 0) {
        SET_CONFIG_STRING_OPTION(state->restauthdbfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "restauthkey") == 0) {
        SET_CONFIG_STRING_OPTION(state->restauthkey, value);
    }

    return 0;
}

int parse_intercept_config(char *configfile, prov_intercept_conf_t *conf) {
    return yaml_parser(configfile, conf, intercept_parser, 1);
}

int parse_collector_config(char *configfile, collector_global_t *glob) {
    return yaml_parser(configfile, glob, global_parser, 0);
}

int parse_provisioning_config(char *configfile, provision_state_t *state) {

    return yaml_parser(configfile, state, provisioning_parser, 0);
}

int parse_mediator_config(char *configfile, mediator_state_t *state) {
    return yaml_parser(configfile, state, mediator_parser, 0);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
