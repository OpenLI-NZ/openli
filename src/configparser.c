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

static internet_access_method_t map_access_type_string(char *confstr) {

    if (strcasecmp(confstr, "dialup") == 0 ||
            strcasecmp(confstr, "dial-up") == 0) {
        return INTERNET_ACCESS_TYPE_DIALUP;
    }

    if (strcasecmp(confstr, "adsl") == 0 || strcasecmp(confstr, "vdsl") == 0 ||
            strcasecmp(confstr, "dsl") == 0 ||
            strcasecmp(confstr, "adsl2") == 0 ||
            strcasecmp(confstr, "xdsl") == 0) {
        return INTERNET_ACCESS_TYPE_XDSL;
    }

    if (strcasecmp(confstr, "cable") == 0 ||
            strcasecmp(confstr, "cablemodem") == 0 ||
            strcasecmp(confstr, "cable-modem") == 0) {
        return INTERNET_ACCESS_TYPE_CABLEMODEM;
    }

    if (strcasecmp(confstr, "lan") == 0 ||
            strcasecmp(confstr, "ethernet") == 0) {
        return INTERNET_ACCESS_TYPE_LAN;
    }

    if (strcasecmp(confstr, "wirelesslan") == 0 ||
            strcasecmp(confstr, "wireless-lan") == 0 ||
            strcasecmp(confstr, "wireless") == 0 ||
            strcasecmp(confstr, "wifi-lan") == 0 ||
            strcasecmp(confstr, "wifi") == 0) {
        return INTERNET_ACCESS_TYPE_WIRELESS_LAN;
    }

    if (strcasecmp(confstr, "fibre") == 0 || strcasecmp(confstr, "fiber") == 0
            || strcasecmp(confstr, "ufb") == 0) {
        return INTERNET_ACCESS_TYPE_FIBER;
    }

    if (strcasecmp(confstr, "wimax") == 0 ||
            strcasecmp(confstr, "hiperman") == 0) {
        return INTERNET_ACCESS_TYPE_WIMAX;
    }

    if (strcasecmp(confstr, "satellite") == 0) {
        return INTERNET_ACCESS_TYPE_SATELLITE;
    }

    if (strcasecmp(confstr, "wireless-other") == 0 ||
            strcasecmp(confstr, "wifi-other") == 0 ||
            strcasecmp(confstr, "wifiother") == 0 ||
            strcasecmp(confstr, "wirelessother") == 0) {
        return INTERNET_ACCESS_TYPE_WIRELESS_OTHER;
    }

    return INTERNET_ACCESS_TYPE_UNDEFINED;
}

static int parse_input_config(collector_global_t *glob, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;
    int i;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        colinput_t *inp;
        yaml_node_pair_t *pair;

        /* Each sequence item is a new input */
        inp = (colinput_t *)malloc(sizeof(colinput_t));
        inp->uri = NULL;
        inp->threadcount = 1;
        inp->trace = NULL;
        inp->pktcbs = NULL;
        inp->running = 0;
        inp->report_drops = 1;

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
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "realm") == 0) {
                SET_CONFIG_STRING_OPTION(newtgt->realm, value);
                newtgt->realm_len = strlen(newtgt->realm);
            }
        }

        if (newtgt->username) {
            libtrace_list_push_back(targets, &newtgt);
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

static int parse_core_server_list(coreserver_t **servlist, uint8_t cstype,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        coreserver_t *cs;
        char keyspace[256];

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

static inline int parse_iprange_option(static_ipranges_t *newr,
        yaml_node_t *value) {

    char *confrange = (char *)value->data.scalar.value;
    int family = 0;

    if (strchr(confrange, ':') != NULL) {
        family = AF_INET6;
    } else if (strchr(confrange, '.') != NULL) {
        family = AF_INET;
    } else {
        logger(LOG_INFO,
                "OpenLI: '%s' is not a valid prefix or IP address, skipping.",
                confrange);
        return -1;
    }
    if (strchr(confrange, '/') == NULL) {
        /* No slash, so assume /32 or /128 */
        int rlen = strlen(confrange) + 5;   /* '/128' + nul */
        newr->rangestr = (char *)calloc(1, rlen);
        snprintf(newr->rangestr, rlen - 1, "%s/%u", confrange,
                family == AF_INET ? 32 : 128);

    } else {
        newr->rangestr = strdup((char *)value->data.scalar.value);
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
                if (parse_iprange_option(newr, value) < 0) {
                    continue;
                }
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "sessionid") == 0) {
                newr->cin = strtoul((char *)value->data.scalar.value, NULL, 10);
            }
        }

        if (newr->cin >= (uint32_t)(pow(2, 31))) {
            logger(LOG_INFO,
                    "OpenLI: CIN %u for static IP range %s is too large.",
                    newr->cin);
            newr->cin = newr->cin % (uint32_t)(pow(2, 31));
            logger(LOG_INFO, "OpenLI: replaced CIN with %u.",
                    newr->cin);
        }

        if (newr->rangestr) {
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

static int parse_agency_list(provision_state_t *state, yaml_document_t *doc,
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
        newag->keepalivefreq = 300;
        newag->keepalivewait = 30;

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

        if (newag->hi2_ipstr != NULL && newag->hi2_portstr != NULL &&
                newag->hi3_ipstr != NULL && newag->hi3_portstr != NULL &
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

static int parse_voipintercept_list(voipintercept_t **voipints,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;
    int i;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        voipintercept_t *newcept;
        yaml_node_pair_t *pair;

        /* Each sequence item is a new intercept */
        newcept = (voipintercept_t *)malloc(sizeof(voipintercept_t));
        newcept->internalid = nextid;
        nextid ++;

        newcept->common.liid = NULL;
        newcept->common.authcc = NULL;
        newcept->common.delivcc = NULL;
        newcept->active_cins = NULL;
        newcept->active_registrations = NULL;
        newcept->cin_callid_map = NULL;
        newcept->cin_sdp_map = NULL;
        newcept->targets = libtrace_list_init(sizeof(openli_sip_identity_t *));
        newcept->active = 1;
        newcept->common.destid = 0;
        newcept->common.targetagency = NULL;
        newcept->awaitingconfirm = 1;
        newcept->options = 0;


        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "liid") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.liid, value);
                newcept->common.liid_len = strlen(newcept->common.liid);
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                        "authcountrycode") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.authcc, value);
                newcept->common.authcc_len = strlen(newcept->common.authcc);
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                        "deliverycountrycode") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.delivcc, value);
                newcept->common.delivcc_len = strlen(newcept->common.delivcc);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcmp((char *)key->data.scalar.value, "siptargets") == 0) {

                parse_sip_targets(newcept->targets, doc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "mediator") == 0
                    && newcept->common.destid == 0) {
                newcept->common.destid = strtoul((char *)value->data.scalar.value,
                        NULL, 10);
                if (newcept->common.destid == 0) {
                    logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'mediator' config option.");
                }
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "agencyid") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.targetagency, value);
            }

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
        }
    }

    return 0;
}



static int parse_ipintercept_list(ipintercept_t **ipints, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;
    int i;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        ipintercept_t *newcept;
        yaml_node_pair_t *pair;

        /* Each sequence item is a new intercept */
        newcept = (ipintercept_t *)malloc(sizeof(ipintercept_t));

        newcept->common.liid = NULL;
        newcept->common.authcc = NULL;
        newcept->common.delivcc = NULL;
        newcept->username = NULL;
        newcept->common.destid = 0;
        newcept->common.targetagency = NULL;
        newcept->awaitingconfirm = 1;
        newcept->common.liid_len = 0;
        newcept->username_len = 0;
        newcept->common.authcc_len = 0;
        newcept->common.delivcc_len = 0;
        newcept->alushimid = OPENLI_ALUSHIM_NONE;
        newcept->accesstype = INTERNET_ACCESS_TYPE_UNDEFINED; 
        newcept->statics = NULL;

        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "liid") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.liid, value);
                newcept->common.liid_len = strlen(newcept->common.liid);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "authcountrycode") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.authcc, value);
                newcept->common.authcc_len = strlen(newcept->common.authcc);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SEQUENCE_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "staticips") == 0) {
                add_intercept_static_ips(&(newcept->statics), doc, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "deliverycountrycode") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.delivcc, value);
                newcept->common.delivcc_len = strlen(newcept->common.delivcc);
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
                newcept->alushimid = strtoul((char *)value->data.scalar.value,
                        NULL, 10);
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
                    strcmp((char *)key->data.scalar.value, "mediator") == 0
                    && newcept->common.destid == 0) {
                newcept->common.destid = strtoul((char *)value->data.scalar.value,
                        NULL, 10);
                if (newcept->common.destid == 0) {
                    logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'mediator' config option.");
                }
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "agencyid") == 0) {
                SET_CONFIG_STRING_OPTION(newcept->common.targetagency, value);
            }

        }

        if (newcept->common.liid != NULL && newcept->common.authcc != NULL &&
                newcept->common.delivcc != NULL &&
                (newcept->username != NULL ||
                 newcept->alushimid != OPENLI_ALUSHIM_NONE ||
                 newcept->statics != NULL) &&
                newcept->common.destid > 0 &&
                newcept->common.targetagency != NULL) {
            HASH_ADD_KEYPTR(hh_liid, *ipints, newcept->common.liid,
                    newcept->common.liid_len, newcept);

            if (newcept->username && newcept->statics) {
                logger(LOG_INFO, "OpenLI: IP intercept %s specifies both a username and a set of static IPs -- is this intentional?");
            }
        } else {
            logger(LOG_INFO, "OpenLI: IP Intercept configuration was incomplete -- skipping.");
        }
    }

    return 0;
}

static int yaml_parser(char *configfile, void *arg,
        int (*parse_mapping)(void *, yaml_document_t *, yaml_node_t *,
                yaml_node_t *)) {
    FILE *in = NULL;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    int ret = -1;

    if ((in = fopen(configfile, "r")) == NULL) {
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
        logger(LOG_INFO, "OpenLI: Config file is empty!");
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
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "alumirrors") == 0) {
        if (parse_core_server_list(&glob->alumirrors,
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
        SET_CONFIG_STRING_OPTION(state->provport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisioneraddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->provaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "pcapdirectory") == 0) {
        SET_CONFIG_STRING_OPTION(state->pcapdirectory, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "operatorid") == 0) {
        SET_CONFIG_STRING_OPTION(state->operatorid, value);
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
            strcmp((char *)key->data.scalar.value, "pcaprotatefreq") == 0) {
        state->pcaprotatefreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->pcaprotatefreq == 0) {
            logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'pcaprotatefreq' config option.");
            return -1;
        }
    }

    return 0;

}

static int provisioning_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {

    provision_state_t *state = (provision_state_t *)arg;

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
            strcmp((char *)key->data.scalar.value, "agencies") == 0) {
        if (parse_agency_list(state, doc, value) == -1) {
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
            strcmp((char *)key->data.scalar.value, "sipservers") == 0) {
        if (parse_core_server_list(&state->sipservers,
                OPENLI_CORE_SERVER_SIP, doc, value) == -1) {
            return -1;
        }
    }

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
    return 0;
}

int parse_collector_config(char *configfile, collector_global_t *glob) {
    return yaml_parser(configfile, glob, global_parser);
}

int parse_provisioning_config(char *configfile, provision_state_t *state) {

    return yaml_parser(configfile, state, provisioning_parser);
}

int parse_mediator_config(char *configfile, mediator_state_t *state) {
    return yaml_parser(configfile, state, mediator_parser);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
