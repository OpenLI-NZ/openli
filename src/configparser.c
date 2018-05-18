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

#include "configparser.h"
#include "logger.h"
#include "provisioner.h"
#include "mediator.h"
#include "agency.h"
#include "coreserver.h"

uint64_t nextid = 0;

void clear_input(colinput_t *input) {

    if (!input) {
        return;
    }
    if (input->trace) {
        trace_destroy(input->trace);
    }
    if (input->pktcbs) {
        trace_destroy_callback_set(input->pktcbs);
    }
    if (input->uri) {
        free(input->uri);
    }
}

void clear_global_config(collector_global_t *glob) {
    colinput_t *inp, *tmp;

    HASH_ITER(hh, glob->inputs, inp, tmp) {
        HASH_DELETE(hh, glob->inputs, inp);
        clear_input(inp);
        free(inp);
    }

    free_coreserver_list(glob->alumirrors);

    if (glob->syncsendqs) {
        free(glob->syncsendqs);
    }

    if (glob->syncepollevs) {
        free(glob->syncepollevs);
    }

    if (glob->operatorid) {
        free(glob->operatorid);
    }

    if (glob->networkelemid) {
        free(glob->networkelemid);
    }

    if (glob->intpointid) {
        free(glob->intpointid);
    }

    if (glob->provisionerip) {
        free(glob->provisionerip);
    }

    if (glob->provisionerport) {
        free(glob->provisionerport);
    }

    if (glob->expired_inputs) {
        libtrace_list_node_t *n;
        n = glob->expired_inputs->head;
        while (n) {
            inp = *((colinput_t **)(n->data));
            clear_input(inp);
            free(inp);
            n = n->next;
        }
        libtrace_list_deinit(glob->expired_inputs);
    }

    pthread_rwlock_destroy(&glob->config_mutex);
    pthread_mutex_destroy(&glob->syncq_mutex);
    pthread_mutex_destroy(&glob->exportq_mutex);

    if (glob->sync_epollfd != -1) {
        close(glob->sync_epollfd);
    }

    if (glob->export_epollfd != -1) {
        close(glob->export_epollfd);
    }

    free(glob);
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

        /* Mappings describe the parameters for each input */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "uri") == 0 &&
                    inp->uri == NULL) {
                inp->uri = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "threads") == 0) {
                inp->threadcount = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }
        }
        glob->totalthreads += inp->threadcount;
        if (!inp->uri) {
            logger(LOG_DAEMON, "OpenLI collector: input is missing a URI?");
            continue;
        }
        HASH_ADD_KEYPTR(hh, glob->inputs, inp->uri, strlen(inp->uri), inp);
    }

    /*
    glob->syncsendqs = (libtrace_message_queue_t **)malloc(
            sizeof(libtrace_message_queue_t *) * glob->totalthreads);
    memset(glob->syncsendqs, 0,
            sizeof(libtrace_message_queue_t *) * glob->totalthreads);
    glob->syncepollevs = (void **)malloc(sizeof(void *) * glob->totalthreads);
    memset(glob->syncepollevs, 0, sizeof(void *) * glob->totalthreads);
    glob->queuealloced = glob->totalthreads;
    glob->registered_syncqs = 0;
    */

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
                    strcmp((char *)key->data.scalar.value, "ip") == 0 &&
                    cs->ipstr == NULL) {
                cs->ipstr = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "port") == 0 &&
                    cs->portstr == NULL) {
                cs->portstr = strdup((char *)value->data.scalar.value);
            }
        }

        if (construct_coreserver_key(cs) != NULL) {
            HASH_ADD_KEYPTR(hh, *servlist, cs->serverkey,
                    strlen(cs->serverkey), cs);
        } else {
            logger(LOG_DAEMON,
                    "OpenLI: %s server configuration was incomplete -- skipping.",
                    coreserver_type_to_string(cstype));
            free_single_coreserver(cs);
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

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi2address") == 0 && newag->hi2_ipstr == NULL) {
                newag->hi2_ipstr = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi2port") == 0 && newag->hi2_portstr == NULL) {
                newag->hi2_portstr = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi3address") == 0 && newag->hi3_ipstr == NULL) {
                newag->hi3_ipstr = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "hi3port") == 0 && newag->hi3_portstr == NULL) {
                newag->hi3_portstr = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "agencyid") == 0 && newag->agencyid == NULL) {
                newag->agencyid = strdup((char *)value->data.scalar.value);
            }

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
            logger(LOG_DAEMON, "OpenLI: LEA configuration was incomplete -- skipping.");
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
        newcept->cin_callid_map = NULL;
        newcept->cin_sdp_map = NULL;
        newcept->sipuri = NULL;
        newcept->active = 1;
        newcept->common.destid = 0;
        newcept->common.targetagency = NULL;
        newcept->awaitingconfirm = 1;


        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "liid") == 0 &&
                    newcept->common.liid == NULL) {
                newcept->common.liid = strdup((char *)value->data.scalar.value);
                newcept->common.liid_len = strlen(newcept->common.liid);
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                        "authcountrycode") == 0 &&
                    newcept->common.authcc == NULL) {
                newcept->common.authcc = strdup((char *)value->data.scalar.value);
                newcept->common.authcc_len = strlen(newcept->common.authcc);
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                        "deliverycountrycode") == 0 &&
                    newcept->common.delivcc == NULL) {
                newcept->common.delivcc = strdup((char *)value->data.scalar.value);
                newcept->common.delivcc_len = strlen(newcept->common.delivcc);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "sipuri") == 0 &&
                    newcept->sipuri == NULL) {
                newcept->sipuri = strdup((char *)value->data.scalar.value);
                newcept->sipuri_len = strlen(newcept->sipuri);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "mediator") == 0
                    && newcept->common.destid == 0) {
                newcept->common.destid = strtoul((char *)value->data.scalar.value,
                        NULL, 10);
                if (newcept->common.destid == 0) {
                    logger(LOG_DAEMON, "OpenLI: 0 is not a valid value for the 'mediator' config option.");
                }
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "agencyid") == 0
                    && newcept->common.targetagency == NULL) {
                newcept->common.targetagency = strdup((char *)value->data.scalar.value);
            }

        }

        if (newcept->common.liid != NULL && newcept->common.authcc != NULL &&
                newcept->common.delivcc != NULL && newcept->sipuri != NULL &&
                newcept->common.destid > 0 &&
                newcept->common.targetagency != NULL) {
            HASH_ADD_KEYPTR(hh_liid, *voipints, newcept->common.liid,
                    newcept->common.liid_len, newcept);
        } else {
            logger(LOG_DAEMON, "OpenLI: VOIP Intercept configuration was incomplete -- skipping.");
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

        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "liid") == 0 &&
                    newcept->common.liid == NULL) {
                newcept->common.liid = strdup((char *)value->data.scalar.value);
                newcept->common.liid_len = strlen(newcept->common.liid);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "authcountrycode") == 0 &&
                    newcept->common.authcc == NULL) {
                newcept->common.authcc = strdup((char *)value->data.scalar.value);
                newcept->common.authcc_len = strlen(newcept->common.authcc);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "deliverycountrycode") == 0 &&
                    newcept->common.delivcc == NULL) {
                newcept->common.delivcc = strdup((char *)value->data.scalar.value);
                newcept->common.delivcc_len = strlen(newcept->common.delivcc);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "user") == 0 &&
                    newcept->username == NULL) {
                newcept->username = strdup((char *)value->data.scalar.value);
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
                    strcmp((char *)key->data.scalar.value, "mediator") == 0
                    && newcept->common.destid == 0) {
                newcept->common.destid = strtoul((char *)value->data.scalar.value,
                        NULL, 10);
                if (newcept->common.destid == 0) {
                    logger(LOG_DAEMON, "OpenLI: 0 is not a valid value for the 'mediator' config option.");
                }
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "agencyid") == 0
                    && newcept->common.targetagency == NULL) {
                newcept->common.targetagency = strdup((char *)value->data.scalar.value);
            }

        }

        if (newcept->common.liid != NULL && newcept->common.authcc != NULL &&
                newcept->common.delivcc != NULL &&
                (newcept->username != NULL ||
                 newcept->alushimid != OPENLI_ALUSHIM_NONE) &&
                newcept->common.destid > 0 &&
                newcept->common.targetagency != NULL) {
            HASH_ADD_KEYPTR(hh_liid, *ipints, newcept->common.liid, newcept->common.liid_len,
                    newcept);
        } else {
            logger(LOG_DAEMON, "OpenLI: IP Intercept configuration was incomplete -- skipping.");
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
        logger(LOG_DAEMON, "OpenLI: Failed to open config file: %s",
                strerror(errno));
        return -1;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

    if (!yaml_parser_load(&parser, &document)) {
        logger(LOG_DAEMON, "OpenLI: Malformed config file");
        goto yamlfail;
    }

    root = yaml_document_get_root_node(&document);
    if (!root) {
        logger(LOG_DAEMON, "OpenLI: Config file is empty!");
        goto endconfig;
    }

    if (root->type != YAML_MAPPING_NODE) {
        logger(LOG_DAEMON, "OpenLI: Top level of config should be a map");
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
            clear_global_config(glob);
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "operatorid") == 0) {
        glob->operatorid = strdup((char *) value->data.scalar.value);
        glob->operatorid_len = strlen(glob->operatorid);

        /* Limited to 16 chars */
        if (glob->operatorid_len > 16) {
            logger(LOG_DAEMON, "OpenLI: Operator ID must be 16 characters or less!");
            clear_global_config(glob);
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "networkelementid")
            == 0) {
        glob->networkelemid = strdup((char *) value->data.scalar.value);
        glob->networkelemid_len = strlen(glob->networkelemid);

        /* Limited to 16 chars */
        if (glob->networkelemid_len > 16) {
            logger(LOG_DAEMON, "OpenLI: Network Element ID must be 16 characters or less!");
            clear_global_config(glob);
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "interceptpointid")
            == 0) {
        glob->intpointid = strdup((char *) value->data.scalar.value);
        glob->intpointid_len = strlen(glob->intpointid);

        /* Limited to 8 chars */
        if (glob->intpointid_len > 8) {
            logger(LOG_DAEMON, "OpenLI: Intercept Point ID must be 8 characters or less!");
            clear_global_config(glob);
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisionerport") == 0) {
        glob->provisionerport = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisionerip") == 0) {
        glob->provisionerip = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcmp((char *)key->data.scalar.value, "alumirrors") == 0) {
        if (parse_core_server_list(&glob->alumirrors,
                OPENLI_CORE_SERVER_ALUMIRROR, doc, value) == -1) {
            return -1;
        }
    }

    return 0;
}

collector_global_t *parse_global_config(char *configfile) {

    collector_global_t *glob = NULL;

    glob = (collector_global_t *)malloc(sizeof(collector_global_t));

    glob->inputs = NULL;
    glob->totalthreads = 0;
    glob->queuealloced = 0;
    glob->registered_syncqs = 0;
    glob->syncsendqs = NULL;
    glob->syncepollevs = 0;
    glob->intpointid = NULL;
    glob->intpointid_len = 0;
    glob->operatorid = NULL;
    glob->operatorid_len = 0;
    glob->networkelemid = NULL;
    glob->networkelemid_len = 0;
    glob->syncthreadid = 0;
    glob->exportthreadid = 0;
    glob->sync_epollfd = epoll_create1(0);
    glob->export_epollfd = epoll_create1(0);
    glob->configfile = configfile;
    glob->export_epoll_evs = NULL;
    glob->provisionerip = NULL;
    glob->provisionerport = NULL;
    glob->alumirrors = NULL;
    glob->expired_inputs = libtrace_list_init(sizeof(colinput_t *));

    pthread_rwlock_init(&glob->config_mutex, NULL);
    pthread_mutex_init(&glob->syncq_mutex, NULL);
    pthread_mutex_init(&glob->exportq_mutex, NULL);

    if (yaml_parser(configfile, glob, global_parser) == -1) {
        return NULL;
    }

    if (glob->provisionerport == NULL) {
        glob->provisionerport = strdup("8993");
    }

    if (glob->networkelemid == NULL) {
        logger(LOG_DAEMON, "OpenLI: No network element ID specified in config file. Exiting.");
        clear_global_config(glob);
        glob = NULL;
    }

    else if (glob->operatorid == NULL) {
        logger(LOG_DAEMON, "OpenLI: No operator ID specified in config file. Exiting.");
        clear_global_config(glob);
        glob = NULL;
    }

    else if (glob->provisionerip == NULL) {
        logger(LOG_DAEMON, "OpenLI collector: no provisioner IP address specified in config file. Exiting.");
        clear_global_config(glob);
        glob = NULL;
    }

    return glob;

}

static int mediator_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {

    mediator_state_t *state = (mediator_state_t *)arg;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "listenport") == 0) {
        state->listenport = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "listenaddr") == 0) {
        state->listenaddr = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisionerport") == 0) {
        state->provport = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "provisioneraddr") == 0) {
        state->provaddr = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "mediatorid") == 0) {
        state->mediatorid = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->mediatorid == 0) {
            logger(LOG_DAEMON, "OpenLI: 0 is not a valid value for the 'mediatorid' config option.");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "keepalivefreq") == 0) {
        state->keepalivefreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->keepalivefreq == 0) {
            logger(LOG_DAEMON, "OpenLI: 0 is not a valid value for the 'keepalivefreq' config option.");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "keepalivewait") == 0) {
        state->keepalivewait = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->keepalivewait == 0) {
            logger(LOG_DAEMON, "OpenLI: 0 is not a valid value for the 'keepalivewait' config option.");
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
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "clientport") == 0) {
        state->listenport = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "clientaddr") == 0) {
        state->listenaddr = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "updateport") == 0) {
        state->pushport = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "updateaddr") == 0) {
        state->pushaddr = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "mediationport") == 0) {
        state->mediateport = strdup((char *) value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcmp((char *)key->data.scalar.value, "mediationaddr") == 0) {
        state->mediateaddr = strdup((char *) value->data.scalar.value);
    }
    return 0;
}

int parse_provisioning_config(char *configfile, provision_state_t *state) {

    return yaml_parser(configfile, state, provisioning_parser);
}

int parse_mediator_config(char *configfile, mediator_state_t *state) {
    return yaml_parser(configfile, state, mediator_parser);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
