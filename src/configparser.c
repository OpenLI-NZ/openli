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
 * GNU Lesser General Public License for more details.
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

#include "configparser.h"
#include "logger.h"
#include "collector_buffer.h"

void clear_global_config(collector_global_t *glob) {
        int i;

	if (glob->inputs) {
        for (i = 0; i < glob->inputcount; i++) {
            if (glob->inputs[i].config.uri) {
                free(glob->inputs[i].config.uri);
            }
            if (glob->inputs[i].trace) {
                trace_destroy(glob->inputs[i].trace);
            }
            if (glob->inputs[i].pktcbs) {
                trace_destroy_callback_set(glob->inputs[i].pktcbs);
            }
        }
        free(glob->inputs);
    }

    if (glob->syncsendqs) {
        free(glob->syncsendqs);
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

    pthread_mutex_destroy(&glob->syncq_mutex);
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
        if (glob->inputcount == glob->inputalloced) {
            if (glob->inputalloced == 0) {
                glob->inputs = (colinput_t *)malloc(sizeof(colinput_t) * 10);
                glob->inputalloced = 10;
            } else {
                glob->inputs = (colinput_t *)realloc(glob->inputs,
                        sizeof(colinput_t) * (10 + glob->inputalloced));
                glob->inputalloced += 10;
            }
        }

        inp = &(glob->inputs[glob->inputcount]);
        inp->config.uri = NULL;
        inp->config.threadcount = 1;
        inp->trace = NULL;
        inp->pktcbs = NULL;

        /* Mappings describe the parameters for each input */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "uri") == 0 &&
                    inp->config.uri == NULL) {
                inp->config.uri = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "threads") == 0) {
                inp->config.threadcount = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }
        }
        glob->inputcount ++;
        glob->totalthreads += inp->config.threadcount;
    }

    glob->syncsendqs = (libtrace_message_queue_t **)malloc(
            sizeof(libtrace_message_queue_t *) * glob->totalthreads);
    memset(glob->syncsendqs, 0,
            sizeof(libtrace_message_queue_t *) * glob->totalthreads);
    glob->queuealloced = glob->totalthreads;
    glob->registered_syncqs = 0;

    return 0;
}

static int parse_export_target_list(libtrace_list_t *targets,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;
    int i;
    uint64_t nextid = 0;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        export_dest_t dest;
        yaml_node_pair_t *pair;

        dest.details.ipstr = NULL;
        dest.details.portstr = NULL;
        dest.details.destid = 0;
        init_export_buffer(&(dest.buffer));
        dest.fd = -1;
        dest.failmsg = 0;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "address") == 0 && dest.details.ipstr == NULL) {
                dest.details.ipstr = strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "port") == 0 && dest.details.portstr == NULL) {
                dest.details.portstr =
                        strdup((char *)value->data.scalar.value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "destid") == 0) {
                dest.details.destid = strtoul((char *)value->data.scalar.value,
                        NULL, 10);
                if (dest.details.destid == 0) {
                    logger(LOG_DAEMON, "OpenLI: 0 is not a valid value for the 'destid' config option.");
                }
            }
        }

        if (dest.details.ipstr != NULL && dest.details.portstr != NULL &&
                    dest.details.destid > 0) {
            libtrace_list_push_front(targets, (void *)(&dest));
        } else {
            logger(LOG_DAEMON, "OpenLI: Export target configuration was incomplete -- skipping.");
        }
    }

    return 0;
}

static int parse_ipintercept_list(libtrace_list_t *ipints, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;
    int i;
    uint64_t nextid = 0;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        ipintercept_t newcept;
        yaml_node_pair_t *pair;
        char *addrstr;
        struct addrinfo *res = NULL;
        struct addrinfo hints;

        /* Each sequence item is a new intercept */
        newcept.internalid = nextid;
        nextid ++;

        newcept.liid = NULL;
        newcept.authcc = NULL;
        newcept.delivcc = NULL;
        newcept.cin = 0;
        newcept.ipaddr = NULL;
        newcept.ai_family = AF_UNSPEC;
        newcept.username = NULL;
        newcept.active = 1;
        newcept.destid = 0;

        /* Mappings describe the parameters for each intercept */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "ipaddr") == 0 &&
                    newcept.ipaddr == NULL) {
                addrstr = ((char *)value->data.scalar.value);

                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_UNSPEC;

                if (getaddrinfo(addrstr, NULL, &hints, &res) != 0) {
                    logger(LOG_DAEMON, "OpenLI: getaddrinfo cannot parse IP address %s: %s",
                            addrstr, strerror(errno));
                    continue;
                }

                newcept.ai_family = res->ai_family;
                newcept.ipaddr = (struct sockaddr_storage *)malloc(
                        sizeof(struct sockaddr_storage));
                memcpy(newcept.ipaddr, res->ai_addr, res->ai_addrlen);

                freeaddrinfo(res);
                res = NULL;
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "liid") == 0 &&
                    newcept.liid == NULL) {
                newcept.liid = strdup((char *)value->data.scalar.value);
                newcept.liid_len = strlen(newcept.liid);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "authcountrycode") == 0 &&
                    newcept.authcc == NULL) {
                newcept.authcc = strdup((char *)value->data.scalar.value);
                newcept.authcc_len = strlen(newcept.authcc);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value,
                            "deliverycountrycode") == 0 &&
                    newcept.delivcc == NULL) {
                newcept.delivcc = strdup((char *)value->data.scalar.value);
                newcept.delivcc_len = strlen(newcept.delivcc);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "user") == 0 &&
                    newcept.username == NULL) {
                newcept.username = strdup((char *)value->data.scalar.value);
                newcept.username_len = strlen(newcept.username);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "exportto") == 0) {
                newcept.destid = strtoul((char *)value->data.scalar.value,
                        NULL, 10);
                if (newcept.destid == 0) {
                    logger(LOG_DAEMON, "OpenLI: 0 is not a valid value for the 'exportto' config option.");
                }
            }

        }

        if (newcept.liid != NULL && newcept.authcc != NULL &&
                newcept.delivcc != NULL && newcept.ipaddr != NULL &&
                newcept.destid > 0) {
            libtrace_list_push_front(ipints, (void *)(&newcept));
        } else {
            logger(LOG_DAEMON, "OpenLI: IP Intercept configuration was incomplete -- skipping.");
        }
    }

    return 0;
}


/* TODO lots of duplicated code in the next 3 functions, replace with
 * something nicer?
 */

int parse_export_config(char *configfile, libtrace_list_t *exptargets) {

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

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SEQUENCE_NODE &&
                strcmp((char *)key->data.scalar.value, "exporttargets") == 0) {
            if (parse_export_target_list(exptargets, &document, value) == -1) {
                ret = -1;
                break;
            }
            ret = 0;
        }
    }

endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return ret;
}

int parse_ipintercept_config(char *configfile, libtrace_list_t *ipints) {

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

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SEQUENCE_NODE &&
                strcmp((char *)key->data.scalar.value, "ipintercepts") == 0) {
            if (parse_ipintercept_list(ipints, &document, value) == -1) {
                ret = -1;
                break;
            }
            ret = 0;
        }
    }

endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return ret;
}

collector_global_t *parse_global_config(char *configfile) {

    FILE *in = NULL;
    collector_global_t *glob = NULL;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;

    glob = (collector_global_t *)malloc(sizeof(collector_global_t));

    glob->inputcount = 0;
    glob->inputalloced = 0;
    glob->inputs = NULL;
    glob->totalthreads = 0;
    glob->queuealloced = 0;
    glob->registered_syncqs = 0;
    glob->syncsendqs = NULL;
    glob->intpointid = NULL;
    glob->intpointid_len = 0;
    glob->operatorid = NULL;
    glob->operatorid_len = 0;
    glob->networkelemid = NULL;
    glob->networkelemid_len = 0;
    glob->syncthreadid = 0;
    glob->exportthreadid = 0;
    glob->sync_epollfd = -1;
    glob->export_epollfd = -1;
    glob->configfile = configfile;
    glob->export_epoll_evs = NULL;

    pthread_mutex_init(&glob->syncq_mutex, NULL);

    if ((in = fopen(configfile, "r")) == NULL) {
        logger(LOG_DAEMON, "OpenLI: Failed to open config file: %s", strerror(errno));
        free(glob);
        return NULL;
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

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SEQUENCE_NODE &&
                strcmp((char *)key->data.scalar.value, "inputs") == 0) {
            if (parse_input_config(glob, &document, value) == -1) {
                clear_global_config(glob);
                glob = NULL;
                break;
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
                glob = NULL;
                break;
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
                glob = NULL;
                break;
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
                glob = NULL;
                break;
            }
        }
    }

    if (glob->networkelemid == NULL) {
        logger(LOG_DAEMON, "OpenLI: No network element ID specified in config file. Exiting.\n");
        clear_global_config(glob);
        glob = NULL;
    }

    if (glob->operatorid == NULL) {
        logger(LOG_DAEMON, "OpenLI: No operator ID specified in config file. Exiting.\n");
        clear_global_config(glob);
        glob = NULL;
    }

endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return glob;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
