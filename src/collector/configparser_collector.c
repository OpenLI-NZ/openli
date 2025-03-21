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

#include "configparser_collector.h"
#include "configparser_common.h"
#include "collector/x2x3_ingest.h"

static int parse_x2x3_ingestion_config(collector_global_t *glob,
        yaml_document_t *doc, yaml_node_t *ingests) {

    yaml_node_item_t *item;
    for (item = ingests->data.sequence.items.start;
            item != ingests->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        x_input_t *inp, *found;
        yaml_node_pair_t *pair;
        char identifier[512];

        inp = calloc(1, sizeof(x_input_t));
        inp->use_tls = 1;
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "listenaddr") == 0) {
                SET_CONFIG_STRING_OPTION(inp->listenaddr, value);
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "listenport") == 0) {
                SET_CONFIG_STRING_OPTION(inp->listenport, value);
            }
            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                            "disable_tls") == 0) {
                if (config_check_onoff((char *)value->data.scalar.value) == 0) {
                    inp->use_tls = 1;
                } else {
                    inp->use_tls = 0;
                }
            }
        }

        if (inp->listenaddr == NULL) {
            logger(LOG_INFO,
                    "OpenLI: X2-X3 input must include a 'listenaddr' parameter");
            destroy_x_input(inp);
            continue;
        }

        if (inp->listenport == NULL) {
            logger(LOG_INFO,
                    "OpenLI: X2-X3 input must include a 'listenport' parameter");
            destroy_x_input(inp);
            continue;
        }

        snprintf(identifier, 512, "%s-%s", inp->listenaddr, inp->listenport);
        HASH_FIND(hh, glob->x_inputs, identifier, strlen(identifier), found);
        if (found) {
            logger(LOG_INFO,
                    "OpenLI: X2-X3 input '%s' has been defined multiple times",
                    identifier);
            destroy_x_input(inp);
        } else {
            inp->identifier = strdup(identifier);
            HASH_ADD_KEYPTR(hh, glob->x_inputs, inp->identifier,
                    strlen(inp->identifier), inp);
        };
    }
    return 0;
}

static int parse_input_config(collector_global_t *glob, yaml_document_t *doc,
        yaml_node_t *inputs) {

    yaml_node_item_t *item;
    colinput_t *inp = NULL;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        /* Each sequence item is a new input */
        inp = (colinput_t *)calloc(1, sizeof(colinput_t));
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
    	inp->coremap = NULL;

        /* Mappings describe the parameters for each input */
        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "uri") == 0) {
                SET_CONFIG_STRING_OPTION(inp->uri, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "filter") == 0) {
                SET_CONFIG_STRING_OPTION(inp->filterstring, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
			    "coremap") == 0) {
                SET_CONFIG_STRING_OPTION(inp->coremap, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value,
                        "reportdrops") == 0) {
                if (config_check_onoff((char *)value->data.scalar.value) == 0) {
                    inp->report_drops = 0;
                } else {
                    inp->report_drops = 1;
                }
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "threads") == 0) {
                inp->threadcount = strtoul(
                        (char *)value->data.scalar.value, NULL, 10);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "hasher") == 0) {
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
            if (inp->filterstring) {
                free(inp->filterstring);
            }
            if (inp->coremap) {
                free(inp->coremap);
            }
            free(inp);
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
                strcasecmp((char *)key->data.scalar.value, "enabled") == 0) {
            glob->emailconf.enabled =
                    config_check_onoff((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcasecmp((char *)key->data.scalar.value, "requiretls") == 0) {
            glob->emailconf.tlsrequired =
                    config_check_onoff((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcasecmp((char *)key->data.scalar.value, "authpassword") == 0) {
            glob->emailconf.authrequired = true;
            SET_CONFIG_STRING_OPTION(glob->emailconf.authpassword, value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcasecmp((char *)key->data.scalar.value, "listenaddress") == 0) {
            SET_CONFIG_STRING_OPTION(glob->emailconf.listenaddr, value);
        }

        if (key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SCALAR_NODE &&
                strcasecmp((char *)key->data.scalar.value, "listenport") == 0) {
            SET_CONFIG_STRING_OPTION(glob->emailconf.listenport, value);
        }
    }

    return 0;
}

static int parse_email_forwarding_headers(collector_global_t *glob,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {

        yaml_node_t *node = yaml_document_get_node(doc, *item);
        if (node->type != YAML_SCALAR_NODE) {
            continue;
        }

        if (add_to_string_set(&(glob->email_forwarding_headers),
                (char *)(node->data.scalar.value)) == -1) {

            logger(LOG_INFO, "OpenLI: error while parsing emailforwardingheaders configuration for collector");
            return -1;
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

static void parse_col_thread_count(int *toset, const char *expectedkey,
        yaml_node_t *key, yaml_node_t *value, const char *errlabel, int min) {

    if (key->type != YAML_SCALAR_NODE) {
        return;
    }
    if (value->type != YAML_SCALAR_NODE) {
        return;
    }

    if (strcasecmp(expectedkey, (const char *)key->data.scalar.value) != 0) {
        return;
    }

    *toset = strtoul((const char *)value->data.scalar.value, NULL, 10);
    if (*toset < min) {
        *toset = min;
        logger(LOG_INFO,
                "OpenLI: must have at least %s %s thread per collector!",
                min, errlabel);
    }
}

static int collector_parser(void *arg, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value) {
    collector_global_t *glob = (collector_global_t *)arg;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "inputs") == 0) {
        if (parse_input_config(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "x2x3inputs") == 0) {
        if (parse_x2x3_ingestion_config(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "operatorid") == 0) {
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
            strcasecmp((char *)key->data.scalar.value, "networkelementid")
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
            strcasecmp((char *)key->data.scalar.value, "interceptpointid")
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
            strcasecmp((char *)key->data.scalar.value, "provisionerport") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sharedinfo.provisionerport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "provisioneraddr") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sharedinfo.provisionerip, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "sipdebugfile") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sipdebugfile, value);
    }


    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_MAPPING_NODE &&
            strcasecmp((char *)key->data.scalar.value, "emailingest") == 0) {
        if (parse_email_ingest_config(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "alumirrors") == 0) {
        if (parse_core_server_list(&glob->alumirrors,
                OPENLI_CORE_SERVER_ALUMIRROR, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "jmirrors") == 0) {
        if (parse_core_server_list(&glob->jmirrors,
                OPENLI_CORE_SERVER_ALUMIRROR, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "ciscomirrors") == 0) {
        if (parse_core_server_list(&glob->ciscomirrors,
                OPENLI_CORE_SERVER_ALUMIRROR, doc, value) == -1) {
            return -1;
        }
    }

    parse_col_thread_count(&(glob->encoding_threads), "seqtrackerthreads",
            key, value, "sequence tracker", 1);
    parse_col_thread_count(&(glob->encoding_threads), "encoderthreads",
            key, value, "encoder", 1);
    parse_col_thread_count(&(glob->forwarding_threads), "forwardingthreads",
            key, value, "forwarding", 1);
    parse_col_thread_count(&(glob->email_threads), "emailthreads",
            key, value, "email worker", 0);
    parse_col_thread_count(&(glob->gtp_threads), "gtpthreads",
            key, value, "GTP worker", 0);
    parse_col_thread_count(&(glob->sip_threads), "smsthreads",
            key, value, "SIP worker", 1);
    parse_col_thread_count(&(glob->sip_threads), "sipthreads",
            key, value, "SIP worker", 1);

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "logstatfrequency") == 0) {
        glob->stat_frequency = strtoul((char *) value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "tlscert") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sslconf.certfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "tlskey") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sslconf.keyfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "tlsca") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sslconf.cacertfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "tlskeylogfile") == 0) {
        SET_CONFIG_STRING_OPTION(glob->sslconf.logkeyfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "etsitls") == 0) {
        glob->etsitls = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "sipignoresdpo") == 0) {
        glob->ignore_sdpo_matches = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "encoding") == 0) {

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

       glob->sharedinfo.trust_sip_from =
                config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "SIPdisableredirect") == 0) {

       glob->sharedinfo.disable_sip_redirect =
                config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "maskimapcreds") == 0) {

       glob->mask_imap_creds = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "maskpop3creds") == 0) {

       glob->mask_pop3_creds = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "emailingest-usetargetid") == 0) {

       glob->email_ingest_use_targetid =
            config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "cisconoradius") == 0) {

       glob->sharedinfo.cisco_noradius =
                config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value,
                    "emailsessiontimeouts") == 0) {
        if (parse_email_timeouts_config(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "defaultemaildomain") == 0) {
        SET_CONFIG_STRING_OPTION(glob->default_email_domain, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SEQUENCE_NODE &&
            strcasecmp((char *)key->data.scalar.value, "emailforwardingheaders")
                    == 0) {
        if (parse_email_forwarding_headers(glob, doc, value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "RMQname") == 0) {
        SET_CONFIG_STRING_OPTION(glob->RMQ_conf.name, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "RMQpass") == 0) {
        SET_CONFIG_STRING_OPTION(glob->RMQ_conf.pass, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "RMQhostname") == 0) {
        SET_CONFIG_STRING_OPTION(glob->RMQ_conf.hostname, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "RMQheartbeatfreq") == 0) {
        glob->RMQ_conf.heartbeatFreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "RMQenabled") == 0) {
        glob->RMQ_conf.enabled = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp((char *)key->data.scalar.value, "RMQport") == 0) {
        glob->RMQ_conf.port = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }
    return 0;
}

int parse_collector_config(char *configfile, collector_global_t *glob) {
    return config_yaml_parser(configfile, glob, collector_parser, 0, NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
