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
#include <json-c/json.h>

#include "configparser_common.h"
#include "configparser_mediator.h"

char *mediator_config_to_json(mediator_state_t *state) {

    json_object *jobj = json_object_new_object();
    json_object *jags = json_object_new_object();
    const char *json_str;
    char *result;
    lea_thread_state_t *lea, *ltmp;
    int agency_total = 0;

    json_object_object_add(jobj, "mediatorid",
            json_object_new_int(state->mediatorid));

    if (state->operatorid) {
        json_object_object_add(jobj, "operatorid",
                json_object_new_string(state->operatorid));
    }

    if (state->shortoperatorid) {
        json_object_object_add(jobj, "shortoperatorid",
                json_object_new_string(state->shortoperatorid));
    }

    json_object_object_add(jobj, "etsitls",
            json_object_new_boolean(state->etsitls != 0));
    json_object_object_add(jobj, "etsitls_certset",
            json_object_new_boolean(state->sslconf.certfile &&
                    state->sslconf.keyfile));

    if (state->pcapdirectory) {
        json_object_object_add(jobj, "pcapdirectory",
                json_object_new_string(state->pcapdirectory));
    }

    if (state->pcaptemplate) {
        json_object_object_add(jobj, "pcaptemplate",
                json_object_new_string(state->pcaptemplate));
    }

    json_object_object_add(jobj, "pcaprotatefreq",
            json_object_new_int64(state->pcaprotatefreq));

    json_object_object_add(jobj, "pcapcompress",
            json_object_new_int(state->pcapcompress));

    json_object_object_add(jobj, "RMQenabled",
            json_object_new_boolean(state->RMQ_conf.enabled));
    if (state->RMQ_conf.name) {
        json_object_object_add(jobj, "RMQname",
                json_object_new_string(state->RMQ_conf.name));
    }
    if (state->RMQ_conf.hostname) {
        json_object_object_add(jobj, "RMQhostname",
                json_object_new_string(state->RMQ_conf.hostname));
    }
    if (state->RMQ_conf.port) {
        json_object_object_add(jobj, "RMQport",
                json_object_new_int(state->RMQ_conf.port));
    }
    json_object_object_add(jobj, "RMQpassset",
            json_object_new_boolean(state->RMQ_conf.pass != NULL));
    json_object_object_add(jobj, "RMQSSLenabled",
            json_object_new_boolean(state->RMQ_conf.SSLenabled != 0));
    json_object_object_add(jobj, "RMQheartbeatfreq",
            json_object_new_int(state->RMQ_conf.heartbeatFreq));

    HASH_ITER(hh, state->agency_threads.threads, lea, ltmp) {
        json_object *jagency;
        openli_dest_conn_state_t st;
        const char *status_str;

        if (strcmp(lea->agencyid, "pcapdisk") == 0) {
            continue;
        }
        agency_total ++;

        jagency = json_object_new_object();
        if (lea->agency.hi2) {
            st = __atomic_load_n(&(lea->agency.hi2->status), __ATOMIC_ACQUIRE);
            if (st == OPENLI_DEST_STATE_CONNECTED) {
                status_str = "connected";
            } else if (st == OPENLI_DEST_STATE_DISCONNECTED) {
                status_str = "disconnected";
            } else {
                status_str = "failed";
            }
            json_object_object_add(jagency, "hi2_status",
                    json_object_new_string(status_str));
            if (st != OPENLI_DEST_STATE_CONNECTED &&
                    lea->agency.hi2->lasterror[0] != '\0') {
                json_object_object_add(jagency, "hi2_error",
                        json_object_new_string(lea->agency.hi2->lasterror));
            }
        }

        if (lea->agency.hi3) {
            st = __atomic_load_n(&(lea->agency.hi3->status), __ATOMIC_ACQUIRE);
            if (st == OPENLI_DEST_STATE_CONNECTED) {
                status_str = "connected";
            } else if (st == OPENLI_DEST_STATE_DISCONNECTED) {
                status_str = "disconnected";
            } else {
                status_str = "failed";
            }
            json_object_object_add(jagency, "hi3_status",
                    json_object_new_string(status_str));
            if (st != OPENLI_DEST_STATE_CONNECTED &&
                    lea->agency.hi3->lasterror[0] != '\0') {
                json_object_object_add(jagency, "hi3_error",
                        json_object_new_string(lea->agency.hi3->lasterror));
            }
        }

        json_object_object_add(jags, lea->agencyid, jagency);
    }
    json_object_object_add(jobj, "handover_status", jags);
    json_object_object_add(jobj, "total_leas",
            json_object_new_int(agency_total));

    json_str = json_object_to_json_string(jobj);
    result = strdup(json_str);
    json_object_put(jobj);
    return result;

}

static int mediator_parser(void *arg, yaml_document_t *doc UNUSED,
        yaml_node_t *key, yaml_node_t *value) {

    mediator_state_t *state = (mediator_state_t *)arg;
    char *keyname = (char *)key->data.scalar.value;

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "listenport") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "listenaddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->listenaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "provisionerport") == 0) {
        SET_CONFIG_STRING_OPTION(state->provisioner.provport, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "provisioneraddr") == 0) {
        SET_CONFIG_STRING_OPTION(state->provisioner.provaddr, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "pcapdirectory") == 0) {
        SET_CONFIG_STRING_OPTION(state->pcapdirectory, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "pcapfilename") == 0) {
        SET_CONFIG_STRING_OPTION(state->pcaptemplate, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "operatorid") == 0) {
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
            strcasecmp(keyname, "altoperatorid") == 0) {
        SET_CONFIG_STRING_OPTION(state->shortoperatorid, value);

        /* 5 chars max allowed for this field (defined in ETSI HI2 spec) */
        if (strlen(state->shortoperatorid) > 5) {
            state->shortoperatorid[5] = '\0';
            logger(LOG_INFO, "OpenLI: warning, 'altoperatorid' must be no longer than 5 characters -- truncated to %s", state->shortoperatorid);
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "mediatorid") == 0) {
        state->mediatorid = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->mediatorid == 0) {
            logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'mediatorid' config option.");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "pcapcompress") == 0) {
        state->pcapcompress = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->pcapcompress > 9) {
            logger(LOG_INFO, "OpenLI: maximum pcap compression level is 9, setting to that instead.");
            state->pcapcompress = 9;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "pcaprotatefreq") == 0) {
        state->pcaprotatefreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
        if (state->pcaprotatefreq == 0) {
            logger(LOG_INFO, "OpenLI: 0 is not a valid value for the 'pcaprotatefreq' config option.");
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "tlscert") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.certfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "tlskey") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.keyfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "tlsca") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.cacertfile, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "tlsgroups") == 0) {
        SET_CONFIG_STRING_OPTION(state->sslconf.tlsgroups, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "etsitls") == 0) {
            state->etsitls = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "RMQname") == 0) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.name, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "RMQpass") == 0) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.pass, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            (strcasecmp(keyname, "RMQlocalpass") == 0 ||
             strcasecmp(keyname, "RMQinternalpass") == 0)) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.internalpass, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "RMQhostname") == 0) {
        SET_CONFIG_STRING_OPTION(state->RMQ_conf.hostname, value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "RMQheartbeatfreq") == 0) {
        state->RMQ_conf.heartbeatFreq = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "RMQenabled") == 0) {
        state->RMQ_conf.enabled = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "RMQSSL") == 0) {
        state->RMQ_conf.SSLenabled = config_check_onoff((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE &&
            value->type == YAML_SCALAR_NODE &&
            strcasecmp(keyname, "RMQport") == 0) {
        state->RMQ_conf.port = strtoul((char *)value->data.scalar.value,
                NULL, 10);
    }

    return 0;

}

int parse_mediator_config(char *configfile, mediator_state_t *state) {
    return config_yaml_parser(configfile, state, mediator_parser, 0, NULL);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
