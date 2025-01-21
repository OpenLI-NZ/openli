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

#include "configparser_common.h"
#include "configparser_mediator.h"

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
    return config_yaml_parser(configfile, state, mediator_parser, 0);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
