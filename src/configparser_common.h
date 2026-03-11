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

#ifndef OPENLI_CONFIGPARSER_COMMON_H_
#define OPENLI_CONFIGPARSER_COMMON_H_

#include <string.h>
#include <stdint.h>
#include <yaml.h>

#include "util.h"
#include "logger.h"
#include "agency.h"
#include "coreserver.h"


#define AES_ENCRYPT_ITERATIONS 10000

#define SET_CONFIG_STRING_OPTION(optname, yamlval) \
    if (optname) { \
        free(optname); \
    } \
    optname = strdup((char *)yamlval->data.scalar.value);

int config_yaml_parser(char *configfile, void *arg,
        int (*parse_mapping)(void *, yaml_document_t *, yaml_node_t *,
                yaml_node_t *), int createifmissing, const char *encpassfile);
int config_check_onoff(char *value);
int config_parse_uuid(char *srcvalue, uuid_t dest);
int parse_core_server_list(coreserver_t **servlist, uint8_t cstype,
        yaml_document_t *doc, yaml_node_t *inputs);

int openli_is_valid_aes192_hex_key(const char *key_str);     // 0x + 48 hex?
int openli_hex_to_bytes_24(const char *key_str, uint8_t out[24]);

#endif
