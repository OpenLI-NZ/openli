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

#ifndef OPENLI_CONFIGPARSER_H_
#define OPENLI_CONFIGPARSER_H_

#include "collector/collector.h"
#include "provisioner/provisioner.h"
#include "mediator/mediator.h"
#include <yaml.h>

int parse_intercept_config(char *configfile, prov_intercept_conf_t *conf);
int parse_collector_config(char *configfile, collector_global_t *glob);
int parse_provisioning_config(char *configfile, provision_state_t *state);
int parse_mediator_config(char *configfile, mediator_state_t *state);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
