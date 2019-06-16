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

#include <yaml.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "logger.h"
#include "agency.h"
#include "coreserver.h"
#include "provisioner.h"

static int emit_core_server_list(coreserver_t *servers, const char *label,
        yaml_emitter_t *emitter) {

    return 0;
}

static int emit_agencies(prov_agency_t *agencies, yaml_emitter_t *emitter) {

    return 0;
}

static int emit_voipintercepts(voipintercept_t *vints, yaml_emitter_t *emitter) 
{

    return 0;
}

static int emit_ipintercepts(ipintercept_t *ipints, yaml_emitter_t *emitter) {

    return 0;
}



int emit_intercept_config(char *configfile, prov_intercept_conf_t *conf) {

    yaml_emitter_t emitter;
    yaml_event_t event;
    FILE *f;

    f = fopen(configfile, "w");
    if (ferror(f)) {
        logger(LOG_INFO, "OpenLI: unable to open config file '%s' to write updated intercept config: %s", configfile, strerror(errno));
        return -1;
    }

    /* TODO write warning comments to not edit the file manually */

    yaml_emitter_initialize(&emitter);
    yaml_emitter_set_output_file(&emitter, f);

    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    if (emit_core_server_list(conf->sipservers, "sipservers", &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->radiusservers, "radiusservers",
            &emitter) < 0) {
        goto error;
    }

    if (emit_agencies(conf->leas, &emitter) < 0) {
        goto error;
    }

    if (emit_voipintercepts(conf->voipintercepts, &emitter) < 0) {
        goto error;
    }

    if (emit_ipintercepts(conf->ipintercepts, &emitter) < 0) {
        goto error;
    }

    yaml_document_end_event_initialize(&event, 0);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_emitter_delete(&emitter);
    if (f) {
        fclose(f);
    }
    return 0;

error:
    logger(LOG_INFO, "OpenLI: error while emitting intercept config: %s",
            emitter.problem);
    yaml_emitter_delete(&emitter);
    if (f) {
        fclose(f);
    }
    return -1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
