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

#include <assert.h>
#include <libtrace_parallel.h>
#include <pthread.h>
#include <Judy.h>

#include "ipiri.h"
#include "logger.h"
#include "internetaccess.h"
#include "util.h"

static void gtp_init_plugin_data(access_plugin_t *p) {

}

static void gtp_destroy_plugin_data(access_plugin_t *p) {

}

static void gtp_uncouple_parsed_data(access_plugin_t *p) {

}

static void gtp_destroy_parsed_data(access_plugin_t *p, void *parsed) {

}

static void *gtp_parse_packet(access_plugin_t *p, libtrace_packet_t *pkt) {

    return NULL;
}

static char *gtp_get_userid(access_plugin_t *p, void *parsed,
        int *useridlen) {
    return NULL;
}

static access_session_t *gtp_update_session_state(access_plugin_t *p,
        void *parsed, access_session_t **sesslist,
        session_state_t *oldstate, session_state_t *newstate,
        access_action_t *action) {

    return NULL;
}

static int gtp_generate_iri_data(access_plugin_t *p, void *parseddata,
        etsili_generic_t **params, etsili_iri_type_t *iritype,
        etsili_generic_freelist_t *freelist, int iteration) {

    return -1;
}

static void gtp_destroy_session_data(access_plugin_t *p,
        access_session_t *sess) {

}

static access_plugin_t gtpplugin = {

    "GTP",
    ACCESS_GTP,
    NULL,

    gtp_init_plugin_data,
    gtp_destroy_plugin_data,
    gtp_parse_packet,
    gtp_destroy_parsed_data,
    gtp_uncouple_parsed_data,
    gtp_get_userid,
    gtp_update_session_state,
    gtp_generate_iri_data,
    gtp_destroy_session_data
};

access_plugin_t *get_gtp_access_plugin(void) {
    return &gtpplugin;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :


