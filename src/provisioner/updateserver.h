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

#ifndef OPENLI_PROV_UPDATESERVER_H_
#define OPENLI_PROV_UPDATESERVER_H_

#include <json-c/json.h>
#include <microhttpd.h>
#include "provisioner.h"

typedef struct con_info {
    int connectiontype;
    int answercode;
    char answerstring[4096];
    const char *content_type;

    int target;
    char *jsonbuffer;
    int jsonlen;

} update_con_info_t;

enum {
    TARGET_AGENCY,
    TARGET_SIPSERVER,
    TARGET_RADIUSSERVER,
    TARGET_IPINTERCEPT,
    TARGET_VOIPINTERCEPT,
    TARGET_GTPSERVER,
    TARGET_DEFAULTRADIUS,
};

static const char *update_success_page =
        "<html><body>OpenLI provisioner configuration was successfully updated.</body></html>\n";

static const char *update_failure_page_start =
        "<html><body><p>OpenLI provisioner configuration failed.";
static const char *update_failure_page_end = "</body></html>\n";

static const char *get_not_implemented =
        "<html><body>OpenLI provisioner does not support fetching intercept config (yet).</body></html>\n";

static const char *auth_failed =
        "<html><body>Authentication failed</body></html>\n";

static const char *unsupported_operation =
        "<html><body>OpenLI provisioner does not support that type of request.</body></html>\n";

static const char *get404 =
        "<html><body>OpenLI provisioner was unable to find the requested resource in its running intercept configuration.</body></html>\n";

int handle_update_request(void *cls, struct MHD_Connection *conn,
        const char *url, const char *method, const char *version,
        const char *upload_data, size_t *upload_data_size,
        void **con_cls);

void complete_update_request(void *cls, struct MHD_Connection *conn,
        void **con_cls, enum MHD_RequestTerminationCode toe);


int init_restauth_db(provision_state_t *state);
void close_restauth_db(provision_state_t *state);

int remove_agency(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr);
int remove_coreserver(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr, uint8_t srvtype);
int remove_defaultradius(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr);
int remove_ip_intercept(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr);
int remove_voip_intercept(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr);

int add_new_agency(update_con_info_t *cinfo, provision_state_t *state);
int add_new_defaultradius(update_con_info_t *cinfo, provision_state_t *state);
int add_new_voipintercept(update_con_info_t *cinfo, provision_state_t *state);
int add_new_ipintercept(update_con_info_t *cinfo, provision_state_t *state);
int add_new_coreserver(update_con_info_t *cinfo, provision_state_t *state,
        uint8_t srvtype);

int modify_agency(update_con_info_t *cinfo, provision_state_t *state);
int modify_ipintercept(update_con_info_t *cinfo, provision_state_t *state);
int modify_voipintercept(update_con_info_t *cinfo, provision_state_t *state);

struct json_object *get_agency(update_con_info_t *cinfo,
        provision_state_t *state, char *target);
struct json_object *get_coreservers(update_con_info_t *cinfo,
        provision_state_t *state, uint8_t srvtype);
struct json_object *get_default_radius(update_con_info_t *cinfo,
        provision_state_t *state);
struct json_object *get_voip_intercept(update_con_info_t *cinfo,
        provision_state_t *state, char *target);
struct json_object *get_ip_intercept(update_con_info_t *cinfo,
        provision_state_t *state, char *target);
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
