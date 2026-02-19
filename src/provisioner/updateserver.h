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

#ifndef OPENLI_PROV_UPDATESERVER_H_
#define OPENLI_PROV_UPDATESERVER_H_

#include <json-c/json.h>
#include <microhttpd.h>
#include "provisioner.h"

#if MHD_VERSION < 0x0097002
#define MHD_RESULT int
#else
#define MHD_RESULT enum MHD_Result
#endif

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
    TARGET_EMAILINTERCEPT,
    TARGET_SMTPSERVER,
    TARGET_IMAPSERVER,
    TARGET_POP3SERVER,
    TARGET_OPTIONS,
    TARGET_OPENLIVERSION,
    TARGET_COLLECTOR,
    TARGET_MEDIATOR,
    TARGET_DIGESTHASHKEY,
    TARGET_X2X3LISTENER,
    TARGET_UDPSINK,
};

extern const char *update_success_page;
extern const char *update_failure_page_start;
extern const char *update_failure_page_end;

extern const char *get_not_implemented;
extern const char *auth_failed;
extern const char *unsupported_operation;
extern const char *get404;

MHD_RESULT handle_update_request(void *cls, struct MHD_Connection *conn,
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
int remove_email_intercept(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr);
int remove_x2x3_listener(update_con_info_t *cinfo, provision_state_t *state,
        const char *fullid);

int add_new_agency(update_con_info_t *cinfo, provision_state_t *state);
int add_new_defaultradius(update_con_info_t *cinfo, provision_state_t *state);
int add_new_voipintercept(update_con_info_t *cinfo, provision_state_t *state);
int add_new_ipintercept(update_con_info_t *cinfo, provision_state_t *state);
int add_new_emailintercept(update_con_info_t *cinfo, provision_state_t *state);
int add_new_coreserver(update_con_info_t *cinfo, provision_state_t *state,
        uint8_t srvtype);
int add_new_x2x3_listener(update_con_info_t *cinfo, provision_state_t *state);

int modify_agency(update_con_info_t *cinfo, provision_state_t *state);
int modify_ipintercept(update_con_info_t *cinfo, provision_state_t *state);
int modify_voipintercept(update_con_info_t *cinfo, provision_state_t *state);
int modify_emailintercept(update_con_info_t *cinfo, provision_state_t *state);
int modify_provisioner_options(update_con_info_t *cinfo,
        provision_state_t *state);
int modify_collector_configuration(update_con_info_t *cinfo,
        provision_state_t *state);

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
struct json_object *get_email_intercept(update_con_info_t *cinfo,
        provision_state_t *state, char *target);
struct json_object *get_provisioner_options(update_con_info_t *cinfo,
        provision_state_t *state);
struct json_object *get_openli_version(void);
struct json_object *get_known_collectors(update_con_info_t *cinfo,
        provision_state_t *state);
struct json_object *get_known_mediators(update_con_info_t *cinfo,
        provision_state_t *state);
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
