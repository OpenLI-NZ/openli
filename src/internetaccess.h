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

#ifndef OPENLI_INTERNETACCESS_H_
#define OPENLI_INTERNETACCESS_H_

#include <uthash.h>
#include <libtrace.h>
#include <libtrace/message_queue.h>

#include "intercept.h"
#include "collector.h"

enum {
    ACCESS_RADIUS,
    ACCESS_DHCP
};

typedef enum {
    SESSION_STATE_NEW,
    SESSION_STATE_AUTHING,
    SESSION_STATE_ACTIVE,
    SESSION_STATE_RENEW,
    SESSION_STATE_OVER,
} session_state_t;

typedef enum {
    ACCESS_ACTION_ATTEMPT,
    ACCESS_ACTION_FAILED,
    ACCESS_ACTION_ACCEPT,
    ACCESS_ACTION_REJECT,
    ACCESS_ACTION_ALREADY_ACTIVE,
    ACCESS_ACTION_INTERIM_UPDATE,
    ACCESS_ACTION_END,
    ACCESS_ACTION_END_SUDDEN,
    ACCESS_ACTION_RETRY,
    ACCESS_ACTION_NONE
} access_action_t;

typedef struct access_plugin access_plugin_t;

typedef struct access_session access_session_t;

struct access_session {

    access_plugin_t *plugin;
    void *sessionid;
    void *statedata;
    int idlength;
    uint32_t cin;
    int ipfamily;
    struct sockaddr *assignedip;
    uint32_t iriseqno;

    struct timeval started;

    access_session_t *next;
    UT_hash_handle hh;
} ;

typedef struct internet_user {
    char *userid;
    access_session_t *sessions;
    UT_hash_handle hh;
} internet_user_t;


struct access_plugin {
    const char *name;
    uint8_t access_type;
    void *plugindata;

    /* Mandatory plugin APIs */
    void (*init_plugin_data)(access_plugin_t *p);
    void (*destroy_plugin_data)(access_plugin_t *p);

    void *(*process_packet)(access_plugin_t *p, libtrace_packet_t *pkt);
    void (*destroy_parsed_data)(access_plugin_t *p, void *parseddata);

    char *(*get_userid)(access_plugin_t *p, void *parseddata);

    access_session_t *(*update_session_state)(access_plugin_t *p,
            void *parseddata, access_session_t **sesslist,
            session_state_t *oldstate, session_state_t *newstate,
            access_action_t *action);

    int (*create_iri_from_packet)(access_plugin_t *p,
            shared_global_info_t *info, etsili_generic_t **freegenerics,
            wandder_encoder_t **encoder, libtrace_message_queue_t *mqueue,
            access_session_t *sess, ipintercept_t *ipint,
            void *parseddata, access_action_t action);

    void (*destroy_session_data)(access_plugin_t *p, access_session_t *sess);

    /* APIs that are internally used but should be required by all plugins
     * so may as well enforce them as part of the plugin definition.
     */

};

access_plugin_t *init_access_plugin(uint8_t accessmethod);
void destroy_access_plugin(access_plugin_t *p);

void free_all_users(internet_user_t *users);
int free_single_session(internet_user_t *user, access_session_t *sess);

access_plugin_t *get_radius_access_plugin(void);

const char *accesstype_to_string(internet_access_method_t am);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
