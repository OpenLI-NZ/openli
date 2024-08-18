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


#include "etsili_core.h"
#include "intercept.h"

#define SESSION_IP_INCR (5)

enum {
    ACCESS_RADIUS,
    ACCESS_GTP,
    ACCESS_DHCP
};

typedef enum {
    SESSION_STATE_NEW,
    SESSION_STATE_AUTHING,
    SESSION_STATE_ACTIVE,
    SESSION_STATE_ACTIVE_NO_IP,
    SESSION_STATE_RENEW,
    SESSION_STATE_ENDING,
    SESSION_STATE_OVER,
} session_state_t;

typedef enum {
    ACCESS_ACTION_ATTEMPT,
    ACCESS_ACTION_FAILED,
    ACCESS_ACTION_ACCEPT,
    ACCESS_ACTION_REJECT,
    ACCESS_ACTION_ALREADY_ACTIVE,
    ACCESS_ACTION_INTERIM_UPDATE,
    ACCESS_ACTION_MODIFIED,
    ACCESS_ACTION_END,
    ACCESS_ACTION_END_SUDDEN,
    ACCESS_ACTION_RETRY,
    ACCESS_ACTION_NONE
} access_action_t;

typedef enum {
    USER_IDENT_RADIUS_USERNAME,
    USER_IDENT_RADIUS_CSID,
    USER_IDENT_GTP_MSISDN,
    USER_IDENT_GTP_IMSI,
    USER_IDENT_GTP_IMEI,
    USER_IDENT_MAX
} user_identity_method_t;

typedef enum {
    SESSION_IP_VERSION_NONE,
    SESSION_IP_VERSION_V4,
    SESSION_IP_VERSION_V6,
    SESSION_IP_VERSION_DUAL,
} session_ipversion_t;

typedef struct access_plugin access_plugin_t;
typedef struct internet_user internet_user_t;
typedef struct access_session access_session_t;

typedef struct user_identity {
    user_identity_method_t method;
    char *idstr;
    int idlength;
    void *plugindata;
} user_identity_t;

typedef struct internetaccess_ip {
    int ipfamily;
    struct sockaddr_storage assignedip;
    uint8_t prefixbits;
} internetaccess_ip_t;

typedef struct ip_to_session {
    internetaccess_ip_t ip;
    int sessioncount;
    access_session_t **session;
    internet_user_t **owner;
    uint32_t cin;
    UT_hash_handle hh;
} ip_to_session_t;

typedef struct teid_to_session {
    char *idstring;
    uint32_t teid;
    int sessioncount;
    access_session_t **session;
    internet_user_t **owner;
    uint32_t cin;
    UT_hash_handle hh;
} teid_to_session_t;

typedef enum {
    OPENLI_ACCESS_SESSION_UNKNOWN = 0,
    OPENLI_ACCESS_SESSION_IP = 1,
    OPENLI_ACCESS_SESSION_TEID = 2,
} openli_access_session_id_t;

struct access_session {

    openli_access_session_id_t identifier_type;

    internetaccess_ip_t *sessionips;
    uint8_t sessipcount;
    session_ipversion_t sessipversion;
    uint8_t ips_mapped;

    access_plugin_t *plugin;
    void *sessionid;
    void *statedata;
    int idlength;
    uint32_t cin;
    uint32_t iriseqno;

    struct timeval started;

    char *gtp_tunnel_endpoints[2];
    uint32_t teids[2];
    uint8_t teids_mapped;

    UT_hash_handle hh;
} ;

struct internet_user {
    char *userid;
    access_session_t *sessions;
    UT_hash_handle hh;
};

struct access_plugin {
    const char *name;
    uint8_t access_type;
    void *plugindata;

    /* Mandatory plugin APIs */
    void (*init_plugin_data)(access_plugin_t *p);
    void (*destroy_plugin_data)(access_plugin_t *p);

    void *(*process_packet)(access_plugin_t *p, libtrace_packet_t *pkt);
    void (*destroy_parsed_data)(access_plugin_t *p, void *parseddata);
    void (*uncouple_parsed_data)(access_plugin_t *p);

    user_identity_t *(*get_userid)(access_plugin_t *p, void *parseddata,
            int *numberids);

    access_session_t *(*update_session_state)(access_plugin_t *p,
            void *parseddata, void *pluginuserdata, access_session_t **sesslist,
            session_state_t *oldstate, session_state_t *newstate,
            access_action_t *action);

    int (*generate_iri_data)(access_plugin_t *p, void *parseddata,
            etsili_generic_t **params, etsili_iri_type_t *iritype,
            etsili_generic_freelist_t *freegenerics, int iteration);

    int (*generate_iri_from_session)(access_plugin_t *p,
            access_session_t *session,
            etsili_generic_t **params, etsili_iri_type_t *iritype,
            etsili_generic_freelist_t *freegenerics, uint8_t trigger);

/*
    int (*create_iri_from_packet)(access_plugin_t *p,
            shared_global_info_t *info, etsili_generic_t **freegenerics,
            openli_export_recv_t *irimsg,
            access_session_t *sess, ipintercept_t *ipint,
            void *parseddata, access_action_t action);
*/

    void (*destroy_session_data)(access_plugin_t *p, access_session_t *sess);

    uint32_t (*get_packet_sequence)(access_plugin_t *p, void *parseddata);
    uint8_t *(*get_ip_contents)(access_plugin_t *p, void *parseddata,
            uint16_t *iplen, int iteration);

    /* APIs that are internally used but should be required by all plugins
     * so may as well enforce them as part of the plugin definition.
     */

};

access_plugin_t *init_access_plugin(uint8_t accessmethod);
void destroy_access_plugin(access_plugin_t *p);

void free_all_users(internet_user_t *users);
int free_single_session(access_session_t *sess);

access_plugin_t *get_radius_access_plugin(void);
access_plugin_t *get_gtp_access_plugin(void);
void destroy_gtp_access_plugin(access_plugin_t *gtp);

access_session_t *create_access_session(access_plugin_t *p,
        char *idstr, int idstr_len);
void add_new_session_ip(access_session_t *sess, void *att_val,
        int family, uint8_t pfxbits, int att_len);
int remove_session_ip(access_session_t *sess, internetaccess_ip_t *sessip);
int push_session_ips_to_collector_queue(libtrace_message_queue_t *q,
        ipintercept_t *ipint, access_session_t *session);
void push_session_update_to_collector_queue(libtrace_message_queue_t *q,
        ipintercept_t *ipint, access_session_t *sess, int updatetype);

const char *accesstype_to_string(internet_access_method_t am);

internet_user_t *lookup_user_by_identity(internet_user_t *allusers,
        user_identity_t *userid);
int add_userid_to_allusers_map(internet_user_t **allusers,
        internet_user_t *newuser, user_identity_t *userid);
internet_user_t *lookup_user_by_intercept(internet_user_t *allusers,
        ipintercept_t *ipint);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
