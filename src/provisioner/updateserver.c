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

#define _GNU_SOURCE

#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <json-c/json.h>
#include <pthread.h>
#include <assert.h>

#ifdef HAVE_SQLCIPHER
#include <sqlcipher/sqlite3.h>
#endif

#include "provisioner.h"
#include "logger.h"
#include "util.h"
#include "updateserver.h"

#define MICRO_POST 0
#define MICRO_GET 1
#define MICRO_DELETE 2

#define OPAQUE_TOKEN "a7844291bd990a17bfe389e1ccb0981ed6d187a"

const char *delete_active_collector_page =
        "<html><body>Cannot delete a collector that is currently active.</body></html>\n";

const char *delete_active_mediator_page =
        "<html><body>Cannot delete a mediator that is currently active.</body></html>\n";

const char *update_success_page =
        "<html><body>OpenLI provisioner configuration was successfully updated.</body></html>\n";

const char *update_failure_page_start =
        "<html><body><p>OpenLI provisioner configuration failed.";
const char *update_failure_page_end = "</body></html>\n";

const char *get_not_implemented =
        "<html><body>OpenLI provisioner does not support fetching intercept config (yet).</body></html>\n";

const char *auth_failed =
        "<html><body>Authentication failed</body></html>\n";

const char *unsupported_operation =
        "<html><body>OpenLI provisioner does not support that type of request.</body></html>\n";

const char *get404 =
        "<html><body>OpenLI provisioner was unable to find the requested resource in its running intercept configuration.</body></html>\n";

int init_restauth_db(provision_state_t *state) {
#ifdef HAVE_SQLCIPHER
    int rc;

    assert(state != NULL);

    if (state->authdb) {
        sqlite3_close(state->authdb);
    }

    rc = sqlite3_open(state->restauthdbfile, (sqlite3 **)(&(state->authdb)));
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: Failed to open REST authentication database: %s: %s",
                state->restauthdbfile, sqlite3_errmsg(state->authdb));
        sqlite3_close(state->authdb);
        state->authdb = NULL;
        return -1;
    }

    sqlite3_key(state->authdb, state->restauthkey, strlen(state->restauthkey));

    if (sqlite3_exec(state->authdb, "SELECT count(*) from sqlite_master;",
            NULL, NULL, NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: Failed to open REST authentication database due to incorrect key");
        sqlite3_close(state->authdb);
        state->authdb = NULL;
        return -1;
    }

    logger(LOG_INFO, "OpenLI provisioner: Authentication enabled for the REST API (using DB %s)",
            state->restauthdbfile);
    state->restauthenabled = 1;
	return 1;
#else
	state->restauthenabled = 0;
    return 0;
#endif
}

void close_restauth_db(provision_state_t *state) {
#ifdef HAVE_SQLCIPHER
    if (state->authdb) {
        sqlite3_close(state->authdb);
    }
#endif
    state->authdb = NULL;
    return;
}

static int send_auth_failure(struct MHD_Connection *connection,
        const char *realm, int cause) {
    int ret;
    struct MHD_Response *resp;

    resp = MHD_create_response_from_buffer(strlen(auth_failed),
            (void *)auth_failed, MHD_RESPMEM_MUST_COPY);
    if (!resp) {
        return MHD_NO;
    }
    ret = MHD_queue_auth_fail_response(connection, realm, OPAQUE_TOKEN, resp,
            (cause == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO);
    MHD_destroy_response(resp);
    return ret;
}

static int send_http_page(struct MHD_Connection *connection, const char *page,
        int status_code) {

    int ret;
    struct MHD_Response *resp;

    resp = MHD_create_response_from_buffer(strlen(page), (void *)page,
            MHD_RESPMEM_MUST_COPY);
    if (!resp) {
        return MHD_NO;
    }
    MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
    ret = MHD_queue_response(connection, status_code, resp);
    MHD_destroy_response(resp);
    return ret;
}

static int send_json_object(struct MHD_Connection *connection,
        json_object *jobj) {

    int ret;
    struct MHD_Response *resp;
    const char *jsonstr;

    if (jobj) {
        jsonstr = json_object_to_json_string(jobj);
        if (!jsonstr) {
            return MHD_NO;
        }

        resp = MHD_create_response_from_buffer(strlen(jsonstr), (void *)jsonstr,
                MHD_RESPMEM_MUST_COPY);
        if (!resp) {
            return MHD_NO;
        }

        MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
                "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
    } else {

        resp = MHD_create_response_from_buffer(strlen(get404), (void *)get404,
                MHD_RESPMEM_MUST_COPY);
        if (!resp) {
            return MHD_NO;
        }

        MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
                "text/html");
        ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, resp);
    }
    MHD_destroy_response(resp);
    return ret;
}

static inline int extract_target_from_url(update_con_info_t *cinfo,
        char *url, char *targetspace, int spacelen, const char *methodtype) {

    char *targetstart, *targetend, *urlstart;

    if (*url != '/') {
        logger(LOG_INFO, "OpenLI: invalid %s url from update socket: %s",
                methodtype, url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse %s instruction from update socket. %s",
                update_failure_page_start, methodtype, update_failure_page_end);
        return -1;
    }

    urlstart = url;
    while (*urlstart == '/') {
        urlstart ++;
    }

    targetstart = strchr(urlstart, '/');
    if (targetstart == NULL) {
        return 0;
    }

    while (*(targetstart + 1) == '/') {
        targetstart ++;
    }

    targetend = strchrnul(targetstart + 1, '/');

    if (targetend - targetstart >= spacelen) {
        logger(LOG_INFO, "OpenLI: invalid %s url from update socket: %s",
                methodtype, url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse %s instruction from update socket. %s",
                update_failure_page_start, methodtype, update_failure_page_end);
        return -1;
    }

    memcpy(targetspace, targetstart + 1, targetend - targetstart - 1);
    targetspace[targetend - (targetstart + 1)] = '\0';
    return 1;
}

static int update_configuration_delete(update_con_info_t *cinfo,
        provision_state_t *state, const char *url) {

    int ret = 0;
    char *urlcopy = strdup(url);
    char target[4096];

    if ((ret = extract_target_from_url(cinfo, urlcopy, target, 4096, "DELETE"))
             < 0) {
        free(urlcopy);
        return -1;
    }

    if (ret == 0) {
        /* no target specified, just return quietly? */
        free(urlcopy);
        return ret;
    }
    ret = 0;

    pthread_mutex_lock(&(state->interceptconf.safelock));
    switch(cinfo->target) {
        case TARGET_AGENCY:
            ret = remove_agency(cinfo, state, target);
            break;
        case TARGET_SIPSERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_SIP);
            break;
        case TARGET_RADIUSSERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_RADIUS);
            break;
        case TARGET_GTPSERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_GTP);
            break;
        case TARGET_SMTPSERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_SMTP);
            break;
        case TARGET_IMAPSERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_IMAP);
            break;
        case TARGET_POP3SERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_POP3);
            break;
        case TARGET_IPINTERCEPT:
            ret = remove_ip_intercept(cinfo, state, target);
            break;
        case TARGET_VOIPINTERCEPT:
            ret = remove_voip_intercept(cinfo, state, target);
            break;
        case TARGET_EMAILINTERCEPT:
            ret = remove_email_intercept(cinfo, state, target);
            break;
        case TARGET_DEFAULTRADIUS:
            ret = remove_defaultradius(cinfo, state, target);
            break;
        case TARGET_OPTIONS:
            /* deleting options doesn't make sense? */
            break;
        case TARGET_OPENLIVERSION:
            /* deleting this is not sensible either */
            break;
        case TARGET_COLLECTOR:
            ret = remove_collector_from_clientdb(state, target);
            if (ret == 0) {
                snprintf(cinfo->answerstring, 4096, "%s",
                        delete_active_collector_page);
                cinfo->answercode = MHD_HTTP_FORBIDDEN;
            }
            break;

        case TARGET_MEDIATOR:
            /* You shouldn't be able to delete known collectors or mediators */
            break;
    }

    /* Safe to unlock before emitting, since all accesses should be reads
     * anyway... */
    pthread_mutex_unlock(&(state->interceptconf.safelock));
    emit_intercept_config(state->interceptconffile,
            state->encrypt_intercept_config ? state->encpassfile : NULL,
            &(state->interceptconf));
    free(urlcopy);
    return ret;
}

static json_object *create_get_response(update_con_info_t *cinfo,
        provision_state_t *state, const char *url) {

    json_object *jobj = NULL;
    int ret = 0;
    char *tgtptr = NULL;
    char *urlcopy = strdup(url);
    char target[4096];

    if ((ret = extract_target_from_url(cinfo, urlcopy, target, 4096, "GET"))
            < 0) {
        free(urlcopy);
        return NULL;
    }

    if (ret > 0) {
        tgtptr = target;
    }
    ret = 0;

    pthread_mutex_lock(&(state->interceptconf.safelock));
    switch(cinfo->target) {
        case TARGET_AGENCY:
            jobj = get_agency(cinfo, state, tgtptr);
            break;
        case TARGET_SIPSERVER:
            jobj = get_coreservers(cinfo, state, OPENLI_CORE_SERVER_SIP);
            break;
        case TARGET_RADIUSSERVER:
            jobj = get_coreservers(cinfo, state, OPENLI_CORE_SERVER_RADIUS);
            break;
        case TARGET_DEFAULTRADIUS:
            jobj = get_default_radius(cinfo, state);
            break;
        case TARGET_OPTIONS:
            jobj = get_provisioner_options(cinfo, state);
            break;
        case TARGET_MEDIATOR:
            jobj = get_known_mediators(cinfo, state);
            break;
        case TARGET_COLLECTOR:
            jobj = get_known_collectors(cinfo, state);
            break;
        case TARGET_OPENLIVERSION:
            jobj = get_openli_version();
            break;
        case TARGET_GTPSERVER:
            jobj = get_coreservers(cinfo, state, OPENLI_CORE_SERVER_GTP);
            break;
        case TARGET_SMTPSERVER:
            jobj = get_coreservers(cinfo, state, OPENLI_CORE_SERVER_SMTP);
            break;
        case TARGET_IMAPSERVER:
            jobj = get_coreservers(cinfo, state, OPENLI_CORE_SERVER_IMAP);
            break;
        case TARGET_POP3SERVER:
            jobj = get_coreservers(cinfo, state, OPENLI_CORE_SERVER_POP3);
            break;
        case TARGET_IPINTERCEPT:
            jobj = get_ip_intercept(cinfo, state, tgtptr);
            break;
        case TARGET_VOIPINTERCEPT:
            jobj = get_voip_intercept(cinfo, state, tgtptr);
            break;
        case TARGET_EMAILINTERCEPT:
            jobj = get_email_intercept(cinfo, state, tgtptr);
            break;
    }


    /* Safe to unlock before emitting, since all accesses should be reads
     * anyway... */
    pthread_mutex_unlock(&(state->interceptconf.safelock));
    free(urlcopy);
    return jobj;
}


static int update_configuration_post(update_con_info_t *cinfo,
        provision_state_t *state, const char *method) {

    int ret = 0;

    if (cinfo->content_type == NULL || strcasecmp(cinfo->content_type,
                "application/json") != 0) {
        return -1;
    }

    if (!cinfo->jsonbuffer) {
        return -1;
    }

    pthread_mutex_lock(&(state->interceptconf.safelock));
    switch(cinfo->target) {
        case TARGET_AGENCY:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_agency(cinfo, state);
            }
            else {
                ret = modify_agency(cinfo, state);
            }
            break;
        case TARGET_SIPSERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_SIP);
            break;
        case TARGET_RADIUSSERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_RADIUS);
            break;
        case TARGET_DEFAULTRADIUS:
            ret = add_new_defaultradius(cinfo, state);
            break;
        case TARGET_OPTIONS:
            ret = modify_provisioner_options(cinfo, state);
            break;
        case TARGET_GTPSERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_GTP);
            break;
        case TARGET_SMTPSERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_SMTP);
            break;
        case TARGET_IMAPSERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_IMAP);
            break;
        case TARGET_POP3SERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_POP3);
            break;
        case TARGET_IPINTERCEPT:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_ipintercept(cinfo, state);
            } else {
                ret = modify_ipintercept(cinfo, state);
            }
            break;
        case TARGET_VOIPINTERCEPT:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_voipintercept(cinfo, state);
            } else {
                ret = modify_voipintercept(cinfo, state);
            }
            break;
        case TARGET_EMAILINTERCEPT:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_emailintercept(cinfo, state);
            } else {
                ret = modify_emailintercept(cinfo, state);
            }
            break;
        case TARGET_OPENLIVERSION:
            break;
        case TARGET_COLLECTOR:
            if (strcmp(method, "PUT") == 0) {
                // allow for modification of the collector config
                ret = modify_collector_configuration(cinfo, state);
            }
            break;
        case TARGET_MEDIATOR:
            break;
    }


    /* Safe to unlock before emitting, since all accesses should be reads
     * anyway... */
    pthread_mutex_unlock(&(state->interceptconf.safelock));

    emit_intercept_config(state->interceptconffile,
            state->encrypt_intercept_config ? state->encpassfile : NULL,
            &(state->interceptconf));
    return ret;
}

static int consume_upload_data(update_con_info_t *cinfo, const char *data,
        size_t size) {

    cinfo->jsonbuffer = realloc(cinfo->jsonbuffer, cinfo->jsonlen + size + 1);
    if (cinfo->jsonbuffer == NULL) {
        snprintf(cinfo->answerstring, 4096, "%s %s", update_failure_page_start,
                update_failure_page_end);
        cinfo->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return MHD_NO;
    }

    memcpy(cinfo->jsonbuffer + cinfo->jsonlen, data, size);
    cinfo->jsonlen += size;
    cinfo->jsonbuffer[cinfo->jsonlen] = '\0';
    return MHD_YES;
}

void complete_update_request(void *cls UNUSED,
        struct MHD_Connection *conn UNUSED, void **con_cls,
        enum MHD_RequestTerminationCode toe UNUSED) {

    update_con_info_t *cinfo = (update_con_info_t *)(*con_cls);

    if (cinfo == NULL) {
        return;
    }

    if (cinfo->connectiontype == MICRO_POST) {
        if (cinfo->jsonbuffer) {
            free(cinfo->jsonbuffer);
        }
    }

    free(cinfo);
    *con_cls = NULL;
}

#define VALID_DIGEST_CHAR(x) \
    ((x >= 'a' && x <= 'f') || (x >= '0' && x <= '9'))

#define CHAR_TO_VALUE(x) \
    ((x >= 'a' && x <= 'f') ? (x - 'a' + 10) : (x - '0'))

#ifdef HAVE_SQLCIPHER
static unsigned char *lookup_user_digest(provision_state_t *provstate,
        char *username, unsigned char *digestres) {

    int rc, step;
    sqlite3_stmt *res;
    const char *sql =
            "SELECT username, digesthash FROM authcreds where username = ?";
    unsigned char *returning = NULL;
    const unsigned char *hashtext;

    rc = sqlite3_prepare_v2(provstate->authdb, sql, -1, &res, 0);
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI: Failed to prepare SQL SELECT to lookup user credentials for %s: %s",
                username, sqlite3_errmsg(provstate->authdb));
        return NULL;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_TRANSIENT);

    memset(digestres, 0, 16);

    step = sqlite3_step(res);
    if (step == SQLITE_ROW) {
        int i;
        hashtext = sqlite3_column_blob(res, 1);

        if (strlen((const char *)hashtext) < 32) {
            logger(LOG_INFO, "OpenLI: Invalid digest hash in database for user %s", username);
            return NULL;
        }

        for (i = 0; i < 16; i++) {
            if (!(VALID_DIGEST_CHAR(hashtext[i * 2])) ||
                    !(VALID_DIGEST_CHAR(hashtext[(i * 2) + 1]))) {
                logger(LOG_INFO, "OpenLI: Invalid digest hash contents in database for user %s", username);
                return NULL;
            }
            digestres[i] = (CHAR_TO_VALUE(hashtext[i * 2]) << 4) +
                    (CHAR_TO_VALUE(hashtext[(i * 2) + 1]));
        }

        returning = digestres;
    }

    sqlite3_finalize(res);
    return returning;
}
#endif

static int validate_user_apikey(provision_state_t *provstate,
        const char *apikey) {

#ifdef HAVE_SQLCIPHER
    int rc, step;
    sqlite3_stmt *res;
    const char *sql = "SELECT username, apikey FROM authcreds where apikey = ?";

    rc = sqlite3_prepare_v2(provstate->authdb, sql, -1, &res, 0);
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI: Failed to prepare SQL SELECT to lookup API key: %s",
                sqlite3_errmsg(provstate->authdb));
        return MHD_NO;
    }

    sqlite3_bind_text(res, 1, apikey, -1, SQLITE_TRANSIENT);

    step = sqlite3_step(res);
    if (step == SQLITE_ROW) {
        logger(LOG_INFO, "OpenLI: User %s has used their API key to send a request via the REST API", sqlite3_column_text(res, 0));
        sqlite3_finalize(res);
        return MHD_YES;
    }

    sqlite3_finalize(res);
#endif
    return MHD_NO;
}

static int authenticate_request(provision_state_t *provstate,
        struct MHD_Connection *conn, const char *realm) {

    unsigned char digest[16];
    const char *apikey;
    char *username;
    int ret;


    username = MHD_digest_auth_get_username(conn);
    if (username == NULL) {
        apikey = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
                "X-API-KEY");
        if (apikey != NULL) {
            if (validate_user_apikey(provstate, apikey) == 0) {
                logger(LOG_INFO,
                        "OpenLI: user attempted to provide an invalid API key");
                return send_auth_failure(conn, realm, MHD_NO);
            } else {
                return MHD_YES;
            }
        }
        return send_auth_failure(conn, realm, MHD_NO);
    }

    ret = MHD_NO;
#ifdef HAVE_SQLCIPHER
    if (lookup_user_digest(provstate, username, digest) == NULL) {
        logger(LOG_INFO,
                "OpenLI: user '%s' attempted to authenticate against provisioner update service, but they don't exist in the database", username);
        return send_auth_failure(conn, realm, MHD_NO);
    }

    ret = MHD_digest_auth_check_digest(conn, realm, username, digest,
            300);
#endif
    if ( ret == MHD_INVALID_NONCE || ret == MHD_NO) {
        logger(LOG_INFO, "OpenLI: user '%s' failed to authenticate against provisioner update service", username);
        free(username);
        return send_auth_failure(conn, realm, ret);
    }
    logger(LOG_INFO, "OpenLI: user '%s' successfully authenticated against provisioner update service", username);
    free(username);

    return MHD_YES;
}

MHD_RESULT handle_update_request(void *cls, struct MHD_Connection *conn,
        const char *url, const char *method, const char *version UNUSED,
        const char *upload_data, size_t *upload_data_size,
        void **con_cls) {

    update_con_info_t *cinfo;
    provision_state_t *provstate = (provision_state_t *)cls;
    MHD_RESULT ret;
    const char *realm = "provisioner@openli.nz";

    if (*con_cls == NULL) {
        if (provstate->restauthenabled) {
            ret = authenticate_request(provstate, conn, realm);

            if (ret != MHD_YES) {
                return send_auth_failure(conn, realm, ret);
            }
        } else {
            /* TODO log all "anonymous" accesses to this socket? */
        }

        cinfo = calloc(1, sizeof(update_con_info_t));
        if (cinfo == NULL) {
            return MHD_NO;
        }

        if (strncmp(url, "/agency", 7) == 0) {
            cinfo->target = TARGET_AGENCY;
        } else if (strncmp(url, "/sipserver", 10) == 0) {
            cinfo->target = TARGET_SIPSERVER;
        } else if (strncmp(url, "/radiusserver", 13) == 0) {
            cinfo->target = TARGET_RADIUSSERVER;
        } else if (strncmp(url, "/gtpserver", 10) == 0) {
            cinfo->target = TARGET_GTPSERVER;
        } else if (strncmp(url, "/smtpserver", 11) == 0) {
            cinfo->target = TARGET_SMTPSERVER;
        } else if (strncmp(url, "/imapserver", 11) == 0) {
            cinfo->target = TARGET_IMAPSERVER;
        } else if (strncmp(url, "/pop3server", 11) == 0) {
            cinfo->target = TARGET_POP3SERVER;
        } else if (strncmp(url, "/ipintercept", 12) == 0) {
            cinfo->target = TARGET_IPINTERCEPT;
        } else if (strncmp(url, "/voipintercept", 14) == 0) {
            cinfo->target = TARGET_VOIPINTERCEPT;
        } else if (strncmp(url, "/emailintercept", 15) == 0) {
            cinfo->target = TARGET_EMAILINTERCEPT;
        } else if (strncmp(url, "/defaultradius", 14) == 0) {
            cinfo->target = TARGET_DEFAULTRADIUS;
        } else if (strncmp(url, "/openliversion",
                strlen("/openliversion")) == 0) {
            cinfo->target = TARGET_OPENLIVERSION;
        } else if (strncmp(url, "/collectors",
                strlen("/collectors")) == 0) {
            cinfo->target = TARGET_COLLECTOR;
        } else if (strncmp(url, "/mediators",
                strlen("/mediators")) == 0) {
            cinfo->target = TARGET_MEDIATOR;
        } else if (strncmp(url, "/options", strlen("/options")) == 0) {
            cinfo->target = TARGET_OPTIONS;
        } else {
            free(cinfo);
            return MHD_NO;
        }

        if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0) {
            cinfo->content_type = MHD_lookup_connection_value(conn,
                    MHD_HEADER_KIND, "Content-Type");

            cinfo->connectiontype = MICRO_POST;
            cinfo->answercode = MHD_HTTP_OK;
            snprintf(cinfo->answerstring, 4096, "%s", update_success_page);
        } else if (strcmp(method, "DELETE") == 0) {
            cinfo->connectiontype = MICRO_DELETE;
            cinfo->answercode = MHD_HTTP_OK;
            snprintf(cinfo->answerstring, 4096, "%s", update_success_page);
        } else {
            cinfo->connectiontype = MICRO_GET;
            cinfo->answercode = MHD_HTTP_OK;
        }

        *con_cls = (void *)cinfo;
        return MHD_YES;
    }


    if (strcmp(method, "GET") == 0) {
        json_object *respjson = NULL;
        cinfo = (update_con_info_t *)(*con_cls);

        respjson = create_get_response(cinfo, provstate, url);
        ret = send_json_object(conn, respjson);

        if (respjson) {
            json_object_put(respjson);
        }
        return ret;
    } else if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0) {
        cinfo = (update_con_info_t *)(*con_cls);

        if (*upload_data_size != 0) {
            int ret = consume_upload_data(cinfo, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return ret;
        } else {
            /* POST / PUT is complete */
            if (update_configuration_post(cinfo, provstate, method) < 0) {
                return send_http_page(conn, cinfo->answerstring,
                        MHD_HTTP_BAD_REQUEST);
            }

            return send_http_page(conn, cinfo->answerstring, cinfo->answercode);
        }
    } else if (strcmp(method, "DELETE") == 0) {
        cinfo = (update_con_info_t *)(*con_cls);

        if (update_configuration_delete(cinfo, provstate, url) < 0) {
            return send_http_page(conn, cinfo->answerstring,
                    MHD_HTTP_BAD_REQUEST);
        }
        return send_http_page(conn, cinfo->answerstring, cinfo->answercode);
    }

    return send_http_page(conn, unsupported_operation, MHD_HTTP_BAD_REQUEST);

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

