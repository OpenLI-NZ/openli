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

#define _GNU_SOURCE

#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <json-c/json.h>

#include "provisioner.h"
#include "logger.h"

#define MICRO_POST 0
#define MICRO_GET 1
#define MICRO_DELETE 2

enum {
    TARGET_AGENCY,
    TARGET_CORESERVER,
    TARGET_IPINTERCEPT,
    TARGET_VOIPINTERCEPT,
};

typedef struct con_info {
    int connectiontype;
    int answercode;
    char answerstring[4096];
    const char *content_type;

    int target;
    char *jsonbuffer;
    int jsonlen;

} con_info_t;

struct json_agency {
    struct json_object *hi3addr;
    struct json_object *hi3port;
    struct json_object *hi2addr;
    struct json_object *hi2port;
    struct json_object *ka_freq;
    struct json_object *ka_wait;
};

const char *update_success_page =
        "<html><body>OpenLI provisioner configuration was successfully updated.</body></html>\n";

const char *update_failure_page_start =
        "<html><body><p>OpenLI provisioner configuration failed.";
const char *update_failure_page_end = "</body></html>\n";

const char *get_not_implemented =
        "<html><body>OpenLI provisioner does not support fetching intercept config (yet).</body></html>\n";

const char *unsupported_operation =
        "<html><body>OpenLI provisioner does not support that type of request.</body></html>\n";

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

#define EXTRACT_JSON_INT_PARAM(name, uptype, jsonobj, dest, errflag, force) \
    if ((*errflag) == 0) { \
        int64_t ival; \
        errno = 0; \
        if (jsonobj != NULL) { \
            ival = json_object_get_int64(jsonobj); \
        } \
        if (errno != 0 || jsonobj == NULL) { \
            if (force) { \
                logger(LOG_INFO, "error, could not parse '%s' in %s update socket message", name, uptype); \
                snprintf(cinfo->answerstring, 4096, "%s <p>OpenLI provisioner could not parse '%s' in %s update socket message. %s", update_failure_page_start, name, uptype, update_failure_page_end); \
                *errflag = 1; \
            } \
        } else { \
            dest = ival; \
        } \
    }


#define EXTRACT_JSON_STRING_PARAM(name, uptype, jsonobj, dest, errflag, force) \
    if ((*errflag) == 0) { \
        const char *objstr; \
        if (jsonobj != NULL) { \
            objstr = json_object_get_string(jsonobj); \
        } \
        if (objstr == NULL || jsonobj == NULL) { \
            if (force) { \
                logger(LOG_INFO, "error, could not parse '%s' in %s update socket message", name, uptype); \
                snprintf(cinfo->answerstring, 4096, "%s <p>OpenLI provisioner could not parse '%s' in %s update socket message. %s", update_failure_page_start, name, uptype, update_failure_page_end); \
                *errflag = 1; \
            } \
        } else { \
            dest = strdup(objstr); \
        } \
    }

static inline void extract_agency_json_objects(struct json_agency *agjson,
        struct json_object *parsed) {

    json_object_object_get_ex(parsed, "hi3address", &(agjson->hi3addr));
    json_object_object_get_ex(parsed, "hi2address", &(agjson->hi2addr));
    json_object_object_get_ex(parsed, "hi3port", &(agjson->hi3port));
    json_object_object_get_ex(parsed, "hi2port", &(agjson->hi2port));
    json_object_object_get_ex(parsed, "keepalivefreq", &(agjson->ka_freq));
    json_object_object_get_ex(parsed, "keepalivewait", &(agjson->ka_wait));

}

static int remove_agency(con_info_t *cinfo, provision_state_t *state,
        const char *idstr) {

    prov_agency_t *found;

    HASH_FIND(hh, state->interceptconf.leas, idstr, strlen(idstr), found);

    if (found) {
        HASH_DEL(state->interceptconf.leas, found);
        withdraw_agency_from_mediators(state, found);
        free_liagency(found->ag);
        free(found);
        logger(LOG_INFO, "OpenLI: removed agency '%s' via update socket.",
                idstr);
        return 1;
    }
    return 0;

}

static int add_new_agency(con_info_t *cinfo, provision_state_t *state) {

    struct json_object *agencyid;
    struct json_agency agjson;

    const char *idstr;
    struct json_object *parsed;
    struct json_tokener *tknr;
    liagency_t *nag = NULL;
    prov_agency_t *lea, *found;
    int parseerr = 0;

    memset(&agjson, 0, sizeof(struct json_agency));
    tknr = json_tokener_new();

    parsed = json_tokener_parse_ex(tknr, cinfo->jsonbuffer, cinfo->jsonlen);
    if (parsed == NULL) {
        logger(LOG_INFO, "unable to parse JSON received over update socket: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse JSON received over update socket: %s. %s",
                update_failure_page_start,
                json_tokener_error_desc(json_tokener_get_error(tknr)),
                update_failure_page_end);
        goto agencyerr;
    }

    if (!(json_object_object_get_ex(parsed, "agencyid", &agencyid))) {
        logger(LOG_INFO, "error, agency update socket messages must include an 'agencyid'!");
        snprintf(cinfo->answerstring, 4096,
                "%s <p>Agency update socket messages must include an 'agencyid'! %s",
                update_failure_page_start, update_failure_page_end);
        goto agencyerr;
    }

    idstr = json_object_get_string(agencyid);
    if (idstr == NULL) {
        logger(LOG_INFO, "error, could not parse 'agencyid' in agency update socket message");
        snprintf(cinfo->answerstring, 4096,
                "%s <p>'agencyid' field in agency update was unparseable. %s",
                update_failure_page_start, update_failure_page_end);
        goto agencyerr;
    }

    extract_agency_json_objects(&agjson, parsed);

    nag = calloc(1, sizeof(liagency_t));
    nag->agencyid = strdup(idstr);
    nag->keepalivefreq = DEFAULT_AGENCY_KEEPALIVE_FREQ;
    nag->keepalivewait = DEFAULT_AGENCY_KEEPALIVE_WAIT;

    EXTRACT_JSON_STRING_PARAM("hi3address", "agency", agjson.hi3addr,
            nag->hi3_ipstr, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("hi2address", "agency", agjson.hi2addr,
            nag->hi2_ipstr, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("hi3port", "agency", agjson.hi3port,
            nag->hi3_portstr, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("hi2port", "agency", agjson.hi2port,
            nag->hi2_portstr, &parseerr, true);

    EXTRACT_JSON_INT_PARAM("keepalivefreq", "agency", agjson.ka_freq,
            nag->keepalivefreq, &parseerr, false);
    EXTRACT_JSON_INT_PARAM("keepalivewait", "agency", agjson.ka_wait,
            nag->keepalivewait, &parseerr, false);

    if (parseerr) {
        goto agencyerr;
    }

    lea = calloc(1, sizeof(prov_agency_t));
    lea->ag = nag;
    lea->announcereq = 1;

    HASH_FIND(hh, state->interceptconf.leas, nag->agencyid,
            strlen(nag->agencyid), found);
    if (found) {
        HASH_DEL(state->interceptconf.leas, found);
        withdraw_agency_from_mediators(state, found);
        free_liagency(found->ag);
        free(found);
    }

    HASH_ADD_KEYPTR(hh, state->interceptconf.leas, nag->agencyid,
            strlen(nag->agencyid), lea);
    announce_lea_to_mediators(state, lea);

    logger(LOG_INFO, "OpenLI: added new agency '%s' via update socket.",
            nag->agencyid);

    json_tokener_free(tknr);
    return 0;

agencyerr:
    if (nag) {
        if (nag->hi2_ipstr) {
            free(nag->hi2_ipstr);
        }
        if (nag->hi3_ipstr) {
            free(nag->hi3_ipstr);
        }
        if (nag->hi2_portstr) {
            free(nag->hi2_portstr);
        }
        if (nag->hi3_portstr) {
            free(nag->hi3_portstr);
        }
        if (nag->agencyid) {
            free(nag->agencyid);
        }
        free(nag);
    }
    json_tokener_free(tknr);
    return -1;
}

static int update_configuration_delete(con_info_t *cinfo,
        provision_state_t *state, const char *url) {

    int ret = 0;
    char *urlcopy = strdup(url);
    char *targetstart, *targetend, *urlstart;
    char target[4096];

    if (*url != '/') {
        free(urlcopy);
        logger(LOG_INFO, "OpenLI: invalid DELETE url from update socket: %s", url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse delete instruction from update socket. %s",
                update_failure_page_start, update_failure_page_end);
        return -1;
    }

    urlstart = urlcopy;
    while (*urlstart == '/') {
        urlstart ++;
    }

    targetstart = strchr(urlstart, '/');
    if (targetstart == NULL) {
        free(urlcopy);
        logger(LOG_INFO, "OpenLI: invalid DELETE url from update socket: %s", url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse delete instruction from update socket. %s",
                update_failure_page_start, update_failure_page_end);
        return -1;
    }

    while (*(targetstart + 1) == '/') {
        targetstart ++;
    }

    targetend = strchrnul(targetstart + 1, '/');

    if (targetend - targetstart >= 4096) {
        free(urlcopy);
        logger(LOG_INFO, "OpenLI: invalid DELETE url from update socket: %s", url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse delete instruction from update socket. %s",
                update_failure_page_start, update_failure_page_end);
        return -1;
    }

    memcpy(target, targetstart + 1, targetend - targetstart + 1);
    target[targetend - (targetstart + 1)] = '\0';

    switch(cinfo->target) {
        case TARGET_AGENCY:
            ret = remove_agency(cinfo, state, target);
            break;
        case TARGET_CORESERVER:
        case TARGET_IPINTERCEPT:
        case TARGET_VOIPINTERCEPT:
            break;
    }

    emit_intercept_config(state->interceptconffile, &(state->interceptconf));
    free(urlcopy);
    return ret;
}


static int update_configuration_post(con_info_t *cinfo,
        provision_state_t *state, const char *method) {

    int ret = 0;

    if (cinfo->content_type == NULL || strcasecmp(cinfo->content_type,
                "application/json") != 0) {
        return -1;
    }

    if (!cinfo->jsonbuffer) {
        return -1;
    }

    switch(cinfo->target) {
        case TARGET_AGENCY:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_agency(cinfo, state);
            }
            break;
        case TARGET_CORESERVER:
        case TARGET_IPINTERCEPT:
        case TARGET_VOIPINTERCEPT:
            break;
    }


    emit_intercept_config(state->interceptconffile, &(state->interceptconf));
    return ret;
}

static int consume_upload_data(con_info_t *cinfo, const char *data,
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

void complete_update_request(void *cls, struct MHD_Connection *conn,
        void **con_cls, enum MHD_RequestTerminationCode toe) {

    con_info_t *cinfo = (con_info_t *)(*con_cls);

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

int handle_update_request(void *cls, struct MHD_Connection *conn,
        const char *url, const char *method, const char *version,
        const char *upload_data, size_t *upload_data_size,
        void **con_cls) {

    con_info_t *cinfo;
    provision_state_t *provstate = (provision_state_t *)cls;

    if (*con_cls == NULL) {
        cinfo = calloc(1, sizeof(con_info_t));
        if (cinfo == NULL) {
            return MHD_NO;
        }

        if (strncmp(url, "/agency", 7) == 0) {
            cinfo->target = TARGET_AGENCY;
        } else if (strncmp(url, "/coreserver", 11) == 0) {
            cinfo->target = TARGET_CORESERVER;
        } else if (strncmp(url, "/ipintercept", 11) == 0) {
            cinfo->target = TARGET_IPINTERCEPT;
        } else if (strncmp(url, "/voipintercept", 13) == 0) {
            cinfo->target = TARGET_VOIPINTERCEPT;
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
        }

        *con_cls = (void *)cinfo;
        return MHD_YES;
    }


    if (strcmp(method, "GET") == 0) {
        return send_http_page(conn, get_not_implemented, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0) {
        cinfo = (con_info_t *)(*con_cls);

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
        cinfo = (con_info_t *)(*con_cls);

        if (update_configuration_delete(cinfo, provstate, url) < 0) {
            return send_http_page(conn, cinfo->answerstring,
                    MHD_HTTP_BAD_REQUEST);
        }
        return send_http_page(conn, cinfo->answerstring, cinfo->answercode);
    }

    return send_http_page(conn, unsupported_operation, MHD_HTTP_BAD_REQUEST);

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

