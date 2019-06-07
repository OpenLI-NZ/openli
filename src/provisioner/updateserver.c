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

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>

#include "provisioner.h"

#define MICRO_POST 0
#define MICRO_GET 1

enum {
    TARGET_AGENCY,
    TARGET_CORESERVER,
    TARGET_IPINTERCEPT,
    TARGET_VOIPINTERCEPT,
};

typedef struct con_info {
    int connectiontype;
    int answercode;
    const char *answerstring;
    const char *content_type;

    int target;
    char *jsonbuffer;
    int jsonlen;

} con_info_t;

const char *update_success_page =
        "<html><body>OpenLI provisioner configuration was successfully updated.</body></html>";

const char *update_failure_page =
        "<html><body>OpenLI provisioner configuration failed.</body></html>";

const char *get_not_implemented =
        "<html><body>OpenLI provisioner does not support fetching intercept config (yet).</body></html>";

const char *unsupported_operation =
        "<html><body>OpenLI provisioner does not support that type of request.</body></html>";

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

static int update_configuration(con_info_t *cinfo, provision_state_t *state) {


    if (cinfo->content_type == NULL || strcasecmp(cinfo->content_type,
                "application/json") != 0) {
        return -1;
    }

    if (cinfo->jsonbuffer) {
        fprintf(stderr, "%s\n", cinfo->jsonbuffer);
        free(cinfo->jsonbuffer);
    }

    return 0;
}

static int consume_post_data(con_info_t *cinfo, const char *data, size_t size) {

    cinfo->jsonbuffer = realloc(cinfo->jsonbuffer, cinfo->jsonlen + size + 1);
    if (cinfo->jsonbuffer == NULL) {
        cinfo->answerstring = update_failure_page;
        cinfo->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return MHD_NO;
    }

    memcpy(cinfo->jsonbuffer + cinfo->jsonlen, data, size);
    cinfo->jsonlen += size;
    cinfo->jsonbuffer[cinfo->jsonlen + 1] = '\0';
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

        if (strcmp(method, "POST") == 0) {

            if (strcmp(url, "/agency") == 0) {
                cinfo->target = TARGET_AGENCY;
            } else if (strcmp(url, "/coreserver") == 0) {
                cinfo->target = TARGET_CORESERVER;
            } else if (strcmp(url, "/ipintercept") == 0) {
                cinfo->target = TARGET_IPINTERCEPT;
            } else if (strcmp(url, "/voipintercept") == 0) {
                cinfo->target = TARGET_VOIPINTERCEPT;
            } else {
                free(cinfo);
                return MHD_NO;
            }

            cinfo->content_type = MHD_lookup_connection_value(conn,
                    MHD_HEADER_KIND, "Content-Type");

            cinfo->connectiontype = MICRO_POST;
            cinfo->answercode = MHD_HTTP_OK;
            cinfo->answerstring = update_success_page;
        } else {
            cinfo->connectiontype = MICRO_GET;
        }

        *con_cls = (void *)cinfo;
        return MHD_YES;
    }

    if (strcmp(method, "GET") == 0) {
        return send_http_page(conn, get_not_implemented, MHD_HTTP_OK);
    }

    if (strcmp(method, "POST") == 0) {
        cinfo = (con_info_t *)(*con_cls);

        if (*upload_data_size != 0) {
            int ret = consume_post_data(cinfo, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return ret;
        } else {
            /* POST is complete */
            if (update_configuration(cinfo, provstate) < 0) {
                return send_http_page(conn, update_failure_page, MHD_HTTP_BAD_REQUEST);
            }

            return send_http_page(conn, cinfo->answerstring, cinfo->answercode);
        }
    }

    return send_http_page(conn, unsupported_operation, MHD_HTTP_BAD_REQUEST);

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

