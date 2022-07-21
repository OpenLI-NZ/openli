/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "logger.h"
#include "email_ingest_service.h"

const char *busypage =
  "<html><body>This server is busy, please try again later.</body></html>";

const char *completepage =
  "<html><body>Your message has been received.</body></html>";

const char *errorpage =
  "<html><body>Something went horribly wrong...</body></html>";
const char *servererrorpage =
  "<html><body>An internal server error has occured.</body></html>";

static unsigned int uploading_clients = 0;

static void init_email_ingest_state(email_ingestor_state_t *state,
        openli_email_ingest_config_t *config) {
    state->daemon = NULL;
    state->config = config;
}

static int iterate_post (void *coninfo_cls, enum MHD_ValueKind kind,
            const char *key, const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, uint64_t off,
            size_t size) {

    email_connection_t *con_info = (email_connection_t *)(coninfo_cls);

    logger(LOG_INFO, "KEY %s", key);
    logger(LOG_INFO, "VALUE %s", data);

    con_info->answerstring = completepage;
    con_info->answercode = MHD_HTTP_OK;

    return MHD_YES;

}

static int send_page(struct MHD_Connection *connection, const char *page,
        int status_code) {

    int ret;
    struct MHD_Response *response;

    response =
        MHD_create_response_from_buffer (strlen (page), (void *) page,
                MHD_RESPMEM_MUST_COPY);
    if (!response) {
        return MHD_NO;
    }
    MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE,
            "text/html");
    ret = MHD_queue_response (connection, status_code, response);
    MHD_destroy_response (response);

    return ret;
}

static void email_request_completed(void *cls,
        struct MHD_Connection *connection,
        void **con_cls, enum MHD_RequestTerminationCode toe) {

    email_connection_t *con_info = (email_connection_t *)(*con_cls);

    if (con_info == NULL) {
        return;
    }

    if (con_info->postproc) {
        MHD_destroy_post_processor(con_info->postproc);
        uploading_clients --;
    }

    free(con_info);
    *con_cls = NULL;
}

static int answer_email_connection(void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method,
                      const char *version, const char *upload_data,
                      size_t *upload_data_size, void **con_cls) {

    email_connection_t *con_info = (email_connection_t *)(*con_cls);
    email_ingestor_state_t *state = (email_ingestor_state_t *)cls;


    if (con_info == NULL) {
        if (uploading_clients >= state->config->maxclients) {
            return send_page(connection, busypage,
                    MHD_HTTP_SERVICE_UNAVAILABLE);
        }

        con_info = calloc(1, sizeof(email_connection_t));
        if (con_info == NULL) {
            return MHD_NO;
        }
        con_info->parentstate = state;
        if (strcmp(method, "POST") == 0) {
            con_info->postproc = MHD_create_post_processor(connection,
                    16 * 1024, iterate_post, (void *)con_info);
            if (con_info->postproc == NULL) {
                free(con_info);
                return MHD_NO;
            }

            uploading_clients ++;
            con_info->answercode = MHD_HTTP_OK;
            con_info->answerstring = completepage;
        }

        *con_cls = (void *)con_info;
        return MHD_YES;
    }

    if (strcmp(method, "POST") == 0) {
        if (*upload_data_size != 0) {
            MHD_post_process(con_info->postproc, upload_data,
                    *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            return send_page(connection, con_info->answerstring,
                    con_info->answercode);
        }
    }

    return send_page(connection, errorpage, MHD_HTTP_BAD_REQUEST);
}

struct MHD_Daemon *start_email_mhd_daemon(openli_email_ingest_config_t *config,
        int sockfd, email_ingestor_state_t *state) {

    int fd, off, len;
    char rndseed[8];

    if (sockfd <= 0) {
        return NULL;
    }

    memset(rndseed, 0, sizeof(rndseed));

    if (config->authrequired) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1) {
            logger(LOG_INFO, "Failed to generate random seed for authentication for email ingestion socket: %s", strerror(errno));
            return NULL;
        }

        off = 0;
        while (off < 8) {
            if ((len = read(fd, rndseed + off, 8 - off)) == -1) {
                logger(LOG_INFO, "Failed to populate random seed for authentication for email ingestion socket: %s", strerror(errno));
                close(fd);
                return NULL;
            }
            off += len;
        }
        close(fd);
    }

    init_email_ingest_state(state, config);

    /* TODO support TLS */


    state->daemon = MHD_start_daemon(
            MHD_USE_SELECT_INTERNALLY,
            0,
            NULL,
            NULL,
            &answer_email_connection,
            state,
            MHD_OPTION_LISTEN_SOCKET,
            sockfd,
            MHD_OPTION_NOTIFY_COMPLETED,
            &email_request_completed,
            state,
            MHD_OPTION_NONCE_NC_SIZE,
            300,
            MHD_OPTION_DIGEST_AUTH_RANDOM,
            sizeof(rndseed), rndseed,
            MHD_OPTION_END);

    return state->daemon;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
