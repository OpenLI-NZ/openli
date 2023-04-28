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
#include <zmq.h>
#include <assert.h>

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
const char *accessdenied = "<html><body>Access DENIED</body></html>";

#define REALM "emailingest@openli.nz"
#define OPAQUE "2153ab20f777ce3106003ac9af7da810ea97dd20"

static unsigned int uploading_clients = 0;

static int init_email_ingest_state(email_ingestor_state_t *state,
        openli_email_ingest_config_t *config, openli_ssl_config_t *sslconf) {

    state->daemon = NULL;
    state->config = config;
    state->zmq_publishers = NULL;
    state->key_pem = NULL;
    state->cert_pem = NULL;

    if (config->tlsrequired) {
        if (!sslconf->certfile) {
            logger(LOG_INFO, "OpenLI: email ingest socket requires TLS but no certificate has been provided -- not creating ingestion socket");
            return -1;
        }

        if (!sslconf->keyfile) {
            logger(LOG_INFO, "OpenLI: email ingest socket requires TLS but no key has been provided -- not creating ingestion socket");
            return -1;
        }

        if (load_pem_into_memory(sslconf->keyfile, &(state->key_pem)) < 0) {
            logger(LOG_INFO, "OpenLI: failed to load SSL key file for email ingestion socket -- not creating ingestion socket");
            return -1;
        }

        if (load_pem_into_memory(sslconf->certfile, &(state->cert_pem)) < 0) {
            logger(LOG_INFO, "OpenLI: failed to load SSL certificate file for email ingestion socket -- not creating ingestion socket");
            return -1;
        }
    }
    return 0;
}

static MHD_RESULT iterate_post (void *coninfo_cls, enum MHD_ValueKind kind,
            const char *key, const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, uint64_t off,
            size_t size) {

    email_connection_t *con_info = (email_connection_t *)(coninfo_cls);
    char *ptr;

    if (con_info->thismsg == NULL) {
        con_info->thismsg = calloc(1, sizeof(openli_email_captured_t));
    }

    if (strcmp(key, "TARGET_ID") == 0) {
        con_info->thismsg->target_id = strdup(data);
    } else if (strcmp(key, "REMOTE_IP") == 0) {
        con_info->thismsg->remote_ip = strdup(data);
    } else if (strcmp(key, "REMOTE_PORT") == 0) {
        con_info->thismsg->remote_port = strdup(data);
    } else if (strcmp(key, "HOST_IP") == 0) {
        con_info->thismsg->host_ip = strdup(data);
    } else if (strcmp(key, "HOST_PORT") == 0) {
        con_info->thismsg->host_port = strdup(data);
    } else if (strcmp(key, "DATA_SOURCE") == 0) {
        con_info->thismsg->datasource = strdup(data);
    } else if (strcmp(key, "SESSION_ID") == 0) {
        con_info->thismsg->session_id = strdup(data);
    } else if (strcmp(key, "DIRECTION") == 0) {
        if (strcasecmp(data, "out") == 0) {
            con_info->thismsg->direction = OPENLI_EMAIL_DIRECTION_OUTBOUND;
        } else if (strcasecmp(data, "in") == 0) {
            con_info->thismsg->direction = OPENLI_EMAIL_DIRECTION_INBOUND;
        } else {
            con_info->thismsg->direction = OPENLI_EMAIL_DIRECTION_UNKNOWN;
        }

    } else if (strcmp(key, "TIMESTAMP") == 0) {
        con_info->thismsg->timestamp = strtoul(data, NULL, 10);

    } else if (strcmp(key, "MAIL_ID") == 0) {
        con_info->thismsg->mail_id = strtoul(data, NULL, 10);
    } else if (strcmp(key, "SERVICE") == 0) {

        if (strcasecmp(data, "smtp") == 0) {
            con_info->thismsg->type = OPENLI_EMAIL_TYPE_SMTP;
        } else if (strcasecmp(data, "pop3") == 0) {
            con_info->thismsg->type = OPENLI_EMAIL_TYPE_POP3;
        } else if (strcasecmp(data, "imap") == 0) {
            con_info->thismsg->type = OPENLI_EMAIL_TYPE_IMAP;
        } else {
            con_info->thismsg->type = OPENLI_EMAIL_TYPE_UNKNOWN;
        }


    } else if (strcmp(key, "BYTES") == 0) {
        //con_info->thismsg->msg_length = strtoul(data, NULL, 10);
    } else if (strcmp(key, "BUFFER") == 0) {
        int datalen = 0;

        ptr = (char *)data;
        while (*ptr == 0x0a || *ptr == 0x0d) {
            ptr ++;
        }

        if (*ptr == '\0' || ptr - data >= size) {
            free(con_info->thismsg->content);
            con_info->thismsg->content = NULL;
        }

        datalen = strlen(ptr);
        con_info->thismsg->own_content = 1;
        con_info->thismsg->content = strdup(ptr);
        con_info->thismsg->msg_length = datalen;
    }

    //logger(LOG_INFO, "KEY %s", key);
    //logger(LOG_INFO, "VALUE %s", data);

    con_info->answerstring = completepage;
    con_info->answercode = MHD_HTTP_OK;

    return MHD_YES;

}

static int send_auth_fail_page(struct MHD_Connection *connection,
        const char *page, int invalid_nonce) {

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

    ret = MHD_queue_auth_fail_response(connection, REALM, OPAQUE,
            response, (invalid_nonce == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO);
    MHD_destroy_response(response);
    return ret;
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

    if (con_info->thismsg) {
        int r = 0;
        while (1) {
            r = zmq_send(con_info->parentstate->zmq_publishers[0],
                    &(con_info->thismsg), sizeof(openli_email_captured_t *),
                    0);
            if (r < 0 && errno == EAGAIN) {
                continue;
            }

            if (r < 0) {
                logger(LOG_INFO, "OpenLI: email ingestor thread failed to send captured email to worker thread %d: %s", 0, strerror(errno));
                free_captured_email(con_info->thismsg);
                break;
            }

            break;
        }
    }

    if (con_info->postproc) {
        MHD_destroy_post_processor(con_info->postproc);
        uploading_clients --;
    }

    free(con_info);
    *con_cls = NULL;
}


static MHD_RESULT answer_email_connection(void *cls,
                      struct MHD_Connection *connection,
                      const char *url, const char *method,
                      const char *version, const char *upload_data,
                      size_t *upload_data_size, void **con_cls) {

    email_connection_t *con_info = (email_connection_t *)(*con_cls);
    email_ingestor_state_t *state = (email_ingestor_state_t *)cls;

    if (con_info == NULL) {
        if (state->config->authrequired) {
            char *username;
            int r;

            if (state->config->authpassword == NULL) {
                return send_page(connection, accessdenied,
                        MHD_HTTP_PRECONDITION_FAILED);
            }

            username = MHD_digest_auth_get_username(connection);
            if (username == NULL) {
                return send_auth_fail_page(connection, accessdenied, MHD_NO);
            }

            r = MHD_digest_auth_check(connection, "emailingest@openli.nz",
                    username, state->config->authpassword, 300);
            free(username);

            if (r == MHD_INVALID_NONCE || r == MHD_NO) {
                return send_auth_fail_page(connection, accessdenied, r);
            }

        }

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

        con_info->thismsg = NULL;
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

static void connect_email_worker_sockets(email_ingestor_state_t *state) {

    int i;
    char sockname[256];

    state->zmq_publishers = calloc(state->email_worker_count, sizeof(void *));

    for (i = 0; i < state->email_worker_count; i++) {
        state->zmq_publishers[i] = zmq_socket(state->zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 256, "inproc://openliemailworker-ingest%d", i);
        if (zmq_connect(state->zmq_publishers[i], sockname) != 0) {
            logger(LOG_INFO, "OpenLI: email ingestor thread is unable to connect to RMQ socket for email worker thread %d: %s", i, strerror(errno));
            zmq_close(state->zmq_publishers[i]);
            state->zmq_publishers[i] = NULL;
        }
    }

}

struct MHD_Daemon *start_email_mhd_daemon(openli_email_ingest_config_t *config,
        int sockfd, email_ingestor_state_t *state,
        openli_ssl_config_t *sslconf) {

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

    if (init_email_ingest_state(state, config, sslconf) < 0) {
        close(fd);
        if (state->key_pem) {
            free(state->key_pem);
        }
        if (state->cert_pem) {
            free(state->cert_pem);
        }
        return NULL;
    }
    connect_email_worker_sockets(state);

    if (state->key_pem && state->cert_pem) {
        state->daemon = MHD_start_daemon(
                MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
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
                MHD_OPTION_HTTPS_MEM_KEY,
                state->key_pem,
                MHD_OPTION_HTTPS_MEM_CERT,
                state->cert_pem,
                MHD_OPTION_END);
    } else {

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
    }
    return state->daemon;

}

void stop_email_mhd_daemon(email_ingestor_state_t *state) {
    int i, zero;
    if (state->daemon) {
        MHD_stop_daemon(state->daemon);
    }

    if (state->zmq_publishers) {
        for (i = 0; i < state->email_worker_count; i++) {
            zero = 0;
            zmq_setsockopt(state->zmq_publishers[i],
                    ZMQ_LINGER, &zero, sizeof(zero));
            zmq_close(state->zmq_publishers[i]);
        }
        free(state->zmq_publishers);
    }

    if (state->key_pem) {
        free(state->key_pem);
    }
    if (state->cert_pem) {
        free(state->cert_pem);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
