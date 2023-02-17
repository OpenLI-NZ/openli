/*
 *
 * Copyright (c) 2018-2023 The University of Waikato, Hamilton, New Zealand.
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
#include <assert.h>
#include <regex.h>

#include "email_worker.h"
#include "logger.h"


enum {
    OPENLI_POP3_STATE_START,
    OPENLI_POP3_STATE_SERVER_REPLY,
    OPENLI_POP3_STATE_XCLIENT_SEEN,
    OPENLI_POP3_STATE_WAITING_COMMAND,
    OPENLI_POP3_STATE_WAITING_SERVER,
    OPENLI_POP3_STATE_MULTI_CONTENT,
    OPENLI_POP3_STATE_IGNORING,
    OPENLI_POP3_STATE_OVER,
    OPENLI_POP3_STATE_CONSUME_SERVER,
    OPENLI_POP3_STATE_CONSUME_CLIENT,

};

enum {
    OPENLI_POP3_INIT,
    OPENLI_POP3_PREAUTH,
    OPENLI_POP3_POSTAUTH,
    OPENLI_POP3_POSTQUIT,
};

enum {
    OPENLI_POP3_COMMAND_NONE,
    OPENLI_POP3_COMMAND_USER,
    OPENLI_POP3_COMMAND_PASS,
    OPENLI_POP3_COMMAND_APOP,
    OPENLI_POP3_COMMAND_RETR,
    OPENLI_POP3_COMMAND_TOP,
    OPENLI_POP3_COMMAND_QUIT,
    OPENLI_POP3_COMMAND_XCLIENT,
    OPENLI_POP3_COMMAND_OTHER_MULTI,
    OPENLI_POP3_COMMAND_OTHER_SINGLE,
    OPENLI_POP3_COMMAND_UNKNOWN,
};

enum {
    OPENLI_POP3_SERV_OK,
    OPENLI_POP3_SERV_ERR,
};

typedef struct pop3session {

    uint8_t *contbuffer;
    int contbufsize;
    int contbufused;
    int contbufread;

    int auth_state;
    int last_command_type;
    int server_indicator;

    int command_start;
    int command_end;
    int reply_start;

    char *mailbox;
    char *mail_sender;

    char *client_ip;
    char *client_port;
    char *server_ip;
    char *server_port;
    int seen_xclient;
    int seen_xclient_reply;

} pop3_session_t;

/* this is basically a direct copy of the imap version -- maybe we could
 * just have one version of this in utils.c somewhere? XXX
 */
static int append_content_to_pop3_buffer(pop3_session_t *pop3sess,
        openli_email_captured_t *cap) {

    /* +1 to account for a null terminator */
    while (pop3sess->contbufsize - pop3sess->contbufused <=
                cap->msg_length + 1) {
        pop3sess->contbuffer = realloc(pop3sess->contbuffer,
                pop3sess->contbufsize + 4096);
        if (pop3sess->contbuffer == NULL) {
            return -1;
        }
        pop3sess->contbufsize += 4096;
    }

    memcpy(pop3sess->contbuffer + pop3sess->contbufused,
            cap->content, cap->msg_length);
    pop3sess->contbufused += cap->msg_length;
    pop3sess->contbuffer[pop3sess->contbufused] = '\0';

    assert(pop3sess->contbufused <= pop3sess->contbufsize);
    assert(*(pop3sess->contbuffer + pop3sess->contbufread) != 0);
    return 0;
}

static int find_next_crlf(pop3_session_t *pop3sess, int start_index) {
    int rem;
    uint8_t *found;

    assert(pop3sess->contbufused >= start_index);

    rem = pop3sess->contbufused - start_index;

    found = (uint8_t *)memmem(pop3sess->contbuffer + start_index, rem,
            "\r\n", 2);

    if (found) {
        pop3sess->contbufread = (found - pop3sess->contbuffer) + 2;
        return 1;
    }
    return 0;
}

static int find_multi_end(pop3_session_t *pop3sess, int start_index) {
    int rem;
    uint8_t *found;

    assert(pop3sess->contbufused >= start_index);

    rem = pop3sess->contbufused - start_index;

    found = (uint8_t *)memmem(pop3sess->contbuffer + start_index, rem,
            "\r\n.\r\n", 5);

    if (found) {
        pop3sess->contbufread = (found - pop3sess->contbuffer) + 5;
        return 1;
    }
    return 0;
}

static int parse_xclient_content(pop3_session_t *pop3sess) {


    char *xcontent = (char *)pop3sess->contbuffer + pop3sess->command_start;
    int xcontlen = (pop3sess->command_end - pop3sess->command_start) - 2;
    char xcopy[2048];
    int ret = 0;
    char *key, *value, *next;

    char *ptr = xcopy;

    memcpy(xcopy, xcontent, xcontlen);
    xcopy[xcontlen] = '\0';

    /* TODO replace pop3sess->server_port with pop3sess->client_port */

    /* XCLIENT means that the POP3 session has been proxied to mirror it
     * towards us, so what we see as the client is actually the real POP3
     * server and the "server" is just the proxy target.
     */

    /* The real client IP and port will be contained in the XCLIENT
     * message payload, and what we have currently saved as the "client"
     * is more likely to be the real server */

    if (pop3sess->server_port) {
        free(pop3sess->server_port);
    }
    if (pop3sess->server_ip) {
        free(pop3sess->server_ip);
    }
    pop3sess->server_port = pop3sess->client_port;
    pop3sess->client_port = NULL;
    pop3sess->server_ip = pop3sess->client_ip;
    pop3sess->client_ip = NULL;

    while (ptr) {
        if (*ptr == '\r' || *ptr == '\n' || *ptr == '\0') {
            break;
        }
        next = strchr(ptr, ' ');
        key = ptr;

        value = strchr(ptr, '=');
        if (value == NULL) {
            ret = -1;
            break;
        }

        if (next != NULL && next < value) {
            if (key == xcopy) {
                /* this is the XCLIENT command itself */
                ptr = next + 1;
                continue;
            }
            return -1;
        }

        *value = '\0';
        value ++;

        if (next) {
            *next = '\0';
            next ++;
        }
        ptr = next;

        if (strcmp(key, "ADDR") == 0) {
            pop3sess->client_ip = strdup(value);
        }

        if (strcmp(key, "PORT") == 0) {
            pop3sess->client_port = strdup(value);
        }

    }

    return ret;

}

static int parse_pop3_command(pop3_session_t *pop3sess) {

    int comm_size = (pop3sess->contbufread - pop3sess->command_start) - 2;
    char comm_copy[1024];
    assert(pop3sess->contbufread > (pop3sess->command_start + 2));

    if (comm_size >= 1024) {
        comm_size = 1023;
    }

    memcpy(comm_copy, pop3sess->contbuffer + pop3sess->command_start, comm_size);
    comm_copy[comm_size] = '\0';

    printf("%s\n", comm_copy);

    if (strncmp(comm_copy, "CAPA", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_MULTI;
    }
    else if (strncmp(comm_copy, "XCLIENT ", 8) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_XCLIENT;
    }
    else if (strncmp(comm_copy, "USER ", 5) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_USER;
    }
    else if (strncmp(comm_copy, "PASS ", 5) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_PASS;
    }
    else if (strncmp(comm_copy, "RETR ", 5) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_RETR;
    }
    else if (strncmp(comm_copy, "TOP ", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_TOP;
    }
    else if (strncmp(comm_copy, "LIST", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_MULTI;
    }
    else if (strncmp(comm_copy, "APOP ", 5) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_APOP;
    }
    else if (strncmp(comm_copy, "NOOP", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_SINGLE;
    }
    else if (strncmp(comm_copy, "RSET", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_SINGLE;
    }
    else if (strncmp(comm_copy, "STAT", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_SINGLE;
    }
    else if (strncmp(comm_copy, "UIDL", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_MULTI;
    }
    else if (strncmp(comm_copy, "DELE ", 5) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_SINGLE;
    }
    else if (strncmp(comm_copy, "QUIT", 4) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_QUIT;
        pop3sess->auth_state = OPENLI_POP3_POSTQUIT;
    }

    return 0;
}

static int process_server_indicator(pop3_session_t *pop3sess) {
    int rem = pop3sess->contbufused - pop3sess->reply_start;
    uint8_t *found;

    if (rem < 3) {
        return -1;
    }

    found = (uint8_t *)memmem(pop3sess->contbuffer + pop3sess->reply_start,
            rem, "+OK", 3);
    if (found) {
        pop3sess->server_indicator = OPENLI_POP3_SERV_OK;
        return 1;
    }

    if (rem < 4) {
        return -1;
    }

    found = (uint8_t *)memmem(pop3sess->contbuffer + pop3sess->reply_start,
            rem, "-ERR", 4);
    if (found) {
        pop3sess->server_indicator = OPENLI_POP3_SERV_ERR;
        return 1;
    }

    if (pop3sess->last_command_type != OPENLI_POP3_COMMAND_XCLIENT) {
        printf("%d \"%s\"\n", rem, (char *) pop3sess->contbuffer + pop3sess->reply_start);

        printf("?WHAT\n");
    }
    return 0;
}

static int is_single_line_response(pop3_session_t *pop3sess) {

    switch (pop3sess->last_command_type) {
        case OPENLI_POP3_COMMAND_RETR:
        case OPENLI_POP3_COMMAND_TOP:
        case OPENLI_POP3_COMMAND_OTHER_MULTI:
            return 0;
    }

    return 1;
}

static int handle_xclient_seen_state(emailsession_t *sess,
        pop3_session_t *pop3sess) {

    int r;
    /* We might get a server reply, or the proxy might just
     * carry on and forward the next client command -- who knows?
     */
    r = process_server_indicator(pop3sess);
    if (r < 0) {
        return 0;
    }
    if (r == 1) {
        sess->currstate = OPENLI_POP3_STATE_SERVER_REPLY;
    } else {
        /* Must be a command instead? */
        sess->currstate = OPENLI_POP3_STATE_WAITING_COMMAND;
        pop3sess->command_start = pop3sess->reply_start;
        return 1;
    }

    return 0;
}

static int handle_multi_reply_state(emailsession_t *sess,
        pop3_session_t *pop3sess) {

    int r;

    if ((r = find_multi_end(pop3sess, pop3sess->reply_start)) < 0) {
        return r;
    }

    /* TODO command response is complete -- generate the CCs */
    if (pop3sess->server_indicator == OPENLI_POP3_SERV_OK) {

        /* if command was RETR, generate an email download IRI */
        /* if command was TOP, generate a partial download IRI */
        if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_RETR) {
            printf("email download IRI\n");
        } else if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_TOP) {
            printf("partial download IRI\n");
        }

    }
    printf("CCs REQUIRED for completed multi command\n");

    pop3sess->command_start = pop3sess->contbufread;
    sess->currstate = OPENLI_POP3_STATE_WAITING_COMMAND;

    return 1;
}

static int handle_client_command(emailsession_t *sess,
        pop3_session_t *pop3sess) {

    int r;

    if ((r = find_next_crlf(pop3sess, pop3sess->command_start)) <= 0) {
        return r;
    }

    if (parse_pop3_command(pop3sess) < 0) {
        return -1;
    }
    pop3sess->command_end = pop3sess->contbufread;
    pop3sess->reply_start = pop3sess->contbufread;
    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_XCLIENT)
    {
        sess->currstate = OPENLI_POP3_STATE_XCLIENT_SEEN;
        pop3sess->seen_xclient = 1;

        if (parse_xclient_content(pop3sess) < 0) {
            return -1;
        }
    } else {
        sess->currstate = OPENLI_POP3_STATE_WAITING_SERVER;
    }
    return 1;
}


static int handle_server_reply_state(emailsession_t *sess,
        pop3_session_t *pop3sess) {

    int r;

    if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) <= 0) {
        return r;
    }

    /* Server reply line is complete */

    if (pop3sess->auth_state == OPENLI_POP3_POSTQUIT) {
        sess->currstate = OPENLI_POP3_STATE_OVER;

        /* TODO generate email logoff IRI */
        printf("LOGOFF\n");
        return 0;
    }

    /* If our last command is one that will produce multi-line responses,
     * then we need to keep parsing lines until we see a line with just
     * a full stop
     */
    if (is_single_line_response(pop3sess)) {
        if (pop3sess->seen_xclient && !pop3sess->seen_xclient_reply) {
            /* This is the first reply since we saw XCLIENT */
            pop3sess->seen_xclient_reply = 1;
            if (pop3sess->last_command_type != OPENLI_POP3_COMMAND_XCLIENT) {
                /* We saw another command before we saw this reply, so we
                 * now need to wait for the reply to that subsequent
                 * command
                 */
                sess->currstate = OPENLI_POP3_STATE_WAITING_SERVER;
                pop3sess->reply_start = pop3sess->contbufread;
                return 1;
            }

            /* Otherwise, the XCLIENT reply was the first thing we
             * saw after the XCLIENT command, so we can carry on
             * normally and expect a client command next.
             */
        }

        sess->currstate = OPENLI_POP3_STATE_WAITING_COMMAND;
        pop3sess->command_start = pop3sess->contbufread;

    } else {
        sess->currstate = OPENLI_POP3_STATE_MULTI_CONTENT;
        return 1;
    }

    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_PASS ||
            pop3sess->last_command_type ==
            OPENLI_POP3_COMMAND_APOP) {

        /* This is the reply for a login attempt, so we'll need to
         * publish an IRI
         */
        if (pop3sess->server_indicator == OPENLI_POP3_SERV_OK) {
            pop3sess->auth_state = OPENLI_POP3_POSTAUTH;

            printf("LOGIN\n");
        } else {
            printf("LOGIN FAIL\n");
        }
    }

    /* TODO command response is complete -- generate the CCs */
    if (pop3sess->last_command_type != OPENLI_POP3_COMMAND_NONE &&
            pop3sess->last_command_type != OPENLI_POP3_COMMAND_XCLIENT) {
        printf("CCs REQUIRED for completed command\n");
    }

    return 1;
}

static int process_next_pop3_line(openli_email_worker_t *state,
        emailsession_t *sess, pop3_session_t *pop3sess, uint64_t timestamp) {

    int r;

    switch(sess->currstate) {
        case OPENLI_POP3_STATE_START:
            pop3sess->reply_start = pop3sess->contbufread;

            // fall through
        case OPENLI_POP3_STATE_WAITING_SERVER:

            r = process_server_indicator(pop3sess);
            if (r < 0) {
                return 0;
            }
            if (r == 0) {
                sess->currstate = OPENLI_POP3_STATE_CONSUME_SERVER;
            } else {
                sess->currstate = OPENLI_POP3_STATE_SERVER_REPLY;
            }

            break;

        case OPENLI_POP3_STATE_XCLIENT_SEEN:
            r = handle_xclient_seen_state(sess, pop3sess);
            return r;


        case OPENLI_POP3_STATE_CONSUME_SERVER:
            /* Let's hope we never have to use this case... */
            if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) == 1) {
                sess->currstate = OPENLI_POP3_STATE_WAITING_SERVER;
                pop3sess->reply_start = pop3sess->contbufread;
                return 1;
            }
            break;

        case OPENLI_POP3_STATE_SERVER_REPLY:
            r = handle_server_reply_state(sess, pop3sess);
            return r;

        case OPENLI_POP3_STATE_MULTI_CONTENT:
            r = handle_multi_reply_state(sess, pop3sess);
            return r;

        case OPENLI_POP3_STATE_WAITING_COMMAND:
            r = handle_client_command(sess, pop3sess);
            return r;

        case OPENLI_POP3_STATE_IGNORING:
        case OPENLI_POP3_STATE_OVER:
            return 0;
    }


    return 0;
}

void free_pop3_session_state(emailsession_t *sess, void *pop3state) {
    pop3_session_t *pop3sess;

    if (pop3state == NULL) {
        return;
    }

    pop3sess = (pop3_session_t *)pop3state;
    if (pop3sess->server_ip) {
        free(pop3sess->server_ip);
    }
    if (pop3sess->server_port) {
        free(pop3sess->server_port);
    }
    if (pop3sess->client_ip) {
        free(pop3sess->client_ip);
    }
    if (pop3sess->client_port) {
        free(pop3sess->client_port);
    }
    if (pop3sess->mailbox) {
        free(pop3sess->mailbox);
    }
    if (pop3sess->mail_sender) {
        free(pop3sess->mail_sender);
    }
    free(pop3sess->contbuffer);
    free(pop3sess);

}

int update_pop3_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap) {

    pop3_session_t *pop3sess;
    int r;

    if (sess->proto_state == NULL) {
        pop3sess = calloc(1, sizeof(pop3_session_t));
        pop3sess->contbuffer = calloc(2048, sizeof(uint8_t));
        pop3sess->contbufused = 0;
        pop3sess->contbufread = 0;
        pop3sess->contbufsize = 2048;
        pop3sess->auth_state = OPENLI_POP3_INIT;
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_NONE;

        pop3sess->server_port = strdup(cap->host_port);
        pop3sess->server_ip = strdup(cap->host_ip);
        pop3sess->client_port = strdup(cap->remote_port);
        pop3sess->client_ip = strdup(cap->remote_ip);

        sess->currstate = OPENLI_POP3_STATE_START;

        sess->proto_state = (void *)pop3sess;
    } else {
        pop3sess = (pop3_session_t *)sess->proto_state;
    }

    if (sess->currstate == OPENLI_POP3_STATE_IGNORING) {
        return 0;
    }

    if (append_content_to_pop3_buffer(pop3sess, cap) < 0) {
        logger(LOG_INFO, "OpenLI: Failed to append POP3 message content to session buffer for %s", sess->key);
        return -1;
    }

    while (1) {
        if ((r = process_next_pop3_line(state, sess, pop3sess,
                cap->timestamp)) <= 0) {
            break;
        }
        if (sess->currstate == OPENLI_POP3_STATE_IGNORING) {
            break;
        }
    }

    if (sess->currstate == OPENLI_POP3_STATE_OVER) {
        return 1;
    }
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
