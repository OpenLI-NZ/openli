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
    int reply_start;

    char *mailbox;
    char *mail_sender;

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

static int parse_pop3_command(pop3_session_t *pop3sess) {


    return 0;
}

static int process_server_indicator(pop3_session_t *pop3sess) {
    int rem = pop3sess->contbufused - pop3sess->reply_start;
    uint8_t *found;

    found = (uint8_t *)memmem(pop3sess->contbuffer + pop3sess->reply_start,
            rem, "+OK ", 4);
    if (found) {
        pop3sess->server_indicator = OPENLI_POP3_SERV_OK;
        return 1;
    }

    found = (uint8_t *)memmem(pop3sess->contbuffer + pop3sess->reply_start,
            rem, "-ERR ", 5);
    if (found) {
        pop3sess->server_indicator = OPENLI_POP3_SERV_ERR;
        return 1;
    }

    return 0;
}

static int is_single_line_response(pop3_session_t *pop3sess) {

    switch (pop3sess->last_command_type) {
        case OPENLI_POP3_COMMAND_RETR:
        case OPENLI_POP3_COMMAND_TOP:
        case OPENLI_POP3_COMMAND_OTHER_MULTI:
            return 1;
    }

    return 0;
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
                return r;
            }
            if (r == 0) {
                sess->currstate = OPENLI_POP3_STATE_CONSUME_SERVER;
            } else {
                sess->currstate = OPENLI_POP3_STATE_SERVER_REPLY;
            }

            break;

        case OPENLI_POP3_STATE_CONSUME_SERVER:
            /* Let's hope we never have to use this case... */
            if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) == 1) {
                sess->currstate = OPENLI_POP3_STATE_WAITING_SERVER;
                pop3sess->reply_start = pop3sess->contbufread;
            }
            break;

        case OPENLI_POP3_STATE_SERVER_REPLY:
            if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) == 1) {
                if (pop3sess->auth_state == OPENLI_POP3_POSTQUIT) {
                    sess->currstate = OPENLI_POP3_STATE_OVER;

                    /* TODO generate email logoff IRI */
                    return 0;
                }

                if (is_single_line_response(pop3sess)) {
                    sess->currstate = OPENLI_POP3_STATE_WAITING_COMMAND;
                    pop3sess->command_start = pop3sess->contbufread;
                } else {
                    sess->currstate = OPENLI_POP3_STATE_MULTI_CONTENT;
                    return 1;
                }

                /* TODO command response is complete -- generate the CCs */

                /* if command was PASS or APOP and server said OK,
                 * generate a login event IRI */
                /* if command was PASS or APOP and server said ERR,
                 * generate a login failed IRI */

            } else if (r < 0) {
                return r;
            }
            break;

        case OPENLI_POP3_STATE_MULTI_CONTENT:
            if ((r = find_multi_end(pop3sess, pop3sess->reply_start)) == 1) {
                pop3sess->command_start = pop3sess->contbufread;
                sess->currstate = OPENLI_POP3_STATE_WAITING_COMMAND;

                if (pop3sess->server_indicator == OPENLI_POP3_SERV_OK) {
                    /* TODO command response is complete -- generate the CCs */

                    /* if command was RETR, generate an email download IRI */

                    /* if command was TOP, generate a partial download IRI */
                }

            } else if (r < 0) {
                return r;
            }
            break;

        case OPENLI_POP3_STATE_WAITING_COMMAND:
            if ((r = find_next_crlf(pop3sess, pop3sess->command_start)) == 1) {
                sess->currstate = OPENLI_POP3_STATE_WAITING_SERVER;
                if (parse_pop3_command(pop3sess) < 0) {
                    return -1;
                }
                pop3sess->reply_start = pop3sess->contbufread;
            }
            break;

        case OPENLI_POP3_STATE_IGNORING:
        case OPENLI_POP3_STATE_OVER:
            return 0;
    }

        /* USER, PASS, QUIT, and APOP are valid here */
        /* STATE, LIST, RETR, DELE, NOOP, RSET, QUIT, TOP, and UIDL are valid */

    return 1;
}

void free_pop3_session_state(emailsession_t *sess, void *pop3state) {
    pop3_session_t *pop3sess;

    if (pop3state == NULL) {
        return;
    }

    pop3sess = (pop3_session_t *)pop3state;
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
