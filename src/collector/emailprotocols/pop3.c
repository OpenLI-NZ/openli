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
#include <b64/cdecode.h>

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
    OPENLI_POP3_STATE_AUTH,
    OPENLI_POP3_STATE_AUTH_SERVER_CONTENT,
    OPENLI_POP3_STATE_AUTH_CLIENT_CONTENT,
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
    OPENLI_POP3_COMMAND_AUTH,
    OPENLI_POP3_COMMAND_QUIT,
    OPENLI_POP3_COMMAND_XCLIENT,
    OPENLI_POP3_COMMAND_OTHER_MULTI,
    OPENLI_POP3_COMMAND_OTHER_SINGLE,
    OPENLI_POP3_COMMAND_UNKNOWN,
};

enum {
    OPENLI_POP3_SERV_OK,
    OPENLI_POP3_SERV_ERR,
    OPENLI_POP3_SERV_AUTH,
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

    int auth_read_from;
    openli_email_auth_type_t auth_type;

    char *mailbox;
    char *mail_sender;
    char *password_content;

    char *client_ip;
    char *client_port;
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

    return 0;
}

static int decode_login_username_command(emailsession_t *sess,
        pop3_session_t *pop3sess) {

    char *usermsg;
    int msglen;
    char *username;

    // strip \r\n from end of command
    msglen = pop3sess->command_end - pop3sess->command_start - 2;
    usermsg = calloc(msglen + 1, sizeof(char));

    memcpy(usermsg, pop3sess->contbuffer + pop3sess->command_start,
            msglen);

    username = strchr(usermsg, ' ');
    if (username == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse POP3 USER command -- no space found in command (\"%s\")", usermsg);
        free(usermsg);
        return -1;
    }

    username += 1;
    pop3sess->mailbox = strdup(username);
    add_email_participant(sess, pop3sess->mailbox, 0);
    free(usermsg);
    return 1;
}

static int update_auth_command(pop3_session_t *pop3sess, char *replace,
        const char *origtoken, int origtoklen, const char *sesskey) {

    char *ptr;
    int replacelen;

    ptr = strstr((const char *)(pop3sess->contbuffer +
            pop3sess->auth_read_from), origtoken);
    if (!ptr) {
        logger(LOG_INFO, "OpenLI: cannot find original auth token for POP3 AUTH command, session %s", sesskey);
        return -1;
    }

    replacelen = strlen(replace);
    if (replacelen + 2 > origtoklen) {
        logger(LOG_INFO, "OpenLI: cannot replace original auth token for POP3 AUTH command -- new token is longer than the original (session %s)", sesskey);
        return 0;
    }

    memcpy(ptr, replace, replacelen);
    ptr += replacelen;
    *ptr = '\r'; ptr ++;
    *ptr = '\n'; ptr ++;

    /* wipe any remaining original token bytes, just to be safe */
    memset(ptr, 0, origtoklen - (replacelen + 2));

    pop3sess->command_end -= (origtoklen - (replacelen + 2));

    return 1;
}

static int decode_plain_auth_content(char *authmsg, pop3_session_t *pop3sess,
        emailsession_t *sess) {

    char decoded[2048];
    char reencoded[2048];
    char *ptr;
    int cnt, r;
    char *crlf;
    base64_decodestate s;

    if (*authmsg == '\0') {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_NONE;
        sess->currstate = OPENLI_POP3_STATE_AUTH;
        return 0;
    }

    crlf = strstr(authmsg, "\r\n");
    if (crlf == NULL) {
        return 0;
    }

    /* auth plain can be split across two messages with a
     * "+" from the server in between :( */

    if (*authmsg == '+') {
        /* Client has not yet sent the auth token, so this line is
         * the server indicating that it is waiting for the token.
         * Skip the "+" line and remain in auth command state until
         * the token arrives.
         */
        pop3sess->auth_read_from += ((crlf - authmsg) + 2);
        sess->server_octets += ((crlf - authmsg) + 2);
        return 0;
    }

    base64_init_decodestate(&s);
    cnt = base64_decode_block(authmsg, strlen(authmsg), decoded, &s);
    if (cnt == 0) {
        return 0;
    }
    decoded[cnt] = '\0';

    if (decoded[0] == '\0') {
        ptr = decoded + 1;
    } else {
        ptr = decoded;
    }
    /* username and password are also inside 'decoded', each term is
     * separated by null bytes (e.g. <mailbox> \0 <username> \0 <password>)
     */
    pop3sess->mailbox = strdup(ptr);
    add_email_participant(sess, pop3sess->mailbox, 0);

    /* replace encoded credentials, if requested by the user */
    if (sess->mask_credentials) {
        mask_plainauth_creds(pop3sess->mailbox, reencoded, 2048);
        /* replace saved command with re-encoded auth token */
        r = update_auth_command(pop3sess, reencoded, authmsg, crlf - authmsg,
                sess->key);
        if (r < 0) {
            return r;
        }
        sess->client_octets += strlen(reencoded);
    } else {
        sess->client_octets += strlen(authmsg);
    }

    return 1;


}

static inline char *clone_authentication_message(pop3_session_t *pop3sess,
        int msglen) {
    char *authmsg;
    authmsg = calloc(msglen + 1, sizeof(uint8_t));
    memcpy(authmsg, pop3sess->contbuffer + pop3sess->auth_read_from, msglen);
    return authmsg;
}

static int decode_auth_command(emailsession_t *sess, pop3_session_t *pop3sess) {
    /* this command is essentially a clone of the IMAP AUTH command, so
     * we can handle it using very similar code...
     */

    char *authmsg;
    int msglen, r;

    while (1) {
        if (pop3sess->auth_read_from >= pop3sess->contbufused) {
            pop3sess->last_command_type = OPENLI_POP3_COMMAND_NONE;
            pop3sess->command_start = 0;
            pop3sess->reply_start = 0;
            return 0;
        }
        msglen = pop3sess->contbufread - pop3sess->auth_read_from;
        authmsg = clone_authentication_message(pop3sess, msglen);

        if (pop3sess->auth_type == OPENLI_EMAIL_AUTH_NONE) {
            r = get_email_authentication_type(authmsg, sess->key,
                    &(pop3sess->auth_type), 0);
            if (r > 0) {
                sess->client_octets -= msglen;
                sess->client_octets += r;
                pop3sess->auth_read_from += r;
            }
            free(authmsg);
            if (r < 0) {
                sess->currstate = OPENLI_POP3_STATE_IGNORING;
            }
            if (r <= 0) {
                break;
            }
            continue;
        }

        /* TODO support other AUTH types? */
        if (pop3sess->auth_type == OPENLI_EMAIL_AUTH_PLAIN) {
            r = decode_plain_auth_content(authmsg, pop3sess, sess);
            free(authmsg);
            return r;
        } else {
            free(authmsg);
            return -1;
        }
    }
    return 1;

}

static int decode_login_apop_command(emailsession_t *sess,
        pop3_session_t *pop3sess) {

    char *usermsg;
    int msglen;
    char *username;
    char *username_end;

    // strip \r\n from end of command
    msglen = pop3sess->command_end - pop3sess->command_start - 2;
    usermsg = calloc(msglen + 1, sizeof(char));

    memcpy(usermsg, pop3sess->contbuffer + pop3sess->command_start,
            msglen);

    username = strchr(usermsg, ' ');
    if (username == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse POP3 APOP command -- no space found in command (\"%s\")", usermsg);
        return -1;
    }

    username += 1;


    username_end = strchr(username, ' ');
    if (username_end == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse POP3 APOP command -- not enough terms in command (\"%s\")", usermsg);
        return -1;
    }

    pop3sess->mailbox = strndup(username, username_end - username);
    add_email_participant(sess, pop3sess->mailbox, 0);
    return 1;
}

static int save_pop3_password(emailsession_t *sess, pop3_session_t *pop3sess) {

    if (sess->mask_credentials) {
        /* Replace the password with 'XXX' */
        pop3sess->password_content = strdup("PASS XXX\r\n");
    } else {
        int msglen = pop3sess->command_end - pop3sess->command_start;
        pop3sess->password_content = calloc(msglen + 1, sizeof(char));

        memcpy(pop3sess->password_content,
                pop3sess->contbuffer + pop3sess->command_start, msglen);
    }

    return 1;
}

static int find_next_crlf(pop3_session_t *pop3sess, int start_index) {
    int rem;
    uint8_t *found;

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

    rem = pop3sess->contbufused - start_index;

    found = (uint8_t *)memmem(pop3sess->contbuffer + start_index, rem,
            "\r\n.\r\n", 5);

    if (found) {
        pop3sess->contbufread = (found - pop3sess->contbuffer) + 5;
        return 1;
    }
    return 0;
}

static int parse_xclient_content(emailsession_t *sess,
        pop3_session_t *pop3sess) {


    char *xcontent = (char *)pop3sess->contbuffer + pop3sess->command_start;
    int xcontlen = (pop3sess->command_end - pop3sess->command_start) - 2;
    char xcopy[2048];
    int ret = 0;
    char *key, *value, *next;

    char *ptr = xcopy;

    memcpy(xcopy, xcontent, xcontlen);
    xcopy[xcontlen] = '\0';

    /* The real client IP and port will be contained in the XCLIENT
     * message payload -- we don't know the "real" server for sure,
     * though so let's just use the server that received the XCLIENT
     * message instead */

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
            if (pop3sess->client_ip) {
                free(pop3sess->client_ip);
            }
            pop3sess->client_ip = strdup(value);
        }

        if (strcmp(key, "PORT") == 0) {
            if (pop3sess->client_port) {
                free(pop3sess->client_port);
            }
            pop3sess->client_port = strdup(value);
        }
        replace_email_session_clientaddr(sess, pop3sess->client_ip,
                pop3sess->client_port);
    }

    return ret;

}

static int parse_pop3_command(pop3_session_t *pop3sess) {

    int comm_size = (pop3sess->contbufread - pop3sess->command_start) - 2;
    char comm_copy[1024];

    if (comm_size >= 1024) {
        comm_size = 1023;
    }

    memcpy(comm_copy, pop3sess->contbuffer + pop3sess->command_start, comm_size);
    comm_copy[comm_size] = '\0';

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
    else if (strncmp(comm_copy, "AUTH ", 5) == 0) {
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_AUTH;
        pop3sess->auth_read_from = pop3sess->command_start;
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
    } else {
        /* Unknown command -- let's guess a single line reply and pray */
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_OTHER_SINGLE;
    }

    return 0;
}

static int process_server_indicator(emailsession_t *sess,
        pop3_session_t *pop3sess, int isauth) {
    int rem = pop3sess->contbufused - pop3sess->reply_start;
    uint8_t *found;

    if (isauth) {
        if (rem < 2) {
            return -1;
        }

        if (memcmp(pop3sess->contbuffer + pop3sess->reply_start,
                "+ ", 2) == 0) {
            pop3sess->server_indicator = OPENLI_POP3_SERV_AUTH;
            return 1;
        }
    }


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
        logger(LOG_INFO, "OpenLI: unexpected server reply observed for POP3 session '%s'", sess->key);
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
    r = process_server_indicator(sess, pop3sess, 0);
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

static int extract_pop3_email_sender(openli_email_worker_t *state,
        emailsession_t *sess, pop3_session_t *pop3sess) {

    int r;
    char *extracted = NULL;
    char *safecopy;
    int copylen;
    char *search = (char *)(pop3sess->contbuffer + pop3sess->reply_start);
    char *end = (char *)(pop3sess->contbuffer + pop3sess->contbufread);

    copylen = (end - search) + 1;
    safecopy = calloc(sizeof(char), copylen);
    memcpy(safecopy, search, (end - search));

    r = extract_email_sender_from_body(state, sess, safecopy, &extracted);

    if (r == 0 || extracted == NULL) {
        free(safecopy);
        return r;
    }

    pop3sess->mail_sender = extracted;
    add_email_participant(sess, pop3sess->mail_sender, 1);
    free(safecopy);

    return r;
}

static int handle_multi_reply_state(openli_email_worker_t *state,
        emailsession_t *sess, pop3_session_t *pop3sess, uint64_t timestamp) {

    int r;

    if ((r = find_multi_end(pop3sess, pop3sess->reply_start)) <= 0) {
        return r;
    }

    sess->server_octets += (pop3sess->contbufread - pop3sess->reply_start);

    /* TODO command response is complete -- generate the CCs */
    if (pop3sess->server_indicator == OPENLI_POP3_SERV_OK) {
        sess->event_time = timestamp;
        /* if command was RETR, generate an email download IRI */
        /* if command was TOP, generate a partial download IRI */
        if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_RETR) {
            extract_pop3_email_sender(state, sess, pop3sess);
            generate_email_download_success_iri(state, sess, pop3sess->mailbox);
        } else if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_TOP) {
            extract_pop3_email_sender(state, sess, pop3sess);
            generate_email_partial_download_success_iri(state, sess,
                    pop3sess->mailbox);
        }

        /* free the sender so we don't include it in future IRIs where
         * it is not relevant (e.g. logoff)
         */
        if (pop3sess->mail_sender) {
            clear_email_sender(sess);
            /* the memory is freed inside clear_email_sender()... */
            pop3sess->mail_sender = NULL;
        }

    }
    generate_email_cc_from_pop3_payload(state, sess,
                pop3sess->contbuffer + pop3sess->command_start,
                pop3sess->command_end - pop3sess->command_start,
                timestamp, ETSI_DIR_FROM_TARGET);
    generate_email_cc_from_pop3_payload(state, sess,
            pop3sess->contbuffer + pop3sess->reply_start,
            pop3sess->contbufread - pop3sess->reply_start,
            timestamp, ETSI_DIR_TO_TARGET);
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

    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_PASS &&
            sess->mask_credentials) {
        sess->client_octets += 10;
    } else {
        sess->client_octets += (pop3sess->contbufread - pop3sess->command_start);
    }
    pop3sess->command_end = pop3sess->contbufread;
    pop3sess->reply_start = pop3sess->contbufread;
    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_XCLIENT)
    {
        sess->currstate = OPENLI_POP3_STATE_XCLIENT_SEEN;
        pop3sess->seen_xclient = 1;

        if (parse_xclient_content(sess, pop3sess) < 0) {
            return -1;
        }
    } else if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_AUTH) {
        sess->currstate = OPENLI_POP3_STATE_AUTH;
        if (decode_auth_command(sess, pop3sess) < 0) {
            return -1;
        }
    } else {
        sess->currstate = OPENLI_POP3_STATE_WAITING_SERVER;
    }

    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_USER) {
        if (decode_login_username_command(sess, pop3sess) < 0) {
            return -1;
        }
    }

    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_APOP) {
        if (decode_login_apop_command(sess, pop3sess) < 0) {
            return -1;
        }
    }

    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_PASS) {
        if (save_pop3_password(sess, pop3sess) < 0) {
            return -1;
        }
    }

    return 1;
}


static int handle_server_reply_state(openli_email_worker_t *state,
        emailsession_t *sess, pop3_session_t *pop3sess, uint64_t timestamp) {

    int r = 1;

    if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) <= 0) {
        return r;
    }

    /* Server reply line is complete */

    sess->server_octets += (pop3sess->contbufread - pop3sess->reply_start);

    if (pop3sess->auth_state == OPENLI_POP3_POSTQUIT) {
        sess->currstate = OPENLI_POP3_STATE_OVER;
        sess->event_time = timestamp;
        /* generate email logoff IRI */
        generate_email_logoff_iri(state, sess);
    }
    /* If our last command is one that will produce multi-line responses,
     * then we need to keep parsing lines until we see a line with just
     * a full stop
     */
    else if (is_single_line_response(pop3sess)) {
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

    } else {
        sess->currstate = OPENLI_POP3_STATE_MULTI_CONTENT;
        return 1;
    }

    if (pop3sess->last_command_type == OPENLI_POP3_COMMAND_PASS ||
            pop3sess->last_command_type ==
            OPENLI_POP3_COMMAND_APOP ||
            pop3sess->last_command_type == OPENLI_POP3_COMMAND_AUTH) {

        /* This is the reply for a login attempt, so we'll need to
         * publish an IRI
         */
        if (pop3sess->server_indicator == OPENLI_POP3_SERV_OK) {
            pop3sess->auth_state = OPENLI_POP3_POSTAUTH;
            sess->login_time = timestamp;
            generate_email_login_success_iri(state, sess, pop3sess->mailbox);
        } else {
            generate_email_login_failure_iri(state, sess, pop3sess->mailbox);
        }
    }

    /* TODO command response is complete -- generate the CCs */
    if (pop3sess->last_command_type != OPENLI_POP3_COMMAND_NONE &&
            pop3sess->last_command_type != OPENLI_POP3_COMMAND_XCLIENT) {

        if (pop3sess->last_command_type != OPENLI_POP3_COMMAND_PASS) {
            generate_email_cc_from_pop3_payload(state, sess,
                    pop3sess->contbuffer + pop3sess->command_start,
                    pop3sess->command_end - pop3sess->command_start,
                    timestamp, ETSI_DIR_FROM_TARGET);
        } else {
            generate_email_cc_from_pop3_payload(state, sess,
                    (uint8_t *)pop3sess->password_content,
                    strlen(pop3sess->password_content),
                    timestamp, ETSI_DIR_FROM_TARGET);
        }


        generate_email_cc_from_pop3_payload(state, sess,
                pop3sess->contbuffer + pop3sess->reply_start,
                pop3sess->contbufread - pop3sess->reply_start,
                timestamp, ETSI_DIR_TO_TARGET);

    }

    pop3sess->command_start = pop3sess->contbufread;
    return r;
}

static int process_next_pop3_line(openli_email_worker_t *state,
        emailsession_t *sess, pop3_session_t *pop3sess, uint64_t timestamp) {

    int r;

    switch(sess->currstate) {
        case OPENLI_POP3_STATE_START:
            pop3sess->reply_start = pop3sess->contbufread;

            // fall through
        case OPENLI_POP3_STATE_WAITING_SERVER:
            r = process_server_indicator(sess, pop3sess, 0);
            if (r < 0) {
                return 0;
            }
            if (r == 0) {
                sess->currstate = OPENLI_POP3_STATE_CONSUME_SERVER;
            } else {
                sess->currstate = OPENLI_POP3_STATE_SERVER_REPLY;
            }

            return 1;

        case OPENLI_POP3_STATE_XCLIENT_SEEN:
            r = handle_xclient_seen_state(sess, pop3sess);
            return r;

        case OPENLI_POP3_STATE_AUTH:
            r = process_server_indicator(sess, pop3sess, 1);
            if (r < 0) {
                return 0;
            }
            if (r == 0) {
                logger(LOG_INFO, "OpenLI: POP3 session '%s' has bogus authentication exchange -- ignoring for our sanity", sess->key);
                sess->currstate = OPENLI_POP3_STATE_IGNORING;
                return -1;
            }
            if (pop3sess->server_indicator == OPENLI_POP3_SERV_AUTH) {
                sess->currstate = OPENLI_POP3_STATE_AUTH_SERVER_CONTENT;
            } else {
                sess->currstate = OPENLI_POP3_STATE_SERVER_REPLY;
            }
            return 1;

        case OPENLI_POP3_STATE_AUTH_SERVER_CONTENT:
            /* TODO figure out a way to do CCs properly in this state */
            if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) == 1) {
                sess->currstate = OPENLI_POP3_STATE_AUTH_CLIENT_CONTENT;
                pop3sess->reply_start = pop3sess->contbufread;
                return 1;
            }
            break;

        case OPENLI_POP3_STATE_AUTH_CLIENT_CONTENT:
            /* TODO figure out a way to do CCs properly in this state */
            if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) == 1) {
                sess->currstate = OPENLI_POP3_STATE_AUTH;
                pop3sess->reply_start = pop3sess->contbufread;
                return 1;
            }
            break;

        case OPENLI_POP3_STATE_CONSUME_SERVER:
            /* Let's hope we never have to use this case... */
            if ((r = find_next_crlf(pop3sess, pop3sess->reply_start)) == 1) {
                sess->currstate = OPENLI_POP3_STATE_WAITING_SERVER;
                pop3sess->reply_start = pop3sess->contbufread;
                return 1;
            }
            break;

        case OPENLI_POP3_STATE_SERVER_REPLY:
            r = handle_server_reply_state(state, sess, pop3sess, timestamp);
            return r;

        case OPENLI_POP3_STATE_MULTI_CONTENT:
            r = handle_multi_reply_state(state, sess, pop3sess, timestamp);
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
    if (pop3sess->client_ip) {
        free(pop3sess->client_ip);
    }
    if (pop3sess->client_port) {
        free(pop3sess->client_port);
    }
    if (pop3sess->password_content) {
        free(pop3sess->password_content);
    }

    /* Don't free 'mailbox' or 'mail_sender', as these are owned by the
     * participant list for the overall email session.
     */


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
        pop3sess->auth_type = OPENLI_EMAIL_AUTH_NONE;
        pop3sess->auth_read_from = 0;
        pop3sess->last_command_type = OPENLI_POP3_COMMAND_NONE;

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
