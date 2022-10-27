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

#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <regex.h>

#include "email_worker.h"
#include "logger.h"

enum {
    OPENLI_IMAP_COMMAND_NONE = 0,
    OPENLI_IMAP_COMMAND_SERVREADY,
    OPENLI_IMAP_COMMAND_REPLY,
    OPENLI_IMAP_COMMAND_REPLY_ONGOING,
    OPENLI_IMAP_COMMAND_BYE,
    OPENLI_IMAP_COMMAND_GENERIC,
    OPENLI_IMAP_COMMAND_PREAUTH,
    OPENLI_IMAP_COMMAND_AUTH,
    OPENLI_IMAP_COMMAND_LOGOUT,
    OPENLI_IMAP_COMMAND_IDLE,
    OPENLI_IMAP_COMMAND_ID,
};

typedef struct imap_cc_index {

    int cc_start;
    int cc_end;
    uint8_t dir;

} imap_cc_index_t;

typedef struct imap_comm {
    uint8_t *commbuffer;
    int commbufsize;
    int commbufused;

    char *imap_command;
    char *tag;
    char *imap_reply;

    imap_cc_index_t *ccs;
    int cc_used;
    int cc_alloc;

    int reply_start;
    int reply_end;
} imap_command_t;

typedef struct imapsession {

    uint8_t *contbuffer;
    int contbufsize;
    int contbufused;
    int contbufread;

    imap_command_t *commands;
    int commands_size;

    char *auth_tag;

    int reply_start;
    int next_comm_start;
    uint8_t next_command_type;
    char *next_comm_tag;
    char *next_command_name;

    int idle_command_index;
    int auth_command_index;

} imap_session_t;

static void init_imap_command(imap_command_t *comm) {
    comm->commbuffer = calloc(4096, sizeof(uint8_t));
    comm->commbufsize = 4096;
    comm->commbufused = 0;
    comm->tag = NULL;
    comm->imap_reply = NULL;
    comm->imap_command = NULL;

    comm->reply_start = 0;
    comm->reply_end = 0;

    comm->ccs = calloc(8, sizeof(imap_cc_index_t));
    comm->cc_used = 0;
    comm->cc_alloc = 8;
};

static inline int extend_command_buffer(imap_command_t *comm, int required) {
    while (comm->commbufsize - comm->commbufused <= required + 1) {
        comm->commbuffer = realloc(comm->commbuffer, comm->commbufsize + 4096);
        if (comm->commbuffer == NULL) {
            return -1;
        }
        comm->commbufsize += 4096;
    }
    return 0;
}

static void add_cc_to_imap_command(imap_command_t *comm, int start_ind,
        int end_ind, uint8_t dir) {

    /* dir 1 == from client (COMMAND), dir 0 == from server (RESPONSE) */
    if (comm->cc_alloc == comm->cc_used) {
        comm->ccs = realloc(comm->ccs,
            (comm->cc_alloc + 8) * sizeof(imap_cc_index_t));
        comm->cc_alloc += 8;
    }

    comm->ccs[comm->cc_used].cc_start = start_ind;
    comm->ccs[comm->cc_used].cc_end = end_ind;
    comm->ccs[comm->cc_used].dir = dir;

    comm->cc_used ++;

}

static int save_imap_command(imap_session_t *sess, char *sesskey) {

    int i, index;
    int comm_start;

    imap_command_t *comm = NULL;

    for (i = 0; i < sess->commands_size; i++) {
        if (sess->commands[i].imap_command == OPENLI_IMAP_COMMAND_NONE) {
            comm = &(sess->commands[i]);
            index = i;
            break;
        }
    }

    if (comm == NULL) {
        sess->commands = realloc(sess->commands,
                (sess->commands_size + 5) * sizeof(imap_command_t));
        for (i = sess->commands_size; i < sess->commands_size + 5; i++) {
            init_imap_command(&(sess->commands[i]));
        }
        comm = &(sess->commands[sess->commands_size]);
        index = sess->commands_size;
        sess->commands_size += 5;
    }

    if (extend_command_buffer(comm, sess->contbufread - sess->next_comm_start)
            < 0) {
        return -1;
    }

    comm_start = comm->commbufused;
    memcpy(comm->commbuffer + comm->commbufused,
            sess->contbuffer + sess->next_comm_start,
            sess->contbufread - sess->next_comm_start);
    comm->commbufused += (sess->contbufread - sess->next_comm_start);

    comm->commbuffer[comm->commbufused] = '\0';

    add_cc_to_imap_command(comm, comm_start, comm->commbufused, 1);

    comm->reply_start = comm->commbufused;
    comm->reply_end = 0;
    comm->imap_command = sess->next_command_name;
    comm->tag = sess->next_comm_tag;


    sess->next_comm_tag = NULL;
    sess->next_command_name = NULL;

    logger(LOG_INFO, "OpenLI: DEVDEBUG %s saved IMAP command %s, %s",
            sesskey, comm->tag, comm->imap_command);
    return index;
}

static int save_imap_reply(imap_session_t *sess, char *sesskey,
        char **origcommand) {

    int i;
    int comm_start;

    imap_command_t *comm = NULL;

    for (i = 0; i < sess->commands_size; i++) {
        if (sess->commands[i].tag == NULL) {
            break;
        }
        if (strcmp(sess->commands[i].tag, sess->next_comm_tag) == 0) {
            comm = &(sess->commands[i]);
            break;
        }
    }

    if (comm == NULL) {
        logger(LOG_INFO, "OpenLI: %s unable to match IMAP reply (%s, %s) to any existing commands?", sesskey, sess->next_comm_tag, sess->next_command_name);
        return 0;
    }

    logger(LOG_INFO, "OpenLI: DEVDEBUG %s got IMAP reply for %s, %s --> %s",
            sesskey, comm->tag, comm->imap_command, sess->next_command_name);

    if (extend_command_buffer(comm, sess->contbufread - sess->reply_start)
            < 0) {
        return -1;
    }

    comm_start = comm->commbufused;
    memcpy(comm->commbuffer + comm->commbufused,
            sess->contbuffer + sess->reply_start,
            sess->contbufread - sess->reply_start);
    comm->commbufused += (sess->contbufread - sess->reply_start);

    add_cc_to_imap_command(comm, comm_start, comm->commbufused, 0);

    comm->commbuffer[comm->commbufused] = '\0';
    comm->reply_end = comm->commbufused;
    comm->imap_reply = sess->next_command_name;

    *origcommand = comm->imap_command;

    free(sess->next_comm_tag);
    sess->next_comm_tag = NULL;
    sess->next_command_name = NULL;

    return 1;
}

static void reset_imap_saved_command(imap_command_t *comm) {

    comm->commbufused = 0;
    comm->reply_start = 0;
    comm->reply_end = 0;
    comm->cc_used = 0;

    if (comm->tag) {
        free(comm->tag);
        comm->tag = NULL;
    }
    if (comm->imap_command) {
        free(comm->imap_command);
        comm->imap_command = NULL;
    }
    if (comm->imap_reply) {
        free(comm->imap_reply);
        comm->imap_reply = NULL;
    }
}

void free_imap_session_state(emailsession_t *sess, void *imapstate) {
    imap_session_t *imapsess;
    int i;

    if (imapstate == NULL) {
        return;
    }
    imapsess = (imap_session_t *)imapstate;

    for (i = 0; i < imapsess->commands_size; i++) {
        if (imapsess->commands[i].commbuffer) {
            free(imapsess->commands[i].commbuffer);
        }
        if (imapsess->commands[i].tag) {
            free(imapsess->commands[i].tag);
        }
        if (imapsess->commands[i].imap_command) {
            free(imapsess->commands[i].imap_command);
        }
        if (imapsess->commands[i].imap_reply) {
            free(imapsess->commands[i].imap_reply);
        }
        if (imapsess->commands[i].ccs) {
            free(imapsess->commands[i].ccs);
        }
    }

    if (imapsess->next_comm_tag) {
        free(imapsess->next_comm_tag);
    }
    if (imapsess->next_command_name) {
        free(imapsess->next_command_name);
    }

    free(imapsess->commands);
    free(imapsess->contbuffer);
    free(imapsess);
}

static int append_content_to_imap_buffer(imap_session_t *imapsess,
        openli_email_captured_t *cap) {

    /* +1 to account for a null terminator */
    while (imapsess->contbufsize - imapsess->contbufused <=
                cap->msg_length + 1) {
        imapsess->contbuffer = realloc(imapsess->contbuffer,
                imapsess->contbufsize + 4096);
        if (imapsess->contbuffer == NULL) {
            return -1;
        }
        imapsess->contbufsize += 4096;
    }

    memcpy(imapsess->contbuffer + imapsess->contbufused,
            cap->content, cap->msg_length);
    imapsess->contbufused += cap->msg_length;
    imapsess->contbuffer[imapsess->contbufused] = '\0';

    assert(imapsess->contbufused <= imapsess->contbufsize);
    return 0;
}

static int find_next_crlf(imap_session_t *sess, int start_index) {
    int rem;
    uint8_t *found;

    assert(sess->contbufused >= start_index);

    rem = sess->contbufused - start_index;

    found = (uint8_t *)memmem(sess->contbuffer + start_index, rem, "\r\n", 2);

    if (found) {
        sess->contbufread = (found - sess->contbuffer) + 2;
        return 1;
    }
    return 0;
}

static int find_command_end(emailsession_t *sess, imap_session_t *imapsess) {
    int r, ind;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }

    sess->client_octets += (imapsess->contbufread - imapsess->next_comm_start);

    ind = save_imap_command(imapsess, sess->key);
    if (ind < 0) {
        return ind;
    }

    if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_AUTH) {
        sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATING;
        imapsess->auth_command_index = ind;
    } else if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_LOGOUT) {
        sess->currstate = OPENLI_IMAP_STATE_LOGOUT;
    } else if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_IDLE) {
        sess->currstate = OPENLI_IMAP_STATE_IDLING;
        imapsess->idle_command_index = ind;
    }

    imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
    imapsess->next_comm_start = 0;
    imapsess->reply_start = 0;

    return 1;
}

static int find_reply_end(emailsession_t *sess, imap_session_t *imapsess) {
    int r;
    char *origcommand;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }
    sess->server_octets += (imapsess->contbufread - imapsess->next_comm_start);

    if ((r = save_imap_reply(imapsess, sess->key, &origcommand)) <= 0) {
        return r;
    }

    imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
    imapsess->next_comm_start = 0;
    imapsess->reply_start = 0;

    if (strcasecmp(origcommand, "LOGOUT") == 0) {
        sess->currstate = OPENLI_IMAP_STATE_SESSION_OVER;
        return 0;
    }

    return 1;
}

static int find_partial_reply_end(emailsession_t *sess,
        imap_session_t *imapsess) {
    int r;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }
    sess->server_octets += (imapsess->contbufread - imapsess->next_comm_start);

    logger(LOG_INFO, "OpenLI: DEVDEBUG %s got partial IMAP reply ",
            sess->key);
    imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
    imapsess->next_comm_start = 0;

    return 1;
}


static int find_server_ready_end(imap_session_t *imapsess) {

    int r;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }

    return 1;
}

static int find_server_ready(imap_session_t *imapsess) {

    uint8_t *found = NULL;
    assert(imapsess->contbufused >= imapsess->contbufread);

    if (imapsess->contbufused - imapsess->contbufread < 5) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(imapsess->contbuffer + imapsess->contbufread),
                    "* OK ");
    if (found != NULL) {
        imapsess->next_comm_start = (found - imapsess->contbuffer);
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_SERVREADY;
        return 1;
    }
    return 0;
}

static int read_imap_while_idle_state(emailsession_t *sess,
        imap_session_t *imapsess) {

    uint8_t *msgstart = imapsess->contbuffer + imapsess->contbufread;
    imap_command_t *comm;
    uint8_t *found = NULL;
    int idle_server_length = 0;
    int comm_start;

    assert(imapsess->idle_command_index >= 0);

    comm = &(imapsess->commands[imapsess->idle_command_index]);

    /* check for "+ " -- server response to the idle command*/

    if (imapsess->reply_start == 0) {
        found = (uint8_t *)strstr(msgstart, "+ ");
        if (!found) {
            return 0;
        }

        imapsess->reply_start = found - imapsess->contbuffer;
    }

    /* all untagged messages are updates from the server
     * add them to our reply */

    /* check for "DONE\r\n" -- client message to end idling state */
    /*      make sure we add everything from reply_start to the start
     *      of "DONE" as a separate server->client CC, then add the
     *      "DONE" as a client->server CC.
     */
    found = (uint8_t *)strstr(msgstart, "\r\nDONE\r\n");
    if (!found) {
        return 0;
    }

    idle_server_length = (found + 2 - imapsess->contbuffer) -
            imapsess->reply_start;

    imapsess->contbufread = (found - imapsess->contbuffer) + 8;

    if (extend_command_buffer(comm, idle_server_length + 6) < 0) {
        return -1;
    }

    comm_start = comm->commbufused;
    memcpy(comm->commbuffer + comm->commbufused,
            imapsess->contbuffer + imapsess->reply_start,
            idle_server_length + 6);
    comm->commbufused += (idle_server_length + 6);
    comm->commbuffer[comm->commbufused] = '\0';

    add_cc_to_imap_command(comm, comm_start,
            comm_start + idle_server_length, 0);
    add_cc_to_imap_command(comm, comm_start + idle_server_length,
            comm_start + idle_server_length + 6, 1);

    sess->server_octets += idle_server_length;
    sess->client_octets += 6;

    imapsess->reply_start = 0;
    sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATED;

    return 1;
}

static int find_next_imap_message(emailsession_t *sess,
        imap_session_t *imapsess) {

    char *tag;
    char *comm_resp;
    uint8_t *spacefound = NULL;
    uint8_t *spacefound2 = NULL;
    uint8_t *crlffound = NULL;
    uint8_t *msgstart = imapsess->contbuffer + imapsess->contbufread;


    if (sess->currstate == OPENLI_IMAP_STATE_AUTHENTICATING) {
    /* if we see "+\r\n" or "+ \r\n", assume we're doing auth challenges and
     * that we should treat everything as part of the challenge process
     * until we see an eventual server reply (OK, NO or BAD) */
    /* TODO */
    }

    if (sess->currstate == OPENLI_IMAP_STATE_IDLING) {
        return read_imap_while_idle_state(sess, imapsess);
    }

    spacefound = (uint8_t *)strchr(msgstart, ' ');
    if (!spacefound) {
        return 0;
    }

    tag = calloc((spacefound - msgstart) + 1, sizeof(char *));
    memcpy(tag, msgstart, spacefound - msgstart);
    tag[spacefound - msgstart] = '\0';

    /* Most commands are "<tag> <type> <extra context>\r\n", but some
     * have no extra context and are just "<tag> <type>\r\n".
     * Therefore if we see a \r\n BEFORE the next space, we want to
     * treat that as our string boundary.
     */
    spacefound2 = (uint8_t *)strchr(spacefound + 1, ' ');
    crlffound = (uint8_t *)strstr(spacefound + 1, "\r\n");

    if (!spacefound2 && !crlffound) {
        free(tag);
        return 0;
    }

    if (spacefound2 == NULL || (crlffound != NULL && crlffound < spacefound2)) {
        spacefound2 = crlffound;
    }

    comm_resp = calloc((spacefound2 - spacefound), sizeof(char *));
    memcpy(comm_resp, spacefound + 1, (spacefound2 - spacefound) - 1);
    comm_resp[spacefound2 - spacefound - 1] = '\0';

    if (strcmp(tag, "*") == 0) {
        if (strcasecmp(comm_resp, "BYE") == 0 &&
                sess->currstate != OPENLI_IMAP_STATE_LOGOUT) {

            /* server is doing an immediate shutdown */

            /* TODO force an IRI for connection termination?
             *      dump CCs for any incomplete commands (including the
             *      sudden BYE)?
             */
            sess->currstate = OPENLI_IMAP_STATE_SESSION_OVER;
            free(tag);
            free(comm_resp);
            return 0;

        } else if (strcasecmp(comm_resp, "PREAUTH") == 0) {
            //imapsess->next_command_type = OPENLI_IMAP_COMMAND_PREAUTH;
        } else {
            /* a partial reply to a command, more to come... */
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_REPLY_ONGOING;
            free(comm_resp);
            comm_resp = NULL;

            if (imapsess->reply_start == 0) {
                imapsess->reply_start = msgstart - imapsess->contbuffer;
            }
        }
    } else if (strcasecmp(comm_resp, "OK") == 0 ||
            strcasecmp(comm_resp, "NO") == 0 ||
            strcasecmp(comm_resp, "BAD") == 0) {

        /* this is a reply that completes the response to a command */
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_REPLY;
        if (imapsess->reply_start == 0) {
            imapsess->reply_start = msgstart - imapsess->contbuffer;
        }
    } else if (strcasecmp(comm_resp, "ID") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_ID;
    } else if (strcasecmp(comm_resp, "IDLE") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_IDLE;
    } else if (strcasecmp(comm_resp, "LOGOUT") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_LOGOUT;
    } else if (strcasecmp(comm_resp, "AUTHENTICATE") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_AUTH;
        imapsess->auth_tag = tag;
        sess->currstate = OPENLI_IMAP_STATE_AUTH_STARTED;
    } else {
        /* just a regular IMAP command that requires no special treatment */
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_GENERIC;
    }

    if (imapsess->next_comm_tag) {
        free(imapsess->next_comm_tag);
    }
    imapsess->next_comm_tag = tag;

    if (imapsess->next_command_name) {
        free(imapsess->next_command_name);
    }
    imapsess->next_command_name = comm_resp;
    imapsess->next_comm_start = msgstart - imapsess->contbuffer;

    return 1;
}

static int process_next_imap_state(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess, uint64_t timestamp) {

    int r;

    if (sess->currstate == OPENLI_IMAP_STATE_INIT) {
        r = find_server_ready(imapsess);
        if (r == 1) {
            sess->currstate = OPENLI_IMAP_STATE_SERVER_READY;
        }
    }

    if (sess->currstate == OPENLI_IMAP_STATE_SERVER_READY) {
        r = find_server_ready_end(imapsess);
        if (r == 1) {
            sess->currstate = OPENLI_IMAP_STATE_PRE_AUTH;
            sess->server_octets +=
                    (imapsess->contbufread - imapsess->next_comm_start);
            imapsess->next_comm_start = 0;
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
            logger(LOG_INFO, "OpenLI DEVDEBUG: IMAP Server Ready %s",
                    sess->key);
        }
        return r;
    }

    if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_NONE) {
        r = find_next_imap_message(sess, imapsess);
        return r;
    } else if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_REPLY) {
        r = find_reply_end(sess, imapsess);

        if (r == 1) {
            /* TODO send any IRIs or CCs */

            /* TODO if command was ID, update session endpoint details using
             * command content */
        }
        return r;
    } else if (imapsess->next_command_type ==
            OPENLI_IMAP_COMMAND_REPLY_ONGOING) {
        r = find_partial_reply_end(sess, imapsess);
        return r;
    } else {
        r = find_command_end(sess, imapsess);
        return r;
    }

    return 0;
}

int update_imap_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap) {

    imap_session_t *imapsess;
    int r, i;

    if (sess->proto_state == NULL) {
        imapsess = calloc(1, sizeof(imap_session_t));
        imapsess->contbuffer = calloc(1024, sizeof(uint8_t));
        imapsess->contbufused = 0;
        imapsess->contbufread = 0;
        imapsess->contbufsize = 1024;
        imapsess->commands = calloc(5, sizeof(imap_command_t));
        imapsess->commands_size = 5;
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
        imapsess->idle_command_index = -1;
        imapsess->auth_command_index = -1;

        for (i = 0; i < imapsess->commands_size; i++) {
            init_imap_command(&(imapsess->commands[i]));
        }

        sess->proto_state = (void *)imapsess;
    } else {
        imapsess = (imap_session_t *)sess->proto_state;
    }

    if (append_content_to_imap_buffer(imapsess, cap) < 0) {
        logger(LOG_INFO, "OpenLI: Failed to append IMAP message content to session buffer for %s", sess->key);
        return -1;
    }

    while (1) {
        if ((r = process_next_imap_state(state, sess, imapsess,
                cap->timestamp)) <= 0) {
            break;
        }
    }

    if (sess->currstate == OPENLI_IMAP_STATE_SESSION_OVER) {
        return 1;
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
