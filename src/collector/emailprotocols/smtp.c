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

typedef struct smtpsession {
    char *messageid;

    uint8_t *contbuffer;
    int contbufsize;
    int contbufused;
    int contbufread;
    int reply_start;

    uint8_t saved_state;

    uint16_t ehlo_reply_code;
    uint16_t mailfrom_reply_code;
    uint16_t rcptto_reply_code;
    uint16_t data_reply_code;
    uint16_t data_final_reply_code;
    int ehlo_start;
    int ehlo_reply_end;
    int mailfrom_start;
    int rcptto_start;
    int data_start;
    int data_end;
} smtp_session_t;

void free_smtp_session_state(emailsession_t *sess, void *smtpstate) {

    smtp_session_t *smtpsess;
    if (smtpstate == NULL) {
        return;
    }
    smtpsess = (smtp_session_t *)smtpstate;
    free(smtpsess->contbuffer);
    free(smtpsess);

}

static int append_content_to_smtp_buffer(smtp_session_t *smtpsess,
        openli_email_captured_t *cap) {

    /* "16" is just a bit of extra buffer space to account for
     * special cases where we need to insert missing "DATA" commands
     * into the application data stream.
     */
    while (smtpsess->contbufsize - smtpsess->contbufused <=
            cap->msg_length + 16) {
        smtpsess->contbuffer = realloc(smtpsess->contbuffer,
                smtpsess->contbufsize + 4096);
        if (smtpsess->contbuffer == NULL) {
            return -1;
        }

        smtpsess->contbufsize += 4096;
    }

    /* Special case -- some ingested data sources skip the DATA
     * command, so we're going to try and squeeze that in ourselves
     * whenever we see content beginning with the "354 " response.
     */
    if (smtpsess->data_start == 0 &&
            memcmp(cap->content, (const void *)"354 ", 4) == 0) {
        memcpy(smtpsess->contbuffer + smtpsess->contbufused,
                "DATA\r\n", 6);
        smtpsess->contbufused += 6;
    }

    memcpy(smtpsess->contbuffer + smtpsess->contbufused,
            cap->content, cap->msg_length);
    smtpsess->contbufused += cap->msg_length;
    smtpsess->contbuffer[smtpsess->contbufused] = '\0';

    return 0;
}

static int extract_smtp_participant(emailsession_t *sess,
        smtp_session_t *smtpstate, int contoffset, int contend) {

    char *addr, *addrstart, *addrend;
    const char *search = (const char *)(smtpstate->contbuffer + contoffset);

    addrstart = strchr(search, '<');
    if (addrstart == NULL) {
        return -1;
    }

    addrend = strchr(search, '>');
    if (addrend == NULL) {
        return -1;
    }

    if (addrstart >= (char *)(smtpstate->contbuffer + contend)) {
        return -1;
    }

    if (addrend >= (char *)(smtpstate->contbuffer + contend)) {
        return -1;
    }


    addr = strndup(addrstart + 1, addrend - addrstart - 1);

    add_email_participant(sess, addr,
            (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_OVER));
    return 1;

}

static int find_next_crlf(smtp_session_t *sess, int start_index) {

    int rem;
    uint8_t *found;

    rem = sess->contbufused - start_index;

    found = (uint8_t *)memmem(sess->contbuffer + start_index, rem, "\r\n", 2);

    if (found) {
        sess->contbufread = (found - sess->contbuffer) + 2;
        return 1;
    }
    return 0;
}

static int find_smtp_reply_code(smtp_session_t *sess, uint16_t *storage) {

    int res;
    regex_t lastreply;
    regmatch_t pmatch[1];
    const char *search;

    if (regcomp(&lastreply, "[[:digit:]][[:digit:]][[:digit:]] ", 0) != 0) {
        return -1;
    }

    search = (const char *)(sess->contbuffer + sess->contbufread);

    res = regexec(&lastreply, search, 1, pmatch, 0);
    if (res != 0) {
        regfree(&lastreply);
        return 0;
    }

    if (storage) {
        (*storage) = strtoul(search + pmatch[0].rm_so, NULL, 10);
    }
    regfree(&lastreply);
    return find_next_crlf(sess, sess->contbufread + pmatch[0].rm_so);
}

static int find_ehlo_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->ehlo_start);
}

static int find_mail_from_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->mailfrom_start);
}

static int find_rcpt_to_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->rcptto_start);
}

static int find_data_init_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->data_reply_code));
}

static int find_data_final_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->data_final_reply_code));
}

static int find_reset_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, NULL);
}

static int find_quit_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, NULL);
}

static int find_ehlo_response_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->ehlo_reply_code));
}

static int find_mail_from_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->mailfrom_reply_code));
}

static int find_rcpt_to_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->rcptto_reply_code));
}

static int find_data_start(smtp_session_t *sess) {
    uint8_t *found = NULL;
    if (sess->contbufused - sess->contbufread < 6) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(sess->contbuffer + sess->contbufread),
            "DATA\r\n");
    if (found == NULL) {
        return 0;
    }

    /* Skip past "DATA\r\n" automatically */
    sess->data_start = (found - sess->contbuffer);
    sess->contbufread = sess->data_start + 6;
    return 1;
}

static int find_reset_command(smtp_session_t *sess) {
    uint8_t *found = NULL;
    if (sess->contbufused - sess->contbufread < 6) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(sess->contbuffer + sess->contbufread),
            "RSET\r\n");
    if (found == NULL) {
        return 0;
    }

    /* Skip past "RSET\r\n" automatically */
    sess->contbufread = (found - sess->contbuffer);
    sess->contbufread += 6;
    return 1;
}

static int find_quit_command(smtp_session_t *sess) {
    uint8_t *found = NULL;
    if (sess->contbufused - sess->contbufread < 6) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(sess->contbuffer + sess->contbufread),
            "QUIT\r\n");
    if (found == NULL) {
        return 0;
    }

    /* Skip past "QUIT\r\n" automatically */
    sess->contbufread = (found - sess->contbuffer);
    sess->contbufread += 6;
    return 1;
}

static int find_mail_from(smtp_session_t *sess) {
    uint8_t *found = NULL;
    if (sess->contbufused - sess->contbufread < 10) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(sess->contbuffer + sess->contbufread),
            "MAIL FROM:");
    if (found != NULL) {
        sess->mailfrom_start = (found - sess->contbuffer);
        return 1;
    }

    return 0;
}

static int find_rcpt_to(smtp_session_t *sess) {
    uint8_t *found = NULL;
    if (sess->contbufused - sess->contbufread < 8) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(sess->contbuffer + sess->contbufread),
            "RCPT TO:");
    if (found != NULL) {
        sess->rcptto_start = (found - sess->contbuffer);
        return 1;
    }

    return 0;
}

static int find_data_content_ending(smtp_session_t *sess) {
    const char *search = (const char *)(sess->contbuffer + sess->contbufread);
    uint8_t *found = NULL;

    /* An "empty" mail message is ".\r\n" -- edge case, but let's try to
     * handle it regardless.
     */
    if (strncmp(search, ".\r\n", 3) == 0) {
        sess->contbufread += 3;
        return 1;
    }

    found = (uint8_t *)strstr(search, "\r\n.\r\n");
    if (found != NULL) {
        sess->contbufread = (found - sess->contbuffer) + 5;
        sess->data_end = sess->contbufread;
        return 1;
    }

    return 0;
}


static int find_ehlo_start(emailsession_t *mailsess, smtp_session_t *sess) {
    uint8_t *found = NULL;
    const char *search;

    if (sess->contbufused - sess->contbufread < 5) {
        return 0;
    }
    search = (const char *)(sess->contbuffer + sess->contbufread);

    found = (uint8_t *)strcasestr(search, "EHLO ");

    /* In theory, we can have multiple EHLOs (e.g. when STARTTLS is used),
     * so don't reset the EHLO start pointer if we haven't transitioned past
     * the EHLO OVER state.
     */
    if (found != NULL) {
        if (mailsess->currstate != OPENLI_SMTP_STATE_EHLO_OVER) {
            sess->ehlo_start = (found - sess->contbuffer);
        }
        return 1;
    }

    found = (uint8_t *)strcasestr(search, "HELO ");
    if (found != NULL) {
        if (mailsess->currstate != OPENLI_SMTP_STATE_EHLO_OVER) {
            sess->ehlo_start = (found - sess->contbuffer);
        }
        return 1;
    }

    return 0;
}

static int process_next_smtp_state(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {
    int r;

    /* TODO consider adding state parsing for AUTH, STARTTLS, VRFY, EXPN
     * and any other SMTP commands that exist -- it will only really
     * matter for octet counting reasons and I doubt the LEAs care that
     * much, but something to bear in mind...
     */

    if (sess->currstate != OPENLI_SMTP_STATE_DATA_CONTENT) {
        if ((r = find_quit_command(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_QUIT;
            sess->client_octets += 6;
            smtpsess->reply_start = smtpsess->contbufread;
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate != OPENLI_SMTP_STATE_DATA_CONTENT) {
        if ((r = find_reset_command(smtpsess)) == 1) {
            smtpsess->saved_state = sess->currstate;
            sess->currstate = OPENLI_SMTP_STATE_RESET;
            sess->client_octets += 6;
            smtpsess->reply_start = smtpsess->contbufread;
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_INIT ||
            sess->currstate == OPENLI_SMTP_STATE_EHLO_OVER) {
        if ((r = find_ehlo_start(sess, smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_EHLO;
            sess->server_octets +=
                    (smtpsess->ehlo_start - smtpsess->contbufread);
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO) {
        if ((r = find_ehlo_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_EHLO_RESPONSE;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->ehlo_start);
            smtpsess->reply_start = smtpsess->contbufread;
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO_RESPONSE) {
        if ((r = find_ehlo_response_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);

            return 1;
        } else if (r < 0) {
            return r;
        }

    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO_OVER) {
        if ((r = find_mail_from(smtpsess)) == 1) {
            smtpsess->ehlo_reply_end = smtpsess->mailfrom_start;
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM;
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM) {
        if ((r = find_mail_from_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->mailfrom_start);
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_REPLY) {
        if ((r = find_mail_from_reply_end(smtpsess)) == 1) {
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);
            if (smtpsess->mailfrom_reply_code == 250) {
                char *saved_sender = NULL;
                int skip_login_iri = 0;
                sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_OVER;

                if (sess->login_sent && sess->sender.emailaddr) {
                    saved_sender = strdup(sess->sender.emailaddr);
                }

                /* extract latest sender info from mail from content */
                if (extract_smtp_participant(sess, smtpsess,
                        smtpsess->mailfrom_start, smtpsess->contbufread) < 0) {
                    if (saved_sender) {
                        free(saved_sender);
                    }
                    return -1;
                }

                if (sess->login_sent) {
                    /* If we have sent a login IRI and the MAIL FROM
                     * address has now changed, send a logoff IRI to indicate
                     * that this session is no longer being used by the
                     * previous address (remember, the new address may
                     * not be a target so we cannot rely on a login event
                     * IRI for the new address being seen by the LEA.
                     */
                    if (strcmp(saved_sender, sess->sender.emailaddr) != 0) {
                        sess->event_time = timestamp;
                        generate_email_logoff_iri(state, sess);
                    } else {
                        skip_login_iri = 1;
                    }
                }
                if (saved_sender) {
                    free(saved_sender);
                }
                clear_email_participant_list(sess);

                /* send email login event IRI (and CC?) if any of the
                   participants match a known target.
                */
                sess->login_time = timestamp;
                if (smtpsess->ehlo_reply_code >= 200 &&
                       smtpsess->ehlo_reply_code < 300) {
                    if (!skip_login_iri) {
                        generate_email_login_success_iri(state, sess);
                        sess->login_sent = 1;
                    }
                } else {
                    generate_email_login_failure_iri(state, sess);
                }
            } else {
                sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
            }
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_OVER) {
        if ((r = find_rcpt_to(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_RCPT_TO;
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO) {
        if ((r = find_rcpt_to_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->rcptto_start);
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO_REPLY) {
        if ((r = find_rcpt_to_reply_end(smtpsess)) == 1) {
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);
            if (smtpsess->rcptto_reply_code == 250) {
                sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_OVER;

                /* extract recipient info from rcpt to content */
                if (extract_smtp_participant(sess, smtpsess,
                        smtpsess->rcptto_start, smtpsess->contbufread) < 0) {
                    return -1;
                }
            } else {
                sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_OVER;
            }
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO_OVER) {
        if ((r = find_rcpt_to(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_RCPT_TO;
            /* Need to restart the loop to handle RCPT_TO state again */
            return 1;
        } else if ((r = find_data_start(smtpsess)) == 1) {

            sess->currstate = OPENLI_SMTP_STATE_DATA_INIT_REPLY;
            sess->client_octets += 6;
            smtpsess->reply_start = smtpsess->contbufread;
            return 1;
        } else if ((r = find_mail_from(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM;
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_INIT_REPLY) {
        if ((r = find_data_init_reply_code(smtpsess)) == 1) {
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);
            if (smtpsess->data_reply_code == 354) {
                sess->currstate = OPENLI_SMTP_STATE_DATA_CONTENT;
            } else {
                sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_OVER;
            }
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_CONTENT) {
        if ((r = find_data_content_ending(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_DATA_FINAL_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->data_start);
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_FINAL_REPLY) {
        if ((r = find_data_final_reply_code(smtpsess)) == 1) {
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);
            if (smtpsess->data_final_reply_code == 250) {
                sess->currstate = OPENLI_SMTP_STATE_DATA_OVER;
                sess->event_time = timestamp;
                /* generate email send CC and IRI */
                generate_email_send_iri(state, sess);
                generate_email_cc_from_smtp_payload(state, sess,
                        smtpsess->contbuffer + smtpsess->data_start,
                        smtpsess->contbufread - smtpsess->data_start,
                        timestamp);
            } else {
                sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_OVER;
            }
            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_OVER) {
        if ((r = find_mail_from(smtpsess)) == 1) {
            /* client is re-using the session to send another email? */
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM;
            return 1;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RESET) {
        if ((r = find_reset_reply_code(smtpsess)) == 1) {
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);
            if (smtpsess->saved_state == OPENLI_SMTP_STATE_INIT ||
                    smtpsess->saved_state == OPENLI_SMTP_STATE_EHLO_OVER ||
                    smtpsess->saved_state == OPENLI_SMTP_STATE_DATA_OVER) {
                sess->currstate = smtpsess->saved_state;
                smtpsess->saved_state = OPENLI_SMTP_STATE_INIT;
            } else {
                sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
                smtpsess->saved_state = OPENLI_SMTP_STATE_INIT;

                smtpsess->mailfrom_start = 0;
                smtpsess->rcptto_start = 0;
                smtpsess->data_start = 0;
                smtpsess->data_end = 0;
            }

            return 1;
        } else if (r < 0) {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_QUIT) {
        if ((r = find_quit_reply_code(smtpsess)) == 1) {
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);
            sess->currstate = OPENLI_SMTP_STATE_QUIT_REPLY;
            sess->event_time = timestamp;
            generate_email_logoff_iri(state, sess);
            return 0;
        } else if (r < 0) {
            return r;
        }
    }

    return 0;
}

int update_smtp_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap) {
    smtp_session_t *smtpsess;
    int r;

    if (sess->proto_state == NULL) {
        smtpsess = calloc(1, sizeof(smtp_session_t));
        smtpsess->messageid = NULL;
        smtpsess->contbuffer = calloc(1024, sizeof(uint8_t));
        smtpsess->contbufused = 0;
        smtpsess->contbufread = 0;
        smtpsess->contbufsize = 1024;
        sess->proto_state = (void *)smtpsess;
    } else {
        smtpsess = (smtp_session_t *)sess->proto_state;
    }

    if (cap->content != NULL) {

        if (append_content_to_smtp_buffer(smtpsess, cap) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to append SMTP message content to session buffer for %s", sess->key);
            return -1;
        }

        while (1) {
            if ((r = process_next_smtp_state(state, sess, smtpsess,
                    cap->timestamp)) <= 0) {
                break;
            }
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_QUIT_REPLY) {
        return 1;
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
