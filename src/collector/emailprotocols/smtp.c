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

    while (smtpsess->contbufsize - smtpsess->contbufused <=
            cap->msg_length + 1) {
        smtpsess->contbuffer = realloc(smtpsess->contbuffer,
                smtpsess->contbufsize + 4096);
        if (smtpsess->contbuffer == NULL) {
            return -1;
        }

        smtpsess->contbufsize += 4096;
    }

    memcpy(smtpsess->contbuffer + smtpsess->contbufused,
            cap->content, cap->msg_length);
    smtpsess->contbufused += cap->msg_length;
    smtpsess->contbuffer[smtpsess->contbufused] = '\0';

    assert(smtpsess->contbufused <= smtpsess->contbufsize);

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

    assert(sess->contbufused >= start_index);

    rem = sess->contbufused - start_index;

    found = (uint8_t *)memmem(sess->contbuffer + start_index, rem, "\r\n", 2);

    if (found) {
        sess->contbufread = (found - sess->contbuffer) + 2;
        return 1;
    }
    return 0;
}

static int find_smtp_reply_code(smtp_session_t *sess, uint16_t *storage) {

    uint8_t *found;
    int rem, res;
    regex_t lastreply;
    regmatch_t pmatch[1];
    const char *search;

    assert(sess->contbufused >= sess->contbufread);
    rem = (sess->contbufused - sess->contbufread);

    if (regcomp(&lastreply, "[[:digit:]][[:digit:]][[:digit:]] ", 0) != 0) {
        return -1;
    }

    search = (const char *)(sess->contbuffer + sess->contbufread);

    res = regexec(&lastreply, search, 1, pmatch, 0);
    if (res != 0) {
        regfree(&lastreply);
        return 0;
    }

    (*storage) = strtoul(search + pmatch[0].rm_so, NULL, 10);
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

static int find_ehlo_response_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->ehlo_reply_code));
}

static int find_mail_from_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->mailfrom_reply_code));
}

static int find_rcpt_to_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->rcptto_reply_code));
}

static int find_mail_from(smtp_session_t *sess) {
    uint8_t *found = NULL;
    assert(sess->contbufused >= sess->contbufread);
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
    assert(sess->contbufused >= sess->contbufread);
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

static int find_ehlo_start(smtp_session_t *sess) {
    uint8_t *found = NULL;

    if (sess->contbufused < 5) {
        return 0;
    }

    found = (uint8_t *)strcasestr((const char *)sess->contbuffer, "EHLO ");
    if (found != NULL) {
        sess->ehlo_start = (found - sess->contbuffer);
        return 1;
    }

    found = (uint8_t *)strcasestr((const char *)sess->contbuffer, "HELO ");
    if (found != NULL) {
        sess->ehlo_start = (found - sess->contbuffer);
        return 1;
    }

    return 0;
}

static int process_next_smtp_state(emailsession_t *sess,
        smtp_session_t *smtpsess) {
    int r;

    if (sess->currstate == OPENLI_SMTP_STATE_INIT ||
            sess->currstate == OPENLI_SMTP_STATE_EHLO_OVER) {
        if ((r = find_ehlo_start(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_EHLO;
            logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP EHLO found at position %d in message content", smtpsess->ehlo_start);
        } else {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO) {
        if ((r = find_ehlo_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_EHLO_RESPONSE;
            logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP now looking for EHLO response starting from %d", smtpsess->contbufread);
        } else {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO_RESPONSE) {
        if ((r = find_ehlo_response_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
            logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP server replied to EHLO with code %u, skipped ahead to %d", smtpsess->ehlo_reply_code, smtpsess->contbufread);

            /* TODO send email login event IRI (and CC?) */
        } else {
            return r;
        }

    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO_OVER) {
        if ((r = find_mail_from(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM;
            logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP MAIL FROM found at position %d in message content", smtpsess->mailfrom_start);
        } else {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM) {
        if ((r = find_mail_from_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_REPLY;
        } else {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_REPLY) {
        if ((r = find_mail_from_reply_end(smtpsess)) == 1) {
            if (smtpsess->mailfrom_reply_code == 250) {
                sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_OVER;
                logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP MAIL FROM command completed successfully");


                /* extract sender info from mail from content */
                if (extract_smtp_participant(sess, smtpsess,
                        smtpsess->mailfrom_start, smtpsess->contbufread) < 0) {
                    return -1;
                }
            } else {
                logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP MAIL FROM command received reply code %u -- resetting MAIL FROM state", smtpsess->mailfrom_reply_code);
                sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
                return 1;
            }
        } else {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_OVER ||
            sess->currstate == OPENLI_SMTP_STATE_RCPT_TO_OVER) {
        if ((r = find_rcpt_to(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_RCPT_TO;
            logger(LOG_INFO, "OpenLI: DEVDEBUG RCPT TO command found at position %d in message content", smtpsess->rcptto_start);
        } else {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO) {
        if ((r = find_rcpt_to_end(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_REPLY;
        } else {
            return r;
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO_REPLY) {
        if ((r = find_rcpt_to_reply_end(smtpsess)) == 1) {
            if (smtpsess->rcptto_reply_code == 250) {
                sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_OVER;
                logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP RCPT TO command completed successfully");


                /* extract recipient info from rcpt to content */
                if (extract_smtp_participant(sess, smtpsess,
                        smtpsess->rcptto_start, smtpsess->contbufread) < 0) {
                    return -1;
                }
            } else {
                logger(LOG_INFO, "OpenLI: DEVDEBUG SMTP RCPT TO command received reply code %u -- resetting RCPT TO state", smtpsess->rcptto_reply_code);
                sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_OVER;
                return 1;
            }
        } else {
            return r;
        }
    }

    return 1;
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

    logger(LOG_INFO, "OpenLI: DEVDEBUG updating SMTP session %s",
            sess->key);

    if (append_content_to_smtp_buffer(smtpsess, cap) < 0) {
        logger(LOG_INFO, "OpenLI: Failed to append SMTP message content to session buffer for %s", sess->key);
        return -1;
    }

    while (1) {
        if (r = (process_next_smtp_state(sess, smtpsess)) <= 0) {
            break;
        }
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
