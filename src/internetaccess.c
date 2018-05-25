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

#include "logger.h"
#include "internetaccess.h"

static inline void free_session(access_session_t *sess) {

    if (sess == NULL) {
        return;
    }

    if (sess->assignedip) {
        free(sess->assignedip);
    }

    /* session id and state data should be handled by the appropriate plugin */

    /* TODO */

    free(sess);
}

void free_single_user(internet_user_t *u) {

    access_session_t *sess, *tmp;
    if (u->userid) {
        free(u->userid);
    }

    HASH_ITER(hh, u->sessions, sess, tmp) {
        HASH_DELETE(hh, u->sessions, sess);
        free_session(sess);
    }

    free(u);

}

void free_all_users(internet_user_t *users) {

    internet_user_t *u, *tmp;

    HASH_ITER(hh, users, u, tmp) {
        HASH_DELETE(hh, users, u);
        free_single_user(u);
    }
}

int free_single_session(internet_user_t *user, void *sessionid, void *idlen) {

    access_session_t *sess;

    if (user == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: called free_single_session() for a NULL user!");
        return -1;
    }

    HASH_FIND(hh, user->sessions, sessionid, idlen, sess);
    if (!sess) {
        logger(LOG_DAEMON, "OpenLI: unable to free expired Internet session because it was not present in the session map for user %s", user->userid);

        /* TODO use the plugin to help log the session ID */

        return -1;
    }

    free_session(sess);
    return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
