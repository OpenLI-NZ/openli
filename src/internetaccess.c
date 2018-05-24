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

access_plugin_t *init_access_plugin(uint8_t accessmethod) {

    access_plugin_t *p = NULL;

    switch(accessmethod) {
        case ACCESS_RADIUS:
            p = get_radius_access_plugin();
            break;
    }

    if (p == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: invalid access method %d observed in init_access_plugin()");
        return NULL;
    }

    p->init_plugin_data(p);
    return p;
}

void destroy_access_plugin(access_plugin_t *p) {
    p->destroy_plugin_data(p);
}

static inline void free_session(access_session_t *sess) {

    if (sess == NULL) {
        return;
    }

    if (sess->assignedip) {
        free(sess->assignedip);
    }

    /* session id and state data should be handled by the appropriate plugin */
    if (sess->plugin) {
        sess->plugin->destroy_session_data(sess->plugin, sess);
    }
    free(sess);
}

void free_single_user(internet_user_t *u) {

    access_session_t *sess, *tmp;
    if (u->userid) {
        free(u->userid);
    }

    tmp = u->sessions;
    while (tmp) {
        sess = tmp;
        tmp = tmp->next;
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

int free_single_session(internet_user_t *user, access_session_t *sess) {

    access_session_t *prev, *tmp;

    if (user == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: called free_single_session() for a NULL user!");
        return -1;
    }

    tmp = user->sessions;
    prev = NULL;
    while (tmp) {
        if (sess == tmp) {
            break;
        }
        prev = tmp;
        tmp = tmp->next;
    }

    //HASH_DELETE(hh, user->sessions, sess);
    if (tmp != NULL) {
        if (prev) {
            prev->next = tmp->next;
        } else {
            user->sessions = tmp->next;
        }
    }

    free_session(sess);
    return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
