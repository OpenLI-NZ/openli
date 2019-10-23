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
        case ACCESS_GTP:
            p = get_gtp_access_plugin();
            break;
    }

    if (p == NULL) {
        logger(LOG_INFO,
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

static inline char *fast_strdup(char *orig, int origlen) {
    char *dup = malloc(origlen + 1);

    memcpy(dup, orig, origlen + 1);
    return dup;
}

access_session_t *create_access_session(access_plugin_t *p, char *sessid,
        int sessid_len) {
    access_session_t *newsess;

    newsess = (access_session_t *)malloc(sizeof(access_session_t));

    newsess->plugin = p;
    newsess->sessionid = fast_strdup(sessid, sessid_len);
	newsess->statedata = NULL;
	newsess->idlength = sessid_len;
	newsess->cin = 0;
	memset(&(newsess->sessionip), 0, sizeof(newsess->sessionip));

	newsess->iriseqno = 0;
	newsess->started.tv_sec = 0;
	newsess->started.tv_usec = 0;
	newsess->activeipentry = NULL;

	return newsess;
}

int free_single_session(internet_user_t *user, access_session_t *sess) {

    access_session_t *prev, *tmp;

    if (user == NULL) {
        logger(LOG_INFO,
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

const char *accesstype_to_string(internet_access_method_t am) {
    switch(am) {
        case INTERNET_ACCESS_TYPE_UNDEFINED:
            return "undefined";
        case INTERNET_ACCESS_TYPE_DIALUP:
            return "dialup";
        case INTERNET_ACCESS_TYPE_XDSL:
            return "DSL";
        case INTERNET_ACCESS_TYPE_CABLEMODEM:
            return "cable modem";
        case INTERNET_ACCESS_TYPE_LAN:
            return "LAN";
        case INTERNET_ACCESS_TYPE_WIRELESS_LAN:
            return "wireless LAN";
        case INTERNET_ACCESS_TYPE_FIBER:
            return "fiber";
        case INTERNET_ACCESS_TYPE_WIMAX:
            return "WIMAX/HIPERMAN";
        case INTERNET_ACCESS_TYPE_SATELLITE:
            return "satellite";
        case INTERNET_ACCESS_TYPE_WIRELESS_OTHER:
            return "wireless (Other)";
    }
    return "invalid";
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
