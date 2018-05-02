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

#ifndef OPENLI_INTERNETACCESS_H_
#define OPENLI_INTERNETACCESS_H_

#include <uthash.h>

enum {
    ACCESS_RADIUS,
    ACCESS_DHCP
};

typedef struct access_session {

    uint8_t accesstype;
    void *sessionid;
    void *statedata;
    int idlength;
    uint32_t cin;
    int ipfamily;
    struct sockaddr *assignedip;
    uint32_t iriseqno;

    UT_hash_handle hh;
} access_session_t;

typedef struct internet_user {
    char *userid;
    access_session_t *sessions;
    UT_hash_handle hh;
} internet_user_t;

void free_all_users(internet_user_t *users);
int free_single_session(internet_user_t *user, void *sessionid, void *idlen);


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
