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
#include "util.h"
#include "internetaccess.h"
#include "collector.h"

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


int push_session_ips_to_collector_queue(libtrace_message_queue_t *q,
        ipintercept_t *ipint, access_session_t *session) {

    ipsession_t *ipsess;
    openli_pushed_t msg;
    int i;

    for (i = 0; i < session->sessipcount; i++) {

        ipsess = create_ipsession(ipint, session->cin,
            session->sessionips[i].ipfamily,
            (struct sockaddr *)&(session->sessionips[i].assignedip),
            session->sessionips[i].prefixbits);

        if (!ipsess) {
            logger(LOG_INFO,
                    "OpenLI: ran out of memory while creating IP session message.");
            return -1;
        }
        memset(&msg, 0, sizeof(openli_pushed_t));
        msg.type = OPENLI_PUSH_IPINTERCEPT;
        msg.data.ipsess = ipsess;

        libtrace_message_queue_put(q, (void *)(&msg));
    }
    return session->sessipcount;
}

void push_session_update_to_collector_queue(libtrace_message_queue_t *q,
        ipintercept_t *ipint, access_session_t *sess, int updatetype) {

    openli_pushed_t pmsg;
    int i;
    ipsession_t *sessdup;

    for (i = 0; i < sess->sessipcount; i++) {
        memset(&pmsg, 0, sizeof(openli_pushed_t));
        pmsg.type = updatetype;
        sessdup = create_ipsession(ipint, sess->cin,
                sess->sessionips[i].ipfamily,
                (struct sockaddr *)&(sess->sessionips[i].assignedip),
                sess->sessionips[i].prefixbits);
        pmsg.data.ipsess = sessdup;
        libtrace_message_queue_put(q, &pmsg);
    }
}

static inline void free_session(access_session_t *sess) {

    if (sess == NULL) {
        return;
    }

    /* session id and state data should be handled by the appropriate plugin */
    if (sess->plugin) {
        sess->plugin->destroy_session_data(sess->plugin, sess);
    }
    if (sess->sessionips) {
        free(sess->sessionips);
    }
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

static inline char *fast_strdup(char *orig, int origlen) {
    char *dup = malloc(origlen + 1);

    memcpy(dup, orig, origlen + 1);
    return dup;
}

static int generate_tagged_userid(user_identity_t *userid, char *taggedid,
        int space) {

    char *ptr = taggedid;
    memset(taggedid, 0, space);

    if (userid->method == USER_IDENT_GTP_MSISDN) {
        memcpy(ptr, "msisdn:", strlen("msisdn:"));
        ptr += strlen("msisdn:");
    } else if (userid->method == USER_IDENT_GTP_IMSI) {
        memcpy(ptr, "imsi:", strlen("imsi:"));
        ptr += strlen("imsi:");
    } else if (userid->method == USER_IDENT_GTP_IMEI) {
        memcpy(ptr, "imei:", strlen("imei:"));
        ptr += strlen("imei:");
    }

    if ((ptr - taggedid) + userid->idlength + 1 > space) {
        logger(LOG_INFO,
                "OpenLI: user identity string is too long!");
        return -1;
    }

    memcpy(ptr, userid->idstr, userid->idlength);
    return userid->idlength + (ptr - taggedid);
}

internet_user_t *lookup_user_by_identity(internet_user_t *allusers,
        user_identity_t *userid) {

    char taggedid[2048];
    internet_user_t *found = NULL;

    if (generate_tagged_userid(userid, taggedid, 2048) < 0) {
        return NULL;
    }
    HASH_FIND(hh, allusers, taggedid, strlen(taggedid), found);
    return found;
}

internet_user_t *lookup_user_by_intercept(internet_user_t *allusers,
        ipintercept_t *ipint) {

    char taggedid[2048];
    internet_user_t *found = NULL;

    if (generate_ipint_userkey(ipint, taggedid, 2048) < 0) {
        return NULL;
    }
    HASH_FIND(hh, allusers, taggedid, strlen(taggedid), found);
    return found;
}

int add_userid_to_allusers_map(internet_user_t **allusers,
        internet_user_t *newuser, user_identity_t *userid) {

    char taggedid[2048];

    if (generate_tagged_userid(userid, taggedid, 2048) < 0) {
        return -1;
    }
    newuser->userid = strdup(taggedid);
    HASH_ADD_KEYPTR(hh, *allusers, newuser->userid, strlen(newuser->userid),
            newuser);
    return 0;
}

access_session_t *create_access_session(access_plugin_t *p, char *sessid,
        int sessid_len) {
    access_session_t *newsess;

    newsess = (access_session_t *)malloc(sizeof(access_session_t));

    newsess->identifier_type = OPENLI_ACCESS_SESSION_UNKNOWN;
    newsess->plugin = p;
    newsess->sessionid = fast_strdup(sessid, sessid_len);
	newsess->statedata = NULL;
	newsess->idlength = sessid_len;
	newsess->cin = 0;
    newsess->sessionips = calloc(SESSION_IP_INCR, sizeof(internetaccess_ip_t));
    newsess->sessipcount = 0;
    newsess->sessipversion = SESSION_IP_VERSION_NONE;
    newsess->ips_mapped = 0;

	newsess->iriseqno = 0;
	newsess->started.tv_sec = 0;
	newsess->started.tv_usec = 0;

    newsess->teid = 0;
	return newsess;
}

void add_new_session_ip(access_session_t *sess, void *att_val,
        int family, uint8_t pfxbits, int att_len) {

	int ind = sess->sessipcount;

    if (sess->sessipcount > 0 && (sess->sessipcount % SESSION_IP_INCR) == 0) {
        sess->sessionips = realloc(sess->sessionips,
                (sess->sessipcount + SESSION_IP_INCR) *
                sizeof(internetaccess_ip_t));

    }

    if (family == AF_INET) {
        struct sockaddr_in *in;

        in = (struct sockaddr_in *)&(sess->sessionips[ind].assignedip);

        if (att_len != 4) {
            logger(LOG_INFO, "OpenLI: unexpected attribute length for an IPv4 address: %d\n", att_len);
            return;
        }

        in->sin_family = AF_INET;
        in->sin_port = 0;
        in->sin_addr.s_addr = *((uint32_t *)att_val);

        if (sess->sessipversion == SESSION_IP_VERSION_NONE) {
            sess->sessipversion = SESSION_IP_VERSION_V4;
        } else if (sess->sessipversion == SESSION_IP_VERSION_V6) {
            sess->sessipversion = SESSION_IP_VERSION_DUAL;
        }


    } else if (family == AF_INET6) {

        struct sockaddr_in6 *in6;
        int tocopy = 16;

        if (att_len < tocopy) {
            tocopy = att_len;
        }

        in6 = (struct sockaddr_in6 *)&(sess->sessionips[ind].assignedip);

        in6->sin6_family = AF_INET6;
        in6->sin6_port = 0;
        in6->sin6_flowinfo = 0;

        memset(in6->sin6_addr.s6_addr, 0, sizeof(in6->sin6_addr.s6_addr));
        memcpy(in6->sin6_addr.s6_addr, att_val, tocopy);

        if (sess->sessipversion == SESSION_IP_VERSION_NONE) {
            sess->sessipversion = SESSION_IP_VERSION_V6;
        } else if (sess->sessipversion == SESSION_IP_VERSION_V4) {
            sess->sessipversion = SESSION_IP_VERSION_DUAL;
        }
    } else {
        return;
    }

    sess->sessionips[ind].ipfamily = family;
    sess->sessionips[ind].prefixbits = pfxbits;
    sess->sessipcount ++;
    sess->identifier_type |= OPENLI_ACCESS_SESSION_IP;
}

int free_single_session(access_session_t *sess) {
    free_session(sess);
    return 0;
}

int remove_session_ip(access_session_t *sess, internetaccess_ip_t *sessip) {

    int i;
    int nullips = 0;

    for (i = 0; i < sess->sessipcount; i++) {
        if (sess->sessionips[i].ipfamily == 0) {
            nullips ++;
            continue;
        }

        if (sess->sessionips[i].ipfamily == sessip->ipfamily &&
                sess->sessionips[i].prefixbits == sessip->prefixbits) {

            if (sessip->ipfamily == AF_INET) {
                struct sockaddr_in *in, *this;
                in = (struct sockaddr_in *)&(sessip->assignedip);
                this = (struct sockaddr_in *)&(sess->sessionips[i].assignedip);

                if (this->sin_addr.s_addr == in->sin_addr.s_addr) {
                    sess->sessionips[i].ipfamily = 0;
                    nullips ++;
                }
            } else if (sessip->ipfamily == AF_INET6) {
                struct sockaddr_in6 *in, *this;
                in = (struct sockaddr_in6 *)&(sessip->assignedip);
                this = (struct sockaddr_in6 *)&(sess->sessionips[i].assignedip);

                if (memcmp(&(this->sin6_addr.s6_addr), &(in->sin6_addr.s6_addr),
                        16) == 0) {
                    sess->sessionips[i].ipfamily = 0;
                    nullips ++;
                }
            }
        }
    }

    if (nullips == sess->sessipcount) {
        return 1;
    }
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
        case INTERNET_ACCESS_TYPE_MOBILE:
            return "mobile";
    }
    return "invalid";
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
