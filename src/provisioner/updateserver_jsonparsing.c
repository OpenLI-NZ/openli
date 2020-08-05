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

#define _GNU_SOURCE

#include <string.h>
#include <json-c/json.h>

#include "provisioner.h"
#include "updateserver.h"
#include "logger.h"
#include "util.h"

struct json_agency {
    struct json_object *hi3addr;
    struct json_object *hi3port;
    struct json_object *hi2addr;
    struct json_object *hi2port;
    struct json_object *ka_freq;
    struct json_object *ka_wait;
};

struct json_intercept {
    struct json_object *liid;
    struct json_object *authcc;
    struct json_object *delivcc;
    struct json_object *agencyid;
    struct json_object *mediator;
    struct json_object *accesstype;
    struct json_object *user;
    struct json_object *radiusident;
    struct json_object *vendmirrorid;
    struct json_object *staticips;
    struct json_object *siptargets;
};

#define EXTRACT_JSON_INT_PARAM(name, uptype, jsonobj, dest, errflag, force) \
    if ((*errflag) == 0) { \
        int64_t ival; \
        errno = 0; \
        if (jsonobj != NULL) { \
            ival = json_object_get_int64(jsonobj); \
        } \
        if (errno != 0 || jsonobj == NULL) { \
            if (force) { \
                logger(LOG_INFO, "error, could not parse '%s' in %s update socket message", name, uptype); \
                snprintf(cinfo->answerstring, 4096, "%s <p>OpenLI provisioner could not parse '%s' in %s update socket message. %s", update_failure_page_start, name, uptype, update_failure_page_end); \
                *errflag = 1; \
            } \
        } else { \
            dest = ival; \
        } \
    }


#define EXTRACT_JSON_STRING_PARAM(name, uptype, jsonobj, dest, errflag, force) \
    if ((*errflag) == 0) { \
        const char *objstr = NULL; \
        if (jsonobj != NULL) { \
            objstr = json_object_get_string(jsonobj); \
        } \
        if (objstr == NULL || jsonobj == NULL) { \
            if (force) { \
                logger(LOG_INFO, "error, could not parse '%s' in %s update socket message", name, uptype); \
                snprintf(cinfo->answerstring, 4096, "%s <p>OpenLI provisioner could not parse '%s' in %s update socket message. %s", update_failure_page_start, name, uptype, update_failure_page_end); \
                *errflag = 1; \
            } \
        } else { \
            dest = strdup(objstr); \
        } \
    }

#define MODIFY_STRING_MEMBER(newmem, oldmem, changeflag) \
    if (newmem != NULL && strcmp(newmem, oldmem) != 0) { \
        free(oldmem); oldmem = newmem; *changeflag = 1; \
        newmem = NULL; \
    } else if (newmem) { \
        free(newmem); newmem = NULL; \
    }

#define INIT_JSON_INTERCEPT_PARSING \
    tknr = json_tokener_new(); \
    \
    parsed = json_tokener_parse_ex(tknr, cinfo->jsonbuffer, cinfo->jsonlen); \
    if (parsed == NULL) { \
        logger(LOG_INFO, \
                "OpenLI: unable to parse JSON received over update socket: %s", \
                json_tokener_error_desc(json_tokener_get_error(tknr))); \
        snprintf(cinfo->answerstring, 4096, \
                "%s <p>OpenLI provisioner was unable to parse JSON received over update socket: %s. %s", \
                update_failure_page_start, \
                json_tokener_error_desc(json_tokener_get_error(tknr)), \
                update_failure_page_end); \
        goto cepterr; \
    } \

#define INIT_JSON_AGENCY_PARSING \
    memset(&agjson, 0, sizeof(struct json_agency)); \
    tknr = json_tokener_new(); \
    \
    parsed = json_tokener_parse_ex(tknr, cinfo->jsonbuffer, cinfo->jsonlen); \
    if (parsed == NULL) { \
        logger(LOG_INFO, \
                "OpenLI: unable to parse JSON received over update socket: %s", \
                json_tokener_error_desc(json_tokener_get_error(tknr))); \
        snprintf(cinfo->answerstring, 4096, \
                "%s <p>OpenLI provisioner was unable to parse JSON received over update socket: %s. %s", \
                update_failure_page_start, \
                json_tokener_error_desc(json_tokener_get_error(tknr)), \
                update_failure_page_end); \
        goto agencyerr; \
    } \
    \
    if (!(json_object_object_get_ex(parsed, "agencyid", &agencyid))) { \
        logger(LOG_INFO, "OpenLI: error, agency update socket messages must include an 'agencyid'!"); \
        snprintf(cinfo->answerstring, 4096, \
                "%s <p>Agency update socket messages must include an 'agencyid'! %s", \
                update_failure_page_start, update_failure_page_end); \
        goto agencyerr; \
    } \
    \
    idstr = json_object_get_string(agencyid); \
    if (idstr == NULL) { \
        logger(LOG_INFO, "OpenLI: error, could not parse 'agencyid' in agency update socket message"); \
        snprintf(cinfo->answerstring, 4096, \
                "%s <p>'agencyid' field in agency update was unparseable. %s", \
                update_failure_page_start, update_failure_page_end); \
        goto agencyerr; \
    }


static inline void extract_agency_json_objects(struct json_agency *agjson,
        struct json_object *parsed) {

    json_object_object_get_ex(parsed, "hi3address", &(agjson->hi3addr));
    json_object_object_get_ex(parsed, "hi2address", &(agjson->hi2addr));
    json_object_object_get_ex(parsed, "hi3port", &(agjson->hi3port));
    json_object_object_get_ex(parsed, "hi2port", &(agjson->hi2port));
    json_object_object_get_ex(parsed, "keepalivefreq", &(agjson->ka_freq));
    json_object_object_get_ex(parsed, "keepalivewait", &(agjson->ka_wait));

}

static inline void extract_intercept_json_objects(
        struct json_intercept *ipjson, struct json_object *parsed) {

    memset(ipjson, 0, sizeof(struct json_intercept));

    json_object_object_get_ex(parsed, "liid", &(ipjson->liid));
    json_object_object_get_ex(parsed, "authcc", &(ipjson->authcc));
    json_object_object_get_ex(parsed, "delivcc", &(ipjson->delivcc));
    json_object_object_get_ex(parsed, "agencyid", &(ipjson->agencyid));
    json_object_object_get_ex(parsed, "mediator", &(ipjson->mediator));
    json_object_object_get_ex(parsed, "user", &(ipjson->user));
    json_object_object_get_ex(parsed, "accesstype", &(ipjson->accesstype));
    json_object_object_get_ex(parsed, "radiusident", &(ipjson->radiusident));
    json_object_object_get_ex(parsed, "vendmirrorid", &(ipjson->vendmirrorid));
    json_object_object_get_ex(parsed, "staticips", &(ipjson->staticips));
    json_object_object_get_ex(parsed, "siptargets", &(ipjson->siptargets));
}

static inline int compare_sip_targets(provision_state_t *currstate,
        voipintercept_t *existing, voipintercept_t *reload) {

    openli_sip_identity_t *oldtgt, *newtgt;
    libtrace_list_node_t *n1, *n2;

    /* Sluggish (n^2), but hopefully we don't have many IDs per intercept */

    n1 = existing->targets->head;
    while (n1) {
        oldtgt = *((openli_sip_identity_t **)(n1->data));
        n1 = n1->next;

        oldtgt->awaitingconfirm = 1;
        n2 = reload->targets->head;
        while (n2) {
            newtgt = *((openli_sip_identity_t **)(n2->data));
            n2 = n2->next;
            if (newtgt->awaitingconfirm == 0) {
                continue;
            }

            if (are_sip_identities_same(newtgt, oldtgt)) {
                oldtgt->awaitingconfirm = 0;
                newtgt->awaitingconfirm = 0;
                break;
            }
        }

        if (oldtgt->awaitingconfirm) {
            /* This target is no longer in the intercept config so
             * withdraw it. */
            if (announce_sip_target_change(currstate, oldtgt, existing, 0) < 0)
            {
                return -1;
            }
        }
    }

    n2 = reload->targets->head;
    while (n2) {
        newtgt = *((openli_sip_identity_t **)(n2->data));
        n2 = n2->next;
        if (newtgt->awaitingconfirm == 0) {
            continue;
        }

        /* This target has been added since we last reloaded config so
         * announce it. */
        if (announce_sip_target_change(currstate, newtgt, existing, 1) < 0) {
            return -1;
        }
    }

    return 0;
}

int remove_voip_intercept(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr) {

    voipintercept_t *found;

    HASH_FIND(hh_liid, state->interceptconf.voipintercepts, idstr,
            strlen(idstr), found);

    if (found) {
        HASH_DELETE(hh_liid, state->interceptconf.voipintercepts, found);
        halt_existing_intercept(state, (void *)found,
                OPENLI_PROTO_HALT_VOIPINTERCEPT);
        remove_liid_mapping(state, found->common.liid, found->common.liid_len,
                0);
        free_single_voipintercept(found);
        logger(LOG_INFO,
                "OpenLI: removed VOIP intercept '%s' via update socket.",
                idstr);
        return 1;
    }
    return 0;
}

int remove_ip_intercept(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr) {

    ipintercept_t *found;

    HASH_FIND(hh_liid, state->interceptconf.ipintercepts, idstr,
            strlen(idstr), found);

    if (found) {
        HASH_DELETE(hh_liid, state->interceptconf.ipintercepts, found);
        halt_existing_intercept(state, (void *)found,
                OPENLI_PROTO_HALT_IPINTERCEPT);
        remove_liid_mapping(state, found->common.liid, found->common.liid_len,
                0);
        free_single_ipintercept(found);
        logger(LOG_INFO,
                "OpenLI: removed IP intercept '%s' via update socket.",
                idstr);
        return 1;
    }
    return 0;
}

int remove_agency(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr) {

    prov_agency_t *found;

    HASH_FIND(hh, state->interceptconf.leas, idstr, strlen(idstr), found);

    if (found) {
        HASH_DEL(state->interceptconf.leas, found);
        withdraw_agency_from_mediators(state, found);
        free_liagency(found->ag);
        free(found);
        logger(LOG_INFO, "OpenLI: removed agency '%s' via update socket.",
                idstr);
        return 1;
    }
    return 0;

}

int remove_defaultradius(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr) {

    default_radius_user_t *found;

    HASH_FIND(hh, state->interceptconf.defradusers, idstr, strlen(idstr),
            found);

    if (found) {
        HASH_DELETE(hh, state->interceptconf.defradusers, found);
        withdraw_default_radius_username(state, found);
        free(found->name);
        free(found);
        logger(LOG_INFO, "OpenLI: removed default RADIUS username '%s' via update socket.",
                idstr);
        return 1;
    }
    return 0;
}

int remove_coreserver(update_con_info_t *cinfo, provision_state_t *state,
        const char *idstr, uint8_t srvtype) {

    coreserver_t *found = NULL;
    coreserver_t **src;

    if (srvtype == OPENLI_CORE_SERVER_SIP) {
        HASH_FIND(hh, state->interceptconf.sipservers, idstr, strlen(idstr),
                found);
        src = &(state->interceptconf.sipservers);
    } else if (srvtype == OPENLI_CORE_SERVER_RADIUS) {
        HASH_FIND(hh, state->interceptconf.radiusservers, idstr, strlen(idstr),
                found);
        src = &(state->interceptconf.radiusservers);
    } else if (srvtype == OPENLI_CORE_SERVER_GTP) {
        HASH_FIND(hh, state->interceptconf.gtpservers, idstr, strlen(idstr),
                found);
        src = &(state->interceptconf.gtpservers);
    }

    if (found) {
        HASH_DEL(*src, found);
        announce_coreserver_change(state, found, false);
        free_single_coreserver(found);
        logger(LOG_INFO, "OpenLI: removed %s server via update socket.",
                coreserver_type_to_string(srvtype));
        return 1;
    }

    return 0;
}

int add_new_defaultradius(update_con_info_t *cinfo, provision_state_t *state) {

    struct json_object *parsed = NULL;
    struct json_tokener *tknr;
    struct json_object *username;
    default_radius_user_t *raduser = NULL;
    default_radius_user_t *found = NULL;

    int parseerr = 0;
    tknr = json_tokener_new();

    parsed = json_tokener_parse_ex(tknr, cinfo->jsonbuffer, cinfo->jsonlen);

    if (parsed == NULL) {
        logger(LOG_INFO,
                "OpenLI: unable to parse JSON received over update socket: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse JSON received over update socket: %s. %s",
                update_failure_page_start,
                json_tokener_error_desc(json_tokener_get_error(tknr)),
                update_failure_page_end);
        goto defraderr;
    }

    raduser = (default_radius_user_t *)calloc(1, sizeof(default_radius_user_t));
    raduser->awaitingconfirm = 1;

    json_object_object_get_ex(parsed, "username", &(username));

    EXTRACT_JSON_STRING_PARAM("username", "default RADIUS username",
            username, raduser->name, &parseerr, true);
    if (parseerr || raduser->name == NULL) {
        goto defraderr;
    }

    raduser->namelen = strlen(raduser->name);
    HASH_FIND(hh, state->interceptconf.defradusers, raduser->name,
            raduser->namelen, found);

    if (found) {
        free(raduser->name);
        free(raduser);
    } else {
        HASH_ADD_KEYPTR(hh, state->interceptconf.defradusers, raduser->name,
                raduser->namelen, raduser);
        announce_default_radius_username(state, raduser);

        logger(LOG_INFO, "OpenLI: added default RADIUS username '%s' via update socket.",
                raduser->name);
    }

    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

defraderr:
    if (raduser) {
        if (raduser->name) {
            free(raduser->name);
        }
        free(raduser);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

int add_new_coreserver(update_con_info_t *cinfo, provision_state_t *state,
        uint8_t srvtype) {

    struct json_object *parsed = NULL;
    struct json_tokener *tknr;
    coreserver_t *found = NULL;
    coreserver_t *new_cs = NULL;
    struct json_object *ipaddr;
    struct json_object *port;

    char srvstring[1024];

    int parseerr = 0;
    tknr = json_tokener_new();

    parsed = json_tokener_parse_ex(tknr, cinfo->jsonbuffer, cinfo->jsonlen);
    if (parsed == NULL) {
        logger(LOG_INFO,
                "OpenLI: unable to parse JSON received over update socket: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse JSON received over update socket: %s. %s",
                update_failure_page_start,
                json_tokener_error_desc(json_tokener_get_error(tknr)),
                update_failure_page_end);
        goto cserr;
    }

    new_cs = (coreserver_t *)calloc(1, sizeof(coreserver_t));
    new_cs->servertype = srvtype;
    new_cs->awaitingconfirm = 1;

    json_object_object_get_ex(parsed, "ipaddress", &(ipaddr));
    json_object_object_get_ex(parsed, "port", &(port));

    snprintf(srvstring, 1024, "%s server",
            coreserver_type_to_string(srvtype));

    EXTRACT_JSON_STRING_PARAM("ipaddress", srvstring, ipaddr,
            new_cs->ipstr, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("port", srvstring, port,
            new_cs->portstr, &parseerr, true);

    if (parseerr) {
        goto cserr;
    }

    if (construct_coreserver_key(new_cs) == NULL) {
        logger(LOG_INFO,
                "OpenLI: unable to create %s from provided JSON record.", srvstring);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>Unable to create %s entity from JSON record provided over update socket. %s",
                update_failure_page_start, srvstring, update_failure_page_end);
        goto cserr;
    }

    if (srvtype == OPENLI_CORE_SERVER_SIP) {
        HASH_FIND(hh, state->interceptconf.sipservers, new_cs->serverkey,
                strlen(new_cs->serverkey), found);
    } else if (srvtype == OPENLI_CORE_SERVER_RADIUS) {
        HASH_FIND(hh, state->interceptconf.radiusservers, new_cs->serverkey,
                strlen(new_cs->serverkey), found);
    } else if (srvtype == OPENLI_CORE_SERVER_GTP) {
        HASH_FIND(hh, state->interceptconf.gtpservers, new_cs->serverkey,
                strlen(new_cs->serverkey), found);
    }

    if (found) {
        free_single_coreserver(new_cs);
    } else {
        if (srvtype == OPENLI_CORE_SERVER_SIP) {
            HASH_ADD_KEYPTR(hh, state->interceptconf.sipservers,
                    new_cs->serverkey, strlen(new_cs->serverkey), new_cs);
        } else if (srvtype == OPENLI_CORE_SERVER_RADIUS) {
            HASH_ADD_KEYPTR(hh, state->interceptconf.radiusservers,
                    new_cs->serverkey, strlen(new_cs->serverkey), new_cs);
        } else if (srvtype == OPENLI_CORE_SERVER_GTP) {
            HASH_ADD_KEYPTR(hh, state->interceptconf.gtpservers,
                    new_cs->serverkey, strlen(new_cs->serverkey), new_cs);
        } else {
            logger(LOG_INFO, "OpenLI: update socket received unexpected core server update (type = %u)", srvtype);
            goto cserr;
        }

        announce_coreserver_change(state, new_cs, true);
        logger(LOG_INFO, "OpenLI: added %s '%s:%s' via update socket.",
                srvstring, new_cs->ipstr, new_cs->portstr);
    }

    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

cserr:
    if (new_cs) {
        free_single_coreserver(new_cs);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;

}

int parse_voipintercept_siptargets(provision_state_t *state,
        voipintercept_t *vint, struct json_object *jsontargets,
        update_con_info_t *cinfo) {

    openli_sip_identity_t *newtgt;
    struct json_object *jobj;
    struct json_object *username, *realm;
    int parseerr = 0, i, tgtcnt;

    newtgt = NULL;
    tgtcnt = 0;

    if (json_object_get_type(jsontargets) != json_type_array) {
        logger(LOG_INFO, "OpenLI update socket: 'siptargets' for a VOIP intercept must be expressed as a JSON array");
        snprintf(cinfo->answerstring, 4096, "%s <p>The 'siptargets' members for a VOIP intercept must be expressed as a JSON array. %s",
                update_failure_page_start, update_failure_page_end);
        goto siptargeterr;
    }

    for (i = 0; i < json_object_array_length(jsontargets); i++) {
        jobj = json_object_array_get_idx(jsontargets, i);

        json_object_object_get_ex(jobj, "username", &(username));
        json_object_object_get_ex(jobj, "realm", &(realm));

        newtgt = (openli_sip_identity_t *)calloc(1,
                sizeof(openli_sip_identity_t));
        newtgt->awaitingconfirm = 1;

        EXTRACT_JSON_STRING_PARAM("username", "VOIP intercept SIP target",
                username, newtgt->username, &parseerr, true);
        EXTRACT_JSON_STRING_PARAM("realm", "VOIP intercept SIP target",
                realm, newtgt->realm, &parseerr, false);

        if (parseerr) {
            goto siptargeterr;
        }

        newtgt->username_len = strlen(newtgt->username);
        if (newtgt->realm) {
            newtgt->realm_len = strlen(newtgt->realm);
        }

        tgtcnt ++;
        libtrace_list_push_back(vint->targets, &newtgt);
    }

    return tgtcnt;

siptargeterr:
    if (newtgt) {
        if (newtgt->username) {
            free(newtgt->username);
        }
        if (newtgt->realm) {
            free(newtgt->realm);
        }
        free(newtgt);
    }
    return -1;

}

int parse_ipintercept_staticips(provision_state_t *state,
        ipintercept_t *ipint, struct json_object *jsonips, update_con_info_t *cinfo) {

    static_ipranges_t *newr = NULL;
    static_ipranges_t *existing = NULL;
    struct json_object *jobj;
    struct json_object *iprange, *sessionid;
    char *rangestr = NULL;
    int parseerr = 0;

    int i;

    if (json_object_get_type(jsonips) != json_type_array) {
        logger(LOG_INFO, "OpenLI update socket: 'staticips' for an IP intercept must be expressed as a JSON array");
        snprintf(cinfo->answerstring, 4096, "%s <p>The 'staticips' members for an IP intercept must be expressed as a JSON array. %s",
                update_failure_page_start, update_failure_page_end);
        goto staticerr;
    }

    for (i = 0; i < json_object_array_length(jsonips); i++) {
        jobj = json_object_array_get_idx(jsonips, i);

        json_object_object_get_ex(jobj, "iprange", &(iprange));
        json_object_object_get_ex(jobj, "sessionid", &(sessionid));

        newr = (static_ipranges_t *)malloc(sizeof(static_ipranges_t));
        newr->rangestr = NULL;
        newr->liid = NULL;
        newr->awaitingconfirm = 1;
        newr->cin = 1;

        EXTRACT_JSON_STRING_PARAM("iprange", "IP intercept static IP", iprange,
                rangestr, &parseerr, true);
        EXTRACT_JSON_INT_PARAM("sessionid", "IP intercept static IP", sessionid,
                newr->cin, &parseerr, false);

        if (parseerr) {
            if (rangestr) {
                free(rangestr);
            }
            goto staticerr;
        }

        newr->rangestr = parse_iprange_string(rangestr);
        if (!newr->rangestr) {
            snprintf(cinfo->answerstring, 4096, "%s <p>'%s' is not a valid prefix or IP address... <%s>", update_failure_page_start, rangestr,
                    update_failure_page_end);
            if (rangestr) {
                free(rangestr);
            }
            goto staticerr;
        }

        free(rangestr);
        if (newr->cin >= (uint32_t)(pow(2,31))) {
            logger(LOG_INFO,
                    "OpenLI: CIN %u for static IP range %s is too large.",
                    newr->cin, rangestr);
            newr->cin = newr->cin % (uint32_t)(pow(2, 31));
            logger(LOG_INFO, "OpenLI: replaced CIN with %u.",
                    newr->cin);
        }

        HASH_FIND(hh, ipint->statics, newr->rangestr, strlen(newr->rangestr),
                existing);
        if (!existing) {
            HASH_ADD_KEYPTR(hh, ipint->statics, newr->rangestr,
                    strlen(newr->rangestr), newr);
            if (!ipint->awaitingconfirm) {
                add_new_staticip_range(state, ipint, newr);
            }
        } else {
            free(newr->rangestr);
            free(newr);
        }
    }

    return 0;

staticerr:
    if (newr) {
        if (newr->rangestr) {
            free(newr->rangestr);
        }
        free(newr);
    }
    return -1;

}

int add_new_voipintercept(update_con_info_t *cinfo, provision_state_t *state) {
    struct json_intercept voipjson;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    voipintercept_t *found = NULL;
    voipintercept_t *vint = NULL;
    int parseerr = 0, r, liidmapped = 0;
    prov_agency_t *lea = NULL;

    INIT_JSON_INTERCEPT_PARSING
    extract_intercept_json_objects(&voipjson, parsed);

    vint = calloc(1, sizeof(voipintercept_t));
    /* XXX does internalid still matter? if not, let's remove it */
    vint->awaitingconfirm = 1;
    vint->active = 1;
    vint->targets = libtrace_list_init(sizeof(openli_sip_identity_t *));

    /* XXX potential data race here if we're reloading core provisioner
     * config at the same time, consider adding a mutex */
    if (state->ignorertpcomfort == 1) {
        vint->options |= (1UL << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
    }

    EXTRACT_JSON_STRING_PARAM("liid", "VOIP intercept", voipjson.liid,
            vint->common.liid, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("authcc", "VOIP intercept", voipjson.authcc,
            vint->common.authcc, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("delivcc", "VOIP intercept", voipjson.delivcc,
            vint->common.delivcc, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("agencyid", "VOIP intercept", voipjson.agencyid,
            vint->common.targetagency, &parseerr, true);
    EXTRACT_JSON_INT_PARAM("mediator", "VOIP intercept", voipjson.mediator,
            vint->common.destid, &parseerr, true);

    if (parseerr) {
        goto cepterr;
    }

    r = 0;
    if (voipjson.siptargets != NULL) {
        if ((r = parse_voipintercept_siptargets(state, vint,
                voipjson.siptargets, cinfo)) < 0) {
            goto cepterr;
        }
    }

    if (r == 0) {
        snprintf(cinfo->answerstring, 4096,
                "%s <p>VOIP intercept %s has been specified without valid SIP targets. %s",
                update_failure_page_start, vint->common.liid,
                update_failure_page_end);
        goto cepterr;
    }

    vint->common.liid_len = strlen(vint->common.liid);
    vint->common.authcc_len = strlen(vint->common.authcc);
    vint->common.delivcc_len = strlen(vint->common.delivcc);

    HASH_FIND(hh_liid, state->interceptconf.voipintercepts,
            vint->common.liid, vint->common.liid_len, found);

    if (found) {
        snprintf(cinfo->answerstring, 4096,
                "%s <p>LIID %s already exists as an VOIP intercept, please use PUT method if you wish to modify it. %s",
                update_failure_page_start,
                vint->common.liid,
                update_failure_page_end);
        goto cepterr;
    }

    HASH_ADD_KEYPTR(hh_liid, state->interceptconf.voipintercepts,
            vint->common.liid, vint->common.liid_len, vint);

    if (strcmp(vint->common.targetagency, "pcapdisk") != 0) {
        HASH_FIND_STR(state->interceptconf.leas, vint->common.targetagency,
                lea);
        if (lea) {
            liidmapped = 1;
        }
    } else {
        liidmapped = 1;
    }

    if (liidmapped) {
        liid_hash_t *h = add_liid_mapping(&(state->interceptconf),
                vint->common.liid, vint->common.targetagency);
        if (announce_liidmapping_to_mediators(state, h) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new VOIP intercept %s to mediators.",
                    vint->common.liid);
        }
    }

    if (announce_single_intercept(state, (void *)vint,
            push_voipintercept_onto_net_buffer) < 0) {
        logger(LOG_INFO,
                "OpenLI provisioner: unable to announce new VOIP intercept %s to collectors.",
                vint->common.liid);
    }

    if (announce_all_sip_targets(state, vint) < 0) {
        logger(LOG_INFO,
                "OpenLI provisioner: unable to announce targets for new VOIP intercept %s to collectors.",
                vint->common.liid);
    }

    vint->awaitingconfirm = 0;
    logger(LOG_INFO,
            "OpenLI provisioner: added new VOIP intercept %s via update socket.",
            vint->common.liid);

    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

cepterr:
    if (vint) {
        free_single_voipintercept(vint);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

int add_new_ipintercept(update_con_info_t *cinfo, provision_state_t *state) {
    struct json_intercept ipjson;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    ipintercept_t *found = NULL;

    char *accessstring = NULL;
    char *radiusidentstring = NULL;
    ipintercept_t *ipint = NULL;
    int parseerr = 0, liidmapped = 0;
    prov_agency_t *lea = NULL;

    INIT_JSON_INTERCEPT_PARSING
    extract_intercept_json_objects(&ipjson, parsed);

    ipint = calloc(1, sizeof(ipintercept_t));
    ipint->awaitingconfirm = 1;
    ipint->vendmirrorid = OPENLI_VENDOR_MIRROR_NONE;
    ipint->accesstype = INTERNET_ACCESS_TYPE_UNDEFINED;
    ipint->options = 0;

    EXTRACT_JSON_STRING_PARAM("liid", "IP intercept", ipjson.liid,
            ipint->common.liid, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("authcc", "IP intercept", ipjson.authcc,
            ipint->common.authcc, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("delivcc", "IP intercept", ipjson.delivcc,
            ipint->common.delivcc, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("agencyid", "IP intercept", ipjson.agencyid,
            ipint->common.targetagency, &parseerr, true);
    EXTRACT_JSON_INT_PARAM("mediator", "IP intercept", ipjson.mediator,
            ipint->common.destid, &parseerr, true);
    EXTRACT_JSON_INT_PARAM("vendmirrorid", "IP intercept", ipjson.vendmirrorid,
            ipint->vendmirrorid, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("user", "IP intercept", ipjson.user,
            ipint->username, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("accesstype", "IP intercept", ipjson.accesstype,
            accessstring, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("radiusident", "IP intercept", ipjson.radiusident,
            radiusidentstring, &parseerr, false);

    if (parseerr) {
        goto cepterr;
    }

    if (ipjson.staticips != NULL) {
        if (parse_ipintercept_staticips(state, ipint, ipjson.staticips,
                cinfo) < 0) {
            goto cepterr;
        }
    }

    ipint->common.liid_len = strlen(ipint->common.liid);
    ipint->common.authcc_len = strlen(ipint->common.authcc);
    ipint->common.delivcc_len = strlen(ipint->common.delivcc);
    ipint->username_len = strlen(ipint->username);

    if (accessstring) {
        ipint->accesstype = map_access_type_string(accessstring);
        free(accessstring);
        accessstring = NULL;
    }

    if (radiusidentstring) {
        ipint->options = map_radius_ident_string(radiusidentstring);
        free(radiusidentstring);
        radiusidentstring = NULL;
    } else {
        ipint->options = (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID) |
                (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_USER);
    }

    HASH_FIND(hh_liid, state->interceptconf.ipintercepts,
            ipint->common.liid, ipint->common.liid_len, found);

    if (found) {
        snprintf(cinfo->answerstring, 4096,
                "%s <p>LIID %s already exists as an IP intercept, please use PUT method if you wish to modify it. %s",
                update_failure_page_start,
                ipint->common.liid,
                update_failure_page_end);
        goto cepterr;
    }

    HASH_ADD_KEYPTR(hh_liid, state->interceptconf.ipintercepts,
            ipint->common.liid, ipint->common.liid_len, ipint);

    if (strcmp(ipint->common.targetagency, "pcapdisk") != 0) {
        HASH_FIND_STR(state->interceptconf.leas, ipint->common.targetagency,
                lea);
        if (lea) {
            liidmapped = 1;
        }
    } else {
        liidmapped = 1;
    }

    if (liidmapped) {
        liid_hash_t *h = add_liid_mapping(&(state->interceptconf),
                ipint->common.liid, ipint->common.targetagency);
        if (announce_liidmapping_to_mediators(state, h) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new IP intercept %s to mediators.",
                    ipint->common.liid);
        }
    }

    if (announce_single_intercept(state, (void *)ipint,
            push_ipintercept_onto_net_buffer) < 0) {
        logger(LOG_INFO,
                "OpenLI provisioner: unable to announce new IP intercept %s to collectors.",
                ipint->common.liid);
    }

    ipint->awaitingconfirm = 0;
    logger(LOG_INFO,
            "OpenLI provisioner: added new IP intercept %s via update socket.",
            ipint->common.liid);

    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

cepterr:
    if (ipint) {
        free_single_ipintercept(ipint);
    }
    if (accessstring) {
        free(accessstring);
    }
    if (radiusidentstring) {
        free(radiusidentstring);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

int modify_voipintercept(update_con_info_t *cinfo, provision_state_t *state) {

    struct json_intercept voipjson;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    voipintercept_t *found = NULL;
    voipintercept_t *vint = NULL;

    char *liidstr = NULL;
    int parseerr = 0, changed = 0;

    INIT_JSON_INTERCEPT_PARSING
    extract_intercept_json_objects(&voipjson, parsed);

    EXTRACT_JSON_STRING_PARAM("liid", "VOIP intercept", voipjson.liid,
            liidstr, &parseerr, true);

    if (parseerr) {
        goto cepterr;
    }

    HASH_FIND(hh_liid, state->interceptconf.voipintercepts, liidstr,
            strlen(liidstr), found);

    if (!found) {
        json_object_put(parsed);
        json_tokener_free(tknr);
		if (liidstr) {
			free(liidstr);
		}
        return add_new_voipintercept(cinfo, state);
    }

    vint = calloc(1, sizeof(voipintercept_t));
    vint->awaitingconfirm = 1;
    vint->common.liid = liidstr;
	vint->targets = libtrace_list_init(sizeof(openli_sip_identity_t *));

    EXTRACT_JSON_STRING_PARAM("authcc", "VOIP intercept", voipjson.authcc,
            vint->common.authcc, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("delivcc", "VOIP intercept", voipjson.delivcc,
            vint->common.delivcc, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("agencyid", "VOIP intercept", voipjson.agencyid,
            vint->common.targetagency, &parseerr, false);
    EXTRACT_JSON_INT_PARAM("mediator", "VOIP intercept", voipjson.mediator,
            vint->common.destid, &parseerr, false);

    if (parseerr) {
        goto cepterr;
    }

    if (voipjson.siptargets != NULL) {
        libtrace_list_t *tmp;

        if (parse_voipintercept_siptargets(state, vint, voipjson.siptargets,
                cinfo) < 0) {
            goto cepterr;
        }

        if (compare_sip_targets(state, found, vint) < 0) {
            goto cepterr;
        }
		tmp = found->targets;
		found->targets = vint->targets;
		vint->targets = tmp;
    }

    /* TODO: warn if user tries to change fields that we don't support
     * changing (e.g. mediator) ?
     *
     * TODO: allow target agency to be changed, we just need to remove and
     * then announce the new LIID mapping...
     */

    MODIFY_STRING_MEMBER(vint->common.authcc, found->common.authcc, &changed);
    found->common.authcc_len  = strlen(found->common.authcc);

    if (changed) {
        modify_existing_intercept_options(state, (void *)found,
                    OPENLI_PROTO_MODIFY_VOIPINTERCEPT);
    }

    logger(LOG_INFO,
            "OpenLI provisioner: updated VOIP intercept %s via update socket.",
            found->common.liid);

    if (vint) {
        free_single_voipintercept(vint);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

cepterr:
    if (vint) {
        free_single_voipintercept(vint);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

int modify_ipintercept(update_con_info_t *cinfo, provision_state_t *state) {

    struct json_intercept ipjson;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    ipintercept_t *found = NULL;
    ipintercept_t *ipint = NULL;

    char *liidstr = NULL;
    char *accessstring = NULL;
    char *radiusidentstring = NULL;
    int parseerr = 0, changed = 0;

    INIT_JSON_INTERCEPT_PARSING
    extract_intercept_json_objects(&ipjson, parsed);

    EXTRACT_JSON_STRING_PARAM("liid", "IP intercept", ipjson.liid,
            liidstr, &parseerr, true);

    if (parseerr) {
        goto cepterr;
    }

    HASH_FIND(hh_liid, state->interceptconf.ipintercepts, liidstr,
            strlen(liidstr), found);

    if (!found) {
        json_object_put(parsed);
        json_tokener_free(tknr);
		if (liidstr) {
			free(liidstr);
		}
        return add_new_ipintercept(cinfo, state);
    }

    ipint = calloc(1, sizeof(ipintercept_t));
    ipint->awaitingconfirm = 1;
    ipint->vendmirrorid = OPENLI_VENDOR_MIRROR_NONE;
    ipint->accesstype = INTERNET_ACCESS_TYPE_UNDEFINED;
    ipint->common.liid = liidstr;

    EXTRACT_JSON_STRING_PARAM("authcc", "IP intercept", ipjson.authcc,
            ipint->common.authcc, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("delivcc", "IP intercept", ipjson.delivcc,
            ipint->common.delivcc, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("agencyid", "IP intercept", ipjson.agencyid,
            ipint->common.targetagency, &parseerr, false);
    EXTRACT_JSON_INT_PARAM("mediator", "IP intercept", ipjson.mediator,
            ipint->common.destid, &parseerr, false);
    EXTRACT_JSON_INT_PARAM("vendmirrorid", "IP intercept", ipjson.vendmirrorid,
            ipint->vendmirrorid, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("user", "IP intercept", ipjson.user,
            ipint->username, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("accesstype", "IP intercept", ipjson.accesstype,
            accessstring, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("radiusident", "IP intercept", ipjson.radiusident,
            radiusidentstring, &parseerr, false);

    if (parseerr) {
        goto cepterr;
    }

    if (ipjson.staticips != NULL) {
        static_ipranges_t *range, *tmp, *inmod;

        if (parse_ipintercept_staticips(state, ipint, ipjson.staticips,
                cinfo) < 0) {
            goto cepterr;
        }

        HASH_ITER(hh, found->statics, range, tmp) {
            HASH_FIND(hh, ipint->statics, range->rangestr,
                    strlen(range->rangestr), inmod);

            if (inmod) {
                /* Check if session ID has changed for some reason */
                if (inmod->cin != range->cin) {
                    range->cin = inmod->cin;
                    modify_existing_staticip_range(state, found, range);
                }
                inmod->awaitingconfirm = 0;
            } else {
                /* Withdrawn */
                HASH_DEL(found->statics, range);
                remove_existing_staticip_range(state, found, range);
                if (range->rangestr) {
                    free(range->rangestr);
                }
                free(range);
            }
        }

        HASH_ITER(hh, ipint->statics, range, tmp) {
            if (range->awaitingconfirm) {
                /* New range */
                add_new_staticip_range(state, found, range);
                range->awaitingconfirm = 0;
            }
        }

		tmp = found->statics;
		found->statics = ipint->statics;
		ipint->statics = tmp;
    }

    if (accessstring) {
        ipint->accesstype = map_access_type_string(accessstring);
    }

    if (radiusidentstring) {
        ipint->options = map_radius_ident_string(radiusidentstring);
    } else {
        ipint->options = (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_USER) |
                (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID);
    }

    /* TODO: warn if user tries to change fields that we don't support
     * changing (e.g. mediator) ?
     *
     * TODO: allow target agency to be changed, we just need to remove and
     * then announce the new LIID mapping...
     */

    MODIFY_STRING_MEMBER(ipint->common.authcc, found->common.authcc, &changed);
    found->common.authcc_len  = strlen(found->common.authcc);
    MODIFY_STRING_MEMBER(ipint->username, found->username, &changed);
    found->username_len = strlen(found->username);

    if (accessstring && ipint->accesstype != found->accesstype) {
        changed = 1;
        found->accesstype = ipint->accesstype;
    }

    if (ipint->options != found->options) {
        changed = 1;
        found->options = ipint->options;
    }

    if (accessstring) {
    	free(accessstring);
    }
    if (radiusidentstring) {
        free(radiusidentstring);
    }
    radiusidentstring = NULL;
	accessstring = NULL;

    if (ipint->vendmirrorid != found->vendmirrorid) {
        changed = 1;
        found->vendmirrorid = ipint->vendmirrorid;
    }

    if (changed) {
        modify_existing_intercept_options(state, (void *)found,
                    OPENLI_PROTO_MODIFY_IPINTERCEPT);
    }

    logger(LOG_INFO,
            "OpenLI provisioner: updated IP intercept %s via update socket.",
            found->common.liid);

    if (ipint) {
        free_single_ipintercept(ipint);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

cepterr:
    if (ipint) {
        free_single_ipintercept(ipint);
    }
    if (accessstring) {
        free(accessstring);
    }
    if (radiusidentstring) {
        free(radiusidentstring);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

int add_new_agency(update_con_info_t *cinfo, provision_state_t *state) {

    struct json_object *agencyid;
    struct json_agency agjson;

    const char *idstr;
    struct json_object *parsed = NULL;
    struct json_tokener *tknr;
    liagency_t *nag = NULL;
    prov_agency_t *lea, *found;
    int parseerr = 0;

    INIT_JSON_AGENCY_PARSING
    extract_agency_json_objects(&agjson, parsed);

    nag = calloc(1, sizeof(liagency_t));
    nag->agencyid = strdup(idstr);
    nag->keepalivefreq = DEFAULT_AGENCY_KEEPALIVE_FREQ;
    nag->keepalivewait = DEFAULT_AGENCY_KEEPALIVE_WAIT;

    EXTRACT_JSON_STRING_PARAM("hi3address", "agency", agjson.hi3addr,
            nag->hi3_ipstr, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("hi2address", "agency", agjson.hi2addr,
            nag->hi2_ipstr, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("hi3port", "agency", agjson.hi3port,
            nag->hi3_portstr, &parseerr, true);
    EXTRACT_JSON_STRING_PARAM("hi2port", "agency", agjson.hi2port,
            nag->hi2_portstr, &parseerr, true);

    EXTRACT_JSON_INT_PARAM("keepalivefreq", "agency", agjson.ka_freq,
            nag->keepalivefreq, &parseerr, false);
    EXTRACT_JSON_INT_PARAM("keepalivewait", "agency", agjson.ka_wait,
            nag->keepalivewait, &parseerr, false);

    if (parseerr) {
        goto agencyerr;
    }

    lea = calloc(1, sizeof(prov_agency_t));
    lea->ag = nag;
    lea->announcereq = 1;

    HASH_FIND(hh, state->interceptconf.leas, nag->agencyid,
            strlen(nag->agencyid), found);
    if (found) {
        HASH_DEL(state->interceptconf.leas, found);
        withdraw_agency_from_mediators(state, found);
        free_liagency(found->ag);
        free(found);
    }

    HASH_ADD_KEYPTR(hh, state->interceptconf.leas, nag->agencyid,
            strlen(nag->agencyid), lea);
    announce_lea_to_mediators(state, lea);

    logger(LOG_INFO, "OpenLI: added new agency '%s' via update socket.",
            nag->agencyid);

    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

agencyerr:
    if (nag) {
        if (nag->hi2_ipstr) {
            free(nag->hi2_ipstr);
        }
        if (nag->hi3_ipstr) {
            free(nag->hi3_ipstr);
        }
        if (nag->hi2_portstr) {
            free(nag->hi2_portstr);
        }
        if (nag->hi3_portstr) {
            free(nag->hi3_portstr);
        }
        if (nag->agencyid) {
            free(nag->agencyid);
        }
        free(nag);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

int modify_agency(update_con_info_t *cinfo, provision_state_t *state) {

    struct json_object *agencyid;
    struct json_agency agjson;

    const char *idstr = NULL;
    struct json_object *parsed = NULL;
    struct json_tokener *tknr;
    prov_agency_t *found;
    int parseerr = 0;
    liagency_t modified;
    int changed = 0;

    memset(&modified, 0, sizeof(modified));
    INIT_JSON_AGENCY_PARSING

    HASH_FIND(hh, state->interceptconf.leas, idstr, strlen(idstr), found);

    if (!found) {
        /* Our "modify" is actually an addition? */
        json_object_put(parsed);
        json_tokener_free(tknr);
        return add_new_agency(cinfo, state);
    }

    modified.keepalivefreq = 0xffffffff;
    modified.keepalivewait = 0xffffffff;

    extract_agency_json_objects(&agjson, parsed);
    EXTRACT_JSON_STRING_PARAM("hi3address", "agency", agjson.hi3addr,
            modified.hi3_ipstr, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("hi2address", "agency", agjson.hi2addr,
            modified.hi2_ipstr, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("hi3port", "agency", agjson.hi3port,
            modified.hi3_portstr, &parseerr, false);
    EXTRACT_JSON_STRING_PARAM("hi2port", "agency", agjson.hi2port,
            modified.hi2_portstr, &parseerr, false);

    EXTRACT_JSON_INT_PARAM("keepalivefreq", "agency", agjson.ka_freq,
            modified.keepalivefreq, &parseerr, false);
    EXTRACT_JSON_INT_PARAM("keepalivewait", "agency", agjson.ka_wait,
            modified.keepalivewait, &parseerr, false);

    if (parseerr) {
        goto agencyerr;
    }

    MODIFY_STRING_MEMBER(modified.hi3_ipstr, found->ag->hi3_ipstr, &changed);
    MODIFY_STRING_MEMBER(modified.hi2_ipstr, found->ag->hi2_ipstr, &changed);
    MODIFY_STRING_MEMBER(modified.hi3_portstr, found->ag->hi3_portstr,
            &changed);
    MODIFY_STRING_MEMBER(modified.hi2_portstr, found->ag->hi2_portstr,
            &changed);

    if (modified.keepalivefreq != 0xffffffff &&
                modified.keepalivefreq != found->ag->keepalivefreq) {
        changed = 1;
        found->ag->keepalivefreq = modified.keepalivefreq;
    }

    if (modified.keepalivewait != 0xffffffff &&
                modified.keepalivewait != found->ag->keepalivewait) {
        changed = 1;
        found->ag->keepalivewait = modified.keepalivewait;
    }

    if (changed) {
        withdraw_agency_from_mediators(state, found);
        announce_lea_to_mediators(state, found);
        logger(LOG_INFO,
                "OpenLI: modified existing agency '%s' via update socket.",
                found->ag->agencyid);
    } else {
        logger(LOG_INFO,
                "OpenLI: did not modify existing agency '%s' via update socket, as no agency properties had changed.",
                found->ag->agencyid);
    }


    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return 0;

agencyerr:
    if (modified.hi2_ipstr) {
        free(modified.hi2_ipstr);
    }
    if (modified.hi3_ipstr) {
        free(modified.hi3_ipstr);
    }
    if (modified.hi2_portstr) {
        free(modified.hi2_portstr);
    }
    if (modified.hi3_portstr) {
        free(modified.hi3_portstr);
    }
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

