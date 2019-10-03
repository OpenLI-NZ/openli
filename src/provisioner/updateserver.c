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
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <json-c/json.h>

#include "provisioner.h"
#include "logger.h"
#include "util.h"

#define MICRO_POST 0
#define MICRO_GET 1
#define MICRO_DELETE 2

enum {
    TARGET_AGENCY,
    TARGET_SIPSERVER,
    TARGET_RADIUSSERVER,
    TARGET_IPINTERCEPT,
    TARGET_VOIPINTERCEPT,
};

typedef struct con_info {
    int connectiontype;
    int answercode;
    char answerstring[4096];
    const char *content_type;

    int target;
    char *jsonbuffer;
    int jsonlen;

} con_info_t;

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
    struct json_object *vendmirrorid;
    struct json_object *staticips;
    struct json_object *siptargets;
};


const char *update_success_page =
        "<html><body>OpenLI provisioner configuration was successfully updated.</body></html>\n";

const char *update_failure_page_start =
        "<html><body><p>OpenLI provisioner configuration failed.";
const char *update_failure_page_end = "</body></html>\n";

const char *get_not_implemented =
        "<html><body>OpenLI provisioner does not support fetching intercept config (yet).</body></html>\n";

const char *unsupported_operation =
        "<html><body>OpenLI provisioner does not support that type of request.</body></html>\n";

static int send_http_page(struct MHD_Connection *connection, const char *page,
        int status_code) {

    int ret;
    struct MHD_Response *resp;

    resp = MHD_create_response_from_buffer(strlen(page), (void *)page,
            MHD_RESPMEM_MUST_COPY);
    if (!resp) {
        return MHD_NO;
    }
    MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
    ret = MHD_queue_response(connection, status_code, resp);
    MHD_destroy_response(resp);
    return ret;
}

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
        const char *objstr; \
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
    } else if (newmem) { \
        free(newmem); \
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
    json_object_object_get_ex(parsed, "vendmirrorid", &(ipjson->vendmirrorid));
    json_object_object_get_ex(parsed, "staticips", &(ipjson->staticips));
    json_object_object_get_ex(parsed, "siptargets", &(ipjson->siptargets));
}

static int remove_voip_intercept(con_info_t *cinfo, provision_state_t *state,
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

static int remove_ip_intercept(con_info_t *cinfo, provision_state_t *state,
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

static int remove_agency(con_info_t *cinfo, provision_state_t *state,
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

static int remove_coreserver(con_info_t *cinfo, provision_state_t *state,
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

static int add_new_coreserver(con_info_t *cinfo, provision_state_t *state,
        uint8_t srvtype) {

    struct json_object *parsed;
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
        goto siperr;
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
        goto siperr;
    }

    if (construct_coreserver_key(new_cs) == NULL) {
        logger(LOG_INFO,
                "OpenLI: unable to create %s from provided JSON record.", srvstring);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>Unable to create %s entity from JSON record provided over update socket. %s",
                update_failure_page_start, srvstring, update_failure_page_end);
        goto siperr;
    }

    if (srvtype == OPENLI_CORE_SERVER_SIP) {
        HASH_FIND(hh, state->interceptconf.sipservers, new_cs->serverkey,
                strlen(new_cs->serverkey), found);
    } else if (srvtype == OPENLI_CORE_SERVER_RADIUS) {
        HASH_FIND(hh, state->interceptconf.radiusservers, new_cs->serverkey,
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
        } else {
            logger(LOG_INFO, "OpenLI: update socket received unexpected core server update (type = %u)", srvtype);
            goto siperr;
        }

        announce_coreserver_change(state, new_cs, true);
        logger(LOG_INFO, "OpenLI: added %s '%s:%s' via update socket.",
                srvstring, new_cs->ipstr, new_cs->portstr);
    }

    json_tokener_free(tknr);
    return 0;

siperr:
    if (new_cs) {
        free_single_coreserver(new_cs);
    }
    json_tokener_free(tknr);
    return -1;

}

static int parse_voipintercept_siptargets(provision_state_t *state,
        voipintercept_t *vint, struct json_object *jsontargets,
        con_info_t *cinfo) {

    openli_sip_identity_t *newtgt, *found;
    struct json_object *jobj;
    struct json_object *username, *realm;
    int parseerr = 0, i, tgtcnt;

    newtgt = NULL;
    found = NULL;
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

static int parse_ipintercept_staticips(provision_state_t *state,
        ipintercept_t *ipint, struct json_object *jsonips, con_info_t *cinfo) {

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
        newr->awaitingconfirm = 0;
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

static int add_new_voipintercept(con_info_t *cinfo, provision_state_t *state) {
    struct json_intercept voipjson;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    voipintercept_t *found = NULL;
    voipintercept_t *vint = NULL;
    int parseerr = 0, r;
    prov_agency_t *lea = NULL;

    INIT_JSON_INTERCEPT_PARSING
    extract_intercept_json_objects(&voipjson, parsed);

    vint = calloc(1, sizeof(voipintercept_t));
    /* XXX does internalid still matter? if not, let's remove it */
    vint->awaitingconfirm = 1;
    vint->active = 1;
    vint->targets = libtrace_list_init(sizeof(openli_sip_identity_t *));

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
    }

    if (lea != NULL) {
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

static int add_new_ipintercept(con_info_t *cinfo, provision_state_t *state) {
    struct json_intercept ipjson;
    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    ipintercept_t *found = NULL;

    char *accessstring = NULL;
    ipintercept_t *ipint = NULL;
    int parseerr = 0;
    prov_agency_t *lea = NULL;

    INIT_JSON_INTERCEPT_PARSING
    extract_intercept_json_objects(&ipjson, parsed);

    ipint = calloc(1, sizeof(ipintercept_t));
    ipint->awaitingconfirm = 1;
    ipint->vendmirrorid = OPENLI_VENDOR_MIRROR_NONE;
    ipint->accesstype = INTERNET_ACCESS_TYPE_UNDEFINED;

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
    }

    if (lea != NULL) {
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
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return -1;
}

static int modify_ipintercept(con_info_t *cinfo, provision_state_t *state) {

    /* TODO */
    return 0;
}

static int add_new_agency(con_info_t *cinfo, provision_state_t *state) {

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

static int modify_agency(con_info_t *cinfo, provision_state_t *state) {

    struct json_object *agencyid;
    struct json_agency agjson;

    const char *idstr;
    struct json_object *parsed = NULL;
    struct json_tokener *tknr;
    prov_agency_t *found;
    int parseerr = 0;
    liagency_t modified;
    int changed = 0;

    INIT_JSON_AGENCY_PARSING

    HASH_FIND(hh, state->interceptconf.leas, idstr, strlen(idstr), found);

    if (!found) {
        /* Our "modify" is actually an addition? */
        json_tokener_free(tknr);
        return add_new_agency(cinfo, state);
    }

    memset(&modified, 0, sizeof(modified));
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

    printf("%s %s\n", modified.hi3_portstr, modified.hi2_portstr);

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

static int update_configuration_delete(con_info_t *cinfo,
        provision_state_t *state, const char *url) {

    int ret = 0;
    char *urlcopy = strdup(url);
    char *targetstart, *targetend, *urlstart;
    char target[4096];

    if (*url != '/') {
        free(urlcopy);
        logger(LOG_INFO, "OpenLI: invalid DELETE url from update socket: %s", url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse delete instruction from update socket. %s",
                update_failure_page_start, update_failure_page_end);
        return -1;
    }

    urlstart = urlcopy;
    while (*urlstart == '/') {
        urlstart ++;
    }

    targetstart = strchr(urlstart, '/');
    if (targetstart == NULL) {
        free(urlcopy);
        logger(LOG_INFO, "OpenLI: invalid DELETE url from update socket: %s", url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse delete instruction from update socket. %s",
                update_failure_page_start, update_failure_page_end);
        return -1;
    }

    while (*(targetstart + 1) == '/') {
        targetstart ++;
    }

    targetend = strchrnul(targetstart + 1, '/');

    if (targetend - targetstart >= 4096) {
        free(urlcopy);
        logger(LOG_INFO, "OpenLI: invalid DELETE url from update socket: %s", url);
        snprintf(cinfo->answerstring, 4096,
                "%s <p>OpenLI provisioner was unable to parse delete instruction from update socket. %s",
                update_failure_page_start, update_failure_page_end);
        return -1;
    }

    memcpy(target, targetstart + 1, targetend - targetstart - 1);
    target[targetend - (targetstart + 1)] = '\0';

    switch(cinfo->target) {
        case TARGET_AGENCY:
            ret = remove_agency(cinfo, state, target);
            break;
        case TARGET_SIPSERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_SIP);
            break;
        case TARGET_RADIUSSERVER:
            ret = remove_coreserver(cinfo, state, target,
                    OPENLI_CORE_SERVER_RADIUS);
            break;
        case TARGET_IPINTERCEPT:
            ret = remove_ip_intercept(cinfo, state, target);
            break;
        case TARGET_VOIPINTERCEPT:
            ret = remove_voip_intercept(cinfo, state, target);
            break;
    }

    emit_intercept_config(state->interceptconffile, &(state->interceptconf));
    free(urlcopy);
    return ret;
}


static int update_configuration_post(con_info_t *cinfo,
        provision_state_t *state, const char *method) {

    int ret = 0;

    if (cinfo->content_type == NULL || strcasecmp(cinfo->content_type,
                "application/json") != 0) {
        return -1;
    }

    if (!cinfo->jsonbuffer) {
        return -1;
    }

    switch(cinfo->target) {
        case TARGET_AGENCY:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_agency(cinfo, state);
            }
            else {
                ret = modify_agency(cinfo, state);
            }
            break;
        case TARGET_SIPSERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_SIP);
            break;
        case TARGET_RADIUSSERVER:
            ret = add_new_coreserver(cinfo, state, OPENLI_CORE_SERVER_RADIUS);
            break;
        case TARGET_IPINTERCEPT:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_ipintercept(cinfo, state);
            } else {
                ret = modify_ipintercept(cinfo, state);
            }
            break;
        case TARGET_VOIPINTERCEPT:
            if (strcmp(method, "POST") == 0) {
                ret = add_new_voipintercept(cinfo, state);
            } else {
                //ret = modify_ipintercept(cinfo, state);
            }
            break;
    }


    emit_intercept_config(state->interceptconffile, &(state->interceptconf));
    return ret;
}

static int consume_upload_data(con_info_t *cinfo, const char *data,
        size_t size) {

    cinfo->jsonbuffer = realloc(cinfo->jsonbuffer, cinfo->jsonlen + size + 1);
    if (cinfo->jsonbuffer == NULL) {
        snprintf(cinfo->answerstring, 4096, "%s %s", update_failure_page_start,
                update_failure_page_end);
        cinfo->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return MHD_NO;
    }

    memcpy(cinfo->jsonbuffer + cinfo->jsonlen, data, size);
    cinfo->jsonlen += size;
    cinfo->jsonbuffer[cinfo->jsonlen] = '\0';
    return MHD_YES;
}

void complete_update_request(void *cls, struct MHD_Connection *conn,
        void **con_cls, enum MHD_RequestTerminationCode toe) {

    con_info_t *cinfo = (con_info_t *)(*con_cls);

    if (cinfo == NULL) {
        return;
    }

    if (cinfo->connectiontype == MICRO_POST) {
        if (cinfo->jsonbuffer) {
            free(cinfo->jsonbuffer);
        }
    }

    free(cinfo);
    *con_cls = NULL;
}

int handle_update_request(void *cls, struct MHD_Connection *conn,
        const char *url, const char *method, const char *version,
        const char *upload_data, size_t *upload_data_size,
        void **con_cls) {

    con_info_t *cinfo;
    provision_state_t *provstate = (provision_state_t *)cls;

    if (*con_cls == NULL) {
        cinfo = calloc(1, sizeof(con_info_t));
        if (cinfo == NULL) {
            return MHD_NO;
        }

        if (strncmp(url, "/agency", 7) == 0) {
            cinfo->target = TARGET_AGENCY;
        } else if (strncmp(url, "/sipserver", 10) == 0) {
            cinfo->target = TARGET_SIPSERVER;
        } else if (strncmp(url, "/radiusserver", 13) == 0) {
            cinfo->target = TARGET_RADIUSSERVER;
        } else if (strncmp(url, "/ipintercept", 12) == 0) {
            cinfo->target = TARGET_IPINTERCEPT;
        } else if (strncmp(url, "/voipintercept", 14) == 0) {
            cinfo->target = TARGET_VOIPINTERCEPT;
        } else {
            free(cinfo);
            return MHD_NO;
        }

        if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0) {
            cinfo->content_type = MHD_lookup_connection_value(conn,
                    MHD_HEADER_KIND, "Content-Type");

            cinfo->connectiontype = MICRO_POST;
            cinfo->answercode = MHD_HTTP_OK;
            snprintf(cinfo->answerstring, 4096, "%s", update_success_page);
        } else if (strcmp(method, "DELETE") == 0) {
            cinfo->connectiontype = MICRO_DELETE;
            cinfo->answercode = MHD_HTTP_OK;
            snprintf(cinfo->answerstring, 4096, "%s", update_success_page);
        } else {
            cinfo->connectiontype = MICRO_GET;
        }

        *con_cls = (void *)cinfo;
        return MHD_YES;
    }


    if (strcmp(method, "GET") == 0) {
        return send_http_page(conn, get_not_implemented, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0) {
        cinfo = (con_info_t *)(*con_cls);

        if (*upload_data_size != 0) {
            int ret = consume_upload_data(cinfo, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return ret;
        } else {
            /* POST / PUT is complete */
            if (update_configuration_post(cinfo, provstate, method) < 0) {
                return send_http_page(conn, cinfo->answerstring,
                        MHD_HTTP_BAD_REQUEST);
            }

            return send_http_page(conn, cinfo->answerstring, cinfo->answercode);
        }
    } else if (strcmp(method, "DELETE") == 0) {
        cinfo = (con_info_t *)(*con_cls);

        if (update_configuration_delete(cinfo, provstate, url) < 0) {
            return send_http_page(conn, cinfo->answerstring,
                    MHD_HTTP_BAD_REQUEST);
        }
        return send_http_page(conn, cinfo->answerstring, cinfo->answercode);
    }

    return send_http_page(conn, unsupported_operation, MHD_HTTP_BAD_REQUEST);

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

