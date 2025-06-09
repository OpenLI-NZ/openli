/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

#include "config.h"
static json_object *convert_lea_to_json(prov_agency_t *lea) {

    json_object *jobj;
    json_object *hi3addr;
    json_object *hi3port;
    json_object *hi2addr;
    json_object *hi2port;
    json_object *ka_freq;
    json_object *ka_wait;
    json_object *agencyid;
    json_object *agencycc = NULL;

    jobj = json_object_new_object();

    agencyid = json_object_new_string(lea->ag->agencyid);
    if (lea->ag->agencycc) {
        agencycc = json_object_new_string(lea->ag->agencycc);
    }
    hi3addr = json_object_new_string(lea->ag->hi3_ipstr);
    hi3port = json_object_new_string(lea->ag->hi3_portstr);
    hi2addr = json_object_new_string(lea->ag->hi2_ipstr);
    hi2port = json_object_new_string(lea->ag->hi2_portstr);
    ka_freq = json_object_new_int(lea->ag->keepalivefreq);
    ka_wait = json_object_new_int(lea->ag->keepalivewait);

    json_object_object_add(jobj, "agencyid", agencyid);
    if (agencycc) {
        json_object_object_add(jobj, "agencycc", agencycc);
    }
    json_object_object_add(jobj, "hi3address", hi3addr);
    json_object_object_add(jobj, "hi2address", hi2addr);
    json_object_object_add(jobj, "hi3port", hi3port);
    json_object_object_add(jobj, "hi2port", hi2port);
    json_object_object_add(jobj, "keepalivefreq", ka_freq);
    json_object_object_add(jobj, "keepalivewait", ka_wait);

    return jobj;
}

static void convert_commonintercept_to_json(json_object *jobj,
        intercept_common_t *common) {

    const char *encrypt_str;
    json_object *liid, *authcc, *delivcc, *agencyid, *mediator;
    json_object *encryptkey, *xids;
    json_object *starttime, *endtime, *tomediate, *encryption;
    char uuid[64];

    if (common->encrypt == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        encrypt_str = "aes-192-cbc";
    } else {
        encrypt_str = "none";
    }

    if (!uuid_is_null(common->xid)) {
        uuid_unparse(common->xid, uuid);
        xid = json_object_new_string(uuid);
    } else {
        xid = NULL;
    }


    xids = NULL;
    if (common->xid_count > 0) {
        size_t i;
        json_object *xid;

        xids = json_object_new_array();

        for (i = 0; i < common->xid_count; i++) {
            if (!uuid_is_null(common->xids[i])) {
                uuid_unparse(common->xids[i], uuid);
                xid = json_object_new_string(uuid);

                json_object_array_add(xids, xid);
            }
        }
    }

    liid = json_object_new_string(common->liid);
    authcc = json_object_new_string(common->authcc);
    delivcc = json_object_new_string(common->delivcc);
    agencyid = json_object_new_string(common->targetagency);
    mediator = json_object_new_int(common->destid);
    tomediate = json_object_new_int(common->tomediate);
    encryption = json_object_new_string(encrypt_str);

    if (common->encryptkey) {
        encryptkey = json_object_new_string(common->encryptkey);
    } else {
        encryptkey = NULL;
    }

    json_object_object_add(jobj, "liid", liid);
    json_object_object_add(jobj, "authcc", authcc);
    json_object_object_add(jobj, "delivcc", delivcc);
    json_object_object_add(jobj, "agencyid", agencyid);
    json_object_object_add(jobj, "mediator", mediator);
    json_object_object_add(jobj, "outputhandovers", tomediate);
    json_object_object_add(jobj, "payloadencryption", encryption);
    if (encryptkey) {
        json_object_object_add(jobj, "encryptionkey", encryptkey);
    }

    if (common->tostart_time != 0) {
        starttime = json_object_new_int(common->tostart_time);
        json_object_object_add(jobj, "starttime", starttime);
    }

    if (common->toend_time != 0) {
        endtime = json_object_new_int(common->toend_time);
        json_object_object_add(jobj, "endtime", endtime);
    }
    if (xids) {
        json_object_object_add(jobj, "xids", xids);
    }

}

static json_object *convert_ipintercept_to_json(ipintercept_t *ipint) {
    json_object *jobj;
    json_object *vendmirrorid, *user, *accesstype, *radiusident;
    json_object *staticips, *mobileident;

    jobj = json_object_new_object();
    convert_commonintercept_to_json(jobj, &(ipint->common));

    user = json_object_new_string(ipint->username);
    accesstype = json_object_new_string(
            get_access_type_string(ipint->accesstype));
    radiusident = json_object_new_string(
            get_radius_ident_string(ipint->options));

    json_object_object_add(jobj, "user", user);
    json_object_object_add(jobj, "accesstype", accesstype);
    json_object_object_add(jobj, "radiusident", radiusident);

    if (ipint->mobileident != OPENLI_MOBILE_IDENTIFIER_NOT_SPECIFIED) {
        mobileident = json_object_new_string(
                get_mobile_identifier_string(ipint->mobileident));
        json_object_object_add(jobj, "mobileident", mobileident);
    }

    if (ipint->vendmirrorid != 0xFFFFFFFF) {
        vendmirrorid = json_object_new_int(ipint->vendmirrorid);
        json_object_object_add(jobj, "vendmirrorid", vendmirrorid);
    }

    if (ipint->statics) {
        static_ipranges_t *range, *tmp;
        json_object *statip, *prefix, *sessid;

        staticips = json_object_new_array();

        HASH_ITER(hh, ipint->statics, range, tmp) {
            statip = json_object_new_object();

            prefix = json_object_new_string(range->rangestr);
            sessid = json_object_new_int(range->cin);

            json_object_object_add(statip, "iprange", prefix);
            json_object_object_add(statip, "sessionid", sessid);

            json_object_array_add(staticips, statip);
        }

        json_object_object_add(jobj, "staticips", staticips);
    }

    return jobj;
}

static json_object *convert_emailintercept_to_json(emailintercept_t *mailint) {
    json_object *jobj;
    json_object *targets, *decompress;
    const char *decompress_str;
    email_target_t *tgt, *tmp;

    jobj = json_object_new_object();
    convert_commonintercept_to_json(jobj, &(mailint->common));

    targets = json_object_new_array();

    HASH_ITER(hh, mailint->targets, tgt, tmp) {
        json_object *jsontgt, *address;

        jsontgt = json_object_new_object();
        address = json_object_new_string(tgt->address);
        json_object_object_add(jsontgt, "address", address);

        json_object_array_add(targets, jsontgt);
    }

    json_object_object_add(jobj, "targets", targets);

    if (mailint->delivercompressed == OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS) {
        decompress_str = "as-is";
    } else if (mailint->delivercompressed == OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED) {
        decompress_str = "decompressed";
    } else {
        decompress_str = NULL;
    }

    if (decompress_str) {
        decompress = json_object_new_string(decompress_str);
        json_object_object_add(jobj, "delivercompressed", decompress);
    }

    return jobj;
}

static json_object *convert_voipintercept_to_json(voipintercept_t *vint) {
    json_object *jobj;
    json_object *siptargets;

    libtrace_list_node_t *n;

    siptargets = json_object_new_array();
    jobj = json_object_new_object();

    convert_commonintercept_to_json(jobj, &(vint->common));

    n = vint->targets->head;
    while (n) {
        json_object *tgt, *username, *realm;
        openli_sip_identity_t *sipid = *((openli_sip_identity_t **)(n->data));

        tgt = json_object_new_object();
        username = json_object_new_string(sipid->username);
        json_object_object_add(tgt, "username", username);

        if (sipid->realm) {
            realm = json_object_new_string(sipid->realm);
            json_object_object_add(tgt, "realm", realm);
        }

        json_object_array_add(siptargets, tgt);
        n = n->next;
    }

    json_object_object_add(jobj, "siptargets", siptargets);
    return jobj;
}

static json_object *convert_coreserver_to_json(coreserver_t *cs) {
    json_object *jobj;
    json_object *ipaddr, *port, *upper_port, *lower_port;

    port = upper_port = lower_port = NULL;

    jobj = json_object_new_object();

    ipaddr = json_object_new_string(cs->ipstr);

    json_object_object_add(jobj, "ipaddress", ipaddr);
    if (cs->upper_portstr) {
        upper_port = json_object_new_string(cs->upper_portstr);
        json_object_object_add(jobj, "port_upper", upper_port);
    }

    if (cs->lower_portstr) {
        lower_port = json_object_new_string(cs->lower_portstr);
        json_object_object_add(jobj, "port_lower", lower_port);
    }

    if (cs->portstr) {
        port = json_object_new_string(cs->portstr);
        json_object_object_add(jobj, "port", port);
    }

    return jobj;
}


/* RHEL 8 doesn't have a libjson that provides json_object_new_uint64(), so
 * we need to provide our own version.
 */
#if JSON_C_VERSION_NUM >= 0x000d0100
#define openli_json_object_new_uint64(val) json_object_new_uint64(val)
#else
static inline struct json_object *openli_json_object_new_uint64(uint64_t val) {
    char buf[64];
    snprintf(buf, 64, "%" PRIu64, val);
    return json_object_new_string(buf);
}
#endif

static json_object *convert_client_to_json(known_client_t *c) {
    json_object *jobj;
    json_object *medid, *ipaddress, *firstseen, *lastseen;

    medid = ipaddress = firstseen = lastseen = NULL;

    jobj = json_object_new_object();

    if (c->type == TARGET_MEDIATOR) {
        medid = openli_json_object_new_uint64(c->medid);
        json_object_object_add(jobj, "mediatorid", medid);
    }

    if (c->ipaddress) {
        ipaddress = json_object_new_string(c->ipaddress);
        json_object_object_add(jobj, "ipaddress", ipaddress);
        free((void *)c->ipaddress);
    }

    firstseen = openli_json_object_new_uint64(c->firstseen);
    json_object_object_add(jobj, "firstseen", firstseen);

    lastseen = openli_json_object_new_uint64(c->lastseen);
    json_object_object_add(jobj, "lastseen", lastseen);

    return jobj;
}

struct json_object *get_openli_version(void) {
    json_object *jobj, *major, *minor, *revision, *full;
    int a,b,c;

    if (sscanf(PACKAGE_VERSION, "%d.%d.%d", &a, &b, &c) != 3) {
        return NULL;
    }

    jobj = json_object_new_object();
    major = json_object_new_int(a);
    minor = json_object_new_int(b);
    revision = json_object_new_int(c);
    full = json_object_new_string(PACKAGE_VERSION);

    json_object_object_add(jobj, "fullversion", full);
    json_object_object_add(jobj, "major", major);
    json_object_object_add(jobj, "minor", minor);
    json_object_object_add(jobj, "revision", revision);

    return jobj;
}

json_object *get_provisioner_options(update_con_info_t *cinfo UNUSED,
        provision_state_t *state) {

    json_object *jobj;
    json_object *defaultemaildecompressed = NULL;

    jobj = json_object_new_object();

    if (state->interceptconf.default_email_deliver_compress ==
            OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS) {
        defaultemaildecompressed = json_object_new_string("as-is");
    } else if (state->interceptconf.default_email_deliver_compress ==
            OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED) {
        defaultemaildecompressed = json_object_new_string("decompressed");
    }

    if (defaultemaildecompressed) {
        json_object_object_add(jobj, "email-defaultdelivercompressed",
                defaultemaildecompressed);
    }
    return jobj;
}

json_object *get_known_collectors(update_con_info_t *cinfo UNUSED,
        provision_state_t *state) {

    json_object *jarray, *jobj;
    known_client_t *cols;
    size_t colcount, i;

    cols = fetch_all_collector_clients(state, &colcount);
    if (!cols || colcount == 0) {
        return NULL;
    }

    jarray = json_object_new_array();
    for (i = 0; i < colcount; i++) {
        jobj = convert_client_to_json(&(cols[i]));
        json_object_array_add(jarray, jobj);
    }
    free(cols);

    return jarray;
}

json_object *get_known_mediators(update_con_info_t *cinfo UNUSED,
        provision_state_t *state) {

    json_object *jarray, *jobj;
    known_client_t *meds;
    size_t medcount, i;

    meds = fetch_all_mediator_clients(state, &medcount);
    if (!meds || medcount == 0) {
        return NULL;
    }

    jarray = json_object_new_array();
    for (i = 0; i < medcount; i++) {
        jobj = convert_client_to_json(&(meds[i]));
        json_object_array_add(jarray, jobj);
    }
    free(meds);

    return jarray;
}

json_object *get_default_radius(update_con_info_t *cinfo UNUSED,
        provision_state_t *state) {

    default_radius_user_t *dfr, *tmp;
    json_object *jarray, *jobj;

    jarray = json_object_new_array();

    HASH_ITER(hh, state->interceptconf.defradusers, dfr, tmp) {
        jobj = json_object_new_string(dfr->name);
        json_object_array_add(jarray, jobj);
    }
    return jarray;
}

json_object *get_coreservers(update_con_info_t *cinfo UNUSED,
        provision_state_t *state, uint8_t srvtype) {

    json_object *jobj, *jarray;
    coreserver_t *cs, *tmp, *toiter;

    switch(srvtype) {
        case OPENLI_CORE_SERVER_GTP:
            toiter = state->interceptconf.gtpservers;
            break;
        case OPENLI_CORE_SERVER_SIP:
            toiter = state->interceptconf.sipservers;
            break;
        case OPENLI_CORE_SERVER_SMTP:
            toiter = state->interceptconf.smtpservers;
            break;
        case OPENLI_CORE_SERVER_IMAP:
            toiter = state->interceptconf.imapservers;
            break;
        case OPENLI_CORE_SERVER_POP3:
            toiter = state->interceptconf.pop3servers;
            break;
        case OPENLI_CORE_SERVER_RADIUS:
            toiter = state->interceptconf.radiusservers;
            break;
        default:
            toiter = NULL;
    }

    jarray = json_object_new_array();
    HASH_ITER(hh, toiter, cs, tmp) {
        jobj = convert_coreserver_to_json(cs);
        json_object_array_add(jarray, jobj);
    }

    return jarray;
}

json_object *get_agency(update_con_info_t *cinfo UNUSED,
        provision_state_t *state, char *target) {

    prov_agency_t *found, *tmp;
    json_object *jobj, *jagency;
    json_object *jarray;

    if (target) {
        HASH_FIND(hh, state->interceptconf.leas, target, strlen(target),
                found);

        if (!found) {
            return NULL;
        }

        jobj = convert_lea_to_json(found);
        return jobj;
    }

    /* No specific agency specified, so return them all */

    jarray = json_object_new_array();

    HASH_ITER(hh, state->interceptconf.leas, found, tmp) {
        jagency = convert_lea_to_json(found);
        json_object_array_add(jarray, jagency);
    }

    return jarray;

}

json_object *get_voip_intercept(update_con_info_t *cinfo UNUSED,
        provision_state_t *state, char *target) {

    voipintercept_t *vint, *tmp;
    json_object *jarray, *jobj;

    if (target) {
        HASH_FIND(hh_liid, state->interceptconf.voipintercepts, target,
                strlen(target), vint);
        if (!vint) {
            return NULL;
        }

        jobj = convert_voipintercept_to_json(vint);
        return jobj;
    }

    jarray = json_object_new_array();
    HASH_ITER(hh_liid, state->interceptconf.voipintercepts, vint, tmp) {
        jobj = convert_voipintercept_to_json(vint);
        json_object_array_add(jarray, jobj);
    }

    return jarray;
}

json_object *get_email_intercept(update_con_info_t *cinfo UNUSED,
        provision_state_t *state, char *target) {

    emailintercept_t *mailint, *tmp;
    json_object *jarray, *jobj;

    if (target) {
        HASH_FIND(hh_liid, state->interceptconf.emailintercepts, target,
                strlen(target), mailint);
        if (!mailint) {
            return NULL;
        }

        jobj = convert_emailintercept_to_json(mailint);
        return jobj;
    }

    jarray = json_object_new_array();
    HASH_ITER(hh_liid, state->interceptconf.emailintercepts, mailint, tmp) {
        jobj = convert_emailintercept_to_json(mailint);
        json_object_array_add(jarray, jobj);
    }

    return jarray;
}

json_object *get_ip_intercept(update_con_info_t *cinfo UNUSED,
        provision_state_t *state, char *target) {

    ipintercept_t *ipint, *tmp;
    json_object *jarray, *jobj;

    if (target) {
        HASH_FIND(hh_liid, state->interceptconf.ipintercepts, target,
                strlen(target), ipint);
        if (!ipint) {
            return NULL;
        }

        jobj = convert_ipintercept_to_json(ipint);
        return jobj;
    }

    jarray = json_object_new_array();
    HASH_ITER(hh_liid, state->interceptconf.ipintercepts, ipint, tmp) {
        jobj = convert_ipintercept_to_json(ipint);
        json_object_array_add(jarray, jobj);
    }

    return jarray;
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
