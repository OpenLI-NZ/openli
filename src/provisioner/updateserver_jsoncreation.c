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

static json_object *convert_lea_to_json(prov_agency_t *lea) {

    json_object *jobj;
    json_object *hi3addr;
    json_object *hi3port;
    json_object *hi2addr;
    json_object *hi2port;
    json_object *ka_freq;
    json_object *ka_wait;
    json_object *agencyid;

    jobj = json_object_new_object();

    agencyid = json_object_new_string(lea->ag->agencyid);
    hi3addr = json_object_new_string(lea->ag->hi3_ipstr);
    hi3port = json_object_new_string(lea->ag->hi3_portstr);
    hi2addr = json_object_new_string(lea->ag->hi2_ipstr);
    hi2port = json_object_new_string(lea->ag->hi2_portstr);
    ka_freq = json_object_new_int(lea->ag->keepalivefreq);
    ka_wait = json_object_new_int(lea->ag->keepalivewait);

    json_object_object_add(jobj, "agencyid", agencyid);
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
    json_object *encryptkey;
    json_object *starttime, *endtime, *tomediate, *encryption;

    if (common->encrypt == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        encrypt_str = "aes-192-cbc";
    } else {
        encrypt_str = "none";
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

}

static json_object *convert_ipintercept_to_json(ipintercept_t *ipint) {
    json_object *jobj;
    json_object *vendmirrorid, *user, *accesstype, *radiusident;
    json_object *staticips;

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
    json_object *targets;
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

static json_object *convert_coreserver_to_json(coreserver_t *cs,
        uint8_t srvtype) {
    json_object *jobj;
    json_object *ipaddr, *port;

    jobj = json_object_new_object();

    ipaddr = json_object_new_string(cs->ipstr);
    port = json_object_new_string(cs->portstr);

    json_object_object_add(jobj, "ipaddress", ipaddr);
    json_object_object_add(jobj, "port", port);

    return jobj;
}

json_object *get_default_radius(update_con_info_t *cinfo,
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

json_object *get_coreservers(update_con_info_t *cinfo, provision_state_t *state,
        uint8_t srvtype) {

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
        jobj = convert_coreserver_to_json(cs, srvtype);
        json_object_array_add(jarray, jobj);
    }

    return jarray;
}

json_object *get_agency(update_con_info_t *cinfo, provision_state_t *state,
        char *target) {

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

json_object *get_voip_intercept(update_con_info_t *cinfo,
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

json_object *get_email_intercept(update_con_info_t *cinfo,
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

json_object *get_ip_intercept(update_con_info_t *cinfo,
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
