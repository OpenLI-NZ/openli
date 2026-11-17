/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
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

#include <json-c/json.h>
#include <libtrace.h>
#include <libtrace_parallel.h>

#include "logger.h"
#include "collector.h"
#include "coreserver.h"

static void stop_collector_input(collector_global_t *glob, colinput_t *inp) {
    char prefix[1024];
    char locname[1048];

    colthread_local_t *loc = NULL;
    int i;

    if (!inp->running || !inp->trace) {
        return;
    }

    logger(LOG_INFO, "OpenLI collector: stopping input %s for reconfiguration",
            inp->uri);

    snprintf(prefix, sizeof(prefix), "%s-%s-",
            trace_get_uri_format(inp->trace), trace_get_uri_body(inp->trace));
    trace_pstop(inp->trace);
    trace_join(inp->trace);
    trace_destroy(inp->trace);
    inp->trace = NULL;

    for (i = 0; i < inp->threadcount; i++) {
        snprintf(locname, sizeof(locname), "%s%d", prefix, i);
        HASH_FIND(hh, glob->collocals, locname, strlen(locname), loc);
        if (loc) {
            HASH_DELETE(hh, glob->collocals, loc);
            if (loc->localname) {
                free(loc->localname);
            }
            free(loc);
        }
    }

    if (inp->filter) {
        trace_destroy_filter(inp->filter);
        inp->filter = NULL;
    }

    inp->running = 0;
    inp->start_at = 0;
}

int handle_rmq_config_changes(openli_RMQ_config_t *rmqconf,
        openli_yaml_config_pending_updates_t *pending, char *json,
        int *changed) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *enabled_json = NULL;
    int ret = -1;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));
    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto rmqfail;
    }

    if (json_object_object_get_ex(parsed, "RMQenabled",
                &enabled_json) &&
            json_object_is_type(enabled_json, json_type_boolean)) {
        bool newval = json_object_get_boolean(enabled_json);
        if (newval != rmqconf->enabled) {
            rmqconf->enabled = newval;
            UPDATE_SCALAR_CONFIG(pending, "RMQenabled",
                    GENERATE_CONFIG_BOOLEAN(rmqconf->enabled),
                    false, true);
            *changed = 1;
        }
    }
    ret = 0;
rmqfail:

    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}

int handle_identity_config_changes(collector_identity_t *ident,
        openli_yaml_config_pending_updates_t *pending, char *json) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *operatorid_json, *intpointid_json, *netelemid_json;
    struct json_object *cisconoradius_json;
    int ret = -1;
    const char *operatorid = NULL;
    const char *intpointid = NULL;
    const char *netelemid = NULL;

    operatorid_json = intpointid_json = netelemid_json = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto identfail;
    }
    if (json_object_object_get_ex(parsed, "operatorid",
                &operatorid_json) &&
            json_object_is_type(operatorid_json, json_type_string)) {
        operatorid = json_object_get_string(operatorid_json);
        if (operatorid) {
            if (ident->operatorid) {
                free(ident->operatorid);
            }
            ident->operatorid = strdup((char *)operatorid);
            ident->operatorid_len = strlen(ident->operatorid);
            UPDATE_SCALAR_CONFIG(pending, "operatorid",
                    ident->operatorid, true, true);
        }
    }

    if (json_object_object_get_ex(parsed, "networkelementid",
                &netelemid_json) &&
            json_object_is_type(netelemid_json, json_type_string)) {
        netelemid = json_object_get_string(netelemid_json);
        if (netelemid) {
            if (ident->networkelemid) {
                free(ident->networkelemid);
            }
            ident->networkelemid = strdup((char *)netelemid);
            ident->networkelemid_len = strlen(ident->networkelemid);

            UPDATE_SCALAR_CONFIG(pending, "networkelementid",
                    ident->networkelemid, true, true);
        }
    }

    if (json_object_object_get_ex(parsed, "interceptpointid",
                &intpointid_json) &&
            json_object_is_type(intpointid_json, json_type_string)) {
        intpointid = json_object_get_string(intpointid_json);
        if (intpointid) {
            if (ident->intpointid) {
                free(ident->intpointid);
            }
            ident->intpointid = strdup((char *)intpointid);
            ident->intpointid_len = strlen(ident->intpointid);

            UPDATE_SCALAR_CONFIG(pending, "interceptpointid",
                    ident->intpointid, true, true);
        }
    }

    if (json_object_object_get_ex(parsed, "cisconoradius",
                &cisconoradius_json)) {
        uint8_t newval = 255;
        if (json_object_is_type(cisconoradius_json, json_type_boolean)) {
            newval = json_object_get_boolean(cisconoradius_json) ? 1 : 0;
        } else if (json_object_is_type(cisconoradius_json, json_type_int)) {
            newval = json_object_get_int(cisconoradius_json) ? 1 : 0;
        }

        if (newval != 255 && newval != ident->cisco_noradius) {
            ident->cisco_noradius = newval;
            UPDATE_SCALAR_CONFIG(pending, "cisconoradius",
                    GENERATE_CONFIG_BOOLEAN(ident->cisco_noradius),
                    false, true);
            logger(LOG_INFO, "OpenLI: now %s RADIUS will be included in Cisco mirrored traffic", ident->cisco_noradius ? "not expecting" : "expecting");
        }
    }

    ret = 0;
identfail:

    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;

}

int handle_sip_config_changes(collector_sip_config_t *sipconfig,
        openli_yaml_config_pending_updates_t *pending, char *json) {
    struct json_tokener *tknr;
    struct json_object *ignore_sdpo, *trust_from, *disable_redirect;
    struct json_object *use_sessiondir;
    struct json_object *sipdebugfile, *ignore_sessionid;
    struct json_object *parsed = NULL;
    int ret = -1;
    const char *debugfile = NULL;

    ignore_sdpo = trust_from = disable_redirect = sipdebugfile = NULL;
    ignore_sessionid = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));
    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto sipconffail;
    }

    if (json_object_object_get_ex(parsed, "sipallowfromident", &trust_from)
            && json_object_is_type(trust_from, json_type_boolean)) {
        sipconfig->trust_sip_from = json_object_get_boolean(trust_from);
        UPDATE_SCALAR_CONFIG(pending, "sipallowfromident",
                GENERATE_CONFIG_BOOLEAN(sipconfig->trust_sip_from),
                false, true);
    }
    if (json_object_object_get_ex(parsed, "sipdisableredirect",
                &disable_redirect) && json_object_is_type(disable_redirect,
                        json_type_boolean)) {
        sipconfig->disable_sip_redirect =
                json_object_get_boolean(disable_redirect);
        UPDATE_SCALAR_CONFIG(pending, "sipdisableredirect",
                GENERATE_CONFIG_BOOLEAN(sipconfig->disable_sip_redirect),
                false, true);
    }
    if (json_object_object_get_ex(parsed, "sipignoresdpo", &ignore_sdpo)
            && json_object_is_type(ignore_sdpo, json_type_boolean)) {
        sipconfig->ignore_sdpo_matches =
                json_object_get_boolean(ignore_sdpo);
        UPDATE_SCALAR_CONFIG(pending, "sipignoresdpo",
                GENERATE_CONFIG_BOOLEAN(sipconfig->ignore_sdpo_matches),
                false, true);
    }
    if (json_object_object_get_ex(parsed, "sipusesessiondir", &use_sessiondir)
            && json_object_is_type(use_sessiondir, json_type_boolean)) {
        sipconfig->use_sessiondir =
                json_object_get_boolean(use_sessiondir);
        UPDATE_SCALAR_CONFIG(pending, "sipusesessiondir",
                GENERATE_CONFIG_BOOLEAN(sipconfig->use_sessiondir),
                false, true);
    }

    if (json_object_object_get_ex(parsed, "sipignoresessionid",
            &ignore_sessionid)
            && json_object_is_type(ignore_sessionid, json_type_boolean)) {
        sipconfig->ignore_sessionid_matches =
                json_object_get_boolean(ignore_sessionid);
        UPDATE_SCALAR_CONFIG(pending, "sipignoresessionid",
                GENERATE_CONFIG_BOOLEAN(sipconfig->ignore_sessionid_matches),
                false, true);
    }

    if (json_object_object_get_ex(parsed, "sipdebugfile", &sipdebugfile) &&
            json_object_is_type(sipdebugfile, json_type_string)) {
        debugfile = json_object_get_string(sipdebugfile);
        if (debugfile) {
            if (sipconfig->sipdebugfile) {
                free(sipconfig->sipdebugfile);
            }
            sipconfig->sipdebugfile = strdup((char *)debugfile);
            UPDATE_SCALAR_CONFIG(pending, "sipdebugfile",
                    sipconfig->sipdebugfile, true, true);
        }
    }
    ret = 0;

sipconffail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}

int handle_tls_config_changes(collector_global_t *glob,
        openli_yaml_config_pending_updates_t *pending, char *json,
        int *flagchanged, int *groupschanged) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *flag_json = NULL, *groups_json = NULL;
    int ret = -1;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto tlsconffail;
    }

    if (json_object_object_get_ex(parsed, "tlsgroups", &groups_json)) {
        const char *newgroups = NULL;

        if (json_object_is_type(groups_json, json_type_string)) {
            newgroups = json_object_get_string(groups_json);

            if (newgroups[0] == '\0' || strcasecmp(newgroups, "default") == 0) {
                newgroups = NULL;
            }
        } else if (json_object_is_type(groups_json, json_type_null)) {
            newgroups = NULL;
        }

        if ((glob->sslconf.tlsgroups == NULL && newgroups != NULL) ||
            (glob->sslconf.tlsgroups != NULL && newgroups == NULL) ||
            (glob->sslconf.tlsgroups && newgroups &&
                    strcmp(glob->sslconf.tlsgroups, newgroups) != 0)) {

            if (glob->sslconf.tlsgroups) {
                free(glob->sslconf.tlsgroups);
                glob->sslconf.tlsgroups = NULL;
            }

            if (newgroups) {
                glob->sslconf.tlsgroups = strdup((char *)newgroups);
                UPDATE_SCALAR_CONFIG(pending, "tlsgroups",
                        glob->sslconf.tlsgroups, true, true);
            } else {
                UPDATE_SCALAR_CONFIG(pending, "tlsgroups", "", true, true);
            }
            *groupschanged = 1;
        }
    }

    if (json_object_object_get_ex(parsed, "etsitls", &flag_json) &&
            json_object_is_type(flag_json, json_type_boolean)) {
        bool newflag = json_object_get_boolean(flag_json);
        if (newflag != (bool)glob->etsitls) {
            glob->etsitls = newflag ? 1 : 0;
            UPDATE_SCALAR_CONFIG(pending, "etsitls",
                    GENERATE_CONFIG_BOOLEAN(glob->etsitls), false, true);
            *flagchanged = 1;
        }
    }

    ret = 0;
tlsconffail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}

static void update_thread_count_param(struct json_object *parsed,
        openli_yaml_config_pending_updates_t *pending, const char *key,
        int minval, int *changed) {

    struct json_object *valobj = NULL;
    int c;
    char buf[32];

    if (json_object_object_get_ex(parsed, key, &valobj) &&
            json_object_is_type(valobj, json_type_int)) {

        c = json_object_get_int(valobj);
        if (c >= minval) {
            snprintf(buf, sizeof(buf), "%d", c);
            UPDATE_SCALAR_CONFIG(pending, (char *)key, buf, false, true);
            *changed = 1;
        } else {
            logger(LOG_INFO,
                    "OpenLI: ignoring invalid thread count %d for '%s' (minimum is %d)",
                    c, key, minval);
        }
    }
}

int handle_email_config_changes(collector_global_t *glob,
        openli_yaml_config_pending_updates_t *pending, char *json) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    struct json_object *mask_imap, *mask_pop3, *allow_imap_id;
    struct json_object *delayed_imap, *use_targetid, *def_domain;
    struct json_object *timeouts_obj, *hdrs_obj;
    int ret = -1;

    mask_imap = mask_pop3 = allow_imap_id = delayed_imap = NULL;
    use_targetid = def_domain = timeouts_obj = hdrs_obj = NULL;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));
    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto emailfail;
    }

    if (json_object_object_get_ex(parsed, "emailsessiontimeouts",
            &timeouts_obj) &&
            json_object_is_type(timeouts_obj, json_type_object)) {
        struct json_object *val;
        openli_yaml_config_object_t prototimeouts[3];
        openli_yaml_config_object_field_t fields[3];
        char smtp_str[32], imap_str[32], pop3_str[32];

        if (json_object_object_get_ex(timeouts_obj, "smtp", &val) &&
                json_object_is_type(val, json_type_int)) {
            glob->email_timeouts.smtp = json_object_get_int(val);
        }
        if (json_object_object_get_ex(timeouts_obj, "imap", &val) &&
                json_object_is_type(val, json_type_int)) {
            glob->email_timeouts.imap = json_object_get_int(val);
        }
        if (json_object_object_get_ex(timeouts_obj, "pop3", &val) &&
                json_object_is_type(val, json_type_int)) {
            glob->email_timeouts.pop3 = json_object_get_int(val);
        }

        snprintf(smtp_str, sizeof(smtp_str), "%u", glob->email_timeouts.smtp);
        snprintf(imap_str, sizeof(imap_str), "%u", glob->email_timeouts.imap);
        snprintf(pop3_str, sizeof(pop3_str), "%u", glob->email_timeouts.pop3);

        fields[0].key = "smtp";
        fields[0].value = smtp_str;
        fields[0].is_string = false;

        fields[1].key = "imap";
        fields[1].value = imap_str;
        fields[1].is_string = false;

        fields[2].key = "pop3";
        fields[2].value = pop3_str;
        fields[2].is_string = false;

        prototimeouts[0].fields = &(fields[0]);
        prototimeouts[0].field_count = 1;
        prototimeouts[1].fields = &(fields[1]);
        prototimeouts[1].field_count = 1;
        prototimeouts[2].fields = &(fields[2]);
        prototimeouts[2].field_count = 1;

        prepare_new_openli_yaml_config_update(pending);
        generate_array_object_replace_openli_yaml_config_update(
                &(pending->updates[pending->update_count]),
                "emailsessiontimeouts", prototimeouts, 3, true);
        pending->update_count ++;
    }

    if (json_object_object_get_ex(parsed, "emailforwardingheaders", &hdrs_obj)
            && json_object_is_type(hdrs_obj, json_type_array)) {
        size_t i, hdrcnt, len = json_object_array_length(hdrs_obj);
        struct json_object *item;
        string_set_t *new_headers = NULL;
        char **hdr_strings = NULL;

        if (len > 0) {
            hdr_strings = calloc(len, sizeof(char *));
        }
        hdrcnt = 0;
        for (i = 0; i < len; i++) {
            item = json_object_array_get_idx(hdrs_obj, i);
            if (json_object_is_type(item, json_type_string)) {
                const char *s = json_object_get_string(item);
                add_to_string_set(&new_headers, (char *)s);
                hdr_strings[hdrcnt] = (char *)s;
                hdrcnt ++;
            }
        }

        purge_string_set(&(glob->email_forwarding_headers));
        glob->email_forwarding_headers = new_headers;

        prepare_new_openli_yaml_config_update(pending);
        generate_array_replace_openli_yaml_config_update(
                &pending->updates[pending->update_count],
                "emailforwardingheaders",
                (const char **)hdr_strings,
                true, hdrcnt, true);
        pending->update_count ++;
        free(hdr_strings);
    }

    if (json_object_object_get_ex(parsed, "maskimapcreds", &mask_imap) &&
            json_object_is_type(mask_imap, json_type_boolean)) {
        uint8_t newval = json_object_get_boolean(mask_imap) ? 1 : 0;

        if (newval != glob->mask_imap_creds) {
            glob->mask_imap_creds = newval;
            UPDATE_SCALAR_CONFIG(pending, "maskimapcreds",
                    GENERATE_CONFIG_BOOLEAN(glob->mask_imap_creds), false,
                    true);
            logger(LOG_INFO,
                    "OpenLI: email interception: %s IMAP credential masking",
                    glob->mask_imap_creds ? "enabled" : "disabled");
        }
    }

    if (json_object_object_get_ex(parsed, "maskpop3creds", &mask_pop3) &&
            json_object_is_type(mask_pop3, json_type_boolean)) {
        uint8_t newval = json_object_get_boolean(mask_pop3) ? 1 : 0;

        if (newval != glob->mask_pop3_creds) {
            glob->mask_pop3_creds = newval;
            UPDATE_SCALAR_CONFIG(pending, "maskpop3creds",
                    GENERATE_CONFIG_BOOLEAN(glob->mask_pop3_creds), false,
                    true);
            logger(LOG_INFO,
                    "OpenLI: email interception: %s POP3 credential masking",
                    glob->mask_pop3_creds ? "enabled" : "disabled");
        }
    }

    if (json_object_object_get_ex(parsed, "allowimapidoverrides",
            &allow_imap_id) &&
            json_object_is_type(allow_imap_id, json_type_boolean)) {
        uint8_t newval = json_object_get_boolean(allow_imap_id) ? 1 : 0;

        if (newval != glob->allow_imap_id_overrides) {
            glob->allow_imap_id_overrides = newval;
            UPDATE_SCALAR_CONFIG(pending, "allowimapidoverrides",
                    GENERATE_CONFIG_BOOLEAN(glob->allow_imap_id_overrides),
                    false, true);
            logger(LOG_INFO,
                    "OpenLI: email interception: %s overriding of IMAP IDs",
                    glob->allow_imap_id_overrides ? "enabled" : "disabled");
        }
    }

    if (json_object_object_get_ex(parsed, "delayedimaploginiri",
            &delayed_imap) &&
            json_object_is_type(delayed_imap, json_type_boolean)) {
        uint8_t newval = json_object_get_boolean(delayed_imap) ? 1 : 0;

        if (newval != glob->delayed_imap_id_override) {
            glob->delayed_imap_id_override = newval;
            UPDATE_SCALAR_CONFIG(pending, "delayedimaploginiri",
                    GENERATE_CONFIG_BOOLEAN(glob->delayed_imap_id_override),
                    false, true);
            logger(LOG_INFO,
                    "OpenLI: email interception: %s delayed IRIs after IMAP login",
                    glob->delayed_imap_id_override ? "enabled" : "disabled");
        }
    }

    if (json_object_object_get_ex(parsed, "emailingest-usetargetid",
            &use_targetid) &&
            json_object_is_type(use_targetid, json_type_boolean)) {
        uint8_t newval = json_object_get_boolean(use_targetid) ? 1 : 0;

        if (newval != glob->email_ingest_use_targetid) {
            glob->email_ingest_use_targetid = newval;
            UPDATE_SCALAR_CONFIG(pending, "emailingest-usetargetid",
                    GENERATE_CONFIG_BOOLEAN(glob->email_ingest_use_targetid),
                    false, true);
            logger(LOG_INFO,
                    "OpenLI: email interception: %s matching on ingest target ID",
                    glob->email_ingest_use_targetid ? "enabled" : "disabled");
        }
    }

    if (json_object_object_get_ex(parsed, "defaultemaildomain", &def_domain)) {
        const char *newdomain = NULL;

        if (json_object_is_type(def_domain, json_type_string)) {
            newdomain = json_object_get_string(def_domain);
            if (newdomain[0] == '\0') {
                newdomain = NULL;
            }
        } else if (json_object_is_type(def_domain, json_type_null)) {
            newdomain = NULL;
        }

        if ((glob->default_email_domain == NULL && newdomain != NULL) ||
                (glob->default_email_domain != NULL && newdomain == NULL) ||
                (glob->default_email_domain && newdomain &&
                    strcasecmp(newdomain, glob->default_email_domain) != 0)) {
            if (glob->default_email_domain) {
                free(glob->default_email_domain);
                glob->default_email_domain = NULL;
            }

            if (newdomain) {
                glob->default_email_domain = strdup((char *)newdomain);
                UPDATE_SCALAR_CONFIG(pending, "defaultemaildomain",
                        glob->default_email_domain, true, true);
                logger(LOG_INFO, "OpenLI: setting default email domain to '%s'",
                        glob->default_email_domain);
            } else {
                UPDATE_SCALAR_CONFIG(pending, "defaultemaildomain", "",
                        true, true);
                logger(LOG_INFO, "OpenLI: default email domain has been unset");
            }
        }
    }

    ret = 0;

emailfail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}

int handle_workerthread_config_changes(char *json, int *restart_confirmed,
        openli_yaml_config_pending_updates_t *pending) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL;
    int ret = -1, changed = 0;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    *restart_confirmed = 0;

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto workerfail;
    }

    update_thread_count_param(parsed, pending, "forwardingthreads", 1,
            &changed);
    update_thread_count_param(parsed, pending, "encoderthreads", 1,
            &changed);
    update_thread_count_param(parsed, pending, "seqtrackerthreads", 1,
            &changed);
    update_thread_count_param(parsed, pending, "sipthreads", 1,
            &changed);
    update_thread_count_param(parsed, pending, "emailthreads", 0,
            &changed);
    update_thread_count_param(parsed, pending, "sctpthreads", 0,
            &changed);
    update_thread_count_param(parsed, pending, "gtpthreads", 0,
            &changed);

    if (changed) {
        *restart_confirmed = 1;
    }

    ret = 0;

workerfail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;
}

static void update_input_yaml_config(collector_global_t *glob,
        openli_yaml_config_pending_updates_t *pending) {

    colinput_t *inp = NULL, *tmp = NULL;
    openli_yaml_config_object_t *yamlobjs = NULL;
    openli_yaml_config_object_field_t **fields = NULL;
    char **thread_strs = NULL;
    char **vxlan_strs = NULL;
    size_t i, num_inputs;

    num_inputs = HASH_COUNT(glob->inputs);
    if (num_inputs == 0) {
        return;
    }

    yamlobjs = calloc(num_inputs, sizeof(openli_yaml_config_object_t));
    fields = calloc(num_inputs, sizeof(openli_yaml_config_object_field_t *));
    thread_strs = calloc(num_inputs, sizeof(char *));
    vxlan_strs = calloc(num_inputs, sizeof(char *));

    i = 0;
    HASH_ITER(hh, glob->inputs, inp, tmp) {
        size_t fc = 0;
        fields[i] = calloc(7, sizeof(openli_yaml_config_object_field_t));
        thread_strs[i] = calloc(1, 32);
        vxlan_strs[i] = calloc(1, 32);

        fields[i][fc].key = "uri";
        fields[i][fc].value = inp->uri;
        fields[i][fc].is_string = true;
        fc ++;

        snprintf(thread_strs[i], 32, "%d", inp->threadcount);
        fields[i][fc].key = "threads";
        fields[i][fc].value = thread_strs[i];
        fields[i][fc].is_string = false;
        fc ++;

        if (inp->filterstring) {
            fields[i][fc].key = "filter";
            fields[i][fc].value = inp->filterstring;
            fields[i][fc].is_string = true;
            fc ++;
        }

        if (inp->coremap) {
            fields[i][fc].key = "coremap";
            fields[i][fc].value = inp->coremap;
            fields[i][fc].is_string = true;
            fc ++;
        }

        if (inp->hasher_apply == OPENLI_HASHER_BALANCE) {
            fields[i][fc].key = "hasher";
            fields[i][fc].value = "balanced";
            fields[i][fc].is_string = true;
            fc ++;
        } else if (inp->hasher_apply == OPENLI_HASHER_BIDIR) {
            fields[i][fc].key = "hasher";
            fields[i][fc].value = "bidirectional";
            fields[i][fc].is_string = true;
            fc ++;
        } else if (inp->hasher_apply == OPENLI_HASHER_RADIUS) {
            fields[i][fc].key = "hasher";
            fields[i][fc].value = "radius";
            fields[i][fc].is_string = true;
            fc ++;
        }

        if (inp->vxlan_strip) {
            snprintf(vxlan_strs[i], 32, "%u", inp->vxlan_port);
            fields[i][fc].key = "stripvxlan";
            fields[i][fc].value = vxlan_strs[i];
            fields[i][fc].is_string = false;
            fc ++;
        }

        fields[i][fc].key = "reportdrops";
        fields[i][fc].value = inp->report_drops ? "true" : "false";
        fields[i][fc].is_string = false;
        fc ++;

        yamlobjs[i].fields = fields[i];
        yamlobjs[i].field_count = fc;
        i++;
    }

    prepare_new_openli_yaml_config_update(pending);
    generate_array_object_replace_openli_yaml_config_update(
            &(pending->updates[pending->update_count]), "inputs",
            yamlobjs, num_inputs, true);
    pending->update_count ++;

    for (i = 0; i < num_inputs; i++) {
        if (fields[i]) {
            free(fields[i]);
        }
        if (thread_strs[i]) {
            free(thread_strs[i]);
        }
        if (vxlan_strs[i]) {
            free(vxlan_strs[i]);
        }
    }

    free(yamlobjs);
    free(fields);
    free(thread_strs);
    free(vxlan_strs);

}

int handle_input_config_changes(collector_global_t *glob,
        openli_yaml_config_pending_updates_t *pending, char *json) {

    struct json_tokener *tknr;
    struct json_object *parsed = NULL, *inputs_obj = NULL;
    int ret = -1, changed = 0;
    size_t inp_count, i;

    tknr = json_tokener_new();
    parsed = json_tokener_parse_ex(tknr, json, strlen(json));

    if (parsed == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse JSON configuration received from provisioner: %s",
                json_tokener_error_desc(json_tokener_get_error(tknr)));
        goto inpfail;
    }

    if (!json_object_object_get_ex(parsed, "inputs", &inputs_obj)) {
        ret = 0;
        goto inpfail;
    }

    if (json_object_is_type(inputs_obj, json_type_array)) {
        inp_count = json_object_array_length(inputs_obj);
    } else if (json_object_is_type(inputs_obj, json_type_object)) {
        inp_count = 1;
    } else {
        logger(LOG_WARNING, "OpenLI collector: 'inputs' parameter must be an object or an array of objects -- ignoring");
        ret = 0;
        goto inpfail;
    }

    for (i = 0; i < inp_count; i++) {
        struct json_object *item;
        struct json_object *uri_obj, *threads_obj, *hasher_obj;
        struct json_object *filter_obj, *vxlan_obj, *drop_obj;
        const char *uri_str = NULL;
        colinput_t *inp = NULL;
        int new_threads;
        char *new_filter = NULL;
        uint8_t new_hasher, new_vxlan_strip, new_report_drops;
        uint16_t new_vxlan_port;
        bool specified_threads = false, specified_hasher = false;
        bool specified_filter = false, specified_vxlan = false;
        bool specified_drops = false, filter_changed = false;
        bool restart_required = false;

        if (json_object_is_type(inputs_obj, json_type_array)) {
            item = json_object_array_get_idx(inputs_obj, i);
        } else {
            item = inputs_obj;
        }

        uri_obj = threads_obj = hasher_obj = filter_obj = NULL;
        vxlan_obj = drop_obj = NULL;

        if (item == NULL || !json_object_is_type(item, json_type_object)) {
            continue;
        }

        if (!json_object_object_get_ex(item, "uri", &uri_obj) ||
                !json_object_is_type(uri_obj, json_type_string)) {
            logger(LOG_WARNING, "OpenLI: cannot update collector input due to missing 'uri' parameter -- ignoring");
            continue;
        }

        uri_str = json_object_get_string(uri_obj);
        HASH_FIND(hh, glob->inputs, uri_str, strlen(uri_str), inp);
        if (inp == NULL) {
            logger(LOG_WARNING, "OpenLI: input '%s' is not currently configured on this collector -- ignoring", uri_str);
            continue;
        }

        new_threads = inp->threadcount;
        new_hasher = inp->hasher_apply;
        new_vxlan_strip = inp->vxlan_strip;
        new_vxlan_port = inp->vxlan_port;
        new_report_drops = inp->report_drops;

        if (json_object_object_get_ex(item, "threads", &threads_obj)) {
            if (json_object_is_type(threads_obj, json_type_int)) {
                int thval = json_object_get_int(threads_obj);
                if (thval < 1) {
                    logger(LOG_WARNING, "OpenLI collector: invalid 'threads' parameter provided for input '%s', must be >= 1 -- ignoring", inp->uri);
                } else {
                    new_threads = thval;
                    specified_threads = true;
                }
            } else {
                logger(LOG_WARNING, "OpenLI collector: invalid 'threads' parameter provided for input '%s' -- ignoring", inp->uri);
            }
        }

        if (json_object_object_get_ex(item, "hasher", &hasher_obj)) {
            if (json_object_is_type(hasher_obj, json_type_string)) {
                const char *hstr = json_object_get_string(hasher_obj);
                if (strcasecmp(hstr, "balanced") == 0) {
                    new_hasher = OPENLI_HASHER_BALANCE;
                    specified_hasher = true;
                } else if (strcasecmp(hstr, "bidirectional") == 0) {
                    new_hasher = OPENLI_HASHER_BIDIR;
                    specified_hasher = true;
                } else if (strcasecmp(hstr, "radius") == 0) {
                    new_hasher = OPENLI_HASHER_RADIUS;
                    specified_hasher = true;
                } else {
                    logger(LOG_WARNING, "OpenLI collector: unsupported hasher type '%s' for input '%s' -- ignoring", hstr, inp->uri);
                }
            } else {
                logger(LOG_WARNING, "OpenLI collector: invalid hasher parameter provided for input '%s' -- ignoring", inp->uri);
            }
        }

        if (json_object_object_get_ex(item, "filter", &filter_obj)) {
            if (json_object_is_type(filter_obj, json_type_null)) {
                new_filter = NULL;
                specified_filter = true;
            } else if (json_object_is_type(filter_obj, json_type_string)) {
                const char *ftstr = json_object_get_string(filter_obj);
                if (ftstr[0] == '\0') {
                    new_filter = NULL;
                    specified_filter = true;
                } else {
                    libtrace_filter_t *test_filter = trace_create_filter(ftstr);
                    if (test_filter == NULL) {
                        logger(LOG_WARNING, "OpenLI collector: invalid BPF filter expression '%s' provided for input '%s' -- ignoring", ftstr, inp->uri);
                    } else {
                        trace_destroy_filter(test_filter);
                        new_filter = strdup(ftstr);
                        specified_filter = true;
                    }
                }
            } else {
                logger(LOG_WARNING, "OpenLI collector: invalid parameter provided as 'filter' for input '%s' -- ignoring", inp->uri);
            }
        }

        if (json_object_object_get_ex(item, "reportdrops", &drop_obj)) {
            if (json_object_is_type(drop_obj, json_type_boolean)) {
                new_report_drops = json_object_get_boolean(drop_obj) ? 1 : 0;
                specified_drops = true;
            } else {
                logger(LOG_WARNING, "OpenLI collector: invalid parameter provided as 'reportdrops' for input '%s' -- ignoring", inp->uri);
            }
        }

        if (json_object_object_get_ex(item, "stripvxlan", &vxlan_obj)) {
            if (json_object_is_type(vxlan_obj, json_type_null)) {
                new_vxlan_strip = 0;
                new_vxlan_port = 0;
                specified_vxlan = true;
            } else if (json_object_is_type(vxlan_obj, json_type_boolean)) {
                if (json_object_get_boolean(vxlan_obj) == true) {
                    new_vxlan_strip = 1;
                    new_vxlan_port = 4789;
                    specified_vxlan = true;
                } else {
                    new_vxlan_strip = 0;
                    new_vxlan_port = 0;
                    specified_vxlan = true;
                }
            } else if (json_object_is_type(vxlan_obj, json_type_int)) {
                int port = json_object_get_int(vxlan_obj);
                if (port <= 0) {
                    new_vxlan_strip = 0;
                    new_vxlan_port = 0;
                    specified_vxlan = true;
                } else if (port > 65535) {
                    logger(LOG_WARNING, "OpenLI collector: invalid VXLAN port number %d for input '%s' -- ignoring", port, inp->uri);
                } else {
                    new_vxlan_strip = 1;
                    new_vxlan_port = port;
                    specified_vxlan = true;
                }
            } else {
                logger(LOG_WARNING, "OpenLI collector: invalid 'stripvxlan' parameter provided for input '%s' -- ignoring", inp->uri);
            }
        }

        if (specified_filter) {
            if (inp->filterstring == NULL && new_filter != NULL) {
                filter_changed = true;
            } else if (inp->filterstring != NULL && new_filter == NULL) {
                filter_changed = true;
            } else if (new_filter && inp->filterstring &&
                    strcmp(inp->filterstring, new_filter) != 0) {
                filter_changed = true;
            }
        }

        if (specified_threads) {
            if (new_threads != inp->threadcount) {
                restart_required = true;
            }
        }
        if (specified_hasher) {
            if (new_hasher != inp->hasher_apply) {
                restart_required = true;
            }
        }
        if (specified_vxlan) {
            if (new_vxlan_strip != inp->vxlan_strip) {
                restart_required = true;
            }
            if (new_vxlan_port != inp->vxlan_port) {
                restart_required = true;
            }
        }
        if (filter_changed) {
            restart_required = true;
        }

        if (restart_required) {
            stop_collector_input(glob, inp);

            if (specified_threads && new_threads != inp->threadcount) {
                logger(LOG_INFO, "OpenLI collector: changing thread count for input '%s' from %d to %d",
                        inp->uri, inp->threadcount, new_threads);
                glob->total_col_threads =
                        glob->total_col_threads - inp->threadcount+new_threads;
                inp->threadcount = new_threads;
            }

            if (specified_hasher && new_hasher != inp->hasher_apply) {
                logger(LOG_INFO, "OpenLI collector: changing hasher for input '%s'", inp->uri);
                inp->hasher_apply = new_hasher;
            }

            if (specified_vxlan && (new_vxlan_strip != inp->vxlan_strip ||
                    new_vxlan_port != inp->vxlan_port)) {
                if (new_vxlan_strip) {
                    logger(LOG_INFO, "OpenLI collector: VXLAN stripping now enabled for traffic on port %d for input '%s'", new_vxlan_port, inp->uri);
                } else {
                    logger(LOG_INFO, "OpenLI collector: VXLAN stripping now disabled for input '%s'", inp->uri);
                }

                inp->vxlan_strip = new_vxlan_strip;
                inp->vxlan_port = new_vxlan_port;
            }

            if (filter_changed) {
                logger(LOG_INFO, "OpenLI collector: changing filter for input '%s' to '%s'", inp->uri, new_filter ? new_filter : "none");
                if (inp->filterstring) free(inp->filterstring);
                inp->filterstring = new_filter;
                new_filter = NULL;
            }

            if (specified_drops && new_report_drops != inp->report_drops) {
                if (new_report_drops) {
                    logger(LOG_INFO, "OpenLI collector: enabled drop reporting frequency for input '%s'", inp->uri);
                } else {
                    logger(LOG_INFO, "OpenLI collector: disabled drop reporting frequency for input '%s'", inp->uri);
                }
                inp->report_drops = new_report_drops;
            }

            inp->running = 0;
            inp->start_at = 0;
            changed = 1;
        } else if (specified_drops && new_report_drops != inp->report_drops) {
            if (new_report_drops) {
                logger(LOG_INFO, "OpenLI collector: enabled drop reporting frequency for input '%s'", inp->uri);
            } else {
                logger(LOG_INFO, "OpenLI collector: disabled drop reporting frequency for input '%s'", inp->uri);
            }
            inp->report_drops = new_report_drops;
            changed = 1;
        }

        if (new_filter) free(new_filter);
    }

    if (changed) {
        update_input_yaml_config(glob, pending);
    }

    ret = 0;

inpfail:
    if (parsed) {
        json_object_put(parsed);
    }
    json_tokener_free(tknr);
    return ret;

}

int handle_vendormirror_config_change(collector_global_t *glob,
        sync_thread_global_t *syncglob, coreserver_t *cs, uint8_t removal) {


    coreserver_t **target_list = NULL, *found, *copy;
    const char *yaml_key = NULL;
    openli_yaml_config_object_t newobj;
    openli_yaml_config_pending_updates_t *pending;
    const char *pstr;

    if (cs->servertype == OPENLI_CORE_SERVER_ALUMIRROR) {
        target_list = &(glob->alumirrors);
        yaml_key = "alumirrors";
    } else if (cs->servertype == OPENLI_CORE_SERVER_JMIRROR) {
        target_list = &(glob->jmirrors);
        yaml_key = "jmirrors";
    } else if (cs->servertype == OPENLI_CORE_SERVER_CISCOMIRROR) {
        target_list = &(glob->ciscomirrors);
        yaml_key = "ciscomirrors";
    } else {
        return 0;
    }

    if (!target_list) {
        return 0;
    }

    pthread_rwlock_wrlock(&(glob->config_mutex));
    HASH_FIND(hh, *target_list, cs->serverkey, strlen(cs->serverkey), found);

    if (!removal) {
        if (found) {
            found->awaitingconfirm = 0;
            pthread_rwlock_unlock(&(glob->config_mutex));
            return 0;
        }

        copy = deep_copy_coreserver(cs);
        prepare_coreserver(copy);
        HASH_ADD_KEYPTR(hh, *target_list, copy->serverkey,
                strlen(copy->serverkey), copy);
    } else {
        if (!found) {
            pthread_rwlock_unlock(&(glob->config_mutex));
            return 0;
        }

        HASH_DELETE(hh, *target_list, found);
        free_single_coreserver(found);
    }

    pthread_rwlock_unlock(&(glob->config_mutex));

    pending = &(syncglob->configupdates);

    if (cs->portstr) {
        pstr = strdup(cs->portstr);
    } else if (cs->lower_portstr) {
        pstr = strdup(cs->lower_portstr);
    } else {
        pstr = NULL;
    }

    newobj.fields = calloc(2, sizeof(openli_yaml_config_object_field_t));
    newobj.fields[0].key = strdup("ip");
    newobj.fields[0].value = strdup(cs->ipstr);
    newobj.fields[0].is_string = false;

    if (pstr) {
        newobj.fields[1].key = strdup("port");
        newobj.fields[1].value = (char *)pstr;
        newobj.fields[1].is_string = false;
        newobj.field_count = 2;
    } else {
        newobj.field_count = 1;
    }

    pthread_mutex_lock(syncglob->configupdate_mutex);
    prepare_new_openli_yaml_config_update(pending);

    if (removal) {
        generate_array_remove_object_openli_yaml_config_update(
                &(pending->updates[pending->update_count]),
                yaml_key, &newobj);
    } else {
        generate_array_object_append_openli_yaml_config_update(
                &(pending->updates[pending->update_count]),
                yaml_key, &newobj, 1, true);
    }
    pending->update_count ++;
    __atomic_store_n(&config_write_required, 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(syncglob->configupdate_mutex);
    destroy_openli_yaml_config_array_object(&newobj);

    return 1;
}
