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

#include <yaml.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "logger.h"
#include "collector.h"
#include "configwriter_common.h"

static int emit_email_timeouts(openli_email_timeouts_t *times,
        yaml_emitter_t *emitter) {

    yaml_event_t event;
    char buffer[64];

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"emailsessiontimeouts",
            strlen("emailsessiontimeouts"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_mapping_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    snprintf(buffer, 64, "%u", times->smtp);
    YAML_EMIT_INTEGER(event, "smtp", buffer);
    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_mapping_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    snprintf(buffer, 64, "%u", times->imap);
    YAML_EMIT_INTEGER(event, "imap", buffer);
    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_mapping_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    snprintf(buffer, 64, "%u", times->pop3);
    YAML_EMIT_INTEGER(event, "pop3", buffer);
    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_email_forwarding_headers(string_set_t *hdrs,
        yaml_emitter_t *emitter) {

    string_set_t *s, *tmp;
    yaml_event_t event;

    if (HASH_CNT(hh, hdrs) == 0) {
        return 0;
    }

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"emailforwardingheaders",
            strlen("emailforwardingheaders"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh, hdrs, s, tmp) {

        yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
                (yaml_char_t *)s->term, s->termlen, 1, 0,
                YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

    }
    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_email_ingestion(openli_email_ingest_config_t *conf,
        yaml_emitter_t *emitter) {

    yaml_event_t event;
    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"emailingest", strlen("emailingest"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_mapping_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    YAML_EMIT_BOOLEAN(event, "enabled", conf->enabled);
    YAML_EMIT_BOOLEAN(event, "requiretls", conf->tlsrequired);
    YAML_EMIT_STRING(event, "authpassword", conf->authpassword);
    YAML_EMIT_STRING(event, "listenaddress", conf->listenaddr);
    YAML_EMIT_STRING(event, "listenport", conf->listenport);

    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;
    return 0;
}

static int emit_udpsinks(colsync_udp_sink_t *sinks, yaml_emitter_t *emitter) {
    yaml_event_t event;
    colsync_udp_sink_t *snk, *tmp;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"udpsinks", strlen("udpsinks"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh, sinks, snk, tmp) {
        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        YAML_EMIT_STRING(event, "listenaddr", snk->listenaddr);
        YAML_EMIT_STRING(event, "listenport", snk->listenport);
        YAML_EMIT_STRING(event, "identifier", snk->identifier);

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;

}

static int emit_x2x3_inputs(x_input_t *xinps, yaml_emitter_t *emitter) {
    yaml_event_t event;
    x_input_t *x, *tmp;

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"x2x3inputs", strlen("x2x3inputs"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh, xinps, x, tmp) {
        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        YAML_EMIT_STRING(event, "listenaddr", x->listenaddr);
        YAML_EMIT_STRING(event, "listenport", x->listenport);
        YAML_EMIT_BOOLEAN(event, "disable_tls", (x->use_tls == 0));

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;

}

static int emit_libtrace_inputs(colinput_t *inputs, yaml_emitter_t *emitter) {
    yaml_event_t event;
    colinput_t *inp, *tmp;
    char buffer[64];

    yaml_scalar_event_initialize(&event, NULL, (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)"inputs", strlen("inputs"), 1, 0,
            YAML_PLAIN_SCALAR_STYLE);

    if (!yaml_emitter_emit(emitter, &event)) return -1;

    yaml_sequence_start_event_initialize(&event, NULL,
            (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    HASH_ITER(hh, inputs, inp, tmp) {
        yaml_mapping_start_event_initialize(&event, NULL,
                (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(emitter, &event)) return -1;

        YAML_EMIT_STRING(event, "uri", inp->uri);
        YAML_EMIT_STRING(event, "filter", inp->filterstring);
        YAML_EMIT_STRING(event, "coremap", inp->coremap);
        YAML_EMIT_BOOLEAN(event, "reportdrops", inp->report_drops);
        snprintf(buffer, 64, "%u", inp->threadcount);
        YAML_EMIT_INTEGER(event, "threads", buffer);

        if (inp->hasher_apply == OPENLI_HASHER_BALANCE) {
            YAML_EMIT_STRING(event, "hasher", "balanced");
        } else if (inp->hasher_apply == OPENLI_HASHER_BIDIR) {
            YAML_EMIT_STRING(event, "hasher", "bidirectional");
        } else if (inp->hasher_apply == OPENLI_HASHER_RADIUS) {
            YAML_EMIT_STRING(event, "hasher", "radius");
        }

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(emitter, &event)) return -1;
    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(emitter, &event)) return -1;

    return 0;
}

static int emit_basic_collector_options(collector_global_t *conf,
        yaml_emitter_t *emitter) {

    yaml_event_t event;
    char buffer[512];

    uuid_unparse(conf->sharedinfo.uuid, buffer);
    YAML_EMIT_STRING(event, "uuid", buffer);

    YAML_EMIT_STRING(event, "operatorid", conf->sharedinfo.operatorid);
    YAML_EMIT_STRING(event, "networkelementid", conf->sharedinfo.networkelemid);
    YAML_EMIT_STRING(event, "interceptpointid", conf->sharedinfo.intpointid);
    YAML_EMIT_STRING(event, "provisioneraddr", conf->sharedinfo.provisionerip);
    YAML_EMIT_STRING(event, "provisionerport",
            conf->sharedinfo.provisionerport);

    snprintf(buffer, 512, "%d", conf->seqtracker_threads);
    YAML_EMIT_INTEGER(event, "seqtrackerthreads", buffer);

    snprintf(buffer, 512, "%d", conf->encoding_threads);
    YAML_EMIT_INTEGER(event, "encoderthreads", buffer);

    snprintf(buffer, 512, "%d", conf->forwarding_threads);
    YAML_EMIT_INTEGER(event, "forwardingthreads", buffer);

    snprintf(buffer, 512, "%d", conf->email_threads);
    YAML_EMIT_INTEGER(event, "emailthreads", buffer);

    snprintf(buffer, 512, "%d", conf->gtp_threads);
    YAML_EMIT_INTEGER(event, "gtpthreads", buffer);

    snprintf(buffer, 512, "%d", conf->sip_threads);
    YAML_EMIT_INTEGER(event, "sipthreads", buffer);

    snprintf(buffer, 512, "%d", conf->forwarding_threads);
    YAML_EMIT_INTEGER(event, "forwardingthreads", buffer);

    snprintf(buffer, 512, "%u", conf->stat_frequency);
    YAML_EMIT_INTEGER(event, "logstatfrequency", buffer);

    YAML_EMIT_BOOLEAN(event, "etsitls", conf->etsitls);
    YAML_EMIT_STRING(event, "tlscert", conf->sslconf.certfile);
    YAML_EMIT_STRING(event, "tlskey", conf->sslconf.keyfile);
    YAML_EMIT_STRING(event, "tlsca", conf->sslconf.cacertfile);
    YAML_EMIT_STRING(event, "tlskeylogfile", conf->sslconf.logkeyfile);

    YAML_EMIT_BOOLEAN(event, "sipignoresdpo", conf->ignore_sdpo_matches);
    YAML_EMIT_BOOLEAN(event, "sipallowfromident",
            conf->sharedinfo.trust_sip_from);
    YAML_EMIT_BOOLEAN(event, "sipdisableredirect",
            conf->sharedinfo.disable_sip_redirect);

    YAML_EMIT_STRING(event, "sipdebugfile", conf->sipdebugfile);

    YAML_EMIT_BOOLEAN(event, "maskimapcreds", conf->mask_imap_creds);
    YAML_EMIT_BOOLEAN(event, "maskpop3creds", conf->mask_imap_creds);
    YAML_EMIT_STRING(event, "defaultemaildomain", conf->default_email_domain);
    YAML_EMIT_BOOLEAN(event, "emailingest-usetargetid",
            conf->email_ingest_use_targetid);

    YAML_EMIT_BOOLEAN(event, "cisconoradius",
            conf->sharedinfo.cisco_noradius);

    YAML_EMIT_BOOLEAN(event, "RMQenabled", conf->RMQ_conf.enabled);
    YAML_EMIT_STRING(event, "RMQname", conf->RMQ_conf.name);
    YAML_EMIT_STRING(event, "RMQpass", conf->RMQ_conf.pass);
    YAML_EMIT_STRING(event, "RMQhostname", conf->RMQ_conf.hostname);

    if (conf->RMQ_conf.port != 0) {
        snprintf(buffer, 64, "%d", conf->RMQ_conf.port);
        YAML_EMIT_INTEGER(event, "RMQport", buffer);
    }

    if (conf->RMQ_conf.heartbeatFreq != 0) {
        snprintf(buffer, 64, "%u", conf->RMQ_conf.heartbeatFreq);
        YAML_EMIT_INTEGER(event, "RMQheartbeatfreq", buffer);
    }

    return 0;
}

int emit_collector_config(char *configfile, collector_global_t *conf) {
    yaml_buffer_t buf;
    yaml_emitter_t emitter;
    yaml_event_t event;
    FILE *fout;
    int ret = 0;

    buf.buffer = calloc(1, 65536);
    buf.alloced = 65536;
    buf.used = 0;

    yaml_emitter_initialize(&emitter);
    yaml_emitter_set_output(&emitter, buffer_yaml_memory, (void *)&buf);

    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_mapping_start_event_initialize(&event, NULL,
            (unsigned char *)YAML_DEFAULT_MAPPING_TAG, 1,
            YAML_ANY_MAPPING_STYLE);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    if (emit_basic_collector_options(conf, &emitter) < 0) {
        goto error;
    }

    if (emit_libtrace_inputs(conf->inputs, &emitter) < 0) {
        goto error;
    }

    pthread_rwlock_rdlock(&(conf->config_mutex));
    if (emit_x2x3_inputs(conf->x_inputs, &emitter) < 0) {
        pthread_rwlock_unlock(&(conf->config_mutex));
        goto error;
    }
    pthread_rwlock_unlock(&(conf->config_mutex));

    pthread_mutex_lock(&(conf->syncip.mutex));
    if (emit_udpsinks(conf->syncip.udpsinks, &emitter) < 0) {
        pthread_mutex_unlock(&(conf->syncip.mutex));
        goto error;
    }
    pthread_mutex_unlock(&(conf->syncip.mutex));

    if (emit_email_ingestion(&(conf->emailconf), &emitter) < 0) {
        goto error;
    }

    if (emit_email_timeouts(&(conf->email_timeouts), &emitter) < 0) {
        goto error;
    }

    if (emit_email_forwarding_headers(conf->email_forwarding_headers,
            &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->alumirrors, "alumirrors", &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->jmirrors, "jmirrors", &emitter) < 0) {
        goto error;
    }

    if (emit_core_server_list(conf->ciscomirrors, "ciscomirrors",
            &emitter) < 0) {
        goto error;
    }


    yaml_mapping_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_document_end_event_initialize(&event, 0);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) goto error;

    yaml_emitter_delete(&emitter);


    fout = fopen(configfile, "w");
    if (!fout) {
        logger(LOG_INFO,
                "OpenLI: cannot open new collector config file for writing: %s",
                strerror(errno));
        ret = -1;
        goto endemit;
    }

    if (fwrite(buf.buffer, 1, buf.used, fout) != buf.used) {
        logger(LOG_INFO,
                "OpenLI: error while writing new collector config file: %s",
                strerror(errno));
        ret = -1;
    }

    fclose(fout);

endemit:
    if (buf.buffer) {
        free(buf.buffer);
    }
    return ret;

error:
    logger(LOG_INFO, "OpenLI: error while emitting collector config: %s",
            emitter.problem);
    yaml_emitter_delete(&emitter);
    return -1;
}
