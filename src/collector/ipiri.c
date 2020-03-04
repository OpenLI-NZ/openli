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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libtrace.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "intercept.h"
#include "etsili_core.h"
#include "ipiri.h"
#include "internetaccess.h"

static void free_ipiri_parameters(etsili_generic_t *params) {

    etsili_generic_t *oldp, *tmp;

    HASH_ITER(hh, params, oldp, tmp) {
        HASH_DELETE(hh, params, oldp);
        if (oldp->itemnum == IPIRI_CONTENTS_POP_IDENTIFIER) {
            ipiri_free_id((ipiri_id_t *)(oldp->itemptr));
        } else if (oldp->itemnum == IPIRI_CONTENTS_OTHER_TARGET_IDENTIFIERS) {
            etsili_other_targets_t *others =
                    (etsili_other_targets_t *)oldp->itemptr;
            free(others->targets);
        }

        release_etsili_generic(oldp);
    }

}

int sort_generics(etsili_generic_t *a, etsili_generic_t *b) {
    if (a->itemnum < b->itemnum) {
        return -1;
    }
    if (a->itemnum > b->itemnum) {
        return 1;
    }

    return 0;
}

static inline void add_another_target_identifier(internetaccess_ip_t *nextip,
       etsili_other_targets_t *others,  etsili_ipaddress_t *ipaddr) {

    if (others->alloced == others->count) {
        others->targets = realloc(others->targets,
                (others->alloced + 5) * sizeof(etsili_ipaddress_t));
        others->alloced += 5;
    }

    memcpy(&(others->targets[others->count]), ipaddr,
            sizeof(etsili_ipaddress_t));
    others->count ++;

}

static inline void encode_ipiri_shared(wandder_encoder_t *encoder,
        etsili_generic_freelist_t *freegenerics,
        openli_ipiri_job_t *job,
        etsili_iri_type_t *iritype_p,
        etsili_generic_t **params_p) {

    etsili_generic_t *np, *params = NULL;
    etsili_iri_type_t iritype;
    etsili_ipaddress_t targetip;
    etsili_other_targets_t othertargets;

    int64_t ipversion = 0;
    params = job->customparams;

    othertargets.count = 0;
    othertargets.alloced = 0;
    othertargets.targets = NULL;

    if (job->special == OPENLI_IPIRI_ENDWHILEACTIVE) {
        uint32_t evtype = IPIRI_END_WHILE_ACTIVE;
        iritype = ETSILI_IRI_REPORT;

        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_ACCESS_EVENT_TYPE, sizeof(uint32_t),
                (uint8_t *)(&evtype));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    } else if (job->special == OPENLI_IPIRI_STARTWHILEACTIVE) {
        uint32_t evtype = IPIRI_START_WHILE_ACTIVE;
        iritype = ETSILI_IRI_BEGIN;

        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_ACCESS_EVENT_TYPE, sizeof(uint32_t),
                (uint8_t *)(&evtype));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    } else if (job->special == OPENLI_IPIRI_SILENTLOGOFF) {
        uint32_t evtype = IPIRI_ACCESS_END;     // unsure if correct?
        iritype = ETSILI_IRI_END;

        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_ACCESS_EVENT_TYPE, sizeof(uint32_t),
                (uint8_t *)(&evtype));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);

        /* TODO probably need to set an endReason in here, but not sure
         * what is the right reason to use.
         */
    } else {
        iritype = job->iritype;
    }


    np = create_etsili_generic(freegenerics,
            IPIRI_CONTENTS_INTERNET_ACCESS_TYPE, sizeof(uint32_t),
            (uint8_t *)&(job->access_tech));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    if (job->username) {
        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_TARGET_USERNAME, strlen(job->username),
                job->username);
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    }

    if (job->ipcount > 0) {
        uint8_t etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;
        uint8_t donev4 = 0;
        uint8_t donev6 = 0;
        int i;

        switch(job->ipassignmentmethod) {
            case OPENLI_IPIRI_IPMETHOD_UNKNOWN:
                etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;
                break;
            case OPENLI_IPIRI_IPMETHOD_STATIC:
                etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_STATIC;
                break;
            case OPENLI_IPIRI_IPMETHOD_DYNAMIC:
                etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_DYNAMIC;
                break;
        }

        if (job->ipversioning == SESSION_IP_VERSION_V4) {
            ipversion = IPIRI_IPVERSION_4;
        } else if (job->ipversioning == SESSION_IP_VERSION_V6) {
            ipversion = IPIRI_IPVERSION_6;
        } else if (job->ipversioning == SESSION_IP_VERSION_DUAL) {
            ipversion = IPIRI_IPVERSION_4AND6;
        } else {
            ipversion = 0;
        }

        if (ipversion != 0) {
            np = create_etsili_generic(freegenerics,
                    IPIRI_CONTENTS_IPVERSION, sizeof(int64_t),
                    (uint8_t *)(&ipversion));
            HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                    np);
        }

        for (i = 0; i < job->ipcount; i++) {
            internetaccess_ip_t *nextip = &(job->assignedips[i]);

            if (nextip->ipfamily == AF_INET) {
                struct sockaddr_in *in =
                        (struct sockaddr_in *)&(nextip->assignedip);
                etsili_create_ipaddress_v4(
                        (uint32_t *)(&(in->sin_addr.s_addr)),
                        nextip->prefixbits,
                        etsiipmethod, &targetip);

                if (!donev4) {
                    np = create_etsili_generic(freegenerics,
                            IPIRI_CONTENTS_TARGET_IPADDRESS,
                            sizeof(etsili_ipaddress_t),
                            (uint8_t *)(&targetip));
                    HASH_ADD_KEYPTR(hh, params, &(np->itemnum),
                            sizeof(np->itemnum), np);
                    donev4 = 1;
                } else {
                    add_another_target_identifier(nextip, &othertargets,
                            &targetip);
                }

            } else if (nextip->ipfamily == AF_INET6) {
                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)
                        &(nextip->assignedip);
                etsili_create_ipaddress_v6(
                        (uint8_t *)(&(in6->sin6_addr.s6_addr)),
                        nextip->prefixbits,
                        etsiipmethod, &targetip);

                if (ipversion == IPIRI_IPVERSION_6 && donev6 == 0) {
                    np = create_etsili_generic(freegenerics,
                            IPIRI_CONTENTS_TARGET_IPADDRESS,
                            sizeof(etsili_ipaddress_t),
                            (uint8_t *)(&targetip));
                    HASH_ADD_KEYPTR(hh, params, &(np->itemnum),
                            sizeof(np->itemnum), np);
                    donev6 = 1;
                } else if (ipversion == IPIRI_IPVERSION_4AND6 && donev6 == 0) {
                    np = create_etsili_generic(freegenerics,
                            IPIRI_CONTENTS_ADDITIONAL_IPADDRESS,
                            sizeof(etsili_ipaddress_t),
                            (uint8_t *)(&targetip));
                    HASH_ADD_KEYPTR(hh, params, &(np->itemnum),
                            sizeof(np->itemnum), np);
                    donev6 = 1;
                } else {
                    add_another_target_identifier(nextip, &othertargets,
                            &targetip);
                }
            }
        }

        if (othertargets.count > 0) {
            np = create_etsili_generic(freegenerics,
                    IPIRI_CONTENTS_OTHER_TARGET_IDENTIFIERS,
                    sizeof(etsili_other_targets_t),
                    (uint8_t *)(&othertargets));
            HASH_ADD_KEYPTR(hh, params, &(np->itemnum),
                    sizeof(np->itemnum), np);

        }
    }

    if (job->sessionstartts.tv_sec > 0) {
        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_STARTTIME,
                sizeof(struct timeval), (uint8_t *)&(job->sessionstartts));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    }

    reset_wandder_encoder(encoder);

    *iritype_p = iritype;
    *params_p = params;

}

int encode_ipiri(wandder_encoder_t *encoder,
        etsili_generic_freelist_t *freegenerics,
        wandder_encode_job_t *precomputed,
        openli_ipiri_job_t *job, uint32_t seqno,
        openli_encoded_result_t *res) {

    
    etsili_generic_t *params = NULL;
    etsili_iri_type_t iritype;
    struct timeval tv;
    int ret = 0;
    uint32_t liidlen = precomputed[OPENLI_PREENCODE_LIID].vallen;

    encode_ipiri_shared(encoder,
        freegenerics,
        job,
        &iritype,
        &params);

    gettimeofday(&tv, NULL);

    memset(res, 0, sizeof(openli_encoded_result_t));
    res->msgbody = encode_etsi_ipiri(encoder, precomputed,
            (int64_t)(job->cin), (int64_t)seqno, iritype, &tv, params);

    res->ipcontents = NULL;
    res->ipclen = 0;
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len + liidlen + sizeof(uint16_t));
    res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
    res->header.internalid = 0;

    free_ipiri_parameters(params);
    return ret;
}

int ipiri_create_id_printable(char *idstr, int length, ipiri_id_t *iriid) {

    if (length <= 0) {
        return -1;
    }

    if (length > 128) {
        logger(LOG_INFO, "OpenLI: Printable IPIRI ID is too long, truncating to 128 characters.");
        length = 128;
    }

    iriid->type = IPIRI_ID_PRINTABLE;
    iriid->content.printable = (char *)malloc(length + 1);
    memcpy(iriid->content.printable, idstr, length);

    if (iriid->content.printable[length - 1] != '\0') {
        iriid->content.printable[length] = '\0';
    }
    return 0;
}

int ipiri_create_id_mac(uint8_t *macaddr, ipiri_id_t *iriid) {
    /* TODO */
    return -1;
}

int ipiri_create_id_ipv4(uint32_t addrnum, uint8_t slashbits,
        ipiri_id_t *iriid) {
    /* TODO */
    return -1;
}

void ipiri_free_id(ipiri_id_t *iriid) {
    if (iriid->type == IPIRI_ID_PRINTABLE) {
        free(iriid->content.printable);
    }
}

#ifdef HAVE_BER_ENCODING
int encode_ipiri_ber(wandder_buf_t **preencoded_ber,
        openli_ipiri_job_t *job,
        etsili_generic_freelist_t *freegenerics,
        uint32_t seqno, struct timeval *tv,
        openli_encoded_result_t *res,
        wandder_etsili_top_t *top, 
        wandder_encoder_t *encoder) {

    memset(res, 0, sizeof(openli_encoded_result_t));

    etsili_generic_t *params = NULL;
    etsili_iri_type_t iritype;
    struct timeval current_tv;
    int ret = 0;
    uint32_t liidlen = (uint32_t)((size_t)preencoded_ber[WANDDER_PREENCODE_LIID_LEN]);

    encode_ipiri_shared(encoder,
        freegenerics,
        job,
        &iritype,
        &params);

    gettimeofday(&current_tv, NULL);

    memset(res, 0, sizeof(openli_encoded_result_t));

    wandder_encode_etsi_ipiri_ber (
            preencoded_ber,
            (int64_t)(job->cin),
            (int64_t)seqno,
            &current_tv,
            params,
            iritype,
            top);

    res->msgbody = malloc(sizeof(wandder_encoded_result_t));
    res->msgbody->encoder = NULL;
    res->msgbody->encoded = top->buf;
    res->msgbody->len = top->len;
    res->msgbody->alloced = top->alloc_len;
    res->msgbody->next = NULL;

    res->ipcontents = NULL;
    res->ipclen = 0;
    
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len + liidlen + sizeof(uint16_t));
    res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
    res->header.internalid = 0;

    free_ipiri_parameters(params);
    return ret;
}
#endif

static inline void finish_ipiri_job(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint,
        openli_export_recv_t *irimsg) {

    int i;

    irimsg->data.ipiri.assignedips = calloc(sess->sessipcount,
            sizeof(internetaccess_ip_t));
    irimsg->data.ipiri.ipcount = sess->sessipcount;
    irimsg->data.ipiri.ipversioning = sess->sessipversion;
    irimsg->data.ipiri.ipassignmentmethod = OPENLI_IPIRI_IPMETHOD_DYNAMIC;

    for (i = 0; i < sess->sessipcount; i++) {
        memcpy(&(irimsg->data.ipiri.assignedips[i]), &(sess->sessionips[i]),
                sizeof(internetaccess_ip_t));
    }

    if (sess->sessipcount > 0) {
        irimsg->data.ipiri.sessionstartts = sess->started;
    } else {
        irimsg->data.ipiri.sessionstartts.tv_sec = 0;
        irimsg->data.ipiri.sessionstartts.tv_usec = 0;
    }

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipiri_created ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
    publish_openli_msg(sync->zmq_pubsocks[ipint->common.seqtrackerid],
            irimsg);
}

static inline openli_export_recv_t *_create_ipiri_job_basic(
		collector_sync_t *sync,
        ipintercept_t *ipint, char *username, uint32_t cin) {

    openli_export_recv_t *irimsg;

    irimsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));

    irimsg->type = OPENLI_EXPORT_IPIRI;
    irimsg->destid = ipint->common.destid;
    irimsg->data.ipiri.liid = strdup(ipint->common.liid);
    irimsg->data.ipiri.access_tech = ipint->accesstype;
    irimsg->data.ipiri.cin = cin;
    irimsg->data.ipiri.username = strdup(username);
    irimsg->data.ipiri.iritype = ETSILI_IRI_REPORT;
    irimsg->data.ipiri.customparams = NULL;

    return irimsg;
}


int create_ipiri_job_from_iprange(collector_sync_t *sync,
        static_ipranges_t *staticsess, ipintercept_t *ipint, uint8_t special) {

    int queueused = 0;
    struct timeval tv;
    prefix_t *prefix = NULL;
    openli_export_recv_t *irimsg;

    prefix = ascii2prefix(0, staticsess->rangestr);
    if (prefix == NULL) {
        logger(LOG_INFO,
                "OpenLI: error converting %s into a valid IP prefix in sync thread",
                staticsess->rangestr);
        return -1;
    }

    irimsg = _create_ipiri_job_basic(sync, ipint, "unknownuser",
            staticsess->cin);

    irimsg->data.ipiri.special = special;
    irimsg->data.ipiri.ipassignmentmethod = OPENLI_IPIRI_IPMETHOD_STATIC;

    /* We generally have no idea when a static session would have started. */
    irimsg->data.ipiri.sessionstartts.tv_sec = 0;
    irimsg->data.ipiri.sessionstartts.tv_usec = 0;

    irimsg->data.ipiri.assignedips = calloc(1, sizeof(internetaccess_ip_t));

    irimsg->data.ipiri.assignedips[0].ipfamily = prefix->family;
    irimsg->data.ipiri.assignedips[0].prefixbits = prefix->bitlen;
    if (prefix->family == AF_INET) {
        struct sockaddr_in *sin;

        sin = (struct sockaddr_in *)&(irimsg->data.ipiri.assignedips[0].assignedip);
        memcpy(&(sin->sin_addr), &(prefix->add.sin), sizeof(struct in_addr));
        sin->sin_family = AF_INET;
        sin->sin_port = 0;
    } else if (prefix->family == AF_INET6) {
        struct sockaddr_in6 *sin6;

        sin6 = (struct sockaddr_in6 *)&(irimsg->data.ipiri.assignedips[0].assignedip);
        memcpy(&(sin6->sin6_addr), &(prefix->add.sin6),
                sizeof(struct in6_addr));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = 0;
        sin6->sin6_flowinfo = 0;
        sin6->sin6_scope_id = 0;
    }

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipiri_created ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
    publish_openli_msg(sync->zmq_pubsocks[ipint->common.seqtrackerid], irimsg);
    free(prefix);
    return 0;
}

int create_ipiri_job_from_packet(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, access_plugin_t *p,
        void *parseddata) {

    openli_export_recv_t *irimsg;
    int ret, iter = 0;

    ret = 0;

    if (p == NULL || parseddata == NULL) {
        return -1;
    }

    do {
        irimsg = _create_ipiri_job_basic(sync, ipint, ipint->username,
				sess->cin);

        irimsg->data.ipiri.special = OPENLI_IPIRI_STANDARD;
        irimsg->data.ipiri.customparams = NULL;

        if (parseddata) {
            ret = p->generate_iri_data(p, parseddata,
                    &(irimsg->data.ipiri.customparams),
                    &(irimsg->data.ipiri.iritype),
                    sync->freegenerics, iter);

            if (ret == -1) {
                logger(LOG_INFO,
                        "OpenLI: error while creating IPIRI from session state change for %s.",
                        irimsg->data.ipiri.liid);
                free(irimsg->data.ipiri.username);
                free(irimsg->data.ipiri.liid);
                free(irimsg);
                return -1;
            }
        }

        finish_ipiri_job(sync, sess, ipint, irimsg);
        iter ++;
    } while (ret > 0);

    return 0;
}


int create_ipiri_job_from_session(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, uint8_t special) {

    openli_export_recv_t *irimsg;
    int ret = 0;

    irimsg = _create_ipiri_job_basic(sync, ipint, ipint->username, sess->cin);

    ret = sess->plugin->generate_iri_from_session(sess->plugin, sess,
            &(irimsg->data.ipiri.customparams),
            &(irimsg->data.ipiri.iritype), sync->freegenerics, special);

    irimsg->data.ipiri.special = special;
    if (ret <= 0) {
        if (ret < 0) {
            logger(LOG_INFO,
                    "OpenLI: error whle creating IPIRI from existing session %s.",
                    irimsg->data.ipiri.liid);
        }

        free(irimsg->data.ipiri.username);
        free(irimsg->data.ipiri.liid);
        free(irimsg);
        return ret;
    }
    finish_ipiri_job(sync, sess, ipint, irimsg);
    return 0;

}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
