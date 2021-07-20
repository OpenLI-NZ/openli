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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "logger.h"
#include "collector_base.h"
#include "collector_publish.h"

static inline void free_intercept_msg(exporter_intercept_msg_t *msg) {
    if (msg->liid) {
        free(msg->liid);
    }
    if (msg->authcc) {
        free(msg->authcc);
    }
    if (msg->delivcc) {
        free(msg->delivcc);
    }
}

static inline void free_cinsequencing(exporter_intercept_state_t *intstate) {
    cin_seqno_t *c, *tmp;

    HASH_ITER(hh, intstate->cinsequencing, c, tmp) {
        HASH_DELETE(hh, intstate->cinsequencing, c);
        if (c->cin_string) {
            free(c->cin_string);
        }
        free(c);
    }
}

static inline char *extract_liid_from_job(openli_export_recv_t *recvd) {

    switch(recvd->type) {
        case OPENLI_EXPORT_IPMMCC:
        case OPENLI_EXPORT_IPCC:
        case OPENLI_EXPORT_UMTSCC:
            return recvd->data.ipcc.liid;
        case OPENLI_EXPORT_IPIRI:
            return recvd->data.ipiri.liid;
        case OPENLI_EXPORT_IPMMIRI:
            return recvd->data.ipmmiri.liid;
        case OPENLI_EXPORT_UMTSIRI:
            return recvd->data.mobiri.liid;
        case OPENLI_EXPORT_RAW_SYNC:
            return recvd->data.rawip.liid;
    }
    return NULL;
}

static inline uint32_t extract_cin_from_job(openli_export_recv_t *recvd) {

    switch(recvd->type) {
        case OPENLI_EXPORT_IPMMCC:
        case OPENLI_EXPORT_IPCC:
        case OPENLI_EXPORT_UMTSCC:
            return recvd->data.ipcc.cin;
        case OPENLI_EXPORT_IPIRI:
            return recvd->data.ipiri.cin;
        case OPENLI_EXPORT_IPMMIRI:
            return recvd->data.ipmmiri.cin;
        case OPENLI_EXPORT_UMTSIRI:
            return recvd->data.mobiri.cin;
        case OPENLI_EXPORT_RAW_SYNC:
            return recvd->data.rawip.cin;
    }
    logger(LOG_INFO,
            "OpenLI: invalid message type in extract_cin_from_job: %u",
            recvd->type);
    return 0;
}

static void purge_removedints(seqtracker_thread_data_t *seqdata) {
    struct timeval tv;
    removed_intercept_t *rem, *prev, *tmp;

    rem = seqdata->removedints;
    gettimeofday(&tv, NULL);
    prev = NULL;

    while (rem) {
        if (tv.tv_sec - rem->haltedat < 15) {
            prev = rem;
            rem = rem->next;
            continue;
        }

        if (prev == NULL) {
            seqdata->removedints = rem->next;
        } else {
            prev->next = rem->next;
        }

        etsili_clear_preencoded_fields((wandder_encode_job_t *)rem->preencoded);

        tmp = rem;
        rem = rem->next;
        free(tmp->preencoded);
        free(tmp);
    }
}

static inline void remove_preencoded(seqtracker_thread_data_t *seqdata,
        exporter_intercept_state_t *intstate) {

	removed_intercept_t *rem;
	struct timeval tv;

	rem = calloc(1, sizeof(removed_intercept_t));
	rem->next = NULL;

	gettimeofday(&tv, NULL);
	rem->haltedat = tv.tv_sec;
    rem->preencoded = intstate->preencoded;

	if (seqdata->removedints == NULL) {
		seqdata->removedints = rem;
	} else {
		rem->next = seqdata->removedints;
		seqdata->removedints = rem;
	}

}


static void track_new_intercept(seqtracker_thread_data_t *seqdata,
        published_intercept_msg_t *cept) {

    exporter_intercept_state_t *intstate;
    etsili_intercept_details_t intdetails;

    /* If this LIID already exists, we'll need to replace it */
    HASH_FIND(hh, seqdata->intercepts, cept->liid, strlen(cept->liid),
			intstate);

    if (intstate) {
        remove_preencoded(seqdata, intstate);
        free_intercept_msg(&(intstate->details));

        /* leave the CIN seqno state as is for now */
        intstate->details.liid = cept->liid;
        intstate->details.authcc = cept->authcc;
        intstate->details.delivcc = cept->delivcc;
        intstate->details.liid_len = strlen(cept->liid);
        intstate->details.authcc_len = strlen(cept->authcc);
        intstate->details.delivcc_len = strlen(cept->delivcc);

    } else {

        /* New LIID, create fresh intercept state */
        intstate = (exporter_intercept_state_t *)malloc(
                sizeof(exporter_intercept_state_t));
        intstate->details.liid = cept->liid;
        intstate->details.authcc = cept->authcc;
        intstate->details.delivcc = cept->delivcc;
        intstate->details.liid_len = strlen(cept->liid);
        intstate->details.authcc_len = strlen(cept->authcc);
        intstate->details.delivcc_len = strlen(cept->delivcc);
        intstate->cinsequencing = NULL;

        HASH_ADD_KEYPTR(hh, seqdata->intercepts, intstate->details.liid,
                intstate->details.liid_len, intstate);
    }

    intdetails.liid = cept->liid;
    intdetails.authcc = cept->authcc;
    intdetails.delivcc = cept->delivcc;

    intdetails.operatorid = seqdata->colident->operatorid;
    intdetails.networkelemid = seqdata->colident->networkelemid;
    intdetails.intpointid = seqdata->colident->intpointid;

    if(seqdata->encoding_method == OPENLI_ENCODING_DER){
        intstate->preencoded = calloc(OPENLI_PREENCODE_LAST,
                sizeof(wandder_encode_job_t));
        etsili_preencode_static_fields(intstate->preencoded, &intdetails);
    }
}

static void reconfigure_intercepts(seqtracker_thread_data_t *seqdata) {

    exporter_intercept_state_t *intstate, *tmp;
    etsili_intercept_details_t intdetails;

    logger(LOG_INFO, "OpenLI configuration reloaded -- updating pre-encoded intercept fields");

    HASH_ITER(hh, seqdata->intercepts, intstate, tmp) {
        remove_preencoded(seqdata, intstate);

        intdetails.liid = intstate->details.liid;
        intdetails.authcc = intstate->details.authcc;
        intdetails.delivcc = intstate->details.delivcc;

        intdetails.operatorid = seqdata->colident->operatorid;
        intdetails.networkelemid = seqdata->colident->networkelemid;
        intdetails.intpointid = seqdata->colident->intpointid;

        intstate->preencoded = calloc(OPENLI_PREENCODE_LAST,
                sizeof(wandder_encode_job_t));
        etsili_preencode_static_fields(intstate->preencoded, &intdetails);
    }

}

static inline void free_intercept_state(seqtracker_thread_data_t *seqdata,
        exporter_intercept_state_t *intstate) {

    remove_preencoded(seqdata, intstate);
    free_intercept_msg(&(intstate->details));

    free_cinsequencing(intstate);
    free(intstate);
}

static int remove_tracked_intercept(seqtracker_thread_data_t *seqdata,
        published_intercept_msg_t *msg) {

    exporter_intercept_state_t *intstate;
    HASH_FIND(hh, seqdata->intercepts, msg->liid, strlen(msg->liid), intstate);

    if (!intstate) {
        logger(LOG_INFO, "OpenLI collector: tracker thread was told to end intercept LIID %s, but it is not a valid ID?",
                msg->liid);
        return -1;
    }

/*
    logger(LOG_INFO, "OpenLI collector: tracker thread %d removed intercept %s",
            seqdata->trackerid, msg->liid);
*/
    HASH_DELETE(hh, seqdata->intercepts, intstate);
	if (msg->liid) {
		free(msg->liid);
	}
	if (msg->authcc) {
		free(msg->authcc);
	}
	if (msg->delivcc) {
		free(msg->delivcc);
	}
    free_intercept_state(seqdata, intstate);
    return 1;
}

static int run_encoding_job(seqtracker_thread_data_t *seqdata,
        openli_export_recv_t *recvd) {

    char *liid;
    uint32_t cin;
    cin_seqno_t *cinseq;
    exporter_intercept_state_t *intstate;
    int ret = 1;
    openli_encoding_job_t job;

    memset(&job, 0, sizeof(job));
    liid = extract_liid_from_job(recvd);
    cin = extract_cin_from_job(recvd);

    HASH_FIND(hh, seqdata->intercepts, liid, strlen(liid), intstate);
    if (!intstate) {
        logger(LOG_INFO, "Received encoding job for an unknown LIID: %s??",
                liid);
        free_published_message(recvd);
        return 0;
    }

    HASH_FIND(hh, intstate->cinsequencing, &cin, sizeof(cin), cinseq);
    if (!cinseq) {
        char cinstr[1024];

        cinseq = (cin_seqno_t *)malloc(sizeof(cin_seqno_t));

        if (!cinseq) {
            logger(LOG_INFO,
                    "OpenLI: out of memory when creating CIN seqno tracker in exporter thread");
            return -1;
        }

        snprintf(cinstr, 1024, "%s-%u", liid, cin);

        cinseq->cin = cin;
        cinseq->iri_seqno = 0;
        cinseq->cc_seqno = 0;
        cinseq->cin_string = strdup(cinstr);

        HASH_ADD_KEYPTR(hh, intstate->cinsequencing, &(cinseq->cin),
                sizeof(cin), cinseq);
    }


	job.preencoded = intstate->preencoded;
	job.origreq = recvd;
	job.liid = strdup(liid);
    job.cinstr = strdup(cinseq->cin_string);
    job.cin = (int64_t)cin;

	if (recvd->type == OPENLI_EXPORT_IPMMCC ||
			recvd->type == OPENLI_EXPORT_IPCC ||
            recvd->type == OPENLI_EXPORT_UMTSCC) {
	    job.seqno = cinseq->cc_seqno;
        cinseq->cc_seqno ++;
	} else {
		job.seqno = cinseq->iri_seqno;
        cinseq->iri_seqno ++;
	}

    while (1) {
        if ((ret = zmq_send(seqdata->zmq_pushjobsock, (char *)&job,
                sizeof(openli_encoding_job_t), 0)) < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            logger(LOG_INFO,
                    "Error while pushing encoding job to worker threads: %s",
                    strerror(errno));
            return -1;
        }
        break;
    }

    return ret;
}


static void seqtracker_main(seqtracker_thread_data_t *seqdata) {

    openli_export_recv_t *job = NULL;
    int halted = 0, x;
    int sincepurge = 0;

    while (!halted) {
        x = zmq_recv(seqdata->zmq_recvpublished, &job, sizeof(job), 0);
        if (x < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO, "OpenLI: tracker thread %d got an error receiving from publish queue: %s",
                    seqdata->trackerid, strerror(errno));
            break;
        }
        if (x == 0) {
            break;
        }

        if (job) {
            switch(job->type) {
                case OPENLI_EXPORT_HALT:
                    halted = 1;
                    free(job);
                    break;

                case OPENLI_EXPORT_RECONFIGURE_INTERCEPTS:
                    reconfigure_intercepts(seqdata);
                    free(job);
                    break;

                case OPENLI_EXPORT_INTERCEPT_DETAILS:
                    track_new_intercept(seqdata, &(job->data.cept));
                    free(job);
                    break;

                case OPENLI_EXPORT_INTERCEPT_OVER:
					remove_tracked_intercept(seqdata, &(job->data.cept));
					free(job);
					break;

                case OPENLI_EXPORT_IPMMCC:
                case OPENLI_EXPORT_IPMMIRI:
                case OPENLI_EXPORT_IPIRI:
                case OPENLI_EXPORT_UMTSCC:
                case OPENLI_EXPORT_UMTSIRI:
                case OPENLI_EXPORT_RAW_SYNC:
					run_encoding_job(seqdata, job);
                    sincepurge ++;
                    break;
                case OPENLI_EXPORT_IPCC:
					run_encoding_job(seqdata, job);
                    sincepurge ++;
					break;

            }
        }

		/* purge any longstanding members of removedints every 10K
		 * or so messages.
		 */
        if (sincepurge >= 10000) {
            purge_removedints(seqdata);
            sincepurge = 0;
        }
    }

}

void *start_seqtracker_thread(void *data) {

    char sockname[128];
    seqtracker_thread_data_t *seqdata = (seqtracker_thread_data_t *)data;
    openli_export_recv_t *job = NULL;
    int x, zero = 0, large=1000, sndtimeo=1000;
    exporter_intercept_state_t *intstate, *tmpexp;

    seqdata->zmq_recvpublished = zmq_socket(seqdata->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 128, "inproc://openlipub-%d", seqdata->trackerid);
    if (zmq_bind(seqdata->zmq_recvpublished, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: tracker thread %d failed to bind to recv zmq: %s",
                seqdata->trackerid, strerror(errno));
        goto haltseqtracker;
    }

    if (zmq_setsockopt(seqdata->zmq_recvpublished, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: tracker thread %d failed to configure recv zmq: %s",
                seqdata->trackerid, strerror(errno));
        goto haltseqtracker;
    }


    seqdata->zmq_pushjobsock = zmq_socket(seqdata->zmq_ctxt, ZMQ_PUSH);
    snprintf(sockname, 128, "inproc://openliseqpush-%d", seqdata->trackerid);
    if (zmq_setsockopt(seqdata->zmq_pushjobsock, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: tracker thread %d failed to configure push zmq: %s",
                seqdata->trackerid, strerror(errno));
        goto haltseqtracker;
    }
    if (zmq_setsockopt(seqdata->zmq_pushjobsock, ZMQ_SNDHWM, &large,
                sizeof(large)) != 0) {
        logger(LOG_INFO,
                "OpenLI: tracker thread %d failed to configure push zmq: %s",
                seqdata->trackerid, strerror(errno));
        goto haltseqtracker;
    }
    if (zmq_setsockopt(seqdata->zmq_pushjobsock, ZMQ_SNDTIMEO, &sndtimeo,
                sizeof(sndtimeo)) != 0) {
        logger(LOG_INFO,
                "OpenLI: tracker thread %d failed to configure push zmq: %s",
                seqdata->trackerid, strerror(errno));
        goto haltseqtracker;
    }
    if (zmq_bind(seqdata->zmq_pushjobsock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: tracker thread %d failed to bind to push zmq: %s",
                seqdata->trackerid, strerror(errno));
        goto haltseqtracker;
    }

	seqdata->removedints = NULL;
    seqtracker_main(seqdata);

    /* we're done but we should still drain any remaining items in the queue
     * and free their memory */
    do {
        x = zmq_recv(seqdata->zmq_recvpublished, &job, sizeof(job),
                ZMQ_DONTWAIT);
        if (x < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        }

        /* release published job */
		free_published_message(job);

    } while (x > 0);

haltseqtracker:
    HASH_ITER(hh, seqdata->intercepts, intstate, tmpexp) {
        HASH_DELETE(hh, seqdata->intercepts, intstate);
        free_intercept_state(seqdata, intstate);
    }

    zmq_close(seqdata->zmq_recvpublished);
    zmq_close(seqdata->zmq_pushjobsock);
    pthread_exit(NULL);
}

void clean_seqtracker(seqtracker_thread_data_t *seqdata) {
	removed_intercept_t *rem;

	while (seqdata->removedints) {
		rem = seqdata->removedints;

        etsili_clear_preencoded_fields((wandder_encode_job_t *)rem->preencoded);
        free(rem->preencoded);

		seqdata->removedints = seqdata->removedints->next;
		free(rem);
	}
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
