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

#include "ipiri.h"
#include "ipcc.h"
#include "encoder_worker.h"
#include "logger.h"

static int init_worker(openli_encoder_t *enc) {
    int zero = 0;
    int hwm = 1000000;

    enc->encoder = init_wandder_encoder();
    enc->freegenerics = NULL;
    enc->zmq_recvjob = zmq_socket(enc->zmq_ctxt, ZMQ_PULL);
    if (zmq_connect(enc->zmq_recvjob, "inproc://openliexporterpush") != 0) {
        logger(LOG_INFO, "OpenLI: error connecting to exporter push socket");
        return -1;
    }

    if (zmq_setsockopt(enc->zmq_recvjob, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: error configuring connection to exporter push socket");
        return -1;
    }

    enc->zmq_pushresult = zmq_socket(enc->zmq_ctxt, ZMQ_PUSH);
    if (zmq_connect(enc->zmq_pushresult, "inproc://openliexporterpull") != 0) {
        logger(LOG_INFO, "OpenLI: error connecting to exporter result socket");
        return -1;
    }
    if (zmq_setsockopt(enc->zmq_pushresult, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: error configuring connection to exporter push socket");
        return -1;
    }

    if (zmq_setsockopt(enc->zmq_pushresult, ZMQ_SNDHWM, &hwm, sizeof(hwm))
            != 0) {
        logger(LOG_INFO, "OpenLI: error configuring connection to exporter push socket");
        return -1;
    }

    enc->zmq_control = zmq_socket(enc->zmq_ctxt, ZMQ_SUB);
    if (zmq_connect(enc->zmq_control, "inproc://openliexportercontrol") != 0) {
        logger(LOG_INFO, "OpenLI: error connecting to exporter control socket");
        return -1;
    }

    if (zmq_setsockopt(enc->zmq_control, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: error configuring connection to exporter control socket");
        return -1;
    }

    if (zmq_setsockopt(enc->zmq_control, ZMQ_SUBSCRIBE, "", 0) != 0) {
        logger(LOG_INFO, "OpenLI: error configuring subscription to exporter control socket");
        return -1;
    }

    return 0;

}

void destroy_encoder_worker(openli_encoder_t *enc) {
    int x;
    openli_encoding_job_t job;
    uint32_t drained = 0;

    if (enc->encoder) {
        free_wandder_encoder(enc->encoder);
    }

    if (enc->freegenerics) {
        free_etsili_generics(enc->freegenerics);
    }

    do {
        x = zmq_recv(enc->zmq_recvjob, &job, sizeof(openli_encoding_job_t),
                ZMQ_DONTWAIT);
        if (x < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        }

        if (job.origreq->type == OPENLI_EXPORT_IPCC) {
            free_published_message(job.origreq);
        } else {
            free(job.origreq);
        }
        drained ++;

    } while (x > 0);

    printf("encoder worker drained %u messages\n", drained);

    if (enc->zmq_recvjob) {
        zmq_close(enc->zmq_recvjob);
    }

    if (enc->zmq_control) {
        zmq_close(enc->zmq_control);
    }

    if (enc->zmq_pushresult) {
        zmq_close(enc->zmq_pushresult);
    }

}

static int poll_nextjob(openli_encoder_t *enc, openli_encoding_job_t *job) {
    zmq_pollitem_t items[2];
    int x;

    items[0].socket = enc->zmq_recvjob;
    items[0].fd = 0;
    items[0].events = ZMQ_POLLIN;
    items[0].revents = 0;

    items[1].socket = enc->zmq_control;
    items[1].fd = 0;
    items[1].events = ZMQ_POLLIN;
    items[1].revents = 0;

    zmq_poll(items, 2, -1);

    if (items[1].revents & ZMQ_POLLIN) {
        return 0;
    }

    if (items[0].revents & ZMQ_POLLIN) {
        x = zmq_recv(enc->zmq_recvjob, job, sizeof(openli_encoding_job_t),
                ZMQ_DONTWAIT);
        if (x < 0) {
            if (errno == EAGAIN) {
                return -1;
            }
            logger(LOG_INFO,
                    "OpenLI: error reading job in encoder worker %d",
                    enc->workerid);
            return 0;
        }
        return 1;
    }

    return -1;
}

static int encode_etsi(openli_encoder_t *enc, openli_encoding_job_t *job,
        openli_encoded_result_t *res) {

    int ret = -1;

    if (job->toreturn) {
        wandder_release_encoded_result(enc->encoder, job->toreturn);
    }

    switch(job->origreq->type) {
        case OPENLI_EXPORT_IPCC:
            ret = encode_ipcc(enc->encoder, job->intstate->preencoded,
                    &(job->origreq->data.ipcc), job->seqno,
                    &(job->origreq->ts), res);
            break;
        case OPENLI_EXPORT_IPIRI:
            ret = encode_ipiri(enc->encoder, &(enc->freegenerics),
                    job->intstate->preencoded,
                    &(job->origreq->data.ipiri), job->seqno, res);

            /* TODO this will be handled by releasing the iri message */
            if (job->origreq->data.ipiri.username) {
                free(job->origreq->data.ipiri.username);
            }
            break;
        case OPENLI_EXPORT_IPMMIRI:
            ret = 0;        /* TODO */
            break;
        case OPENLI_EXPORT_IPMMCC:
            ret = 0;        /* TODO */
            break;
    }

    return ret;
}

void *run_encoder_worker(void *encstate) {
    openli_encoder_t *enc = (openli_encoder_t *)encstate;
    openli_encoding_job_t nextjob;
    openli_encoded_result_t result;

    if (init_worker(enc) == -1) {
        logger(LOG_INFO,
                "OpenLI: encoder worker thread %d failed to initialise",
                enc->workerid);
        pthread_exit(NULL);
    }

    while (1) {
        int ret;
        ret = poll_nextjob(enc, &nextjob);

        if (ret == 0) {
            break;
        }
        if (ret == -1) {
            continue;
        }

#if 0
        if (encode_etsi(enc, &nextjob, &result) < 0) {
            /* What do we do in the event of an error? */
            logger(LOG_INFO,
                    "OpenLI: encoder worker had an error when encoding %d record",
                    nextjob.origreq->type);

            continue;
        }
#endif
        result.intstate = nextjob.intstate;
        result.seqno = nextjob.seqno;
        result.destid = nextjob.origreq->destid;
        result.origreq = nextjob.origreq;

        if (zmq_send(enc->zmq_pushresult, &result, sizeof(result), 0) < 0) {
            logger(LOG_INFO, "OpenLI: error while pushing encoded result back to exporter (worker=%d)", enc->workerid);
            break;
        }
#if 0
        if (nextjob.origreq->type == OPENLI_EXPORT_IPCC) {
            release_published_message(nextjob.origreq);
        } else {
            free(nextjob.origreq);
        }
#endif
    }

    logger(LOG_INFO, "OpenLI: halting encoding worker %d", enc->workerid);
    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
