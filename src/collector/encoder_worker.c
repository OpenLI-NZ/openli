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

#include <unistd.h>
#include <assert.h>

#include "ipiri.h"
#include "ipmmcc.h"
#include "ipcc.h"
#include "ipmmiri.h"
#include "collector_base.h"
#include "logger.h"

static int init_worker(openli_encoder_t *enc) {
    int zero = 0, rto = 10;
    int hwm = 1000000;
    int i;
    char sockname[128];

    enc->encoder = init_wandder_encoder();
    enc->freegenerics = create_etsili_generic_freelist(0);
    enc->halted = 0;

    enc->zmq_recvjobs = calloc(enc->seqtrackers, sizeof(void *));
    for (i = 0; i < enc->seqtrackers; i++) {
        enc->zmq_recvjobs[i] = zmq_socket(enc->zmq_ctxt, ZMQ_PULL);
        snprintf(sockname, 128, "inproc://openliseqpush-%d", i);
        if (zmq_connect(enc->zmq_recvjobs[i], sockname) != 0) {
            logger(LOG_INFO, "OpenLI: error connecting to zmq pull socket");
            return -1;
        }

        if (zmq_setsockopt(enc->zmq_recvjobs[i], ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
            logger(LOG_INFO, "OpenLI: error configuring connection to zmq pull socket");
            return -1;
        }

        if (zmq_setsockopt(enc->zmq_recvjobs[i], ZMQ_RCVTIMEO, &rto,
                sizeof(rto)) != 0) {
            logger(LOG_INFO, "OpenLI: error configuring connection to zmq pull socket");
            return -1;
        }
    }

    enc->zmq_pushresults = calloc(enc->forwarders, sizeof(void *));
    for (i = 0; i < enc->forwarders; i++) {
        snprintf(sockname, 128, "inproc://openlirespush-%d", i);
        enc->zmq_pushresults[i] = zmq_socket(enc->zmq_ctxt, ZMQ_PUSH);
        if (zmq_connect(enc->zmq_pushresults[i], sockname) != 0) {
            logger(LOG_INFO,
                    "OpenLI: error connecting to exporter result socket%s: %s",
                    sockname, strerror(errno));
            zmq_close(enc->zmq_pushresults[i]);
            enc->zmq_pushresults[i] = NULL;
            continue;
        }
        if (zmq_setsockopt(enc->zmq_pushresults[i], ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
            logger(LOG_INFO,
                    "OpenLI: error configuring connection to exporter push socket %s: %s",
                    sockname, strerror(errno));
            zmq_close(enc->zmq_pushresults[i]);
            enc->zmq_pushresults[i] = NULL;
            continue;
        }
        if (zmq_setsockopt(enc->zmq_pushresults[i], ZMQ_SNDHWM, &hwm,
                sizeof(hwm)) != 0) {
            logger(LOG_INFO,
                    "OpenLI: error configuring connection to exporter push socket %s: %s",
                    sockname, strerror(errno));
            zmq_close(enc->zmq_pushresults[i]);
            enc->zmq_pushresults[i] = NULL;
            continue;
        }
    }

    enc->zmq_control = zmq_socket(enc->zmq_ctxt, ZMQ_SUB);
    if (zmq_connect(enc->zmq_control, "inproc://openliencodercontrol") != 0) {
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

    enc->topoll = calloc(enc->seqtrackers + 1, sizeof(zmq_pollitem_t));

    enc->topoll[0].socket = enc->zmq_control;
    enc->topoll[0].fd = 0;
    enc->topoll[0].events = ZMQ_POLLIN;

    for (i = 0; i < enc->seqtrackers; i++) {
        enc->topoll[i + 1].socket = enc->zmq_recvjobs[i];
        enc->topoll[i + 1].fd = 0;
        enc->topoll[i + 1].events = ZMQ_POLLIN;
    }

    return 0;

}

void destroy_encoder_worker(openli_encoder_t *enc) {
    int x, i;
    openli_encoding_job_t job;
    uint32_t drained = 0;

    if (enc->encoder) {
        free_wandder_encoder(enc->encoder);
    }

    if (enc->freegenerics) {
        free_etsili_generics(enc->freegenerics);
    }

    for (i = 0; i < enc->seqtrackers; i++) {
        do {
            x = zmq_recv(enc->zmq_recvjobs[i], &job,
                    sizeof(openli_encoding_job_t), ZMQ_DONTWAIT);
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
        zmq_close(enc->zmq_recvjobs[i]);
    }

    if (enc->zmq_control) {
        zmq_close(enc->zmq_control);
    }

    for (i = 0; i < enc->forwarders; i++) {
        if (enc->zmq_pushresults[i]) {
            zmq_close(enc->zmq_pushresults[i]);
        }
    }
    free(enc->zmq_recvjobs);
    free(enc->zmq_pushresults);
    free(enc->topoll);

}

static int encode_etsi(openli_encoder_t *enc, openli_encoding_job_t *job,
        openli_encoded_result_t *res) {

    int ret = -1;

    switch(job->origreq->type) {
        case OPENLI_EXPORT_IPCC:
            ret = encode_ipcc(enc->encoder, job->preencoded,
                    &(job->origreq->data.ipcc), job->seqno,
                    &(job->origreq->ts), res);
            break;
        case OPENLI_EXPORT_IPIRI:
            ret = encode_ipiri(enc->encoder, enc->freegenerics,
                    job->preencoded,
                    &(job->origreq->data.ipiri), job->seqno, res);

            break;
        case OPENLI_EXPORT_IPMMIRI:
            ret = encode_ipmmiri(enc->encoder, job->preencoded,
                    &(job->origreq->data.ipmmiri), job->seqno, res,
                    &(job->origreq->ts));
            break;
        case OPENLI_EXPORT_IPMMCC:
            ret = encode_ipmmcc(enc->encoder, job->preencoded,
                    &(job->origreq->data.ipcc), job->seqno,
                    &(job->origreq->ts), res);
            break;
    }


    return ret;
}


static int process_job(openli_encoder_t *enc, void *socket) {
    int x;
    int batch = 0;
    openli_encoding_job_t job;
    openli_encoded_result_t result;

    while (batch < 50) {
        x = zmq_recv(socket, &job, sizeof(openli_encoding_job_t), 0);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error reading job in encoder worker %d",
                    enc->workerid);
            return 0;
        } else if (x < 0) {
            break;
        } else if (x == 0) {
            return 0;
        }
        if (encode_etsi(enc, &job, &result) < 0) {
            /* What do we do in the event of an error? */
            logger(LOG_INFO,
                    "OpenLI: encoder worker had an error when encoding %d record",
                    job.origreq->type);

            continue;
        }

        result.cinstr = job.cinstr;
        result.liid = job.liid;
        result.seqno = job.seqno;
        result.destid = job.origreq->destid;
        result.origreq = job.origreq;
        result.encodedby = enc->workerid;

        // FIXME -- hash result based on LIID (and CIN?)
        assert(enc->zmq_pushresults[0] != NULL);
        if (zmq_send(enc->zmq_pushresults[0], &result, sizeof(result), 0) < 0) {
            logger(LOG_INFO, "OpenLI: error while pushing encoded result back to exporter (worker=%d)", enc->workerid);
            break;
        }
        batch++;
    }
    return batch;
}

static inline void poll_nextjob(openli_encoder_t *enc) {
    int x, i;
    int tmpbuf;

    x = zmq_recv(enc->zmq_control, &tmpbuf, sizeof(tmpbuf), ZMQ_DONTWAIT);

    if (x < 0 && errno != EAGAIN) {
        logger(LOG_INFO,
                "OpenLI: error reading ctrl msg in encoder worker %d",
                enc->workerid);
    }

    if (x >= 0) {
        enc->halted = 1;
        return;
    }

    /* TODO better error checking / handling for multiple seqtrackers */
    for (i = 0; i < enc->seqtrackers; i++) {
        x = process_job(enc, enc->topoll[i+1].socket);
    }

    return;
}

void *run_encoder_worker(void *encstate) {
    openli_encoder_t *enc = (openli_encoder_t *)encstate;

    if (init_worker(enc) == -1) {
        logger(LOG_INFO,
                "OpenLI: encoder worker thread %d failed to initialise",
                enc->workerid);
        pthread_exit(NULL);
    }

    while (!enc->halted) {
        poll_nextjob(enc);
    }
    logger(LOG_INFO, "OpenLI: halting encoding worker %d", enc->workerid);
    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
