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

#include "ipiri.h"
#include "ipcc.h"
#include "collector_base.h"
#include "logger.h"

static int init_worker(openli_encoder_t *enc) {
    int zero = 0;
    int hwm = 1000000;
    int i;
    char sockname[128];

    enc->encoder = init_wandder_encoder();
    enc->freegenerics = NULL;

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
            logger(LOG_INFO, "OpenLI: error configuring connection to exporter push socket");
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

    printf("encoder worker %d drained %u messages\n", enc->workerid, drained);

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

}

static int poll_nextjob(openli_encoder_t *enc, openli_encoding_job_t *job,
        int trypoll) {
    int x;

    if (trypoll) {
        int tmpbuf;
        x = zmq_recv(enc->zmq_control, &tmpbuf, sizeof(tmpbuf), ZMQ_DONTWAIT);

        if (x < 0) {
            if (errno != EAGAIN) {
                logger(LOG_INFO,
                        "OpenLI: error reading ctrl msg in encoder worker %d",
                        enc->workerid);
                return 0;
            }
        } else {
            return 0;
        }
    }

    x = zmq_recv(enc->zmq_recvjobs[0], job, sizeof(openli_encoding_job_t),
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
    if (x == 0) {
        return 0;
    }
    return 1;
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
            ret = encode_ipiri(enc->encoder, &(enc->freegenerics),
                    job->preencoded,
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
    int trypoll = 1, sincelastpoll;

    if (init_worker(enc) == -1) {
        logger(LOG_INFO,
                "OpenLI: encoder worker thread %d failed to initialise",
                enc->workerid);
        pthread_exit(NULL);
    }

    logger(LOG_INFO, "OpenLI: starting encoding thread %d", enc->workerid);

    sincelastpoll = 0;
    while (1) {
        int ret;
        ret = poll_nextjob(enc, &nextjob, trypoll);

        if (ret == 0) {
            break;
        }
        if (ret == -1) {
            trypoll = 1;
            sincelastpoll = 0;
            usleep(10);
            continue;
        }

        if (encode_etsi(enc, &nextjob, &result) < 0) {
            /* What do we do in the event of an error? */
            logger(LOG_INFO,
                    "OpenLI: encoder worker had an error when encoding %d record",
                    nextjob.origreq->type);

            continue;
        }
        result.liid = nextjob.liid;
        result.seqno = nextjob.seqno;
        result.destid = nextjob.origreq->destid;
        result.origreq = nextjob.origreq;

        // FIXME -- hash result based on LIID (and CIN?)
#if 0
        assert(enc->zmq_pushresults[0] != NULL);
        if (zmq_send(enc->zmq_pushresults[0], &result, sizeof(result), 0) < 0) {
            logger(LOG_INFO, "OpenLI: error while pushing encoded result back to exporter (worker=%d)", enc->workerid);
            break;
        }
#endif
        sincelastpoll ++;

        /* If we've done a pile of jobs without polling, force one anyway
         * just in case we've been told to halt via the control socket.
         */
        if (sincelastpoll > 10000) {
            trypoll = 1;
            sincelastpoll = 0;
        } else {
            trypoll = 0;
        }

        // XXX temporary
        if (nextjob.origreq->type == OPENLI_EXPORT_IPCC) {
            release_published_message(nextjob.origreq);
            free(result.msgbody->encoded);
            free(result.msgbody);
        } else {
            free(nextjob.origreq);
        }
        free(nextjob.liid);
    }
    logger(LOG_INFO, "OpenLI: halting encoding worker %d", enc->workerid);
    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
