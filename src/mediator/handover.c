/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#include <pthread.h>
#include <unistd.h>

#include "logger.h"
#include "util.h"
#include "netcomms.h"
#include "etsili_core.h"
#include "handover.h"
#include "med_epoll.h"
#include "config.h"
#include "mediator_rmq.h"

/** Sends any pending keep-alive message out via a handover.
 *
 *  @param ho              The handover to send the keep-alive over
 *
 *  @return -1 is an error occurs, 0 otherwise.
 */
int xmit_handover_keepalive(handover_t *ho) {

    /* We don't lock the handover mutex here, because we're going to be
     * doing this a lot and the mutex is mostly protecting logging-related
     * members (e.g. disconnect_msg). A few bogus messages are a small
     * price to pay compared with the performance impact of locking a mutex
     * everytime we want to send a record to a client.
     */
    int ret = 0;

    if (!ho->ho_state->pending_ka) {
        return 0;
    }

    /* There's a keep alive to be sent */
    ret = send(ho->outev->fd, ho->ho_state->pending_ka->encoded,
            ho->ho_state->pending_ka->len, MSG_DONTWAIT);

    if (ret < 0) {
        /* XXX should be worry about EAGAIN here? */

        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: error while transmitting keepalive for handover %s:%s HI%d -- %s",
                    ho->ipstr, ho->portstr, ho->handover_type,
                    strerror(errno));
        }
        return -1;
    }
    if (ret == 0) {
        return -1;
    }
    if ((unsigned int)ret == ho->ho_state->pending_ka->len) {
        /* Sent the whole thing successfully */
        wandder_release_encoded_result(NULL, ho->ho_state->pending_ka);
        ho->ho_state->pending_ka = NULL;

        /*
        logger(LOG_INFO, "successfully sent keep alive to %s:%s HI%d",
                ho->ipstr, ho->portstr, ho->handover_type);
        */
        halt_mediator_timer(ho->aliverespev);
        /* Start the timer for the response */
        if (start_mediator_timer(ho->aliverespev,
                ho->ho_state->kawait) == -1) {
            if (ho->disconnect_msg == 0) {
                logger(LOG_INFO,
                        "OpenLI Mediator: unable to start keepalive response timer: %s",
                        strerror(errno));
            }
            return -1;
        }

        if (ho->aliverespev == NULL && ho->disconnect_msg == 1) {
            /* Not expecting a response, so we have to assume that
             * the connection is good again as soon as we successfully
             * send a KA */
            ho->disconnect_msg = 0;
            logger(LOG_INFO,
                "OpenLI Mediator: reconnected to handover %s:%s HI%d successfully.",
                ho->ipstr, ho->portstr, ho->handover_type);
        }
    } else {
        /* Partial send -- try the rest next time */
        memmove(ho->ho_state->pending_ka->encoded,
                ho->ho_state->pending_ka->encoded + ret,
                ho->ho_state->pending_ka->len - ret);
        ho->ho_state->pending_ka->len -= ret;
    }
    return 0;
}

/** Sends a buffer of ETSI records out via a handover.
 *
 *  @param ho              The handover to send the records over
 *  @param maxsend         The maximum amount of data to send (in bytes)
 *
 *  @return -1 is an error occurs, 0 otherwise.
 */
int xmit_handover_records(handover_t *ho, uint32_t maxsend) {
    int ret;
    struct timeval tv;

    /* Send some of our buffered records -- we need to go back to our epoll
     * loop to handle other events rather than getting stuck trying to send
     * massive amounts of data in one go.
     */
    if ((ret = transmit_buffered_records(&(ho->ho_state->buf), ho->outev->fd,
			maxsend, NULL)) == -1) {
        return -1;
    }

    if (ret == 0) {
        return 0;
    }

    /* Reset the keep alive timer */
    gettimeofday(&tv, NULL);
    if (ho->aliveev && ho->ho_state->kafreq != 0 &&
            ho->ho_state->katimer_setsec < tv.tv_sec) {
        halt_mediator_timer(ho->aliveev);
        if (start_mediator_timer(ho->aliveev, ho->ho_state->kafreq) == -1) {
            if (ho->disconnect_msg == 0) {
                logger(LOG_INFO,
                    "OpenLI Mediator: error while trying to disable xmit for handover %s:%s HI%d -- %s",
                    ho->ipstr, ho->portstr, ho->handover_type,
                    strerror(errno));
            }
            return -1;
        }
        ho->ho_state->katimer_setsec = tv.tv_sec;
    }

    return 0;
}

/** Restarts the keep alive timer for a handover
 *
 *  @param ho			The handover to restart the keep alive timer for
 *
 *  @return	-1 if an error occurs, 0 otherwise
 */
static int restart_handover_keepalive(handover_t *ho) {

	int ret = 0;
	pthread_mutex_lock(&(ho->ho_state->ho_mutex));

	halt_mediator_timer(ho->aliveev);
	if (start_mediator_timer(ho->aliveev, ho->ho_state->kafreq) == -1) {
		if (ho->disconnect_msg == 0) {
			logger(LOG_INFO,
                "OpenLI Mediator: unable to reset keepalive timer for  %s:%s HI%d :s",
                ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
        }
		ret = -1;
	}

	pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
	return ret;
}

/** React to a handover's failure to respond to a keep alive before the
 *  response timer expired.
 *
 *  @param ho              The handover that failed to reply to a KA message
 *
 */
void trigger_handover_ka_failure(handover_t *ho) {

    if (ho->disconnect_msg == 0) {
        logger(LOG_INFO, "OpenLI Mediator: failed to receive KA response from LEA on handover %s:%s HI%d, dropping connection.",
                ho->ipstr, ho->portstr, ho->handover_type);
    }

    halt_mediator_timer(ho->aliverespev);
    disconnect_handover(ho);
}

/** Creates and sends a keep-alive message over a handover
 *
 *  @param ho           The handover that needs to send a keep alive
 *  @param mediator_id  The ID of this mediator (to be included in the KA msg)
 *  @param operator_id  The operator ID string (to be included in the KA msg)
 *
 *  @return -1 if an error occurs, 0 otherwise
 */
int trigger_handover_keepalive(handover_t *ho, uint32_t mediator_id,
        char *operator_id, char *agency_cc) {

    wandder_encoded_result_t *kamsg;
    wandder_etsipshdr_data_t hdrdata;
    char elemstring[16];
    char liidstring[24];

    if (ho->outev == NULL) {
        return 0;
    }

    if (ho->ho_state->pending_ka == NULL &&
            ho->aliverespev->fd == -1 &&
            get_buffered_amount(&(ho->ho_state->buf)) == 0) {
        /* Only create a new KA message if we have sent the last one we
         * had queued up.
         * Also only create one if we don't already have data to send. We
         * should only be sending keep alives if the socket is idle.
         */
        if (ho->ho_state->encoder == NULL) {
            ho->ho_state->encoder = init_wandder_encoder();
        } else {
            reset_wandder_encoder(ho->ho_state->encoder);
        }

        /* Include the OpenLI version in the LIID field, so the LEAs can
         * identify which version of the software is being used by the
         * sender.
         *
         * PACKAGE_NAME and PACKAGE_VERSION come from config.h
         */
        if (agency_cc && strlen(agency_cc) == 2) {
            hdrdata.delivcc = agency_cc;
            hdrdata.authcc = agency_cc;
        } else {
            hdrdata.delivcc = "--";
            hdrdata.authcc = "--";
        }
        hdrdata.delivcc_len = strlen(hdrdata.delivcc);
        hdrdata.authcc_len = strlen(hdrdata.authcc);

        /* Netherlands has a specific rule regarding the content of the
         * LIID within keepalives
         */
        if (agency_cc && strcmp(agency_cc, "NL")==0) {
        	snprintf(liidstring, 2, "-");
        } else {
        	snprintf(liidstring, 24, "%s-%s", PACKAGE_NAME, PACKAGE_VERSION);
        }
        hdrdata.liid = liidstring;
        hdrdata.liid_len = strlen(hdrdata.liid);

        if (operator_id) {
            hdrdata.operatorid = operator_id;
        } else {
            hdrdata.operatorid = "unspecified";
        }
        hdrdata.operatorid_len = strlen(hdrdata.operatorid);

        /* Stupid 16 character limit... */
        if (agency_cc && strcmp(agency_cc, "NL")==0) {
        	snprintf(elemstring, 16, "%u", mediator_id);
        } else {
        	snprintf(elemstring, 16, "med-%u", mediator_id);
        }
        hdrdata.networkelemid = elemstring;
        hdrdata.networkelemid_len = strlen(hdrdata.networkelemid);

        hdrdata.intpointid = NULL;
        hdrdata.intpointid_len = 0;

        kamsg = encode_etsi_keepalive(ho->ho_state->encoder, &hdrdata,
                ho->ho_state->lastkaseq + 1);
        if (kamsg == NULL) {
            logger(LOG_INFO,
                    "OpenLI Mediator: failed to construct a keep-alive.");
            return -1;
        }

        ho->ho_state->pending_ka = kamsg;
        ho->ho_state->lastkaseq += 1;
    }

    /* Reset the keep alive timer */
    return restart_handover_keepalive(ho);
}

/** Disconnects a single mediator handover connection to an LEA.
 *
 *  Typically triggered when an LEA is withdrawn, becomes unresponsive,
 *  or fails a keep-alive test.
 *
 *  @param state    The global handover state for this mediator
 *  @param ho       The handover that is being disconnected.
 */
void disconnect_handover(handover_t *ho) {

	/* Grab the lock, because we might be also trying to "connect"
     * at the same time.
	 */
	pthread_mutex_lock(&(ho->ho_state->ho_mutex));

    /* Tidy up all of the epoll event fds related to the handover */

	if (ho->outev && ho->disconnect_msg == 0) {
		logger(LOG_INFO,
				"OpenLI Mediator: Disconnecting from handover %s:%s HI%d",
				ho->ipstr, ho->portstr, ho->handover_type);
	}

	if (remove_mediator_fdevent(ho->outev) < 0 && ho->disconnect_msg == 0) {
		logger(LOG_INFO, "OpenLI Mediator: unable to remove handover fd from epoll: %s.", strerror(errno));
	}
	ho->outev = NULL;

	if (halt_mediator_timer(ho->aliveev) < 0 && ho->disconnect_msg == 0) {
		logger(LOG_INFO, "OpenLI Mediator: unable to remove keepalive timer fd from epoll: %s.", strerror(errno));
	}

	if (halt_mediator_timer(ho->aliverespev) < 0 && ho->disconnect_msg == 0) {
		logger(LOG_INFO, "OpenLI Mediator: unable to remove keepalive response timer fd from epoll: %s.", strerror(errno));
	}

    /* Free the encoder for this handover -- used to create keepalive msgs */
    if (ho->ho_state->encoder) {
        free_wandder_encoder(ho->ho_state->encoder);
        ho->ho_state->encoder = NULL;
    }

    /* Free the decoder for this handover -- used to parse keepalive responses
     */
    if (ho->ho_state->decoder) {
        wandder_free_etsili_decoder(ho->ho_state->decoder);
        ho->ho_state->decoder = NULL;
    }

    /* Free any encoded keepalives that we have sitting around */
    if (ho->ho_state->pending_ka) {
        wandder_release_encoded_result(NULL, ho->ho_state->pending_ka);
        ho->ho_state->pending_ka = NULL;
    }

    /* Release the buffer used to store incoming messages from the LEA */
    if (ho->ho_state->incoming) {
        libtrace_scb_destroy(ho->ho_state->incoming);
        free(ho->ho_state->incoming);
        ho->ho_state->incoming = NULL;
    }

    /* Reset any connection-specific state in the export buffer for this
     * handover.
     */
    reset_export_buffer(&(ho->ho_state->buf));

    /* Drop the RMQ connection */
    reset_handover_rmq(ho);

    /* This handover is officially disconnected, so no more logging for it
     * until / unless it reconnects.
     */
    ho->disconnect_msg = 1;
	pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
}

/** Releases all memory associated with a single handover object.
 *
 *  @param ho       The handover object that is being destroyed
 */
void free_handover(handover_t *ho) {

    /* This should close all of our sockets and halt any running timers */
    disconnect_handover(ho);

    destroy_mediator_timer(ho->aliveev);
    destroy_mediator_timer(ho->aliverespev);

    if (ho->rmq_consumer) {
        amqp_destroy_connection(ho->rmq_consumer);
    }

    if (ho->ho_state) {
    	release_export_buffer(&(ho->ho_state->buf));
	    pthread_mutex_destroy(&(ho->ho_state->ho_mutex));
        free(ho->ho_state);
    }

    if (ho->ipstr) {
        free(ho->ipstr);
    }
    if (ho->portstr) {
        free(ho->portstr);
    }
    free(ho);
}

/** Destroys the state for a particular agency entity, including its
 *  corresponding handovers
 *
 *  @param ag       The agency to be destroyed.
 */
void destroy_agency(mediator_agency_t *ag) {
    /* Disconnect the HI2 and HI3 handovers */
    if (ag == NULL) {
        return;
    }
    if (ag->hi2) {
        free_handover(ag->hi2);
    }
    if (ag->hi3) {
        free_handover(ag->hi3);
    }
    if (ag->agencyid) {
        free(ag->agencyid);
    }
}

/** Registers a single RMQ queue for an LIID with the RMQ consumer for a
 *  handover.
 *
 *  If the handover is HI2, the IRI queue is registered.
 *  If the handover is HI3, the CC queue is registered.
 *
 *  Used as a callback for foreach_liid_agency_mapping() to register all
 *  LIIDs in a known LIID set.
 *
 *  @param m        The LIID to be registered with the handover's RMQ consumer
 *  @param arg      The handover to register with
 *
 *  @return 0 always
 */
static int register_known_liid_consumers(liid_map_entry_t *m, void *arg) {
    handover_t *ho = (handover_t *)arg;
    int r;
    const char *histr = "??";
    uint8_t *delflag = NULL;

    if (ho->handover_type == HANDOVER_HI2) {
        r = register_mediator_iri_RMQ_consumer(ho->rmq_consumer, m->liid);
        histr = "IRI";
        delflag = &(m->iriqueue_deleted);
    } else if (ho->handover_type == HANDOVER_HI3) {
        r = register_mediator_cc_RMQ_consumer(ho->rmq_consumer, m->liid);
        histr = "CC";
        delflag = &(m->ccqueue_deleted);
    } else {
        return 0;
    }

    if (r == -1) {
        logger(LOG_INFO, "OpenLI Mediator: failed to declare consumer %s queue for LIID %s", histr, m->liid);
    } else if (r == -2) {
        logger(LOG_INFO, "OpenLI Mediator: failed to subscribe to consumer %s queue for LIID %s", histr, m->liid);
        *delflag = 0;
    } else {
        *delflag = 0;
    }

    return 0;
}

/** Creates an RMQ connection for consumption and registers it with
 *  the IRI or CC queues for each LIID that is to be exported via this
 *  handover.
 *
 *  @param ho       The handover to be registered with RMQ
 *  @param liidmap  The set of known LIIDs associated with this handover
 *  @param agencyid The name of the agency that this handover belongs to
 *  @param password The password to use to authenticate with RMQ
 *
 *  @return -1 if an error occurs during registration, 1 if all LIIDs
 *          are successfully registered.
 */
int register_handover_RMQ_all(handover_t *ho, liid_map_t *liidmap,
        char *agencyid, char *password) {

    /* Attach to RMQ if required */
    if (ho->rmq_consumer == NULL) {
        ho->rmq_consumer = join_mediator_RMQ_as_consumer(agencyid,
                ho->amqp_log_failure, password);

        if (ho->rmq_consumer == NULL) {
            ho->amqp_log_failure = 0;
        } else {
            ho->amqp_log_failure = 1;
        }
    }

    /* If we've just attached to RMQ, register our interest in any existing
     * LIIDs that we know about.
     */
    if (ho->rmq_registered == 0) {

        if (liidmap && foreach_liid_agency_mapping(liidmap, (void *)ho,
                register_known_liid_consumers) < 0) {
            if (ho->amqp_log_failure) {
                logger(LOG_INFO, "OpenLI Mediator: unable to register consumer queues for HI%d for agency %s", ho->handover_type, agencyid);

                ho->amqp_log_failure = 0;
            }
            reset_handover_rmq(ho);
            return -1;
        }
        ho->amqp_log_failure = 1;
        ho->rmq_registered = 1;
    }

    return 1;
}

/** Establish an agency handover connection
 *
 *  The resulting socket will be added to the provided epoll event set as
 *  available for reading and writing.
 *
 *  This method also starts the keepalive timer for the handover, if
 *  keepalives are required.
 *
 *  @param ho           The handover object that is to be connected
 *  @param epoll_fd     The epoll fd to add handover events to
 *  @param ho_id        The unique ID number for this handover
 *
 *  @return -1 if the connection fails, 0 otherwise.
 */
int connect_mediator_handover(handover_t *ho, int epoll_fd, uint32_t ho_id) {

	uint32_t epollev;
	int outsock;

	/* Check if we're already connected? */
    if (ho->outev) {
        return 0;
    }

    /* Connect the handover socket */
    outsock = connect_socket(ho->ipstr, ho->portstr, ho->disconnect_msg, 1);
    if (outsock == -1) {
        return -1;
    }

    /* If fd is 0, we can try again another time instead */
    if (outsock == 0) {
        ho->disconnect_msg = 1;
        return 0;
    }

    /* Create a buffer for receiving messages (i.e. keep-alive responses)
     * from the LEA via the handover.
     */
    if (!ho->ho_state->incoming) {
        ho->ho_state->incoming =
                (libtrace_scb_t *)malloc(sizeof(libtrace_scb_t));
        ho->ho_state->incoming->fd = -1;
        ho->ho_state->incoming->address = NULL;
        libtrace_scb_init(ho->ho_state->incoming, (64 * 1024 * 1024), ho_id);
    }

    /* Enable both epoll reading and writing for this handover */
    epollev = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

	ho->outev = create_mediator_fdevent(epoll_fd, ho, MED_EPOLL_LEA,
			outsock, epollev);

	if (ho->outev == NULL) {
        if (ho->disconnect_msg == 0) {
    		logger(LOG_INFO,
				"OpenLI Mediator: unable to add agency handover for %s:%s HI%d to epoll.",
				ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
        }
		ho->disconnect_msg = 1;
		close(outsock);
		return 0;
	}

    if (ho->aliveev) {
        halt_mediator_timer(ho->aliveev);
    }

    /* Start a keep alive timer */
    if (start_mediator_timer(ho->aliveev, ho->ho_state->kafreq) == -1) {
        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                "OpenLI Mediator: unable to start keepalive timer for  %s:%s HI%d %s",
                ho->ipstr, ho->portstr,
                ho->handover_type, strerror(errno));
        }
    }

    /* Don't reset disconnect_msg until we've sent a record successfully */
    return 1;
}


/* Creates a new instance of a handover.
 *
 * @param epoll_fd		The global epoll fd for the mediator.
 * @param ipstr         The IP address of the handover recipient (as a string).
 * @param portstr       The port that the handover recipient is listening on
 *                      (as a string).
 * @param handover_type Either HANDOVER_HI2 or HANDOVER_HI3, to indicate which
 *                      type of handover this is.
 * @param kafreq        The frequency to send keep alive requests (in seconds).
 * @param kawait        The time to wait before assuming a keep alive has
 *                      failed (in seconds).
 *
 * @return a pointer to a new handover instance, or NULL if an error occurs.
 */
handover_t *create_new_handover(int epoll_fd, char *ipstr, char *portstr,
        int handover_type, uint32_t kafreq, uint32_t kawait) {

    handover_t *ho = (handover_t *)malloc(sizeof(handover_t));

    if (ho == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: ran out of memory while allocating handover structure.");
        return NULL;
    }

	ho->ho_state = calloc(1, sizeof(per_handover_state_t));
	if (!ho->ho_state) {
		logger(LOG_INFO, "OpenLI Mediator: ran out of memory while allocating per-handover state.");
		free(ho);
		return NULL;
	}

    /* Initialise all of the handover-specific state for this handover */
    init_export_buffer(&(ho->ho_state->buf));
    ho->ho_state->katimer_setsec = 0;
    ho->ho_state->incoming = NULL;
    ho->ho_state->encoder = NULL;
    ho->ho_state->decoder = NULL;
    ho->ho_state->pending_ka = NULL;
    ho->ho_state->kafreq = kafreq;
    ho->ho_state->kawait = kawait;
    ho->ho_state->next_rmq_ack = 0;
    ho->ho_state->valid_rmq_ack = 0;
    ho->rmq_consumer = NULL;
    ho->rmq_registered = 0;
    ho->amqp_log_failure = 1;

	pthread_mutex_init(&(ho->ho_state->ho_mutex), NULL);

    /* Keep alive frequency of 0 (or less) will mean that no keep alives are
     * sent (this may necessary for some agencies).
     */
    ho->aliveev = create_mediator_timer(epoll_fd, ho, MED_EPOLL_KA_TIMER,
            0);
    if (ho->aliveev == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: unable to create keep alive timer for agency %s:%s", ipstr, portstr);
    }

    /* If keep alive wait is 0 (or less), then we will not require a response
     * for a successful keep alive.
     */
    ho->aliverespev = create_mediator_timer(epoll_fd, ho,
            MED_EPOLL_KA_RESPONSE_TIMER, 0);
    if (ho->aliverespev == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: unable to create keep alive response timer for agency %s:%s", ipstr, portstr);
    }

	/* The output event will be created when the handover is connected */
	ho->outev = NULL;

    /* Initialise the remaining handover state */
    ho->ipstr = ipstr;
    ho->portstr = portstr;
    ho->handover_type = handover_type;
    ho->disconnect_msg = 0;

    return ho;
}

/** Receives and actions a message sent to the mediator over a handover
 *  (typically a keep alive response).
 *
 *  @param ho            The handover to receive the message on
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int receive_handover(handover_t *ho) {
	int ret;
    uint8_t *ptr = NULL;
    uint32_t reclen = 0;
    uint32_t available;

    /* receive the incoming message into a local SCB */
	pthread_mutex_lock(&(ho->ho_state->ho_mutex));

    ret = libtrace_scb_recv_sock(ho->ho_state->incoming, ho->outev->fd,
            MSG_DONTWAIT);
    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
			pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
            return 0;
        }
        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO, "OpenLI Mediator: error receiving data from LEA on handover %s:%s HI%d: %s",
                    ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
        }
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return -1;
    }

    if (ret == 0) {
        if (ho->disconnect_msg == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: disconnect on LEA handover %s:%s HI%d",
                    ho->ipstr, ho->portstr, ho->handover_type);
        }
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return -1;
    }

    do {
        ptr = libtrace_scb_get_read(ho->ho_state->incoming, &available);
        if (available == 0 || ptr == NULL) {
            break;
        }

        /* We're only expecting to get keep alive responses back over the
         * handover socket -- however, we will need to decode them to
         * make sure they are valid.
         */
        if (ho->ho_state->decoder == NULL) {
            ho->ho_state->decoder = wandder_create_etsili_decoder();
        }
        wandder_attach_etsili_buffer(ho->ho_state->decoder, ptr, available,
				false);
        reclen = wandder_etsili_get_pdu_length(ho->ho_state->decoder);
        if (reclen == 0) {
            break;
        }
        if (available < reclen) {
            /* Still need to recv more data */
            break;
        }

        if (wandder_etsili_is_keepalive_response(ho->ho_state->decoder)) {
            int64_t recvseq;
            recvseq = wandder_etsili_get_sequence_number(ho->ho_state->decoder);

            if (recvseq != ho->ho_state->lastkaseq) {
                if (ho->disconnect_msg == 0) {
                    logger(LOG_INFO, "OpenLI Mediator: -- unexpected KA response from handover %s:%s HI%d",
                        ho->ipstr, ho->portstr, ho->handover_type);
                    logger(LOG_INFO, "OpenLI Mediator: -- expected %ld, got %ld",
                        ho->ho_state->lastkaseq, recvseq);
                }
				pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
                return -1;
            }
            /*
            logger(LOG_INFO, "OpenLI mediator -- received KA response for %ld from LEA handover %s:%s HI%d",
                    recvseq, ho->ipstr, ho->portstr,
                    ho->handover_type);
            */
            halt_mediator_timer(ho->aliverespev);
            libtrace_scb_advance_read(ho->ho_state->incoming, reclen);

            /* Successful KA response is a good indicator that the
             * connection is stable.
             */
            if (ho->disconnect_msg == 1) {
                logger(LOG_INFO,
                        "OpenLI Mediator: reconnected to handover %s:%s HI%d successfully.",
                        ho->ipstr, ho->portstr, ho->handover_type);
            }
            ho->disconnect_msg = 0;
        } else {
            if (ho->disconnect_msg == 0) {
                logger(LOG_INFO, "OpenLI Mediator: -- received unknown data from LEA handover %s:%s HI%d",
                    ho->ipstr, ho->portstr, ho->handover_type);
            }
			pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
            return -1;
        }
    } while (1);

	pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
    return 0;
}

/** Checks if a handover's RMQ connection is still alive and error-free. If
 *  not, destroy the connection and reset it to NULL
 *
 *  @param ho       The handover which needs its RMQ connection checked.
 *  @param agencyid The name of the agency that the handover belongs to (for
 *                  logging purposes).
 *
 *  @return -1 if the RMQ connection was destroyed, 0 otherwise
 */
int check_handover_rmq_status(handover_t *ho, char *agencyid) {
    const char *hi_str = NULL;
    int r;

    if (ho->handover_type == HANDOVER_HI2) {
        hi_str = "HI2";
        r = consume_mediator_iri_messages(ho->rmq_consumer,
                &(ho->ho_state->buf), 1, &(ho->ho_state->next_rmq_ack));
    } else {
        hi_str = "HI3";
        r = consume_mediator_cc_messages(ho->rmq_consumer,
                &(ho->ho_state->buf), 1, &(ho->ho_state->next_rmq_ack));
    }

    if (r == -2) {
        logger(LOG_INFO, "OpenLI Mediator: RMQ Heartbeat timer expired for %s handover for agency %s", hi_str, agencyid);
        reset_handover_rmq(ho);
        return -1;
    } else if (r == -1) {
        logger(LOG_INFO, "OpenLI Mediator: RMQ connection error for %s handover for agency %s", hi_str, agencyid);
        reset_handover_rmq(ho);
        return -1;
    }

    return 0;
}

/** Resets the RMQ state for a given handover.
 *
 *  This is typically used when an error occurs with the RMQ consumer for
 *  a handover, which will then force the handover to re-register its
 *  connection to the RMQ service.
 *
 *  @param ho       The handover to reset RMQ state for
 */
void reset_handover_rmq(handover_t *ho) {
    if (ho->rmq_consumer) {
        amqp_destroy_connection(ho->rmq_consumer);
    }
    /* MUST set to NULL, so that re-registration will take place */
    ho->rmq_consumer = NULL;
    ho->rmq_registered = 0;
    ho->ho_state->valid_rmq_ack = 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
