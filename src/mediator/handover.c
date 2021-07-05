/*
 *
 * Copyright (c) 2018-2020 The University of Waikato, Hamilton, New Zealand.
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

/** Send some buffered ETSI records out via a handover.
 *
 *  If there is a keep alive message pending for this handover, that will
 *  be sent before sending any buffered records.
 *
 *  @param mev              The epoll event for the handover
 *
 *  @return -1 is an error occurs, 0 otherwise.
 */
int xmit_handover(med_epoll_ev_t *mev) {
	handover_t *ho = (handover_t *)(mev->state);

	/* We don't lock the handover mutex here, because we're going to be
     * doing this a lot and the mutex is mostly protecting logging-related
 	 * members (e.g. disconnect_msg). A few bogus messages are a small
     * price to pay compared with the performance impact of locking a mutex
     * everytime we want to send a record to a client.
     */
	int ret = 0;
    struct timeval tv;

    if (ho->ho_state->pending_ka) {
        /* There's a keep alive to be sent */
        ret = send(mev->fd, ho->ho_state->pending_ka->encoded,
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
        if (ret == ho->ho_state->pending_ka->len) {
            /* Sent the whole thing successfully */
            wandder_release_encoded_result(NULL, ho->ho_state->pending_ka);
            ho->ho_state->pending_ka = NULL;

            /*
            logger(LOG_INFO, "successfully sent keep alive to %s:%s HI%d",
                    ho->ipstr, ho->portstr, ho->handover_type);
            */
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

            /* If there are no actual records waiting to be sent, then
             * we can disable write on this handover and go back to the
             * epoll loop.
             */
            if (get_buffered_amount(&(ho->ho_state->buf)) == 0) {
                if (disable_handover_writing(ho) < 0)
                {
                    return -1;
                }
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

    /* As long as we have an unanswered keep alive, hold off on sending
     * any buffered records -- the recipient may be unavailable and we'd
     * be better off to keep those records in our buffer until we're
     * confident that they're able to receive them.
     */
    if (ho->aliverespev && ho->aliverespev->fd != -1) {
        return 0;
    }

    /* Send some of our buffered records, but no more than 1MB at
     * a time -- we need to go back to our epoll loop to handle other events
     * rather than getting stuck trying to send massive amounts of data in
     * one go.
     */
    if ((ret = transmit_buffered_records(&(ho->ho_state->buf), mev->fd,
			(1024 * 1024), NULL)) == -1) {
        return -1;
    }

    if (ret == 0) {
        return 0;
    }

    /* If we've sent everything that we've got, we can disable the epoll
     * write event for this handover.
     */
    if (get_buffered_amount(&(ho->ho_state->buf)) == 0) {
        if (disable_handover_writing(ho) < 0) {
            return -1;
        }
    }

    /* Reset the keep alive timer */
    gettimeofday(&tv, NULL);
    if (ho->aliveev && ho->ho_state->katimer_setsec < tv.tv_sec) {
        halt_mediator_timer(ho->aliveev);
        if (start_mediator_timer(ho->aliveev, ho->ho_state->kafreq) == -1) {
            if (ho->disconnect_msg == 0) {
                logger(LOG_INFO,
                    "OpenLI Mediator: error while trying to disable xmit for handover %s:%s HI%d -- %s",
                    ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
            }
            return -1;
        }
        ho->ho_state->katimer_setsec = tv.tv_sec;
    }

    if (ho->aliveev == NULL && ho->disconnect_msg == 1) {
        /* Keep alives are disabled, so we are going to use a successful
         * transmit as an indicator that the connection is stable again
         * and we can stop suppressing logs */
        logger(LOG_INFO,
                "OpenLI Mediator: reconnected to handover %s:%s HI%d successfully.",
                ho->ipstr, ho->portstr, ho->handover_type);

        ho->disconnect_msg = 0;
    }

    return 0;
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
static void free_handover(handover_t *ho) {

    /* This should close all of our sockets and halt any running timers */
    disconnect_handover(ho);

    destroy_mediator_timer(ho->aliveev);
    destroy_mediator_timer(ho->aliverespev);

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

/** Modify a handover's epoll event to NOT check if writing is possible.
 *
 *  If an error occurs, the handover will be disconnected.
 *
 *  @param ho				The handover to modify
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int disable_handover_writing(handover_t *ho) {
	int ret = 0;
	uint32_t events = EPOLLRDHUP | EPOLLIN ;

	if (!ho->ho_state->outenabled) {
        return 0;
    }
    ret = modify_mediator_fdevent(ho->outev, events);

	if (ret == -1) {
		logger(LOG_INFO,
				"OpenLI Mediator: error while trying to enable xmit for handover %s:%s HI%d -- %s",
				ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
		disconnect_handover(ho);
	} else {
		ho->ho_state->outenabled = 0;
	}

	return ret;
}

/** Modify a handover's epoll event to check if writing is possible.
 *
 *  If an error occurs, the handover will be disconnected.
 *
 *  @param ho				The handover to modify
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int enable_handover_writing(handover_t *ho) {
	int ret = 0;
	uint32_t events = EPOLLRDHUP | EPOLLIN | EPOLLOUT;

    if (ho->ho_state->outenabled) {
        return 0;
    }

	ret = modify_mediator_fdevent(ho->outev, events);

	if (ret == -1) {
		logger(LOG_INFO,
				"OpenLI Mediator: error while trying to enable xmit for handover %s:%s HI%d -- %s",
				ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
		disconnect_handover(ho);
	} else {
		ho->ho_state->outenabled = 1;
	}
	return ret;
}

/** Disconnects and drops all known agencies
 *
 *  @param state        The global handover state for this mediator.
 */
void drop_all_agencies(handover_state_t *state) {
    mediator_agency_t ag;
	libtrace_list_t *a = state->agencies;

	pthread_mutex_lock(state->agency_mutex);

    while (libtrace_list_get_size(a) > 0) {
        libtrace_list_pop_back(a, &ag);
        /* Disconnect the HI2 and HI3 handovers */
        free_handover(ag.hi2);
        free_handover(ag.hi3);
        if (ag.agencyid) {
            free(ag.agencyid);
        }
    }
	pthread_mutex_unlock(state->agency_mutex);

}

/** Attempt to create a handover connection to an LEA.
 *
 *  @param state        The global handover state for this mediator
 *  @param ho           The handover that we attempting to connect
 *
 *  @return -1 if there was a fatal error, 0 if there was a temporary
 *          error (i.e. try again later) or the handover is already
 *          connected, 1 if a new successful connection is made.
 */
static int connect_handover(handover_state_t *state, handover_t *ho) {
	uint32_t epollev;
	int outsock;

	/* Grab the lock, just in case the other thread decides to disconnect
     * us while we're partway through connecting.
	 */
	pthread_mutex_lock(&(ho->ho_state->ho_mutex));

	/* Check if we're already connected? */
    if (ho->outev) {
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return 0;
    }

    /* Connect the handover socket */
    outsock = connect_socket(ho->ipstr, ho->portstr, ho->disconnect_msg, 1);
    if (outsock == -1) {
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return -1;
    }

    /* If fd is 0, we can try again another time instead */
    if (outsock == 0) {
        ho->disconnect_msg = 1;
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return 0;
    }

    /* Create a buffer for receiving messages (i.e. keep-alive responses)
     * from the LEA via the handover.
     */
    ho->ho_state->incoming = (libtrace_scb_t *)malloc(sizeof(libtrace_scb_t));
    ho->ho_state->incoming->fd = -1;
    ho->ho_state->incoming->address = NULL;
    libtrace_scb_init(ho->ho_state->incoming, (64 * 1024 * 1024),
            state->next_handover_id);

	state->next_handover_id ++;

    /* If we've got records to send via this handover, enable it for
     * write events in epoll.
     */
    if (get_buffered_amount(&(ho->ho_state->buf)) > 0) {
        epollev = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
        ho->ho_state->outenabled = 1;
    } else {
        epollev = EPOLLIN | EPOLLRDHUP;
        ho->ho_state->outenabled = 0;
    }

	ho->outev = create_mediator_fdevent(state->epoll_fd, ho, MED_EPOLL_LEA,
			outsock, epollev);

	if (ho->outev == NULL) {
		logger(LOG_INFO,
				"OpenLI Mediator: unable to add agency handover for %s:%s HI%d to epoll.",
				ho->ipstr, ho->portstr, ho->handover_type, strerror(errno));
		ho->disconnect_msg = 1;
		close(outsock);
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
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

	pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
    return 1;
}

/** Attempt to connect all handovers for all known agencies
 *
 *  @param state        The global handover state for this mediator
 */
void connect_agencies(handover_state_t *state) {
    libtrace_list_node_t *n;
    mediator_agency_t *ag;
    int ret;

    /* This method will be called regularly by the agency connection 
     * thread to ensure that as many handovers as up and running as
     * possible.
     */

    /* Must have agency_mutex at this point! */
    n = state->agencies->head;
    while (n) {
        ag = (mediator_agency_t *)(n->data);
        n = n->next;

        /* Skip any disabled agencies */
        if (ag->disabled) {
            if (!ag->disabled_msg) {
                logger(LOG_INFO,
                    "OpenLI Mediator: cannot connect to agency %s because it is disabled",
                    ag->agencyid);
                ag->disabled_msg = 1;
            }
            continue;
        }

        /* Connect the HI2 handover */
        ret = connect_handover(state, ag->hi2);
        if (ret == -1) {
            continue;
        }

        if (ret == 1) {
            logger(LOG_INFO,
                    "OpenLI Mediator: Connected to agency %s on HI2 %s:%s.",
                    ag->agencyid, ag->hi2->ipstr, ag->hi2->portstr);
            ag->hi2->disconnect_msg = 0;
        }

        /* Connect the HI3 handover */
        ret = connect_handover(state, ag->hi3);
        if (ret == -1) {
            ag->disabled = 1;
            continue;
        }

        if (ret == 1) {
            ag->hi3->disconnect_msg = 0;
            logger(LOG_INFO,
                    "OpenLI Mediator: Connected to agency %s on HI3 %s:%s.",
                    ag->agencyid, ag->hi3->ipstr, ag->hi3->portstr);
        }

    }

}

/** Starts the thread that continuously attempts to connect any handovers
 *  that are not currently active.
 *
 *  @param params       The global state for the mediator
 */
static void *start_connect_thread(void *params) {

    handover_state_t *state = (handover_state_t *)params;

    while (1) {

        /* We need a mutex lock here because our set of agencies could
         * be modified by a message from the provisioner, which will be
         * handled in the main epoll thread.
         */
        pthread_mutex_lock(state->agency_mutex);
		if (state->halt_flag) {
        	pthread_mutex_unlock(state->agency_mutex);
			break;
		}
        connect_agencies(state);
        pthread_mutex_unlock(state->agency_mutex);

        /* Try again in 0.5 of a second */
        usleep(500000);
    }

    logger(LOG_INFO, "OpenLI Mediator: has ended agency connection thread.");
    pthread_exit(NULL);

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
static handover_t *create_new_handover(int epoll_fd, char *ipstr, char *portstr,
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
    ho->ho_state->outenabled = 0;
    ho->ho_state->katimer_setsec = 0;
    ho->ho_state->incoming = NULL;
    ho->ho_state->encoder = NULL;
    ho->ho_state->decoder = NULL;
    ho->ho_state->pending_ka = NULL;
    ho->ho_state->kafreq = kafreq;
    ho->ho_state->kawait = kawait;

	pthread_mutex_init(&(ho->ho_state->ho_mutex), NULL);

    /* Keep alive frequency of 0 (or less) will mean that no keep alives are
     * sent (this may necessary for some agencies).
     */
    if (kafreq > 0) {
		ho->aliveev = create_mediator_timer(epoll_fd, ho, MED_EPOLL_KA_TIMER,
				0);
		if (ho->aliveev == NULL) {
			logger(LOG_INFO, "OpenLI Mediator: unable to create keep alive timer for agency %s:%s", ipstr, portstr);
		}
    } else {
            logger(LOG_INFO, "OpenLI Mediator: Warning, keep alive timer has been disabled for agency %s:%s", ipstr, portstr);
        ho->aliveev = NULL;
    }

    /* If keep alive wait is 0 (or less), then we will not require a response
     * for a successful keep alive.
     */
    if (kawait > 0) {
		ho->aliverespev = create_mediator_timer(epoll_fd, ho,
				MED_EPOLL_KA_RESPONSE_TIMER, 0);
		if (ho->aliverespev == NULL) {
			logger(LOG_INFO, "OpenLI Mediator: unable to create keep alive response timer for agency %s:%s", ipstr, portstr);
		}
    } else {
        ho->aliverespev = NULL;
    }

	/* The output event will be created when the handover is connected by the
     * connection thread.
	 */
	ho->outev = NULL;

    /* Initialise the remaining handover state */
    ho->ipstr = ipstr;
    ho->portstr = portstr;
    ho->handover_type = handover_type;
    ho->disconnect_msg = 0;

    return ho;
}

/** Creates a new instance of an agency.
 *
 *  @param state        The global handover state for this mediator.
 *  @param lea          The agency details received from the provisioner.
 */
static void create_new_agency(handover_state_t *state, liagency_t *lea) {

    mediator_agency_t newagency;

    newagency.agencyid = lea->agencyid;
    newagency.awaitingconfirm = 0;
    newagency.disabled = 0;
    newagency.disabled_msg = 0;

    /* Create the HI2 and HI3 handovers */
    newagency.hi2 = create_new_handover(state->epoll_fd,
			lea->hi2_ipstr, lea->hi2_portstr,
            HANDOVER_HI2, lea->keepalivefreq, lea->keepalivewait);
    newagency.hi3 = create_new_handover(state->epoll_fd,
			lea->hi3_ipstr, lea->hi3_portstr,
            HANDOVER_HI3, lea->keepalivefreq, lea->keepalivewait);

    /* This lock protects the agency list that may be being iterated over
     * by the handover connection thread */
    pthread_mutex_lock(state->agency_mutex);
    libtrace_list_push_back(state->agencies, &newagency);

    /* Start the handover connection thread if necessary */
    if (libtrace_list_get_size(state->agencies) == 1 &&
            state->connectthread == -1) {
        pthread_create(&(state->connectthread), NULL, start_connect_thread,
                state);
    }
    pthread_mutex_unlock(state->agency_mutex);

}

/* Compares a handover announced by the provisioner against an existing
 * local instance of the handover to see if there are any changes that
 * need to made to update the local handover. If so, the changes are
 * actioned (including a possible disconnection of the existing handover if
 * need be).
 *
 * Used when a provisioner re-announces an existing agency -- if the IP
 * address or port for a handover changes, for instance, we would need to
 * close the handover and re-connect to the new IP + port.
 *
 * @param state         The global handover state for the mediator.
 * @param ho            The existing local handover instance.
 * @param ipstr         The IP address of the announced handover (as a string).
 * @param port          The port number of the announced handover (as a string).
 * @param existing      The existing instance of the parent agency.
 * @param newag         The new agency details received from the provisioner.
 *
 * @return -1 if an error occurs, 0 if the handover did not require a reconnect,
 *         1 if a reconnect was required.
 */

static int has_handover_changed(handover_state_t *state,
        handover_t *ho, char *ipstr, char *portstr, mediator_agency_t *existing,
        liagency_t *newag) {
    char *hitypestr;
    int changedloc = 0;
    int changedkaresp = 0;
    int changedkafreq = 0;

    /* TODO this function is a bit awkward at the moment */

    if (ho == NULL) {
        return -1;
    }

	pthread_mutex_lock(&(ho->ho_state->ho_mutex));

    if (!ho->ipstr || !ho->portstr || !ipstr || !portstr) {
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return -1;
    }

    if (newag->keepalivewait != ho->ho_state->kawait &&
            (newag->keepalivewait == 0 || ho->ho_state->kawait == 0)) {
        changedkaresp = 1;
    }

    if (newag->keepalivefreq != ho->ho_state->kafreq &&
            (newag->keepalivefreq == 0 || ho->ho_state->kafreq == 0)) {
        changedkafreq = 1;
    }

    if (strcmp(ho->ipstr, ipstr) != 0 || strcmp(ho->portstr, portstr) != 0) {
        changedloc = 1;
    }

    /* Update keep alive timer frequencies */
    ho->ho_state->kawait = newag->keepalivewait;
    ho->ho_state->kafreq = newag->keepalivefreq;

    if (!changedkaresp && !changedloc && !changedkafreq) {
        /* Nothing has changed so nothing more needs to be done */
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return 0;
    }

    /* Preparing some string bits for logging */
    if (ho->handover_type == HANDOVER_HI2) {
        hitypestr = "HI2";
    } else if (ho->handover_type == HANDOVER_HI3) {
        hitypestr = "HI3";
    } else {
        hitypestr = "Unknown handover";
    }

    if (changedloc) {
        /* Re-connect is going to be required */
        logger(LOG_INFO,
                "OpenLI Mediator: %s connection info for LEA %s has changed from %s:%s to %s:%s.",
                hitypestr, existing->agencyid, ho->ipstr, ho->portstr, ipstr, portstr);
        disconnect_handover(ho);
        free(ho->ipstr);
        free(ho->portstr);
        ho->ipstr = ipstr;
        ho->portstr = portstr;
		pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
        return 1;
    }

    if (changedkaresp) {
        if (newag->keepalivewait == 0) {
            /* Keep alive responses are no longer necessary */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: disabled keep-alive response requirement for LEA %s",
                        existing->agencyid);
            }
            /* Stop any existing keep alive response timer to prevent us
             * from dropping the handover for our most recent keep alive.
             */
			destroy_mediator_timer(ho->aliverespev);
			ho->aliverespev = NULL;
        } else {
            /* Keep alive responses are enabled (or have changed frequency) */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: enabled keep-alive response requirement for LEA %s",
                        existing->agencyid);
            }
            if (ho->aliverespev == NULL) {
				ho->aliverespev = create_mediator_timer(state->epoll_fd,
						ho, MED_EPOLL_KA_RESPONSE_TIMER, 0);
            }
        }
    }

    if (changedkafreq) {
        if (newag->keepalivefreq == 0) {
            /* Sending keep alives is now disabled */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: disabled keep-alives for LEA %s",
                        existing->agencyid);
            }
            /* Halt the existing keep alive timer */
            destroy_mediator_timer(ho->aliveev);
			ho->aliveev = NULL;
        } else {
            /* Keep alives have been enabled (or changed frequency) */
            if (ho->handover_type == HANDOVER_HI2) {
                /* We only log for HI2 to prevent duplicate logging when the
                 * same agency-level option is updated for HI3.
                 */
                logger(LOG_INFO,
                        "OpenLI Mediator: enabled keep-alives for LEA %s",
                        existing->agencyid);
            }

            /* Start a new keep alive timer with the new frequency */
            if (ho->aliveev == NULL) {
                ho->aliveev = create_mediator_timer(state->epoll_fd, ho,
						MED_EPOLL_KA_TIMER, 0);
			} else {
                halt_mediator_timer(ho->aliveev);
			}
			if (start_mediator_timer(ho->aliveev, newag->keepalivefreq) < 0) {
				logger(LOG_INFO,
						"OpenLI Mediator: unable to restart keepalive timer for handover %s:%s HI%d.",
						ho->ipstr, ho->portstr, ho->handover_type,
						strerror(errno));
				pthread_mutex_unlock(&(ho->ho_state->ho_mutex));
				return -1;
			}
        }
    }
	pthread_mutex_unlock(&(ho->ho_state->ho_mutex));

    return 0;
}

/** Adds an agency to the known agency list.
 *
 *  If an agency with the same ID already exists, we update its handovers
 *  to match the details we just received.
 *
 *  If the agency was awaiting confirmation after a lost provisioner
 *  connection, it will be marked as confirmed.
 *
 *  @param state			The global handover state for the mediator
 *  @param agencyid			The agency to add to the list.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int enable_agency(handover_state_t *state, liagency_t *lea) {

	int ret = 0;
	libtrace_list_node_t *n;

    /* Add / enable the agency in the agency list -- note that lock to protect
     * concurrent access to the list by the handover connection thread.
     */
    pthread_mutex_lock(state->agency_mutex);
    n = state->agencies->head;
    while (n) {
        mediator_agency_t *x = (mediator_agency_t *)(n->data);
        n = n->next;

        if (strcmp(x->agencyid, lea->agencyid) == 0) {
            /* Agency with this ID already exists; check if this
             * announcement contains differences to our last knowledge of
             * this agency.
             */
            if ((ret = has_handover_changed(state, x->hi2, lea->hi2_ipstr,
                    lea->hi2_portstr, x, lea)) == -1) {
                x->disabled = 1;
                x->disabled_msg = 0;
                goto freelea;
            } else if (ret == 1) {
                lea->hi2_portstr = NULL;
                lea->hi2_ipstr = NULL;
            }

            if ((ret = has_handover_changed(state, x->hi3, lea->hi3_ipstr,
                    lea->hi3_portstr, x, lea)) == -1) {
                x->disabled = 1;
                x->disabled_msg = 0;
                goto freelea;
            } else if (ret == 1) {
                lea->hi3_portstr = NULL;
                lea->hi3_ipstr = NULL;
            }

            x->awaitingconfirm = 0;
            x->disabled = 0;
            ret = 0;
            goto freelea;
        }
    }

    /* If we get here, this is an entirely new agency so we can create a
     * fresh instance (plus handovers).
     */
    pthread_mutex_unlock(state->agency_mutex);
    create_new_agency(state, lea);
    return 0;

freelea:
    /* If we get here, the agency already existed in our list so we can
     * remove any extra memory left over from the announcement (e.g.
     * IP address or port strings that were unchanged).
     */
    pthread_mutex_unlock(state->agency_mutex);
    if (lea->agencyid) {
        free(lea->agencyid);
    }
    if (lea->hi2_portstr) {
        free(lea->hi2_portstr);
    }
    if (lea->hi2_ipstr) {
        free(lea->hi2_ipstr);
    }
    if (lea->hi3_portstr) {
        free(lea->hi3_portstr);
    }
    if (lea->hi3_ipstr) {
        free(lea->hi3_ipstr);
    }
    return ret;
}

/** Disables a specific agency.
 *
 *  A disabled agency will have its handovers disconnected and they
 *  will not be reconnected until the provisioner announces the agency
 *  is valid again.
 *
 *  @param state			The global handover state for the mediator
 *  @param agencyid			The ID of the agency to be disabled, as a string.
 */
void withdraw_agency(handover_state_t *state, char *agencyid) {
    libtrace_list_node_t *n;

	/* Disable the agency in the agency list -- note that lock to protect
	 * concurrent access to the list by the handover connection thread.
	 */
	pthread_mutex_lock(state->agency_mutex);
	n = state->agencies->head;
	while (n) {
		mediator_agency_t *x = (mediator_agency_t *)(n->data);
		n = n->next;

		if (strcmp(x->agencyid, agencyid) == 0) {
			/* We've found the agency with the appropriate ID to withdraw */
			x->disabled = 1;
			x->disabled_msg = 0;
			disconnect_handover(x->hi2);
			disconnect_handover(x->hi3);

			/* Note that we leave the agency in the list -- it's simpler to do
			 * that than to actually try and remove it.
			 *
			 * TODO replace agency list with a Judy map keyed by agency id.
			 */
			break;
		}
	}
	pthread_mutex_unlock(state->agency_mutex);
}

/** Restarts the keep alive timer for a handover
 *
 *  @param ho			The handover to restart the keep alive timer for
 *
 *  @return	-1 if an error occurs, 0 otherwise
 */
int restart_handover_keepalive(handover_t *ho) {

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

/** Receives and actions a message sent to the mediator over a handover
 *  (typically a keep alive response).
 *
 *  @param mev              The epoll event for the handover
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int receive_handover(med_epoll_ev_t *mev) {
	handover_t *ho = (handover_t *)(mev->state);
	int ret;
    uint8_t *ptr = NULL;
    uint32_t reclen = 0;
    uint32_t available;

    /* receive the incoming message into a local SCB */
	pthread_mutex_lock(&(ho->ho_state->ho_mutex));

    ret = libtrace_scb_recv_sock(ho->ho_state->incoming, mev->fd, MSG_DONTWAIT);
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
                    recvseq, mas->parent->ipstr, mas->parent->portstr,
                    mas->parent->handover_type);
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

/** Finds an agency that matches a given ID in the agency list
 *
 *  @param state        The global handover state for the mediator
 *  @param id           A string containing the agency ID to search for
 *
 *  @return a pointer to the agency with the given ID, or NULL if no such
 *          agency is found.
 */
mediator_agency_t *lookup_agency(handover_state_t *state, char *id) {

    mediator_agency_t *ma;
    libtrace_list_t *alist;
    libtrace_list_node_t *n;

    pthread_mutex_lock(state->agency_mutex);
    alist = state->agencies;

    /* Fingers crossed we don't have too many agencies at any one time. */

    n = alist->head;
    while (n) {
        ma = (mediator_agency_t *)(n->data);
        n = n->next;

        if (strcmp(ma->agencyid, id) == 0) {
            pthread_mutex_unlock(state->agency_mutex);
            return ma;
        }
    }
    pthread_mutex_unlock(state->agency_mutex);
    return NULL;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
