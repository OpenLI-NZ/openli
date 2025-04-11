/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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
#include "logger.h"
#include "lea_send_thread.h"
#include "mediator_rmq.h"
#include "handover.h"
#include "agency.h"

/** The code in this source file implements an "LEA send" thread for the
 *  OpenLI mediator.
 *  Each agency that is configured with the OpenLI provisioner will be
 *  handled using a separate instance of one of these threads.
 *
 *  The core functionality of an LEA send thread is to:
 *    - establish the handovers to the agency for both HI2 and HI3.
 *    - consume any IRIs or CCs for LIIDs that belong to the agency from
 *      their respective internal RMQ queue, placing them in an export
 *      buffer for the corresponding handover.
 *    - send data from the export buffer over the handover socket, when the
 *      LEA end is able to receive data.
 *    - send periodic keepalives on each handover, as required.
 *
 *  A lot of the code in this file is re-used by the pcap thread code, hence
 *  some functions being "public" that might not make sense at first glance.
 *  They're likely being used by the pcap thread code as well, so resist
 *  the urge to revert them to being static or merge them into other
 *  static methods in this file :)
 */

/** Initialises the agency state for an LEA send thread.
 *
 *  Includes creation of the handover instances for the agency.
 *
 *  @param agency       The agency state to be initialised
 *  @param fromprov     The agency details received from the provisioner
 *  @param epollfd      The epoll file descriptor for the LEA send thread
 */
static void init_mediator_agency(mediator_agency_t *agency,
        liagency_t *fromprov, int epollfd) {

    agency->awaitingconfirm = 0;
    agency->agencyid = strdup(fromprov->agencyid);
    if (fromprov->agencycc) {
        agency->agencycc = strdup(fromprov->agencycc);
    } else {
        agency->agencycc = NULL;
    }
    agency->disabled = 0;
    agency->disabled_msg = 0;
    agency->hi2 = create_new_handover(epollfd, fromprov->hi2_ipstr,
            fromprov->hi2_portstr, HANDOVER_HI2, fromprov->keepalivefreq,
            fromprov->keepalivewait);

    agency->hi3 = create_new_handover(epollfd, fromprov->hi3_ipstr,
            fromprov->hi3_portstr, HANDOVER_HI3, fromprov->keepalivefreq,
            fromprov->keepalivewait);

    fromprov->hi2_ipstr = NULL;
    fromprov->hi2_portstr = NULL;
    fromprov->hi3_ipstr = NULL;
    fromprov->hi3_portstr = NULL;
}


/** Starts a timer which, when expired, will cause this LEA send thread
 *  to terminate.
 *
 *  This timer is triggered when the provisioner disconnects, as we now
 *  cannot be sure that our handovers are still pointing at legitimate
 *  agencies. However, if the provisioner is able to reconnect quickly, it
 *  is nicer to have avoided any handover interruption during that brief
 *  period where it was away (e.g. in cases where the provisioner is
 *  restarted to apply new config).
 *
 *  So instead, we give the provisioner a small window to reconnect and
 *  only if it doesn't come back in time, then we go ahead and terminate the
 *  handovers (and the LEA thread itself).
 *
 *  Note: if the provisioner does come back after this timer expires, the
 *  thread will get created anew if the agency remains active in the
 *  provisioner intercept configuration.
 *
 *  @param state        The state object for this LEA send thread
 *  @param timeout      The number of seconds to set the shutdown timer for
 */
static inline void start_shutdown_timer(lea_thread_state_t *state,
        uint16_t timeout) {

    halt_mediator_timer(state->cleanse_liids);
    halt_mediator_timer(state->shutdown_wait);
    if (start_mediator_timer(state->shutdown_wait, timeout) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: unable to set shutdown timer for agency thread %s", state->agencyid);
    }

    /* set all known LIIDs to be "unconfirmed" */
    /* XXX technically, we only need to do this when the provisioner
     * has reconnected (i.e. when timeout is 60 seconds or less), but I
     * don't think it will hurt too much to do this for the case where the
     * provisioner has disconnected and we don't know if it is coming back...
     */
    foreach_liid_agency_mapping(&(state->active_liids), NULL,
            set_liid_as_unconfirmed);

}

/** Deletes any RMQ internal queues for an LIID that has both been withdrawn
 *  (i.e. the intercept is no longer active) AND the queue contains
 *  no more outstanding messages to be consumed.
 *
 *  Used as a callback for foreach_liid_agency_mapping() to periodcally
 *  tidy up any extraneous RMQ internal queues.
 *
 *  @param m            The LIID to be checked for empty queues
 *  @param agencyarg    The agency that this thread belongs to
 *
 *  @return 1 if both the CC and IRI queues for the LIID have been removed,
 *          0 if at least one queue remains or the LIID has not been
 *          withdrawn yet.
 */
static int purge_empty_withdrawn_liid_queues(liid_map_entry_t *m,
        void *agencyarg) {

    mediator_agency_t *agency = (mediator_agency_t *)agencyarg;
    int r;

    /* Don't delete queues for LIIDs that are still active! */
    if (m->withdrawn == 0) {
        return 0;
    }

    if (m->iriqueue_deleted == 0) {
        r = check_empty_mediator_iri_RMQ(agency->hi2->rmq_consumer,
                m->liid);
        if (r > 0) {
            /* TODO delete amqp queue */
            m->iriqueue_deleted = 1;
        }
    }

    if (m->ccqueue_deleted == 0) {
        r = check_empty_mediator_cc_RMQ(agency->hi3->rmq_consumer,
                m->liid);
        if (r > 0) {
            /* TODO delete amqp queue */
            m->ccqueue_deleted = 1;
        }
    }

    if (m->ccqueue_deleted && m->iriqueue_deleted) {
        return 1;
    }

    return 0;
}

/** Updates the handovers for an agency based on new information sent
 *  by the provisioner.
 *
 *  @param currag           The current agency state
 *  @param newag            The agency information sent by the provisioner
 *  @param epollfd          The epoll file descriptor for this agency thread
 */
static void update_agency_handovers(mediator_agency_t *currag,
        liagency_t *newag, int epollfd) {

    /* If a current handover is NULL or missing an IP or port, just
     * try to create a new handover instead.
     */
    if (currag->hi2 == NULL || currag->hi2->ipstr == NULL ||
            currag->hi2->portstr == NULL) {
        currag->hi2 = create_new_handover(epollfd, newag->hi2_ipstr,
            newag->hi2_portstr, HANDOVER_HI2, newag->keepalivefreq,
            newag->keepalivewait);
    } else if (strcmp(newag->hi2_ipstr, currag->hi2->ipstr) != 0 ||
            strcmp(newag->hi2_portstr, currag->hi2->portstr) != 0) {
        /* HI2 has changed */
        disconnect_handover(currag->hi2);

        free(currag->hi2->ipstr);
        currag->hi2->ipstr = newag->hi2_ipstr;
        newag->hi2_ipstr = NULL;

        free(currag->hi2->portstr);
        currag->hi2->portstr = newag->hi2_portstr;
        newag->hi2_portstr = NULL;

    }

    if (currag->agencycc) {
        free(currag->agencycc);
    }
    currag->agencycc = newag->agencycc;
    newag->agencycc = NULL;

    if (currag->hi3 == NULL || currag->hi3->ipstr == NULL ||
            currag->hi3->portstr == NULL) {
        currag->hi3 = create_new_handover(epollfd, newag->hi3_ipstr,
            newag->hi3_portstr, HANDOVER_HI3, newag->keepalivefreq,
            newag->keepalivewait);
    } else if (strcmp(newag->hi3_ipstr, currag->hi3->ipstr) != 0 ||
            strcmp(newag->hi3_portstr, currag->hi3->portstr) != 0) {
        /* HI3 has changed */
        disconnect_handover(currag->hi3);

        free(currag->hi3->ipstr);
        currag->hi3->ipstr = newag->hi3_ipstr;
        newag->hi3_ipstr = NULL;

        free(currag->hi3->portstr);
        currag->hi3->portstr = newag->hi3_portstr;
        newag->hi3_portstr = NULL;
    }

    /* Make sure keepalive frequencies are up to date -- won't affect
     * outstanding KAs but will apply to subsequent ones
     */
    currag->hi2->ho_state->kafreq = newag->keepalivefreq;
    currag->hi2->ho_state->kawait = newag->keepalivewait;
    currag->hi3->ho_state->kafreq = newag->keepalivefreq;
    currag->hi3->ho_state->kawait = newag->keepalivewait;

    free_liagency(newag);
}

/** Sends intercept records from a handover's local buffer to the
 *  corresponding agency.
 *
 *  @param ho       The handover to send records from
 *  @param state    The state object for the LEA send thread
 *
 *  @return -1 if an error occurred while sending, -2 if an error
 *          occurred while acknowledging the sent records in RMQ,
 *          0 if no records were sent, 1 otherwise.
 */
static inline int send_available_rmq_records(handover_t *ho,
        lea_thread_state_t *state) {
    int r;

    if (get_buffered_amount(&(ho->ho_state->buf)) == 0) {
        /* No records available to send */
        return 0;
    }

    /* Send up 16MB at a time */
    if (xmit_handover_records(ho, 1024 * 1024 * 16) < 0) {
        return -1;
    }

    /* We only acknowledge in RMQ once the whole message set has been
     * sent, so try to avoid buffering too many messages at once */
    if (get_buffered_amount(&(ho->ho_state->buf)) == 0 &&
            ho->ho_state->valid_rmq_ack) {
        if (ho->handover_type == HANDOVER_HI2) {
            if (ack_mediator_iri_messages(ho->rmq_consumer,
                        ho->ho_state->next_rmq_ack) < 0) {
                logger(LOG_INFO, "OpenLI Mediator: error while acknowledging sent data from internal IRI queue by agency %s", state->agencyid);
                return -2;
            }
        } else if (ho->handover_type == HANDOVER_HI3) {
            if ((r = ack_mediator_cc_messages(ho->rmq_consumer,
                        ho->ho_state->next_rmq_ack)) != 0) {
                logger(LOG_INFO, "OpenLI Mediator: error while acknowledging sent data from internal CC queue by agency %s: %d", state->agencyid, r);
                return -2;
            }
        }
        ho->ho_state->valid_rmq_ack = 0;
    }
    return 1;
}

/** Consumes any available intercept records from the RMQ connection for
 *  a particular handover and tries to send them to the receiving agency.
 *
 *  Only consumes if the handover local buffer is empty, otherwise this
 *  function will try to send and acknowledge the existing buffer contents
 *  first.
 *
 *  @param ho       The handover to consume and send records for
 *  @param state    The state object for the LEA send thread
 *
 *  @return -1 if a fatal error occurs with the handover, 0 otherwise
 */
static int consume_available_rmq_records(handover_t *ho,
        lea_thread_state_t *state) {

    int r;

    if (ho->rmq_registered == 0) {
        return 0;
    }

    /* If we have records in the buffer already, try to send and
     * acknowledge those.
     */
    if ((r = send_available_rmq_records(ho, state)) == 1) {
        ho->disconnect_msg = 0;
        return 0;
    } else if (r == -2) {
        reset_handover_rmq(ho);
        return 0;
    } else if (r == -1) {
        return -1;
    }

    r = 0;
    /* Otherwise, read some new messages from RMQ and try to send those */
    if (ho->handover_type == HANDOVER_HI3) {
        r = consume_mediator_cc_messages(ho->rmq_consumer,
                &(ho->ho_state->buf), 10, &(ho->ho_state->next_rmq_ack));
        if (r < 0) {
            reset_handover_rmq(ho);
            logger(LOG_INFO, "OpenLI Mediator: error while consuming CC messages from internal queue by agency %s", state->agencyid);
            return 0;
        } else if (r > 0) {
            ho->ho_state->valid_rmq_ack = 1;
        }
    } else if (ho->handover_type == HANDOVER_HI2) {
        r = consume_mediator_iri_messages(ho->rmq_consumer,
                &(ho->ho_state->buf), 10, &(ho->ho_state->next_rmq_ack));
        if (r < 0) {
            reset_handover_rmq(ho);
            logger(LOG_INFO, "OpenLI Mediator: error while consuming IRI messages from internal queue by agency %s", state->agencyid);
            return 0;
        } else if (r > 0) {
            ho->ho_state->valid_rmq_ack = 1;
        }
    }

    /* We can reset the RMQ heartbeat timer because any pending heartbeats
     * will have been handled when we consumed just earlier.
     */
    if (ho->rmq_consumer) {
        halt_mediator_timer(state->rmqhb);
        start_mediator_timer(state->rmqhb, state->rmq_hb_freq);
    }

    /* If our earlier "consume" got us some intercept records, try to send
     * them now.
     */
    r = send_available_rmq_records(ho, state);
    if (r > 0) {
        ho->disconnect_msg = 0;
        return 0;
    } else if (r == -2) {
        reset_handover_rmq(ho);
        return 0;
    }

    return r;
}

/** De-registers the RMQ consumers for an LIID that has not been
 *  re-confirmed as still active by a reconnecting provisioner.
 *
 *  Used as a callback for foreach_liid_agency_mapping() to de-register all
 *  unconfirmed LIIDs in the LIID set.
 *
 *  @param m            The LIID that was not confirmed by the provisioner
 *  @param arg          The state object for the LEA send thread
 *
 *  @return 0 always
 */
static int set_unconfirmed_liid_as_withdrawn(liid_map_entry_t *m, void *arg) {
    lea_thread_state_t *state = (lea_thread_state_t *)arg;
    if (m->unconfirmed == 0) {
        return 0;
    }

    /* de-register from RMQ just in case this LIID is changing agency for
     * some reason, so we don't steal any future records put in the LIID's
     * RMQ queues
     */
    if (state->agency.hi2->rmq_consumer != NULL) {
        deregister_mediator_iri_RMQ_consumer(
                state->agency.hi2->rmq_consumer, m->liid);
    }
    if (state->agency.hi3->rmq_consumer != NULL) {
        deregister_mediator_cc_RMQ_consumer(
                state->agency.hi3->rmq_consumer, m->liid);
    }

    logger(LOG_INFO, "OpenLI Mediator: withdrawing unconfirmed LIID %s from agency thread %s",
            m->liid, state->agencyid);
    m->withdrawn = 1;
    return 0;
}

/** Handle any outstanding heartbeats for this thread's RMQ connections and
 *  tidy up any unused RMQ internal queues.
 *
 *  Should be called periodically using a epoll timer event.
 *
 *  @param state        The state object for this LEA send thread
 *  @param mev          The mediator epoll timer event that fired to trigger
 *                      this function being called
 *
 *  @return 0 if the triggering timer is unable to be reset, 1 otherwise.
 */
int agency_thread_action_rmqcheck_timer(lea_thread_state_t *state,
        med_epoll_ev_t *mev) {
    halt_mediator_timer(mev);
    /* service RMQ connections */
    check_handover_rmq_status(state->agency.hi2, state->agencyid);
    check_handover_rmq_status(state->agency.hi3, state->agencyid);

    /* Remove any empty LIID queues that have been withdrawn */
    foreach_liid_agency_mapping(&(state->active_liids),
            (void *)(&(state->agency)),
            purge_empty_withdrawn_liid_queues);

    if (start_mediator_timer(mev, state->rmq_hb_freq) < 0) {
        logger(LOG_INFO, "OpenLI Mediator: unable to reset RMQ heartbeat timer in agency thread for %s: %s", state->agencyid, strerror(errno));
        return 0;
    }
    return 1;
}


/** Loops over the set of known LIIDs and withdraws any that have not been
 *  confirmed by the provisioner since it last (re-)connected.
 *
 *  Should be called via a epoll timer event set for some amount of time
 *  after a provisioner has re-connected to the main mediator thread.
 *
 *  @param state        The state object for this LEA send thread
 *
 *  @return 0 always
 */
int agency_thread_action_cease_liid_timer(lea_thread_state_t *state) {
    halt_mediator_timer(state->cleanse_liids);
    foreach_liid_agency_mapping(&(state->active_liids), state,
            set_unconfirmed_liid_as_withdrawn);
    return 0;
}

/** Calls the appropriate action method for a mediator epoll event
 *  observed by a LEA send thread.
 *
 *  @param state        The state object for the LEA send thread
 *  @param ev           The epoll event that was observed
 *
 *  @return -1 if an error occurs, 1 if the epoll loop needs to be forced
 *          to "break", 0 otherwise.
 */
static int agency_thread_epoll_event(lea_thread_state_t *state,
        struct epoll_event *ev) {

    med_epoll_ev_t *mev = (med_epoll_ev_t *)(ev->data.ptr);
    int ret = 0;
    handover_t *ho;

    switch (mev->fdtype) {
        case MED_EPOLL_SIGCHECK_TIMER:
            if (ev->events & EPOLLIN) {
                /* Time to check for messages from the parent thread again;
                 * force the epoll loop to break */
                ret = 1;
            } else {
                logger(LOG_INFO, "OpenLI Mediator: main epoll timer has failed in agency thread for %s", state->agencyid);
                ret = 0;
            }
            break;
        case MED_EPOLL_RMQCHECK_TIMER:
            /* timer to perform regular RMQ "maintenance" tasks */
            ret = agency_thread_action_rmqcheck_timer(state, mev);
            break;
        case MED_EPOLL_SHUTDOWN_LEA_THREAD:
            /* shutdown timer has expired, end this LEA thread */
            logger(LOG_INFO, "OpenLI Mediator: shutdown timer expired for agency thread %s", state->agencyid);
            ret = -1;
            break;

        case MED_EPOLL_CEASE_LIID_TIMER:
            /* remove any unconfirmed LIIDs in our LIID set */
            ret = agency_thread_action_cease_liid_timer(state);
            break;

        case MED_EPOLL_KA_TIMER:
            /* we are due to send a keep alive */
            ho = (handover_t *)(mev->state);
            trigger_handover_keepalive(ho, state->mediator_id,
                    state->operator_id, state->agency.agencycc);
            ret = 0;
            break;
        case MED_EPOLL_KA_RESPONSE_TIMER:
            /* we've gone too long without a response to our last keep alive */
            ho = (handover_t *)(mev->state);
            halt_mediator_timer(mev);
            trigger_handover_ka_failure(ho);
            /* Pause briefly to allow the other end to realise we're gone
             * before we try to reconnect the handover
             */
            usleep(500000);
            ret = 1;       // force main thread loop to restart
            break;
        case MED_EPOLL_LEA:
            ho = (handover_t *)(mev->state);
            /* the handover is available for either writing or reading */
            if (ev->events & EPOLLRDHUP) {
                /* actually, the socket connection has failed -- bail */
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                /* message from LEA -- hopefully a keep-alive response */
                ret = receive_handover(ho);
            } else if (ev->events & EPOLLOUT) {
                /* handover is able to send buffered records */

                /* If we're due to send a keep alive, do that first */
                if (ho->ho_state->pending_ka) {
                    ret = xmit_handover_keepalive(ho);
                }

                /* As long as we have an unanswered keep alive, hold off on
                 * sending any buffered records -- the recipient may be
                 * unavailable and we'd be better off to keep those records in
                 * zmq until we're confident that they're able to receive them.
                 */
                if (ret != -1 && ho->aliverespev && ho->aliverespev->fd != -1) {
                    ret = 0;
                } else {
                    ret = consume_available_rmq_records(ho, state);
                }
            } else {
                ret = -1;
            }
            if (ret == -1) {
                /* Something went wrong, disconnect and try again */
                disconnect_handover(ho);
                ret = 0;
            }
            break;
        default:
            logger(LOG_INFO, "OpenLI Mediator: invalid epoll event type %d seen in agency thread for %s", mev->fdtype, state->agencyid);
            ret = -1;
    }

    return ret;

}

/** Disables an LIID for an LEA send thread.
 *
 *  @param state        The state object for the LEA send thread
 *  @param liid         The LIID to disable
 *
 *  @return 1 if successful, 0 if the LIID was not in this thread's LIID set.
 */
int purge_lea_liid_mapping(lea_thread_state_t *state, char *liid) {

    liid_map_entry_t *m = NULL;

    /* An LIID has been withdrawn for this agency -- either because the
     * intercept is over or the intercept has changed agencies (?)
     */

    m = lookup_liid_agency_mapping(&(state->active_liids), liid);
    if (m == NULL) {
        /* This LIID is either already removed, or never was destined for
         * this agency to begin with...
         */
        return 0;
    }

    /* De-register from the LIID's RMQ internal queues */
    if ((deregister_mediator_iri_RMQ_consumer(
                    state->agency.hi2->rmq_consumer, liid) < 0) ||
            (deregister_mediator_cc_RMQ_consumer(
                    state->agency.hi3->rmq_consumer, liid) < 0)) {
        logger(LOG_INFO,
            "OpenLI Mediator: WARNING failed to deregister RMQ for LIID %s -> %s",
            liid, state->agencyid);
    }

    /* Remove from this thread's LIID set */
    remove_liid_agency_mapping(&(state->active_liids), m);
    logger(LOG_INFO, "OpenLI Mediator: purged LIID %s from agency thread %s",
            liid, state->agencyid);
    return 1;
}

/** Adds an LIID to the LIID set for an LEA send thread.
 *
 *  Also registers the corresponding RMQ internal queues with the agency
 *  handovers so records for that LIID will be consumed by this thread.
 *
 *  @param state        The state object for the LEA send thread
 *  @param liid         The LIID to associate with this agency
 *
 *  @return 1 if successful, 0 if the LIID was already in this thread's LIID
 *          set, -1 if an error occurs.
 */
int insert_lea_liid_mapping(lea_thread_state_t *state, char *liid) {
    int r;

    /* Add the LIID to the thread's LIID set */
    r = add_liid_agency_mapping(&(state->active_liids), liid);
    if (r < 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: WARNING failed to add %s -> %s to LIID map",
                liid, state->agencyid);
        return -1;
    }

    if (r == 0) {
        /* LIID was already in the map and does not need to
         * be registered with RMQ (i.e. wasn't currently
         * withdrawn) */
        return 0;
    }

    /* Register to consume from the LIID's internal RMQ queues */
    if ((register_mediator_iri_RMQ_consumer(
                    state->agency.hi2->rmq_consumer, liid) < 0) ||
            (register_mediator_cc_RMQ_consumer(state->agency.hi3->rmq_consumer,
                    liid) < 0)) {
        logger(LOG_INFO,
            "OpenLI Mediator: WARNING failed to register RMQ for LIID %s -> %s",
            liid, state->agencyid);
    } else {
        logger(LOG_INFO, "OpenLI Mediator: added %s -> %s to LIID map",
                liid, state->agencyid);
    }
    return 1;
}

/** Updates local copies of configuration variables to match the shared
 *  version of the configuration managed by the main mediator thread.
 *
 *  @param state        The state object for the LEA send thread
 *
 *  @return 1 if the RMQ internal password has changed (so all RMQ
 *          local connections should be restarted, 0 otherwise.
 */
int read_parent_config(lea_thread_state_t *state) {

    int register_required = 0;

    /* To avoid excessive locking, we maintain a local per-thread copy
     * of all relevant config options. If the config is re-loaded (e.g.
     * via a SIGHUP event observed by the main thread), we need to update
     * our local copies to incorporate any changes resulting from the
     * reload.
     */
    pthread_mutex_lock(&(state->parentconfig->mutex));
    if (state->internalrmqpass) {
        if (state->parentconfig->rmqconf->internalpass == NULL ||
            strcmp(state->parentconfig->rmqconf->internalpass,
                    state->internalrmqpass) != 0) {

            register_required = 1;
        }
        free(state->internalrmqpass);
    }
    if (state->parentconfig->rmqconf->internalpass) {
        state->internalrmqpass =
                strdup(state->parentconfig->rmqconf->internalpass);
    } else {
        state->internalrmqpass = NULL;
    }
    state->rmq_hb_freq = state->parentconfig->rmqconf->heartbeatFreq;
    state->mediator_id = state->parentconfig->mediatorid;
    state->pcap_compress_level = state->parentconfig->pcap_compress_level;
    state->pcap_rotate_frequency = state->parentconfig->pcap_rotate_frequency;

    /* most LEA threads won't need these pcap options, but it's not a
     * big cost for us to copy them
     */
    if (state->pcap_outtemplate) {
        free(state->pcap_outtemplate);
    }
    if (state->parentconfig->pcap_outtemplate) {
        state->pcap_outtemplate = strdup(state->parentconfig->pcap_outtemplate);
    } else {
        state->pcap_outtemplate = NULL;
    }

    if (state->pcap_dir) {
        free(state->pcap_dir);
    }
    if (state->parentconfig->pcap_dir) {
        state->pcap_dir = strdup(state->parentconfig->pcap_dir);
    } else {
        state->pcap_dir = NULL;
    }

    if (state->operator_id) {
        free(state->operator_id);
    }
    if (state->parentconfig->operatorid) {
        state->operator_id = strdup(state->parentconfig->operatorid);
    } else {
        state->operator_id = NULL;
    }
    if (state->short_operator_id) {
        free(state->short_operator_id);
    }
    if (state->parentconfig->shortoperatorid) {
        state->short_operator_id = strdup(state->parentconfig->shortoperatorid);
    } else {
        state->short_operator_id = NULL;
    }
    pthread_mutex_unlock(&(state->parentconfig->mutex));
    return register_required;
}

/** Declares and initialises the mediator epoll timer events that are
 *  used by an LEA send thread (or a pcap writer thread).
 *
 *  @param state        The state object for the LEA send thread
 *
 *  @return -1 if an error occurs, 1 otherwise
 */
int create_agency_thread_timers(lea_thread_state_t *state) {

    /* timer to shutdown the LEA send thread if the provisioner goes
     * missing for a while
     */
    state->shutdown_wait = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_SHUTDOWN_LEA_THREAD, 0);

    if (state->shutdown_wait == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: failed to create shutdown timer in agency thread for %s", state->agencyid);
        return -1;
    }

    /* timer for purging unconfirmed LIIDs after a provisioner reconnect */
    state->cleanse_liids = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_CEASE_LIID_TIMER, 0);

    if (state->cleanse_liids == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: failed to create LIID cleansing timer in agency thread for %s", state->agencyid);
        return -1;
    }

    /* regular once-per-second timer to break out of the epoll loop and check
     * for new messages or signals from the main thread
     */
    state->timerev = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_SIGCHECK_TIMER, 0);
    if (state->timerev == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: failed to create main loop timer in agency thread for %s", state->agencyid);
        return -1;
    }

    /* timer for performing RMQ maintenance tasks */
    state->rmqhb = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_RMQCHECK_TIMER, 0);

    if (start_mediator_timer(state->rmqhb, state->rmq_hb_freq) < 0) {
        logger(LOG_INFO,"OpenLI Mediator: failed to add RMQHB timer to epoll in agency thread for %s", state->agencyid);
        return -1;
    }

    return 1;
}

/** Converts an HI1 notification message a into properly encoded ETSI
 *  record and pushes it onto the HI2 export buffer for the agency.
 *
 *  @param state        The state object for the LEA send thread
 *  @param ndata        The HI1 notification that was received from the
 *                      provisioner (via the main mediator thread).
 */
static void publish_hi1_notification(lea_thread_state_t *state,
        hi1_notify_data_t *ndata) {

    wandder_encoded_result_t *encoded_hi1 = NULL;

    if (!ndata) {
        return;
    }

    if (state->agency.hi2->ho_state->encoder == NULL) {
        state->agency.hi2->ho_state->encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(state->agency.hi2->ho_state->encoder);
    }

    /* encode into ETSI format using libwandder */
    encoded_hi1 = encode_etsi_hi1_notification(
            state->agency.hi2->ho_state->encoder, ndata, state->operator_id,
            state->short_operator_id);
    if (encoded_hi1 == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: failed to construct HI1 Notification message for %s:%s", ndata->agencyid, ndata->liid);
        goto freehi1;
    }

    /* push onto the HI2 export buffer */
    if (append_etsipdu_to_buffer(&(state->agency.hi2->ho_state->buf),
            encoded_hi1->encoded, encoded_hi1->len, 0) == 0) {
        if (state->agency.hi2->disconnect_msg == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: unable to enqueue HI1 Notification PDU for %s:%s", ndata->agencyid, ndata->liid);
        }
    }

    wandder_release_encoded_result(state->agency.hi2->ho_state->encoder,
            encoded_hi1);

freehi1:
    /* free all the malloc'd memory for the HI1 notification */
    if (ndata->agencyid) {
        free(ndata->agencyid);
    }
    if (ndata->liid) {
        free(ndata->liid);
    }
    if (ndata->authcc) {
        free(ndata->authcc);
    }
    if (ndata->delivcc) {
        free(ndata->delivcc);
    }
    if (ndata->target_info) {
        free(ndata->target_info);
    }
    free(ndata);

}

/** Read and act upon any messages in the message queue for an LEA send
 *  thread. These messages all originate from the main mediator thread.
 *
 *  @param state        The state object for the LEA send thread
 *
 *  @return 1 if the calling thread should immediately halt, 0 otherwise.
 */
static int process_agency_messages(lea_thread_state_t *state) {
    lea_thread_msg_t msg;

    /* messages should be relatively rare, so we should be OK with
     * staying in this loop until we've read everything available
     */
    while (libtrace_message_queue_try_get(&(state->in_main), (void *)&msg)
            != LIBTRACE_MQ_FAILED) {

        if (msg.type == MED_LEA_MESSAGE_HALT) {
            /* time to kill this thread! */
            return 1;
        }

        if (msg.type == MED_LEA_MESSAGE_SHUTDOWN_TIMER) {
            /* provisioner has disconnected, start the thread shutdown timer */
            uint16_t *timeout = (uint16_t *)msg.data;
            start_shutdown_timer(state, *timeout);
            free(timeout);
        }

        if (msg.type == MED_LEA_MESSAGE_RECONNECT) {
            /* we need to drop and reconnect the handovers -- do the drop
             * here and the reconnect will happen in the main epoll loop
             */
            disconnect_handover(state->agency.hi2);
            disconnect_handover(state->agency.hi3);
            state->agency.disabled = 0;
        }

        if (msg.type == MED_LEA_MESSAGE_DISCONNECT) {
            /* we need to drop the handovers and NOT try to reconnect until
             * told otherwise, so set the "disabled" flag for the agency
             */
            disconnect_handover(state->agency.hi2);
            disconnect_handover(state->agency.hi3);
            state->agency.disabled = 1;
        }

        if (msg.type == MED_LEA_MESSAGE_RELOAD_CONFIG) {
            /* the main thread has modified the shared config, so we need to
             * check if there are any changes that affect this thread
             */
            if (read_parent_config(state) == 1) {
                reset_handover_rmq(state->agency.hi2);
                reset_handover_rmq(state->agency.hi3);
            }

        }

        if (msg.type == MED_LEA_MESSAGE_UPDATE_AGENCY) {
            /* This agency has been re-announced by the provisioner, so
             * incorporate any changes to our handovers
             */

            /* If a shutdown timer is running, halt it */
            halt_mediator_timer(state->shutdown_wait);

            /* If a handover has changed, disconnect it */
            update_agency_handovers(&(state->agency),
                    (liagency_t *)(msg.data), state->epoll_fd);

            /* Handover reconnections won't happen until the next time
             * around this loop (1 second delay max)
             */

            /* Set a timer which upon expiry will declare any
             * remaining unconfirmed LIIDs to be withdrawn.
             */
            halt_mediator_timer(state->cleanse_liids);
            if (start_mediator_timer(state->cleanse_liids, 30) < 0) {
                logger(LOG_INFO, "OpenLI Mediator: failed to add timer to remove unconfirmed LIID mappings in agency thread %s", state->agencyid);
            }

        }

        if (msg.type == MED_LEA_MESSAGE_REMOVE_LIID) {
            /* An LIID is no longer associated with this agency */
            char *liid = (char *)(msg.data);
            if (state->agency.hi2->rmq_consumer != NULL) {
                deregister_mediator_iri_RMQ_consumer(
                        state->agency.hi2->rmq_consumer, liid);
            }
            if (state->agency.hi3->rmq_consumer != NULL) {
                deregister_mediator_cc_RMQ_consumer(
                        state->agency.hi3->rmq_consumer, liid);
            }

            withdraw_liid_agency_mapping(&(state->active_liids), liid);
            free(liid);
        }

        if (msg.type == MED_LEA_MESSAGE_ADD_LIID) {
            /* An LIID has been assigned to a particular agency. */
            added_liid_t *added = (added_liid_t *)msg.data;

            if (strcmp(added->agencyid, state->agencyid) != 0) {
                /* This agency previously received this LIID but it
                 * has now changed to another agency. We need to remove it
                 * from our current handovers so we don't steal records for
                 * it and send them to the wrong agency.
                 */
                purge_lea_liid_mapping(state, added->liid);
            } else {
                /* If the agency ID matches ours, then we should add it to
                 * our handovers.
                 */
                insert_lea_liid_mapping(state, added->liid);
            }

            free(added->liid);
            free(added->agencyid);
            free(added);
        }

        if (msg.type == MED_LEA_MESSAGE_SEND_HI1_NOTIFICATION) {
            /* An HI1 notification has been delivered from the provisioner */
            hi1_notify_data_t *ndata = (hi1_notify_data_t *)(msg.data);

            publish_hi1_notification(state, ndata);
        }

    }
    return 0;
}

/** Main loop for the LEA send thread -- runs until a HALT message is received
 *  from the main mediator thread, or some irrecoverably fatal error occurs.
 *
 *  @param params       The state object for the LEA send thread (passed as
 *                      a void pointer).
 *
 *  @return NULL to pthread_join() when the thread exits
 */
static void *run_agency_thread(void *params) {
    lea_thread_state_t *state = (lea_thread_state_t *)params;
    int is_connected = 0, is_halted = 0;
    struct epoll_event evs[64];
    int i, nfds, timerexpired = 0;

    read_parent_config(state);
    logger(LOG_INFO, "OpenLI Mediator: starting agency thread for %s",
            state->agencyid);

    if (create_agency_thread_timers(state) < 0) {
        goto threadexit;
    }

    while (!is_halted) {
        /* Connect the handovers, if required */
        /* TODO separate function */
        if (state->agency.hi2->outev && state->agency.hi3->outev) {
            is_connected = 1;
        } else {
            is_connected = 0;
        }

        if (!is_connected && state->agency.disabled == 0) {
            int r_hi2 = 0, r_hi3 = 0;

            r_hi2 = connect_mediator_handover(state->agency.hi2,
                    state->epoll_fd, state->handover_id);
            r_hi3 = connect_mediator_handover(state->agency.hi3,
                    state->epoll_fd, state->handover_id + 1);
            if (r_hi2 < 0 || r_hi3 < 0) {
                break;
            }

            if (r_hi2 > 0 && r_hi3 > 0) {
                is_connected = 1;
            }
        }

        /* Check for messages from the main thread */
        if (process_agency_messages(state)) {
            is_halted = 1;
            continue;
        }

        /* Register all known LIIDs with the handover RMQ consumers -- again,
         * only if the RMQ consumers have not been set up already. */
        if (state->agency.disabled == 0) {
            if (!state->agency.hi2->rmq_registered &&
                    state->agency.hi2->outev) {
                register_handover_RMQ_all(state->agency.hi2,
                        &(state->active_liids), state->agencyid,
                        state->internalrmqpass);
            }
            if (!state->agency.hi3->rmq_registered &&
                    state->agency.hi3->outev) {
                register_handover_RMQ_all(state->agency.hi3,
                        &(state->active_liids), state->agencyid,
                        state->internalrmqpass);
            }
        }


        /* Start the once-per-second timer, so we can check for messages
         * regularly regardless of how busy our epoll socket is
         */
        if (start_mediator_timer(state->timerev, 1) < 0) {
            logger(LOG_INFO,"OpenLI Mediator: failed to add timer to epoll in agency thread for %s", state->agencyid);
            break;
        }

        /* epoll main loop for a LEA send thread */
        timerexpired = 0;
        while (!timerexpired && !is_halted) {
            nfds = epoll_wait(state->epoll_fd, evs, 64, -1);

            if (nfds < 0) {
                if (errno == EINTR) {
                    continue;
                }
                logger(LOG_INFO, "OpenLI Mediator: error while waiting for epoll events in agency thread for %s: %s", state->agencyid, strerror(errno));
                is_halted = 1;
                continue;
            }

            for (i = 0; i < nfds; i++) {
                timerexpired = agency_thread_epoll_event(state, &(evs[i]));
                if (timerexpired == -1) {
                    is_halted = 1;
                    break;
                }
                if (timerexpired) {
                    break;
                }
            }

        }

        halt_mediator_timer(state->timerev);
    }
threadexit:
    logger(LOG_INFO, "OpenLI Mediator: ending agency thread for %s",
            state->agencyid);

    destroy_agency_thread_state(state);
    pthread_exit(NULL);
}

/** Tidy up the state object for an LEA send thread, freeing all allocated
 *  memory and closing any open sockets.
 *
 *  @param state        The state object for the LEA send thread
 */
void destroy_agency_thread_state(lea_thread_state_t *state) {
    destroy_mediator_timer(state->timerev);
    destroy_mediator_timer(state->rmqhb);
    destroy_mediator_timer(state->shutdown_wait);
    destroy_mediator_timer(state->cleanse_liids);

    destroy_agency(&(state->agency));
    if (state->operator_id) {
        free(state->operator_id);
    }
    if (state->short_operator_id) {
        free(state->short_operator_id);
    }
    if (state->pcap_outtemplate) {
        free(state->pcap_outtemplate);
    }
    if (state->internalrmqpass) {
        free(state->internalrmqpass);
    }
    if (state->pcap_dir) {
        free(state->pcap_dir);
    }
    purge_liid_map(&(state->active_liids));
    free(state->agencyid);

    close(state->epoll_fd);
}


/** The methods below are intended to be called by the main mediator thread
 *  =======================================================================
 */


/** Sends an UPDATE AGENCY message to an LEA send thread.
 *
 *  @param thread           The state object for the LEA send thread that is
 *                          to receive the update agency message.
 *  @param lea              The updated definition of the agency that the
 *                          recipient thread corresponds to.
 *
 *  @return 0 always
 */
int mediator_update_agency_thread(lea_thread_state_t *thread, liagency_t *lea) {

    lea_thread_msg_t update_msg;

    update_msg.type = MED_LEA_MESSAGE_UPDATE_AGENCY;
    update_msg.data = (void *)lea;

    libtrace_message_queue_put(&(thread->in_main), &update_msg);
    return 0;
}

/** Initialises and starts a new LEA send thread
 *
 *  @param medleas          The set of LEA threads for this mediator.
 *  @param lea              The definition of the agency that the newly
 *                          created thread will be sending records to.
 *
 *  @return -1 if an error occurs, 1 if successful
 */
int mediator_start_agency_thread(mediator_lea_t *medleas, liagency_t *lea) {

    lea_thread_state_t *found = NULL;
    mediator_lea_config_t *config = &(medleas->config);

    /* "pcapdisk" is reserved as the "agency" for writing intercepts to disk
     * as pcap files
     */
    if (strcmp(lea->agencyid, "pcapdisk") == 0) {
        logger(LOG_INFO, "OpenLI Mediator: Invalid agency ID: \"pcapdisk\" -- please rename the agency to something else");
        return -1;
    }

    /* Declare and initialise the state for the thread */
    found = (lea_thread_state_t *)calloc(1, sizeof(lea_thread_state_t));
    found->parentconfig = config;
    found->epoll_fd = epoll_create1(0);
    found->handover_id = medleas->next_handover_id;

    /* Increment by 2 to account for HI2 and HI3 */
    medleas->next_handover_id += 2;

    libtrace_message_queue_init(&(found->in_main),
            sizeof(lea_thread_msg_t));
    found->agencyid = strdup(lea->agencyid);

    /* Add to the set of running LEA send threads */
    HASH_ADD_KEYPTR(hh, medleas->threads, found->agencyid,
            strlen(found->agencyid), found);

    init_mediator_agency(&(found->agency), lea, found->epoll_fd);
    pthread_create(&(found->tid), NULL, run_agency_thread, found);
    return 1;
}

/** Halts an LEA send thread.
 *
 *  @param medleas          The set of LEA threads for this mediator.
 *  @param agencyid         The ID of the agency whose LEA send thread is to
 *                          be halted.
 */
void mediator_halt_agency_thread(mediator_lea_t *medleas, char *agencyid) {

    lea_thread_state_t *lea;
    lea_thread_msg_t end_msg;
    memset(&end_msg, 0, sizeof(end_msg));

    if (strcmp(agencyid, "pcapdisk") == 0) {
        logger(LOG_INFO, "OpenLI Mediator: cannot withdraw the \"pcapdisk\" LEA because it is special.");
        return;
    }

    /* find the thread that matches the provided agency ID, if it exists */
    HASH_FIND(hh, medleas->threads, agencyid, strlen(agencyid), lea);
    if (!lea) {
        logger(LOG_INFO, "OpenLI Mediator: asked to withdraw LEA %s but no thread for this LEA exists?", agencyid);
        return;
    }

    /* send a HALT message to the thread */
    end_msg.type = MED_LEA_MESSAGE_HALT;
    end_msg.data = NULL;
    libtrace_message_queue_put(&(lea->in_main), &end_msg);

    /* wait for the thread to exit cleanly */
    pthread_join(lea->tid, NULL);

    /* clean up remaining state and remove the thread from the set of active
     * LEA send threads
     */
    libtrace_message_queue_destroy(&(lea->in_main));
    HASH_DELETE(hh, medleas->threads, lea);
    free(lea);
}

/** Halts the LEA send threads for ALL agencies
 *
 *  @param medleas          The set of LEA threads for this mediator.
 */
void mediator_disconnect_all_leas(mediator_lea_t *medleas) {

    lea_thread_state_t *lea, *tmp;

    /* Send a HALT message to every known LEA send thread */
    HASH_ITER(hh, medleas->threads, lea, tmp) {
        lea_thread_msg_t end_msg;
        memset(&end_msg, 0, sizeof(end_msg));
        end_msg.type = MED_LEA_MESSAGE_HALT;
        end_msg.data = NULL;
        libtrace_message_queue_put(&(lea->in_main), &end_msg);
    }

    /* Now wait for each thread to exit cleanly and then tidy up any
     * remaining state for each thread.
     */
    HASH_ITER(hh, medleas->threads, lea, tmp) {
        pthread_join(lea->tid, NULL);
        libtrace_message_queue_destroy(&(lea->in_main));
        HASH_DELETE(hh, medleas->threads, lea);
        free(lea);
    }

}

/** Initialises the shared configuration for the LEA send threads
 *
 *  @param config           The shared configuration instance to be initialised
 *  @param rmqconf          The RMQ configuration for the mediator
 *  @param mediatorid       The ID number assigned to this mediator
 *  @param operatorid       The operator ID configured for this mediator
 *  @param shortopid        The short operator ID configured for this mediator
 *  @param pcapdir          The directory to write pcap files into
 *  @param pcaptemplate     The template to use when naming pcap files
 *  @param pcapcompress     The compression level to use when writing pcap files
 *  @param pcaprotate       The frequency to rotate pcap files, in minutes
 *
 */
void init_med_agency_config(mediator_lea_config_t *config,
        openli_RMQ_config_t *rmqconf, uint32_t mediatorid, char *operatorid,
        char *shortopid, char *pcapdir, char *pcaptemplate,
        uint8_t pcapcompress, uint32_t pcaprotate) {

    memset(config, 0, sizeof(mediator_lea_config_t));

    config->rmqconf = rmqconf;
    config->mediatorid = mediatorid;
    if (operatorid) {
        config->operatorid = strdup(operatorid);
    }
    if (shortopid) {
        config->shortoperatorid = strdup(shortopid);
    }
    config->pcap_compress_level = pcapcompress;
    config->pcap_rotate_frequency = pcaprotate;
    if (pcapdir) {
        config->pcap_dir = strdup(pcapdir);
    }
    if (pcaptemplate) {
        config->pcap_outtemplate = strdup(pcaptemplate);
    }

    pthread_mutex_init(&(config->mutex), NULL);
}

/** Updates the shared configuration for the LEA send threads with new values
 *
 *  @param config           The shared configuration instance to be updated
 *  @param mediatorid       The ID number assigned to this mediator
 *  @param operatorid       The operator ID configured for this mediator
 *  @param shortopid        The short operator ID configured for this mediator
 *  @param pcapdir          The directory to write pcap files into
 *  @param pcaptemplate     The template to use when naming pcap files
 *  @param pcapcompress     The compression level to use when writing pcap files
 *  @param pcaprotate       The frequency to rotate pcap files, in minutes
 *
 */
void update_med_agency_config(mediator_lea_config_t *config,
        uint32_t mediatorid, char *operatorid,
        char *shortopid, char *pcapdir, char *pcaptemplate,
        uint8_t pcapcompress, uint32_t pcaprotate) {

    pthread_mutex_lock(&(config->mutex));
    config->mediatorid = mediatorid;
    config->pcap_compress_level = pcapcompress;
    config->pcap_rotate_frequency = pcaprotate;

    if (config->operatorid) {
        free(config->operatorid);
    }
    config->operatorid = strdup(operatorid);

    if (config->shortoperatorid) {
        free(config->shortoperatorid);
    }
    config->shortoperatorid = strdup(shortopid);

    if (config->pcap_dir) {
        free(config->pcap_dir);
    }
    config->pcap_dir = strdup(pcapdir);

    if (config->pcap_outtemplate) {
        free(config->pcap_outtemplate);
    }
    config->pcap_outtemplate = strdup(pcaptemplate);
    pthread_mutex_unlock(&(config->mutex));

}

/** Destroys the shared configuration for the LEA send threads.
 *
 *  @param config       The shared configuration instance to be destroyed
 */
void destroy_med_agency_config(mediator_lea_config_t *config) {
    if (config->operatorid) {
        free(config->operatorid);
    }
    if (config->shortoperatorid) {
        free(config->shortoperatorid);
    }
    if (config->pcap_dir) {
        free(config->pcap_dir);
    }
    if (config->pcap_outtemplate) {
        free(config->pcap_outtemplate);
    }
    pthread_mutex_destroy(&(config->mutex));
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

