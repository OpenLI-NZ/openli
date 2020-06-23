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

#ifndef OPENLI_MEDIATOR_EPOLL_H_
#define OPENLI_MEDIATOR_EPOLL_H_

#include <inttypes.h>

/** Structure that stores state for a single epoll event */
typedef struct med_epoll_ev {
    /** The type of epoll event -- see enum below for possible values */
    int fdtype;

    /** The file descriptor that this event applies to */
    int fd;

    /** The global epoll file descriptor */
    int epoll_fd;

    /** The event-specific state -- cast to an appropriate type when handling
     *  the event.
     */
    void *state;
} med_epoll_ev_t;

/** The different types of events that are triggered through the mediator epoll
 *  interface.
 */
enum {
    /** A collector is attempting to connect on the listening socket */
    MED_EPOLL_COLL_CONN,

    /** The provisioner socket is available for reading or writing */
    MED_EPOLL_PROVISIONER,

    /** A agency handover is available for reading or writing */
    MED_EPOLL_LEA,

    /** A collector socket is available for reading */
    MED_EPOLL_COLLECTOR,

    /** The mediator is due to send a keep alive on a handover */
    MED_EPOLL_KA_TIMER,

    /** A handover has failed to respond to a keep alive in time */
    MED_EPOLL_KA_RESPONSE_TIMER,

    /** A signal has been detected */
    MED_EPOLL_SIGNAL,

    /** The epoll loop should halt and act on any recent signals */
    MED_EPOLL_SIGCHECK_TIMER,

    /** The pcap output files are due to be flushed or rotated */
    MED_EPOLL_PCAP_TIMER,

    /** An LIID->agency mapping has expired and should be removed */
    MED_EPOLL_CEASE_LIID_TIMER,

    /** The mediator should now attempt to reconnect to a lost provisioner */
    MED_EPOLL_PROVRECONNECT,

    /** An incomplete SSL handshake with a collector can now be resumed */
    MED_EPOLL_COLLECTOR_HANDSHAKE,
};

/** Starts an existing timer and adds it to the global epoll event set.
 *
 *  Examples of timers that would use this function:
 *      - sending the next keep alive to a handover
 *      - attempting to reconnect to a lost provisioner
 *      - deciding that a handover has failed to respond to a keep alive
 *
 *  Only call this on timers that have had their state and epoll_fd
 *  members already set via a call to create_mediator_timer().
 *
 *  @param timerev      The mediator epoll event for the timer.
 *  @param timeoutval   The number of seconds to wait before triggering the
 *                      timer event.
 *
 *  @return -1 if an error occured, 0 otherwise (including not setting
 *          a timer because the timer is disabled).
 */
int start_mediator_timer(med_epoll_ev_t *timerev, int timeoutval);

/** Halts a timer and removes it from the global epoll event set.
 *
 *  This function applies to the same timers that start_mediator_timer
 *  applies to.
 *
 *  @param timerev  The mediator epoll event for the timer.
 *
 *  @return -1 if an error occured, 0 otherwise (including not stopping
 *          a timer because the timer is disabled).
 */
int halt_mediator_timer(med_epoll_ev_t *timerev);

/** Creates an epoll event for a timer. If the timer is given a non-zero
 *  duration, the timer is also started.
 *
 *  Does NOT free the timer structure -- use destroy_mediator_timer() for that.
 *
 *  @param epoll_fd         The global epoll fd being used by the mediator
 *  @param state            A pointer to the state to save with the timer
 *  @param timertype        The type of timer to create, e.g. MED_EPOLL_KA_TIMER
 *  @param duration         The duration of the timer, in seconds. If zero,
 *                          the epoll event is created but no timer is started.
 *
 *  @return NULL if an error occurs, otherwise a pointer to a new mediator
 *          epoll event.
 */
med_epoll_ev_t *create_mediator_timer(int epoll_fd, void *state,
        int timertype, int duration);

/** Destroys the epoll event for a timer, including removal from the epoll fd.
 *
 *  Note that the timer is freed by this function.
 *
 *  @param timerev      The mediator epoll event of the timer to be freed.
 */
void destroy_mediator_timer(med_epoll_ev_t *timerev);

/** Creates an epoll event for an active file descriptor.
 *
 *  @param epoll_fd         The global epoll fd being used by the mediator.
 *  @param state            A pointer to the state to save with the timer.
 *  @param fdtype           The purpose of the file descriptor, e.g.
 *                          MED_EPOLL_PROVISIONER.
 *  @param fd               The file descriptor to create an event for.
 *  @param events           The epoll events to apply to the fd, as a bitmask.
 *                          An example would be EPOLLIN | EPOLLOUT.
 *
 *  @return NULL if an error occurs, otherwise a pointer to a new mediator
 *          epoll event.
 */
med_epoll_ev_t *create_mediator_fdevent(int epoll_fd, void *state,
        int fdtype, int fd, uint32_t events);

/** Modifies a mediator epoll event for an active file descriptor.
 *
 *  Use this method to enable or disable certain epoll event types, e.g.
 *  to disable write events when there is no data to write.
 *
 *  @param modev            The epoll event to modify.
 *  @param events           The new epoll events to apply to the fd, as a
 *                          bitmask.
 *                          An example would be EPOLLIN | EPOLLOUT.
 *
 *  @return -1 if an error occurs, 0 if the epoll event provided is
 *          invalid, 1 if the modification succeeds.
 */
int modify_mediator_fdevent(med_epoll_ev_t *modev, uint32_t events);

/** Removes a mediator epoll event for an active file descriptor.
 *
 *  This function will close the file descriptor and free the mediator
 *  epoll event structure.
 *
 *  @param remev            The epoll event to remove.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int remove_mediator_fdevent(med_epoll_ev_t *remev);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
