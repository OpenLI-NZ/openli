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

#include <sys/epoll.h>
#include "med_epoll.h"
#include "util.h"

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
 *  @param timerev  	The mediator epoll event for the timer.
 *  @param timeoutval   The number of seconds to wait before triggering the
 *                      timer event.
 *
 *  @return -1 if an error occured, 0 otherwise (including not setting
 *          a timer because the timer is disabled).
 */
int start_mediator_timer(med_epoll_ev_t *timerev, int timeoutval) {

    int sock;

    /* Timer is disabled, ignore */
    if (timerev == NULL) {
        return 0;
    }

    if ((sock = epoll_add_timer(timerev->epoll_fd, timeoutval,
            timerev)) == -1) {
        return -1;
    }

    timerev->fd = sock;
    return 0;
}

/** Halts a timer and removes it from the global epoll event set.
 *
 *  This function applies to the same timers that start_mediator_timer
 *  applies to.
 *
 *  Does NOT free the timer structure -- use destroy_mediator_timer() for that.
 *
 *  @param timerev  The mediator epoll event for the timer.
 *
 *  @return -1 if an error occured, 0 otherwise (including not stopping
 *          a timer because the timer is disabled).
 */
int halt_mediator_timer(med_epoll_ev_t *timerev) {

    struct epoll_event ev;

    /* Timer is disabled, ignore */
    if (timerev == NULL) {
        return 0;
    }

    if (epoll_ctl(timerev->epoll_fd, EPOLL_CTL_DEL, timerev->fd, &ev) == -1) {
        return -1;
    }

    close(timerev->fd);
    timerev->fd = -1;
    return 0;
}

/** Destroys the epoll event for a timer, including removal from the epoll fd.
 *
 *  Note that the timer is freed by this function.
 *
 *  @param timerev		The mediator epoll event of the timer to be freed.
 */
void destroy_mediator_timer(med_epoll_ev_t *timerev) {

	if (timerev == NULL) {
		return;
	}

	if (timerev->fd != -1)
		halt_mediator_timer(timerev);
	}
	free(timerev);
}

/** Creates an epoll event for a timer. If the timer is given a non-zero
 *  duration, the timer is also started.
 *
 *  @param epoll_fd			The global epoll fd being used by the mediator
 *  @param state			A pointer to the state to save with the timer
 *  @param timertype		The type of timer to create, e.g. MED_EPOLL_KA_TIMER
 *  @param duration			The duration of the timer, in seconds. If zero,
 *							the epoll event is created but no timer is started.
 *
 *  @return NULL if an error occurs, otherwise a pointer to a new mediator
 *  		epoll event.
 */
med_epoll_ev_t *create_mediator_timer(int epoll_fd, void *state,
		int timertype, int duration) {

	med_epoll_ev_t *newtimer = NULL;
	int sock = -1;

	newtimer = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
	if (!newtimer) {
		return NULL;
	}

	newtimer->fd = -1;
	newtimer->fdtype = timertype;
	newtimer->state = state;
	newtimer->epoll_fd = epoll_fd;

	if (duration > 0) {
		if ((sock = epoll_add_timer(epoll_fd, duration, newtimer)) == -1) {
    	    free(newtimer);
			return NULL;
    	}
	}

	newtimer->fd = sock;
	return newtimer;
}

/** Creates an epoll event for an active file descriptor.
 *
 *  @param epoll_fd			The global epoll fd being used by the mediator.
 *  @param state			A pointer to the state to save with the timer.
 *  @param fdtype			The purpose of the file descriptor, e.g.
 * 							MED_EPOLL_PROVISIONER.
 *	@param fd				The file descriptor to create an event for.
 *  @param events			The epoll events to apply to the fd, as a bitmask.
 *							An example would be EPOLLIN | EPOLLOUT.
 *
 *  @return NULL if an error occurs, otherwise a pointer to a new mediator
 *  		epoll event.
 */
med_epoll_ev_t *create_mediator_fdevent(int epoll_fd, void *state,
		int fdtype, int fd, uint32_t events) {

	med_epoll_ev_t *newev = NULL;
	struct epoll_event epollev;

	newev = (med_epoll_ev_t *)malloc(sizeof(med_epoll_ev_t));
	if (!newev) {
		return NULL;
	}

	newev->fd = fd;
	newev->fdtype = fdtype;
	newev->state = state;
	newev->epoll_fd = epoll_fd;

	epollev.data.ptr = newev;
	epollev.events = events;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &epollev) == -1) {
		free(newev);
		return NULL;
	}

	return newev;
}

/** Modifies a mediator epoll event for an active file descriptor.
 *
 *  Use this method to enable or disable certain epoll event types, e.g.
 *  to disable write events when there is no data to write.
 *
 *  @param modev			The epoll event to modify.
 *  @param events			The new epoll events to apply to the fd, as a
 * 							bitmask.
 *							An example would be EPOLLIN | EPOLLOUT.
 *
 *  @return -1 if an error occurs, 0 if the epoll event provided is
 *    		invalid, 1 if the modification succeeds.
 */
int modify_mediator_fdevent(med_epoll_ev_t *modev, uint32_t events) {
	struct epoll_event ev;

	if (modev == NULL || modev->fd == -1) {
		return 0;
	}

	ev.data.ptr = modev;
	ev.events = events;

	if (epoll_ctl(modev->epoll_fd, EPOLL_CTL_MOD, modev->fd, &ev) == -1) {
		return -1;
	}

	return 1;
}

/** Removes a mediator epoll event for an active file descriptor.
 *
 * 	This function will close the file descriptor and free the mediator
 *  epoll event structure.
 *
 *  @param remev			The epoll event to remove.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int remove_mediator_fdevent(med_epoll_ev_t *remev) {
	struct epoll_event ev;

	if (remev && remev->fd != -1) {
		if (epoll_ctl(remev->epoll_fd, EPOLL_CTL_DEL, remev->fd, &ev) == -1) {
			return -1;
		}
		close(remev->fd);
	}

	if (remev) {
		free(remev);
	}
	return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
