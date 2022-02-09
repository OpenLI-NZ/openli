/*
 *
 * Copyright (c) 2018-2021 The University of Waikato, Hamilton, New Zealand.
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

#include "collector_base.h"
#include "intercept.h"

static inline void remove_time_event(Pvoid_t *timeevents,
        intercept_common_t *common, uint64_t evtime, uint8_t evtype) {

    PWord_t pval;
    struct upcoming_intercept_event *found;
    upcoming_intercept_time_t *timeentry;
    int rcint;

    JLG(pval, (*timeevents), evtime);
    if (pval == NULL) {
        return;
    }

    timeentry = (upcoming_intercept_time_t *)(*pval);
    if (timeentry == NULL) {
        return;
    }

    HASH_FIND(hh, timeentry->events, common->liid, common->liid_len, found);
    if (!found) {
        return;
    }

    if (found->event_type != evtype) {
        return;
    }

    HASH_DELETE(hh, timeentry->events, found);
    free(found->liid);
    free(found);

    if (HASH_CNT(hh, timeentry->events) == 0) {
        JLD(rcint, (*timeevents), evtime);
        free(timeentry);
    }
}

static inline void add_time_event(Pvoid_t *timeevents, void *intercept,
        intercept_common_t *common, uint8_t evtype, uint64_t evtime) {

    PWord_t pval;
    struct upcoming_intercept_event *found;
    upcoming_intercept_time_t *timeentry;

    JLI(pval, (*timeevents), evtime);

    if (*pval) {
        timeentry = (upcoming_intercept_time_t *)(*pval);
    } else {
        timeentry = calloc(1, sizeof(upcoming_intercept_time_t));
        timeentry->timestamp = evtime;
        timeentry->events = NULL;
        *pval = (Word_t)timeentry;
    }

    HASH_FIND(hh, timeentry->events, common->liid, common->liid_len, found);
    if (found) {
        HASH_DELETE(hh, timeentry->events, found);
        free(found->liid);
        free(found);
    }
    found = calloc(1, sizeof(struct upcoming_intercept_event));
    found->event_type = evtype;
    found->intercept = intercept;
    found->liid = strdup(common->liid);

    HASH_ADD_KEYPTR(hh, timeentry->events, found->liid, common->liid_len,
            found);
}


void add_new_intercept_time_event(Pvoid_t *timeevents, void *intercept,
        intercept_common_t *common) {
    struct timeval now;

    gettimeofday(&now, NULL);

    if (common->tostart_time >= now.tv_sec) {
        add_time_event(timeevents, intercept, common,
                OPENLI_UPCOMING_INTERCEPT_EVENT_START, common->tostart_time);
    }

    if (common->toend_time >= now.tv_sec) {
        /* Just to avoid issues that could arise if start == end */
        if (common->toend_time == common->tostart_time) {
            common->toend_time += 1;
        }
        add_time_event(timeevents, intercept, common,
                OPENLI_UPCOMING_INTERCEPT_EVENT_END, common->toend_time);
    }

}

void remove_intercept_time_event(Pvoid_t *timeevents,
        intercept_common_t *common) {

    if (common->tostart_time != 0) {
        remove_time_event(timeevents, common, common->tostart_time,
                OPENLI_UPCOMING_INTERCEPT_EVENT_START);
    }

    if (common->toend_time != 0) {
        remove_time_event(timeevents, common, common->toend_time,
                OPENLI_UPCOMING_INTERCEPT_EVENT_END);
    }

}

void update_intercept_time_event(Pvoid_t *timeevents, void *intercept,
        intercept_common_t *prevcommon, intercept_common_t *newcommon) {
    struct timeval now;

    gettimeofday(&now, NULL);

    if (prevcommon->tostart_time != newcommon->tostart_time) {
        if (prevcommon->tostart_time != 0) {
            remove_time_event(timeevents, prevcommon, prevcommon->tostart_time,
                    OPENLI_UPCOMING_INTERCEPT_EVENT_START);
        }
        if (newcommon->tostart_time >= now.tv_sec) {
            add_time_event(timeevents, intercept, newcommon,
                    OPENLI_UPCOMING_INTERCEPT_EVENT_START,
                    newcommon->tostart_time);
        }
    }

    if (prevcommon->toend_time != newcommon->toend_time) {
        if (prevcommon->toend_time != 0) {
            remove_time_event(timeevents, prevcommon, prevcommon->toend_time,
                    OPENLI_UPCOMING_INTERCEPT_EVENT_END);
        }
        if (newcommon->toend_time >= now.tv_sec) {
            if (newcommon->toend_time == newcommon->tostart_time) {
                newcommon->toend_time += 1;
            }
            add_time_event(timeevents, intercept, newcommon,
                    OPENLI_UPCOMING_INTERCEPT_EVENT_END, newcommon->toend_time);
        }
    }

}

void *check_intercept_time_event(Pvoid_t *timeevents, time_t currtime) {

    PWord_t pval;
    Word_t index;
    struct upcoming_intercept_event *ev;
    upcoming_intercept_time_t *upts;
    int rcint;
    void *toret = NULL;

    index = 0;
    JLF(pval, *timeevents, index);

    while (pval) {
        upts = (upcoming_intercept_time_t *)(*pval);
        if (upts == NULL) {
            JLN(pval, *timeevents, index);
            continue;
        }

        if (upts->timestamp > currtime) {
            return NULL;
        }

        ev = upts->events;
        toret = ev->intercept;
        HASH_DELETE(hh, upts->events, ev);
        free(ev->liid);
        free(ev);

        /* If there are no more events for this time, delete the timestamp
         * entry entirely.
         */
        if (HASH_CNT(hh, upts->events) == 0) {
            JLD(rcint, *timeevents, index);
            free(upts);
        }
        return toret;
    }

    return NULL;
}

void clear_intercept_time_events(Pvoid_t *timeevents) {

    PWord_t pval;
    Word_t index;
    struct upcoming_intercept_event *ev, *evtmp;
    upcoming_intercept_time_t *upts;
    int rcint;

    index = 0;
    JLF(pval, *timeevents, index);
    while (pval) {
        upts = (upcoming_intercept_time_t *)(*pval);
        JLN(pval, *timeevents, index);
        if (upts == NULL) {
            continue;
        }

        HASH_ITER(hh, upts->events, ev, evtmp) {
            HASH_DELETE(hh, upts->events, ev);
            if (ev->liid) {
                free(ev->liid);
            }
            free(ev);
        }
        free(upts);
    }

    JLFA(rcint, *timeevents);

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
