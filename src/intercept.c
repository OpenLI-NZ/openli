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

#include "intercept.h"

void free_single_ipintercept(ipintercept_t *cept) {

    if (cept->liid) {
        free(cept->liid);
    }

    if (cept->authcc) {
        free(cept->authcc);
    }

    if (cept->delivcc) {
        free(cept->delivcc);
    }

    if (cept->username) {
        free(cept->username);
    }

    if (cept->targetagency) {
        free(cept->targetagency);
    }
    free(cept);
}

void free_all_ipintercepts(ipintercept_t *interceptlist) {

    ipintercept_t *cept, *tmp;

    HASH_ITER(hh_liid, interceptlist, cept, tmp) {
        HASH_DELETE(hh_liid, interceptlist, cept);
        free_single_ipintercept(cept);
    }
}

static void free_voip_cinmap(voipcinmap_t *cins) {
    voipcinmap_t *c, *tmp;

    HASH_ITER(hh_callid, cins, c, tmp) {
        HASH_DELETE(hh_callid, cins, c);
        free(c->shared);
        free(c->callid);
        free(c);
    }

}

void free_single_voip_cin(rtpstreaminf_t *rtp) {
    if (rtp->invitecseq) {
        free(rtp->invitecseq);
    }
    if (rtp->byecseq) {
        free(rtp->byecseq);
    }
    if (rtp->targetaddr) {
        free(rtp->targetaddr);
    }
    if (rtp->otheraddr) {
        free(rtp->otheraddr);
    }
    if (rtp->streamkey) {
        free(rtp->streamkey);
    }
    free(rtp);
}

static void free_voip_cins(rtpstreaminf_t *cins) {
    rtpstreaminf_t *rtp, *tmp;

    HASH_ITER(hh, cins, rtp, tmp) {
        HASH_DEL(cins, rtp);
        free_single_voip_cin(rtp);
    }

}

void free_all_voipintercepts(voipintercept_t *vints) {

    voipintercept_t *v, *tmp;
    HASH_ITER(hh_liid, vints, v, tmp) {
        HASH_DELETE(hh_liid, vints, v);
        if (v->liid) {
            free(v->liid);
        }
        if (v->authcc) {
            free(v->authcc);
        }
        if (v->delivcc) {
            free(v->delivcc);
        }
        if (v->sipuri) {
            free(v->sipuri);
        }
        if (v->targetagency) {
            free(v->targetagency);
        }
        if (v->cin_sdp_map) {
            HASH_CLEAR(hh_sdp, v->cin_sdp_map);
        }

        if (v->cin_callid_map) {
            free_voip_cinmap(v->cin_callid_map);
        }
        if (v->active_cins) {
            free_voip_cins(v->active_cins);
        }
        free(v);
    }

}

void free_all_rtpstreams(rtpstreaminf_t *streams) {
    rtpstreaminf_t *rtp, *tmp;

    HASH_ITER(hh, streams, rtp, tmp) {
        HASH_DELETE(hh, streams, rtp);
        if (rtp->targetaddr) {
            free(rtp->targetaddr);
        }
        if (rtp->otheraddr) {
            free(rtp->otheraddr);
        }
        if (rtp->streamkey) {
            free(rtp->streamkey);
        }
        free(rtp);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
