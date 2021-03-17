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

#include <unistd.h>

#include "logger.h"
#include "mediator.h"
#include "util.h"
#include <libtrace.h>
#include <assert.h>

/** Halt all ongoing pcap outputs and close their respective files.
 *
 *  @param pstate           The state for the pcap output thread
 */
static void halt_pcap_outputs(pcap_thread_state_t *pstate) {

    active_pcap_output_t *out, *tmp;

    HASH_ITER(hh, pstate->active, out, tmp) {
        HASH_DELETE(hh, pstate->active, out);
        free(out->liid);
        trace_destroy_output(out->out);
        free(out);
    }
}

static char *stradd(const char *str, char *bufp, char *buflim) {
    while (bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}

static int populate_pcap_uri(pcap_thread_state_t *pstate, char *urispace,
        int urispacelen, active_pcap_output_t *act) {

    char *ptr = pstate->outtemplate;
    struct timeval tv;
    char tsbuf[12];
    char scratch[9500];
    char *w = scratch;
    char *end = scratch + urispacelen;

    assert(ptr);
    gettimeofday(&tv, NULL);
    w = stradd("pcapfile:", w, end);

    w = stradd(pstate->dir, w, end);

    for (; *ptr; ++ptr) {
        if (*ptr == '%') {
            switch(*(++ptr)) {
                case '\0':
                    --ptr;
                    break;
                case 'L':
                    w = stradd(act->liid, w, end);
                    continue;
                case 's':
                    snprintf(tsbuf, sizeof(tsbuf), "%ld", tv.tv_sec);
                    w = stradd(tsbuf, w, end);
                    continue;
                default:
                    /* all other tokens will be handled by strftime */
                    --ptr;
            }
        }
        if (w == end) {
            break;
        }
        *w++ = *ptr;
    }

    w = stradd(".pcap", w, end);
    if (pstate->compresslevel > 0) {
        w = stradd(".gz", w, end);
    }

    if (w >= end || w - scratch >= urispacelen) {
        return 0;
    }

    *w = '\0';
    strftime(urispace, urispacelen, scratch, gmtime(&(tv.tv_sec)));
    return 1;
}

/** Opens a pcap output file using libtrace, named after the current time.
 *
 *  @param pstate           The state for the pcap output thread
 *  @param act              The intercept that requires a new pcap file
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int open_pcap_output_file(pcap_thread_state_t *pstate,
        active_pcap_output_t *act) {

    char uri[4096];
    int compressmethod = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    int compresslevel = pstate->compresslevel;
    struct timeval tv;

    /* Make sure the user configured a directory for us to put files into */
    if (pstate->dir == NULL) {
        if (!pstate->dirwarned) {
            logger(LOG_INFO,
                    "OpenLI Mediator: pcap directory is not configured so will not write any pcap files.");
            pstate->dirwarned = 1;
        }
        return -1;
    }

    if (act == NULL || act->liid == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: attempted to open a pcap trace file for an invalid pcap output.");
        return -1;
    }

    if (pstate->outtemplate == NULL) {

        /* Name the file after the LIID and current timestamp -- this ensures we
         * will have files that have unique and meaningful names, even if we
         * have multiple intercepts that last over multiple rotation periods.
         */
        gettimeofday(&tv, NULL);

        if (pstate->compresslevel > 0) {
            snprintf(uri, 4096, "pcapfile:%s/openli_%s_%lu.pcap.gz",
                pstate->dir, act->liid, tv.tv_sec);
        } else {
            snprintf(uri, 4096, "pcapfile:%s/openli_%s_%lu.pcap",
                pstate->dir, act->liid, tv.tv_sec);
        }
    } else {
        if (populate_pcap_uri(pstate, uri, 4096, act) == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: unable to create pcap output file name from template '%s'",
                    pstate->outtemplate);
            return -1;
        }
    }

    /* Libtrace boiler-plate for creating an output file - we use zlib
     * compression level 1 here for a good balance between compression ratio
     * and inter-operability with other software.
     */
    act->out = trace_create_output(uri);
    if (trace_is_err_output(act->out)) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_INFO,
                "OpenLI Mediator: Error opening %s for writing trace file: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    if (pstate->compresslevel > 0) {
        if (trace_config_output(act->out, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
                &compressmethod) == -1) {
            libtrace_err_t err;
            err = trace_get_err_output(act->out);
            logger(LOG_INFO,
                    "OpenLI Mediator: Error configuring compression for writing trace file %s: %s",
                    uri, err.problem);
            goto pcaptraceerr;
        }

        /* Make sure we use an "int" here rather than pstate->compresslevel
         * directly, just to avoid libtrace trying to read inappropriate
         * bits of memory.
         */
        if (trace_config_output(act->out, TRACE_OPTION_OUTPUT_COMPRESS,
                &compresslevel) == -1) {
            libtrace_err_t err;
            err = trace_get_err_output(act->out);
            logger(LOG_INFO,
                    "OpenLI Mediator: Error configuring compression for writing trace file %s: %s",
                    uri, err.problem);
            goto pcaptraceerr;
        }
    }

    if (trace_start_output(act->out) == -1) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_INFO,
                "OpenLI Mediator: Error starting output trace file %s: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    logger(LOG_INFO, "OpenLI Mediator: opened new trace file %s for LIID %s",
            uri, act->liid);
    act->pktwritten = 0;

    return 0;

pcaptraceerr:
    /* Tidying up in the event that something went wrong. */
    trace_destroy_output(act->out);
    act->out = NULL;
    return -1;
}

/** Start a new pcap output for a particular LIID
 *
 *  @param pstate           The state for the pcap output thread
 *  @param liid             The LIID to create a pcap output for, as a string.
 *
 *  @return a pointer to a new pcap output structure, or NULL if an error
 *          occurred.
 */
static active_pcap_output_t *create_new_pcap_output(pcap_thread_state_t *pstate,
        char *liid) {

    active_pcap_output_t *act;

    act = (active_pcap_output_t *)malloc(sizeof(active_pcap_output_t));
    act->liid = strdup(liid);

    if (open_pcap_output_file(pstate, act) == -1) {
        free(act->liid);
        free(act);
        return NULL;
    }
    HASH_ADD_KEYPTR(hh, pstate->active, act->liid, strlen(act->liid), act);
    return act;
}

/** Writes a raw captured IP packet to a pcap trace file.
 *
 *  The IP packet must be prepended with the LIID of the intercept that
 *  triggered this packet's capture.
 *
 *  @param pstate           The state for the pcap output thread
 *  @param pcapmsg          The message containing the captured packet, as
 *                          received from the collector.
 */
static void write_rawpcap_packet(pcap_thread_state_t *pstate,
        mediator_pcap_msg_t *pcapmsg) {

    active_pcap_output_t *pcapout;
    uint16_t liidlen;
    unsigned char liidspace[2048];
    uint8_t *rawip;

    if (pcapmsg->msgbody == NULL) {
        return;
    }

    /* Strip off the LIID that is at the start of the message */
    extract_liid_from_exported_msg(pcapmsg->msgbody, pcapmsg->msglen,
            liidspace, 2048, &liidlen);

    if (liidlen == pcapmsg->msglen) {
        return;
    }

    /* The IP header starts immediately after the LIID */
    rawip = pcapmsg->msgbody + liidlen;

    /* Have we seen this LIID before? -- if not, create a new pcap output */
    HASH_FIND(hh, pstate->active, liidspace, strlen((char *)liidspace),
            pcapout);
    if (!pcapout) {
        pcapout = create_new_pcap_output(pstate, (char *)liidspace);
    }

    if (pcapout) {
        if (!pstate->packet) {
            pstate->packet = trace_create_packet();
        }

        /* To use the libtrace API to write this packet and construct an
         * appropriate pcap header for it, we'll need to use
         * trace_construct_packet() to turn our buffer containing the IP
         * packet into a libtrace packet.
         */
        trace_construct_packet(pstate->packet, TRACE_TYPE_NONE,
                (const void *)rawip, (uint16_t)pcapmsg->msglen - liidlen);

        /* write resulting packet to libtrace output */
        if (trace_write_packet(pcapout->out, pstate->packet) < 0) {
            libtrace_err_t err = trace_get_err_output(pcapout->out);
            logger(LOG_INFO,
                    "OpenLI mediator: error while writing packet to pcap trace file: %s",
                    err.problem);
            trace_destroy_output(pcapout->out);
            HASH_DELETE(hh, pstate->active, pcapout);
            free(pcapout->liid);
            free(pcapout);
        }
        pcapout->pktwritten = 1;
    }

    free(pcapmsg->msgbody);
}

/** Writes the IP packet contents of an encoded ETSI record to a pcap trace
 *  file.
 *
 *  The IP packet must be prepended with the LIID of the intercept that
 *  triggered this packet's capture.
 *
 *  @param pstate           The state for the pcap output thread
 *  @param pcapmsg          The message containing the captured packet, as
 *                          received from the collector.
 */
static void write_pcap_packet(pcap_thread_state_t *pstate,
        mediator_pcap_msg_t *pcapmsg) {

    uint32_t pdulen;
    char liidspace[1024];
    char ccname[128];
    active_pcap_output_t *pcapout;

    if (pcapmsg->msgbody == NULL) {
        return;
    }

    /* First, we're going to need to decode the ETSI encoding */
    if (pstate->decoder == NULL) {
        pstate->decoder = wandder_create_etsili_decoder();
    }

    wandder_attach_etsili_buffer(pstate->decoder, pcapmsg->msgbody,
            pcapmsg->msglen, false);
    pdulen = wandder_etsili_get_pdu_length(pstate->decoder);
    if (pdulen == 0 || pcapmsg->msglen < pdulen) {
        logger(LOG_INFO,
                "OpenLI Mediator: pcap thread received incomplete ETSI CC?");
        return;
    }

    /* Use the decoder to figure out the LIID for this record */
    if (wandder_etsili_get_liid(pstate->decoder, liidspace, 1024) == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: unable to find LIID for ETSI CC in pcap thread");
        return;
    }

    /* Have we seen this LIID before? -- if not, create a new pcap output */
    HASH_FIND(hh, pstate->active, liidspace, strlen(liidspace), pcapout);
    if (!pcapout) {
        pcapout = create_new_pcap_output(pstate, liidspace);
    }

    if (pcapout && pcapout->out) {
        uint8_t *rawip;
        uint32_t cclen;

        if (!pstate->packet) {
            pstate->packet = trace_create_packet();
        }

        /* Turn the ETSI CC into a libtrace pcap packet */
        rawip = wandder_etsili_get_cc_contents(pstate->decoder, &cclen,
                ccname, 128);
        if (cclen > 65535) {
logger(LOG_INFO,
                    "OpenLI Mediator: ETSI CC record is too large to write as a pcap packet -- possibly corrupt.");
        } else {
            /* To use the libtrace API to write this packet and construct an
             * appropriate pcap header for it, we'll need to use
             * trace_construct_packet() to turn our buffer containing the IP
             * packet into a libtrace packet.
             */
            trace_construct_packet(pstate->packet, TRACE_TYPE_NONE,
                    (const void *)rawip, (uint16_t)cclen);

            /* write resulting packet to libtrace output */
            if (trace_write_packet(pcapout->out, pstate->packet) < 0) {
                libtrace_err_t err = trace_get_err_output(pcapout->out);
                logger(LOG_INFO,
                        "OpenLI Mediator: error while writing packet to pcap trace file: %s",
                        err.problem);
                trace_destroy_output(pcapout->out);
                pcapout->out = NULL;
                HASH_DELETE(hh, pstate->active, pcapout);
                free(pcapout->liid);
                free(pcapout);
            }
            pcapout->pktwritten = 1;
        }
    }

    free(pcapmsg->msgbody);
}

/** Flush any outstanding packets for each active pcap output.
 *
 *  Regular libtrace writes may buffer captured packets for quite some
 *  time before actually writing them to disk, which can lead users to think
 *  that the intercept is not working. Therefore, we regularly trigger
 *  flushing of the pcap outputs to ensure that the file on disk is more
 *  representative of what has been intercepted thus far.
 *
 *  @param pstate           The state for the pcap output thread
 */
static void pcap_flush_traces(pcap_thread_state_t *pstate) {
    active_pcap_output_t *pcapout, *tmp;

    HASH_ITER(hh, pstate->active, pcapout, tmp) {
        /* if pktwritten is zero, then no packets have been added since the
         * last flush so no need to bother with an explicit flush call.
         */
        if (pcapout->out && pcapout->pktwritten &&
                trace_flush_output(pcapout->out) < 0) {
            libtrace_err_t err = trace_get_err_output(pcapout->out);
            logger(LOG_INFO,
                    "OpenLI Mediator: error while flushing pcap trace file: %s",
                    err.problem);
            trace_destroy_output(pcapout->out);
            pcapout->out = NULL;
            HASH_DELETE(hh, pstate->active, pcapout);
            free(pcapout->liid);
            free(pcapout);
        }
        pcapout->pktwritten = 0;
    }
}

/** Rotate the output files being used by each pcap output.
 *
 *  This is done regularly to ensure that there are complete pcap files
 *  (i.e. with no half-written packets and proper footers) available for the
 *  user to hand over to LEAs, if they accept pcap output.
 *
 *  @param pstate           The state for the pcap output thread
 */
static void pcap_rotate_traces(pcap_thread_state_t *pstate) {
    active_pcap_output_t *pcapout, *tmp;

    HASH_ITER(hh, pstate->active, pcapout, tmp) {
        /* Close the existing output file -- this will also flush any
         * remaining output and append any appropriate footer to the file.
         */
        trace_destroy_output(pcapout->out);
        pcapout->out = NULL;

        /* Open a new file, which will be named using the current time */
        if (open_pcap_output_file(pstate, pcapout) == -1) {
            logger(LOG_INFO,
                    "OpenLI Mediator: error while rotating pcap trace file");

            if (pcapout->out) {
                trace_destroy_output(pcapout->out);
                pcapout->out = NULL;
            }
            HASH_DELETE(hh, pstate->active, pcapout);
            free(pcapout->liid);
            free(pcapout);
        }
    }
}

static void pcap_disable_liid(pcap_thread_state_t *pstate, char *liid,
        uint16_t liidlen) {

    active_pcap_output_t *pcapout;

    logger(LOG_INFO, "OpenLI mediator: disabling pcap output for '%s'",
            liid);
    HASH_FIND(hh, pstate->active, liid, strlen(liid), pcapout);
    if (!pcapout) {
        return;
    }

    if (pcapout->out) {
        trace_destroy_output(pcapout->out);
        pcapout->out = NULL;
    }
    HASH_DELETE(hh, pstate->active, pcapout);
    free(pcapout->liid);
    free(pcapout);
    free(liid);
}

/** Main loop for the pcap output thread.
 *
 *  This thread handles any intercepted packets that the user has requested
 *  to be written to pcap files on disk, instead of mediated over the
 *  network using the ETSI LI handovers.
 *
 *  @param params           The message queue on which the main thread will
 *                          be sending packets and instructions to this
 *                          thread.
 */
void *start_pcap_thread(void *params) {

    pcap_thread_state_t pstate;
    mediator_pcap_msg_t pcapmsg;

    pstate.active = NULL;
    pstate.dir = NULL;
    pstate.compresslevel = 10;
    pstate.outtemplate = NULL;
    pstate.dirwarned = 0;
    pstate.inqueue = (libtrace_message_queue_t *)params;
    pstate.decoder = NULL;
    pstate.packet = NULL;

    while (1) {
        if (libtrace_message_queue_try_get(pstate.inqueue,
                (void *)&pcapmsg) == LIBTRACE_MQ_FAILED) {
            usleep(500);
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_HALT) {
            /* Time to halt this thread */
            break;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_FLUSH) {
            /* Time to do our regular flush of the output files */
            pcap_flush_traces(&pstate);
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_ROTATE) {
            /* Time to rotate the output files */
            pcap_rotate_traces(&pstate);
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_DISABLE_LIID) {
            pcap_disable_liid(&pstate, (char *)pcapmsg.msgbody, pcapmsg.msglen);
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_CHANGE_DIR) {
            /* The main thread wants us to write pcap files to this directory */
            if (pstate.dir) {
                /* If we already had a configured directory, we'll need to
                 * close all of our existing files and switch over to the
                 * new directory.
                 */
                free(pstate.dir);
                if (strcmp(pstate.dir, (char *)pcapmsg.msgbody) != 0) {
                    halt_pcap_outputs(&pstate);
                }
            }
            pstate.dir = (char *)pcapmsg.msgbody;
            if (pstate.dir) {
                logger(LOG_INFO,
                        "OpenLI Mediator: any pcap trace files will be written to %s",
                        pstate.dir);
            } else {
                logger(LOG_INFO,
                        "OpenLI Mediator: pcap trace file directory has been set to NULL");
            }
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_CHANGE_TEMPLATE) {
            /* The main thread wants us to write pcap files using a new
             * naming scheme */
            if (pstate.outtemplate) {
                /* If we already had a configured template, we'll need to
                 * close all of our existing files and switch over to the
                 * new template.
                 */
                free(pstate.outtemplate);
                if (strcmp(pstate.outtemplate, (char *)pcapmsg.msgbody) != 0) {
                    halt_pcap_outputs(&pstate);
                }
            }
            pstate.outtemplate = (char *)pcapmsg.msgbody;
            if (pstate.outtemplate) {
                logger(LOG_INFO,
                        "OpenLI Mediator: pcap trace files are now named according to the template '%s'",
                        pstate.outtemplate);
            } else {
                logger(LOG_INFO,
                        "OpenLI Mediator: pcap trace files are named using the default template");
            }
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_CHANGE_COMPRESS) {
            uint8_t *val = (uint8_t *)pcapmsg.msgbody;

            if (*val != pstate.compresslevel) {
                logger(LOG_INFO, "OpenLI Mediator: changing pcap trace compression level to %u (from next file onwards)", *val);
            }

            pstate.compresslevel = *val;
            continue;
        }

        if (pcapmsg.msgtype == PCAP_MESSAGE_RAWIP) {
            /* We've received a "raw" IP packet to be written to disk */
            write_rawpcap_packet(&pstate, &pcapmsg);
            continue;
        }

        /* If we get here, we've received an ETSI record that needs to be
         * reverted back to an IP packet and written to disk.
         */
        write_pcap_packet(&pstate, &pcapmsg);
    }

    /* Clean up any remaining thread state before exiting */
    if (pstate.dir) {
        free(pstate.dir);
        halt_pcap_outputs(&pstate);
    }
    if (pstate.decoder) {
        wandder_free_etsili_decoder(pstate.decoder);
    }
    if (pstate.packet) {
        trace_destroy_packet(pstate.packet);
    }
    logger(LOG_INFO, "OpenLI Mediator: exiting pcap thread.");
    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
