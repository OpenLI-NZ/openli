/*
 *
 * Copyright (c) 2024,2025 SearchLight Ltd, New Zealand.
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

#include <assert.h>
#include <sys/time.h>
#include <inttypes.h>
#include <libtrace.h>
#include <libwandder_etsili.h>
#include "collector_publish.h"
#include "etsiencoding/etsiencoding.h"
#include "logger.h"

static void encode_ipmmcc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed,
        void *content, uint32_t contentlen, uint8_t dir,
        uint8_t frametype, uint8_t mmccproto) {

    wandder_encode_job_t *jobarray[7];
    int nextjob = 0;
    uint32_t upsized;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    if (dir == 0) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
        nextjob = 4;
    } else if (dir == 1) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
        nextjob = 4;
    } else if (dir == 2) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
        nextjob = 4;
    } else {
        uint32_t dir32 = dir;
        wandder_encode_next_preencoded(encoder, jobarray, 3);
        nextjob = 0;
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
                sizeof(uint32_t));
    }

    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_12]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_IPMMCCOID]);
    nextjob ++;

    wandder_encode_next_preencoded(encoder, jobarray, nextjob);
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, content, contentlen);

    /* TODO Consider pre-encoding common frame types and protocols */
    upsized = frametype;
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &upsized,
            sizeof(uint32_t));

    /* do we need streamIdentifier?? */

    upsized = mmccproto;
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &upsized,
            sizeof(uint32_t));

    END_ENCODED_SEQUENCE(encoder, 5);
}

static int etsili_create_ipmmcc_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipmmcc_job_t *mmccjob,
        encoded_global_template_t *tplate) {

    wandder_encoded_result_t *encres;
    wandder_decoder_t *dec;

    if (tplate == NULL) {
        logger(LOG_INFO, "OpenLI: called etsili_create_ipmmcc_template with NULL template?");
        return -1;
    }

    if (encoder == NULL) {
        logger(LOG_INFO, "OpenLI: called etsili_create_ipmmcc_template with NULL encoder?");
        return -1;
    }

    reset_wandder_encoder(encoder);

    encode_ipmmcc_body(encoder, precomputed, mmccjob->content,
            mmccjob->contentlen, mmccjob->dir, mmccjob->frametype,
            mmccjob->mmccproto);
    encres = wandder_encode_finish(encoder);

    if (encres == NULL || encres->len == 0 || encres->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI IPMMCC body for template");
        if (encres) {
            wandder_release_encoded_result(encoder, encres);
        }
        return -1;
    }
    /* Copy the encoded header to the template */
    tplate->cc_content.cc_wrap = malloc(encres->len);
    memcpy(tplate->cc_content.cc_wrap, encres->encoded, encres->len);
    tplate->cc_content.cc_wrap_len = encres->len;
    tplate->cc_content.content_size = mmccjob->contentlen;

    /* Find the MMCCContents and save a pointer to the value location so
     * we can overwrite it when another intercepted packet can use this
     * template.
     */
    dec = init_wandder_decoder(NULL, tplate->cc_content.cc_wrap,
            tplate->cc_content.cc_wrap_len, 0);
    if (dec == NULL) {
        logger(LOG_INFO, "OpenLI: unable to create decoder for templated ETSI IPMMCC");
        return -1;
    }

    /* TODO add tedious error checking */
    wandder_decode_next(dec);       // payload
    wandder_decode_next(dec);       // ccpayloadsequence
    wandder_decode_next(dec);       // ccpayload
    wandder_decode_sequence_until(dec, 2);  // ccContents
    wandder_decode_next(dec);       // IPMMCC
    wandder_decode_next(dec);       // IPMMCCObjId
    wandder_decode_next(dec);       // MMCCContents

    if (wandder_get_identifier(dec) != 1 ||
            wandder_get_itemlen(dec) != mmccjob->contentlen) {
        logger(LOG_INFO, "OpenLI: template created for IPMMCC is invalid");
        return -1;
    }

    tplate->cc_content.content_ptr = wandder_get_itemptr(dec);

    /* Release the encoded result -- the caller will use the templated copy */
    wandder_release_encoded_result(encoder, encres);
    free_wandder_decoder(dec);
    return 0;
}

static int etsili_update_ipmmcc_template(encoded_global_template_t *tplate,
        uint8_t *content, uint16_t contentlen) {

    assert(contentlen == tplate->cc_content.content_size);

    memcpy(tplate->cc_content.content_ptr, content, contentlen);
    return 0;
}

int encode_templated_ipmmcc(wandder_encoder_t *encoder,
        encrypt_encode_state_t *encrypt,
        openli_encoding_job_t *job, encoded_header_template_t *hdr_tplate,
        openli_encoded_result_t *res, Pvoid_t *saved_templates) {

    uint32_t key = 0;
    encoded_global_template_t *ipmmcc_tplate = NULL;
    openli_ipmmcc_job_t *mmccjob;
    uint8_t is_new = 0;

    mmccjob = (openli_ipmmcc_job_t *)&(job->origreq->data.ipmmcc);

    /* XXX This is HIDEOUS */
    if (mmccjob->dir == ETSI_DIR_FROM_TARGET) {
        if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_IP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_RTP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_MSRP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_UDP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_UDP_RTP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_UDP_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_RTP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_RTP_RTP;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_TCP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_TCP_MSRP;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_UDPTL) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_UDPTL_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_MSRP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRFROM_MSRP_MSRP;
            }
        }

    } else if (mmccjob->dir == ETSI_DIR_TO_TARGET) {
        if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_IP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_IP_RTP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_IP_MSRP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_IP_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_UDP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_UDP_RTP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_UDP_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_RTP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_RTP_RTP;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_TCP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_TCP_MSRP;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_UDPTL) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_UDPTL_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_MSRP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIRTO_MSRP_MSRP;
            }
        }
    } else {
        if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_IP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_RTP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_MSRP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_UDP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_UDP_RTP;
            } else if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_UDP_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_RTP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_RTP) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_RTP_RTP;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_TCP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_TCP_MSRP;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_UDPTL) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_UDPTL) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_UDPTL_UDPTL;
            }
        } else if (mmccjob->frametype == OPENLI_IPMMCC_FRAME_TYPE_MSRP) {
            if (mmccjob->mmccproto == OPENLI_IPMMCC_MMCC_PROTOCOL_MSRP) {
                key = TEMPLATE_TYPE_IPMMCC_DIROTHER_MSRP_MSRP;
            }
        }
    }

    if (key == 0) {
        logger(LOG_INFO, "OpenLI: unexpected or unsupported combination of parameters for IPMMCC encoding job: %u %u %u",
                mmccjob->dir, mmccjob->frametype, mmccjob->mmccproto);
        return -1;
    }

    key = (key << 16) + mmccjob->contentlen;

    ipmmcc_tplate = lookup_global_template(saved_templates, key, &is_new);

    if (is_new) {
        if (etsili_create_ipmmcc_template(encoder, job->preencoded,
                mmccjob, ipmmcc_tplate) < 0) {
            return -1;
        }
    } else {
        /* Overwrite the existing MMCCContents field */
        if (etsili_update_ipmmcc_template(ipmmcc_tplate, mmccjob->content,
                mmccjob->contentlen) < 0) {
            return -1;
        }
    }

    if (job->encryptmethod != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (create_preencrypted_message_body(encoder, encrypt,
                res, hdr_tplate,
                ipmmcc_tplate->cc_content.cc_wrap,
                ipmmcc_tplate->cc_content.cc_wrap_len,
                NULL, 0, job) < 0) {
            return -1;
        }

    } else {
        if (create_etsi_encoded_result(res, hdr_tplate,
                ipmmcc_tplate->cc_content.cc_wrap,
                ipmmcc_tplate->cc_content.cc_wrap_len, NULL, 0, job) < 0) {
            return -1;
        }
    }

    /* Success */
    return 1;
}

