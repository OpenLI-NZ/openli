/*
 *
 * Copyright (c) 2023 The OpenLI Foundation
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <libwandder_etsili.h>
#include <assert.h>
#include "etsili_core.h"
#include "logger.h"
#include "intercept.h"
#include "etsiencoding.h"

static void DEVDEBUG_dump_contents(uint8_t *buf, uint16_t len) {

    int i = 0;
    FILE *f;

    for (i = 0; i < len; i++) {
        printf("%02x ", *(buf + i));
        if ((i % 16) == 15) {
            printf("\n");
        }
    }
    printf("\n");

    f = fopen("/tmp/encrypt.debug", "w");
    fwrite(buf, len, 1, f);
    fclose(f);

}

static inline uint32_t job_origreq_to_encrypted_payload_type(
        openli_encoding_job_t *job) {

    switch(job->origreq->type) {
        case OPENLI_EXPORT_EMAILIRI:
        case OPENLI_EXPORT_EMAILCC:
            return OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART2;
        case OPENLI_EXPORT_IPCC:
        case OPENLI_EXPORT_IPIRI:
            return OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART3;
        case OPENLI_EXPORT_UMTSCC:
        case OPENLI_EXPORT_UMTSIRI:
            return OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART7;
        case OPENLI_EXPORT_IPMMCC:
        case OPENLI_EXPORT_IPMMIRI:
            return OPENLI_ENCRYPTED_PAYLOAD_TYPE_PART5;
    }

    return OPENLI_ENCRYPTED_PAYLOAD_TYPE_UNKNOWN;
}

void etsili_destroy_encrypted_templates(openli_encoder_t *enc) {
    Word_t indexint;
    PWord_t pval;
    int rcint;

    indexint = 0;
    JLF(pval, enc->saved_encryption_templates, indexint);
    while (pval) {
        encoded_encrypt_template_t *t;

        t = (encoded_encrypt_template_t *)(*pval);
        if (t->start) {
            free(t->start);
        }
        free(t);
        JLN(pval, enc->saved_encryption_templates, indexint);
    }
    JLFA(rcint, enc->saved_encryption_templates);


}

static int encode_encrypt_container(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, payload_encryption_method_t method,
        uint8_t *enccontent, uint16_t enclen, openli_encoding_job_t *job) {

    wandder_encode_job_t *jobarray[3];
    uint32_t payloadtype = job_origreq_to_encrypted_payload_type(job);

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]); // Payload
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_4]); // encryptionContainer


    if (method == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        jobarray[2] = &(precomputed[OPENLI_PREENCODE_AES_192_CBC]);
    } else {
        jobarray[2] = &(precomputed[OPENLI_PREENCODE_NO_ENCRYPTION]);
    }

    wandder_encode_next_preencoded(encoder, jobarray, 3);

    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, enccontent, enclen);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &payloadtype,
            sizeof(uint32_t));
    END_ENCODED_SEQUENCE(encoder, 2);
    return 0;
}

static int etsili_update_encrypted_template(
        encoded_encrypt_template_t *tplate, uint8_t *enccontent,
        uint16_t enclen, openli_encoding_job_t *job) {

    uint32_t payloadtype = job_origreq_to_encrypted_payload_type(job);
    uint8_t ptype;
    assert(enclen == tplate->payloadlen);
    assert(payloadtype < 255);

    memcpy(tplate->payload, enccontent, enclen);

    ptype = (payloadtype & 0xff);
    memcpy(tplate->payload_type, &ptype, sizeof(uint8_t));
    return 0;
}

static int etsili_create_encrypted_template(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, payload_encryption_method_t method,
        uint8_t *enccontent, uint16_t enclen,
        encoded_encrypt_template_t *tplate, openli_encoding_job_t *job) {

    wandder_encoded_result_t *encres;
    wandder_decoder_t *dec;

    if (tplate == NULL) {
        logger(LOG_INFO, "OpenLI: called etsili_create_encrypted_template with NULL template?");
        return -1;
    }

    if (encoder == NULL) {
        logger(LOG_INFO, "OpenLI: called etsili_create_encrypted_template with NULL encoder?");
        return -1;
    }

    reset_wandder_encoder(encoder);
    if (encode_encrypt_container(encoder, precomputed, method, enccontent,
                enclen, job) < 0){
        return -1;
    }
    encres = wandder_encode_finish(encoder);

    if (encres == NULL || encres->len == 0 || encres->encoded == NULL) {
        logger(LOG_INFO, "OpenLI: failed to encode ETSI encrypted container for template");
        if (encres) {
            wandder_release_encoded_result(encoder, encres);
        }
        return -1;
    }

    /* Copy the encoded header to the template */
    tplate->start = malloc(encres->len);
    memcpy(tplate->start, encres->encoded, encres->len);
    tplate->totallen = encres->len;


    /* Find the encryptionPayload and save a pointer to the value location so
     * we can overwrite it when another encrypted record wants to use this
     * template.
     */
    dec = init_wandder_decoder(NULL, tplate->start, tplate->totallen, 0);
    if (dec == NULL) {
        logger(LOG_INFO, "OpenLI: unable to create decoder for templated ETSI encrypted payload");
        return -1;
    }

    wandder_decode_next(dec);       // payload
    wandder_decode_next(dec);       // encryptionContainer
    wandder_decode_next(dec);       // encryptionType
    wandder_decode_next(dec);       // encryptedPayload

    tplate->payload = wandder_get_itemptr(dec);
    tplate->payloadlen = enclen;
    wandder_decode_next(dec);       // encryptedPayloadType
    tplate->payload_type = wandder_get_itemptr(dec);

    /* Release the encoded result -- the caller will use the templated copy */
    wandder_release_encoded_result(encoder, encres);
    free_wandder_decoder(dec);
    return 0;
}

static encoded_encrypt_template_t *lookup_encrypted_template(
        openli_encoder_t *enc, uint16_t length,
        payload_encryption_method_t method, uint8_t *is_new) {

    PWord_t pval;
    uint32_t key;
    encoded_encrypt_template_t *tplate = NULL;

    key = (method << 16) + length;
    JLG(pval, enc->saved_encryption_templates, key);

    if (pval == NULL) {
        tplate = calloc(1, sizeof(encoded_encrypt_template_t));
        tplate->key = key;
        JLI(pval, enc->saved_encryption_templates, key);
        *pval = (Word_t)tplate;
        *is_new = 1;
    } else {
        tplate = (encoded_encrypt_template_t *)(*pval);
        *is_new = 0;
    }

    return tplate;
}

static int encrypt_aes_192_cbc(EVP_CIPHER_CTX *ctx,
        uint8_t *buf, uint16_t buflen, uint8_t *dest,
        uint16_t destlen, uint32_t seqno, char *encryptkey) {

    uint8_t IV_128[16];
    uint8_t key[24];
    uint32_t swapseqno;
    size_t keylen = strlen(encryptkey);
    int len, i;

    assert(buflen <= destlen);

    /* Generate the IV */
    swapseqno = htonl(seqno);

    for (i = 0; i < 16; i+=sizeof(uint32_t)) {
        memcpy(&(IV_128[i]), &swapseqno, sizeof(uint32_t));
    }

    if (keylen > 24) {
        keylen = 24;
    }
    memcpy(key, encryptkey, keylen);

    /* Do the encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, IV_128) != 1) {
            logger(LOG_INFO, "OpenLI: unable to initialise EVP encryption operation -- openssl error %s", ERR_error_string(ERR_get_error(), NULL));
            return -1;
    }

    if (EVP_EncryptUpdate(ctx, dest, &len, buf, (int)buflen) != 1) {
            logger(LOG_INFO, "OpenLI: unable to perform EVP encryption operation -- openssl error %s", ERR_error_string(ERR_get_error(), NULL));
            return -1;
    }

    if (EVP_EncryptFinal_ex(ctx, dest + len, &len) != 1) {
            logger(LOG_INFO, "OpenLI: unable to finish EVP encryption operation -- openssl error %s", ERR_error_string(ERR_get_error(), NULL));
            return -1;
    }

    return 0;

}

int create_encrypted_message_body(openli_encoder_t *enc,
                openli_encoded_result_t *res,
                encoded_header_template_t *hdr_tplate,
                uint8_t *payloadbody, uint16_t bodylen,
                uint8_t *ipcontents, uint16_t ipclen,
                openli_encoding_job_t *job) {

    uint32_t inplen;
    uint32_t enclen = 0, newbodylen = 0;
    uint8_t containerlen = 0, is_new = 0;
    uint8_t *buf, *ptr;
    uint8_t *encrypted;
    uint32_t bytecounter;
    uint32_t bc_increase;
    encoded_encrypt_template_t *tplate = NULL;

    if (payloadbody == NULL) {
        logger(LOG_INFO, "OpenLI: cannot encrypt an ETSI PDU that does not have valid encoded payload");
        return -1;
    }

    /* Calculate length of encryptable data, including padding. */
    inplen = bodylen + ipclen;
    inplen += 10;       // 10 bytes for byteCounter
    newbodylen = inplen;
    if (inplen < 128) {
        inplen += 2;    // 2 bytes (1 for identifier, 1 for length) for
                        // EncryptedPayload
        containerlen = 1;
    } else if (inplen < 32768) {
        inplen += 4;    // 3 bytes (1 for identifer, 3 for length)
        containerlen = 3;
    } else {
        inplen += 5;    // inplen can't exceed 65536, so we can cap this at
                        // 4 length bytes
        containerlen = 4;
    }

    if (job->encryptmethod == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        enclen = AES_OUTPUT_SIZE(inplen);
    } else {
        enclen = inplen;
    }

    /* Add 16 bytes extra, just to be safe...
     */
    buf = calloc(enclen + 16, sizeof(uint8_t));
    encrypted = calloc(enclen + 16, sizeof(uint8_t));

    /* Take the contents of body_tplate (minus the initial "payload" field).
     * Add EncryptedPayload and byteCounter fields to the front to get
     * the "unencrypted" version of the payload.
     *
     * We shouldn't need the overhead of an encoder to add the two preceding
     * fields (I hope).
     */

    /* Starting with the EncryptedPayload header -- a bit fiddly because of
     * the different possible sizes for the length field */
    ptr = buf;
    *ptr = 0x30;
    ptr ++;

    if (containerlen > 1) {
        *ptr = ((uint8_t)(containerlen - 1)) | 0x80;
        ptr ++;
    }

    if (newbodylen >= 32768) {
        *ptr = (uint8_t)(newbodylen >> 16);
        ptr ++;
    }
    if (newbodylen >= 128) {
        *ptr = (uint8_t)(newbodylen >> 8);
        ptr ++;
    }
    *ptr = (uint8_t)(newbodylen & 0xff);
    ptr ++;

    /* Now do the byteCounter */
    *ptr = 0x80;        /* field 0 */
    ptr++;
    *ptr = 0x08;        /* length is always 8 */
    ptr++;

    /* next four bytes are the unix timestamp when we first started */
    if (enc->encrypt_byte_startts == 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        /* this never changes so we can just store it pre-byteswapped */
        enc->encrypt_byte_startts = htonl(tv.tv_sec);
    }
    memcpy(ptr, &enc->encrypt_byte_startts, sizeof(uint32_t));

    ptr += sizeof(uint32_t);

    /* followed by the byte counter (in network byte order) */
    bytecounter = htonl(enc->encrypt_byte_counter);
    memcpy(ptr, &bytecounter, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* Of course, byte counter has to be incremented based on the size
     * of the "unencrypted" record, not the encrypted one...
     */
    bc_increase = calculate_pspdu_length(inplen + hdr_tplate->header_len);
    enc->encrypt_byte_counter += bc_increase;


    /* Put the body contents and any additional IP packet content into
     * the buffer to be encrypted
     */
    if (payloadbody != NULL) {
        memcpy(ptr, payloadbody, bodylen);
        /* "payload" is item 2 in a PS-PDU, but is item 1 in an encrypted
         * container :shrug:
         */
        *ptr = 0xA1;
        ptr += bodylen;
    }

    if (ipcontents != NULL) {
        memcpy(ptr, ipcontents, ipclen);
        ptr += ipclen;
    }

    /* If this is our first time through, we'll need an encryption context */
    if (enc->evp_ctx == NULL) {
        enc->evp_ctx = EVP_CIPHER_CTX_new();
        if (enc->evp_ctx == NULL) {
            logger(LOG_INFO, "OpenLI: unable to create EVP encryption context -- openssl error %s", ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }
    }

    /* Do the encryption */
    if (job->encryptmethod == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        if (encrypt_aes_192_cbc(enc->evp_ctx, buf, enclen, encrypted, enclen,
                job->seqno, job->encryptkey) < 0) {
            return -1;
        }
    } else {
        memcpy(encrypted, buf, enclen);
    }

    free(buf);

    /* Lookup the template for a message of this length and encryption method */
    tplate = lookup_encrypted_template(enc, enclen, job->encryptmethod,
            &is_new);

    /* If we need to create a template, then do so -- otherwise, update
     * the one that we already have.
     */
    if (is_new) {
        if (etsili_create_encrypted_template(enc->encoder, job->preencoded,
                job->encryptmethod, encrypted, enclen, tplate, job) < 0) {
            free(encrypted);
            return -1;
        }
    } else {
        if (etsili_update_encrypted_template(tplate, encrypted, enclen,
                job) < 0) {
            free(encrypted);
            return -1;
        }
    }

    /* We should now have a suitable header template and body template to
     * create a complete ETSI PSPDU record */
    if (create_etsi_encoded_result(res, hdr_tplate, tplate->start,
            tplate->totallen, NULL, 0, job) < 0) {
        free(encrypted);
        return -1;
    }

    free(encrypted);
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
