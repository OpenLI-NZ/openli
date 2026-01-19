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

#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "configparser_common.h"

int config_check_onoff(char *value) {
    if (strcasecmp(value, "yes") == 0) {
        return 1;
    }

    if (strcasecmp(value, "on") == 0) {
        return 1;
    }

    if (strcasecmp(value, "true") == 0) {
        return 1;
    }

    if (strcasecmp(value, "enabled") == 0) {
        return 1;
    }

    if (strcasecmp(value, "no") == 0) {
        return 0;
    }

    if (strcasecmp(value, "off") == 0) {
        return 0;
    }

    if (strcasecmp(value, "false") == 0) {
        return 0;
    }

    if (strcasecmp(value, "disabled") == 0) {
        return 0;
    }

    return -1;
}

int config_parse_uuid(char *srcvalue, uuid_t dest) {
    if (uuid_parse(srcvalue, dest) < 0) {
        return -1;
    }
    return 0;
}

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define SALT_HEADER "Salted__"
#define SALT_SIZE 8

static int derive_iv_from_encrypt_key(const uint8_t *pass, int passlen,
        const uint8_t *salt, uint8_t *key, uint8_t *iv) {

    uint8_t tmp[AES_KEY_SIZE + AES_IV_SIZE];

    if (!PKCS5_PBKDF2_HMAC((char *)pass, passlen, salt, SALT_SIZE,
                AES_ENCRYPT_ITERATIONS, EVP_sha256(),
                AES_IV_SIZE + AES_KEY_SIZE, tmp)) {
        return -1;
    }

    memcpy(key, tmp, AES_KEY_SIZE);
    memcpy(iv, tmp + AES_KEY_SIZE, AES_IV_SIZE);

    return 0;

}

static int decrypt_aes(uint8_t *ciphertext, uint32_t cipherlen, uint8_t *key,
        uint8_t *iv, uint8_t *plain) {

    EVP_CIPHER_CTX *ctx;
    int len, plainlen;
    char msg[256];
    unsigned long errcode;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        logger(LOG_INFO, "OpenLI: EVP_CIPHER_CTX_new() failed");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        logger(LOG_INFO, "OpenLI: EVP_DecryptInit_ex() failed");
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plain, &len, ciphertext, cipherlen) != 1) {
        logger(LOG_INFO, "OpenLI: EVP_DecryptUpdate() failed");
        return -1;
    }
    plainlen = len;
    if (EVP_DecryptFinal_ex(ctx, plain + len, &len) != 1) {
        errcode = ERR_get_error();
        if (errcode) {
            ERR_error_string_n(errcode, msg, sizeof(msg));
        } else {
            snprintf(msg, 256, "No SSL error");
        }
        logger(LOG_INFO, "OpenLI: EVP_DecryptFinal_ex() failed: %s", msg);

        return -1;
    }
    plainlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return plainlen;

}

size_t read_encryption_password_file(const char *encpassfile, uint8_t *space) {
    FILE *passin;
    char *passptr, *passend;
    size_t readlen;

    passin = fopen(encpassfile, "r");
    if (!passin) {
        logger(LOG_INFO,
                "OpenLI: unable to open file containing the encryption key: %s",
                strerror(errno));
        return 0;
    }

    passptr = (char *)space;
    if (fgets(passptr, 1024, passin) == NULL) {
        logger(LOG_INFO, "OpenLI: unable to read from encryption key file: %s",
                strerror(errno));
        fclose(passin);
        return 0;
    }

    readlen = strlen(passptr);
    passend = passptr + readlen - 1;
    while (passend >= passptr && isspace((unsigned char)(*passend))) {
        (*passend) = '\0';
        passend --;
    }

    fclose(passin);
    return strlen(passptr);
}


/* ===== Helper functions for handling 0x-prefixed AES-192 hex keys =====
 * Public helpers so other modules (e.g., libwandder_etsili.c) can reuse.
 *
 * Returns 1 if key_str looks like "0x" or "0X" + exactly 48 hex digits, else 0.
 */
int openli_is_valid_aes192_hex_key(const char *key_str) {
    if (!key_str) return 0;
    if (!(key_str[0] == '0' && (key_str[1] == 'x' || key_str[1] == 'X')))
        return 0;
    const char *p = key_str + 2;
    size_t n = 0;
    while (*p) {
        unsigned char c = (unsigned char)*p++;
        if (!isxdigit(c)) return 0;
        n++;
    }
    return (n == 48) ? 1 : 0; /* 48 hex chars => 24 bytes */
}

/* Decodes "0x" + 48 hex digits into 24 bytes. Returns 0 on success, -1 on error. */
int openli_hex_to_bytes_24(const char *key_str, uint8_t out[24]) {
    if (!out || !openli_is_valid_aes192_hex_key(key_str)) return -1;
    const char *p = key_str + 2;
    for (size_t i = 0; i < 24; ++i) {
        int hi, lo;
        unsigned char c1 = (unsigned char)p[2*i];
        unsigned char c2 = (unsigned char)p[2*i + 1];
        if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') hi = 10 + (c1 - 'a');
        else if (c1 >= 'A' && c1 <= 'F') hi = 10 + (c1 - 'A');
        else return -1;
        if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') lo = 10 + (c2 - 'a');
        else if (c2 >= 'A' && c2 <= 'F') lo = 10 + (c2 - 'A');
        else return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}


static int load_encrypted_config_yaml(FILE *in, yaml_parser_t *parser,
        unsigned char *encheader, const char *encpassfile,
        unsigned char **decrypted) {

    uint8_t iv[AES_IV_SIZE];
    uint8_t salt[SALT_SIZE];
    uint8_t key[AES_KEY_SIZE];
    uint8_t pass[1024];
    uint32_t file_size;
    uint8_t *ciphered, *plain;
    int plainlen;
    size_t passlen;

    if (encpassfile == NULL) {
        logger(LOG_INFO, "OpenLI: missing the path to the file containing the encryption key!");
        return -1;
    }

    memcpy(salt, encheader + 8, SALT_SIZE);

    passlen = read_encryption_password_file(encpassfile, pass);
    if (passlen == 0) {
        return -1;
    }

    if (derive_iv_from_encrypt_key(pass, passlen, salt, key, iv) < 0) {
        logger(LOG_INFO, "OpenLI: unable to derive IV from password + salt");
        return -1;
    }

    /* figure out how much space we need to read the file into memory, then
     * reset the FILE * offset to point to the first byte after the header
     */
    fseek(in, 0, SEEK_END);
    file_size = ftell(in) - (SALT_SIZE + 8);
    rewind(in);
    fseek(in, SALT_SIZE + 8, SEEK_SET);

    ciphered = malloc(file_size);
    if (fread(ciphered, 1, file_size, in) == 0) {
        logger(LOG_INFO,
                "OpenLI: unable to read full encrypted config file content");
        free(ciphered);
        return -1;
    }

    plain = calloc(file_size + 1, sizeof(uint8_t));
    plainlen = decrypt_aes(ciphered, file_size, key, iv, plain);
    if (plainlen < 0) {
        free(plain);
        free(ciphered);
        return -1;
    }

    yaml_parser_initialize(parser);
    yaml_parser_set_input_string(parser, plain, plainlen);
    free(ciphered);
    *decrypted = plain;
    return 0;

}


int config_yaml_parser(char *configfile, void *arg,
        int (*parse_mapping)(void *, yaml_document_t *, yaml_node_t *,
                yaml_node_t *), int createifmissing, const char *encpassfile) {
    FILE *in = NULL;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    int ret = -1;
    uint8_t was_encrypted = 0;
    unsigned char encheader[SALT_SIZE + 8];
    unsigned char *decrypted = NULL;

    in = fopen(configfile, "rb");

    if (in == NULL && errno == ENOENT && createifmissing) {
        in = fopen(configfile, "w+");
    }

    if (in == NULL) {
        logger(LOG_INFO, "OpenLI: Failed to open config file: %s",
                strerror(errno));
        return -1;
    }

    if (fread(encheader, 1, SALT_SIZE + 8, in) == SALT_SIZE + 8) {
        if (memcmp(encheader, SALT_HEADER, 8) == 0) {
            if (load_encrypted_config_yaml(in, &parser, encheader,
                        encpassfile, &decrypted) < 0) {
                logger(LOG_INFO, "OpenLI: unable to decrypt config file %s",
                        configfile);
                goto yamlfail;
            }
            logger(LOG_DEBUG,
                    "OpenLI: reading encrypted configuration from %s",
                    configfile);
            was_encrypted = 1;
            goto startparsing;
        }
    }

    // file is not encrypted
    logger(LOG_DEBUG, "OpenLI: reading unencrypted configuration from %s",
            configfile);
    rewind(in);
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

startparsing:
    if (!yaml_parser_load(&parser, &document)) {
        logger(LOG_INFO, "OpenLI: Malformed config file");
        goto yamlfail;
    }

    root = yaml_document_get_root_node(&document);
    if (!root) {
        logger(LOG_INFO, "OpenLI: Config file '%s' is empty!", configfile);
        ret = -2;
        goto endconfig;
    }

    if (root->type != YAML_MAPPING_NODE) {
        logger(LOG_INFO, "OpenLI: Top level of config should be a map");
        goto endconfig;
    }
    for (pair = root->data.mapping.pairs.start;
            pair < root->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(&document, pair->key);
        value = yaml_document_get_node(&document, pair->value);

        if (parse_mapping(arg, &document, key, value) == -1) {
            ret = -1;
            break;
        }
        ret = 0;
    }
endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    if (decrypted) {
        free(decrypted);
    }
    fclose(in);
    if (ret < 0) {
        return ret;
    }
    return (int)was_encrypted;
}

int parse_core_server_list(coreserver_t **servlist, uint8_t cstype,
        yaml_document_t *doc, yaml_node_t *inputs) {

    yaml_node_item_t *item;

    for (item = inputs->data.sequence.items.start;
            item != inputs->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        coreserver_t *cs;

        cs = (coreserver_t *)calloc(1, sizeof(coreserver_t));

        cs->serverkey = NULL;
        cs->info = NULL;
        cs->ipstr = NULL;
        cs->portstr = NULL;
        cs->lower_portstr = NULL;
        cs->upper_portstr = NULL;
        cs->servertype = cstype;
        cs->awaitingconfirm = 1;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "ip") == 0) {
                SET_CONFIG_STRING_OPTION(cs->ipstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "port") == 0) {
                SET_CONFIG_STRING_OPTION(cs->portstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "port_lower") == 0) {
                SET_CONFIG_STRING_OPTION(cs->lower_portstr, value);
            }

            if (key->type == YAML_SCALAR_NODE &&
                    value->type == YAML_SCALAR_NODE &&
                    strcasecmp((char *)key->data.scalar.value, "port_upper") == 0) {
                SET_CONFIG_STRING_OPTION(cs->upper_portstr, value);
            }
        }

        if (construct_coreserver_key(cs) != NULL) {
            HASH_ADD_KEYPTR(hh, *servlist, cs->serverkey,
                    strlen(cs->serverkey), cs);
        } else {
            logger(LOG_INFO,
                    "OpenLI: %s server configuration was incomplete -- skipping.",
                    coreserver_type_to_string(cstype));
            free_single_coreserver(cs);
        }
    }
    return 0;
}

