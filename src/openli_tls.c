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
 * (C) 2025 Telefónica Innovación Digital (laura.dominguez.cespedes@telefonica.com)
 * (C) 2019 by Original Author(shane@alcock.co.nz)


 */

#include <string.h>
#include <openssl/ssl.h>
#include "logger.h"
#include "openli_tls.h"

/* global variable?? */
FILE *openli_ssl_keylog_hdl = NULL;

#if 0
static void dump_cert_info(SSL *ssl) {
    logger(LOG_DEBUG,
        "SSL connection version: %s", 
        SSL_get_version(ssl)); //should ALWAYS be TLSv1_2

    logger(LOG_DEBUG,
        "Using cipher %s", 
        SSL_get_cipher(ssl)); //should ALWAYS be AES256-GCM-SHA384

    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {

        char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        logger(LOG_DEBUG,"Connection certificate: Subject: %s", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        logger(LOG_DEBUG,"Connection certificate: Issuer: %s\n", str);
        OPENSSL_free(str);

        X509_free(client_cert);
    }
}
#endif

static void sslkeylog_cb(const SSL *ssl, const char *line) {

    (void)ssl;
    if (openli_ssl_keylog_hdl) {
        fprintf(openli_ssl_keylog_hdl, "%s\n", line);
    }
}

#ifdef ENABLE_OQS
    #include <oqs/oqs.h>
    #include <openssl/provider.h>
    #include <openssl/decoder.h>
    #include <oqs/oqs.h>

    static SSL_CTX * ssl_init(openli_ssl_config_t *sslconf) {

        /* SSL library initialisation */
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_crypto_strings();
    
        /* create the library context */
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
            logger(0, "OpenLI: Failed to create OSSL_LIB_CTX.");
            return NULL;
        }
        OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(libctx, "default");
        if (default_provider == NULL) {
            logger(LOG_INFO, "Error loading the default provider\n");
            OSSL_LIB_CTX_free(libctx);
            return NULL;
        }
        OSSL_PROVIDER *oqs_provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
        if (oqs_provider == NULL) {
            logger(LOG_INFO, "Error loading the oqsprovider provider\n");
            return NULL;
        } else {
            logger(LOG_INFO, "Oqsprovider loaded correctly\n");
        }
        if (!OSSL_PROVIDER_available(libctx, "oqsprovider")) {
            fprintf(stderr, "OQS provider not available.\n");
            OSSL_LIB_CTX_free(libctx);
            return NULL;
        }
        /* create the SSL context mandatory TLS 1.3*/
        const char *tls_version;
    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method());
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        tls_version = "1.3";
    #elif OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, TLSv1_2_method());
        tls_version = "1.2";
    #else
        SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, TLSv1_1_method());
        tls_version = "1.1";
    #endif
        logger(LOG_INFO, "OpenLI: Using TLS Version %s.", tls_version);

        /* Assign Quantum-Safe ciphers (AES256)*/
        if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            OSSL_LIB_CTX_free(libctx);
            return NULL;
        }
        if (!ctx){ //check not NULL
            logger(LOG_INFO, "OpenLI: SSL_CTX creation failed");
            return NULL;
        }

        if (SSL_CTX_load_verify_locations(ctx, sslconf->cacertfile,
                    "./") != 1){ //TODO this might want to be changed
            logger(LOG_INFO, "OpenLI: SSL CA cert loading {%s} failed",
                    sslconf->cacertfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        //enforce cheking of client/server 
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        if (SSL_CTX_use_certificate_file(ctx, sslconf->certfile,
                    SSL_FILETYPE_PEM) != 1){
            logger(LOG_INFO, "OpenLI: SSL cert loading {%s} failed",
                    sslconf->certfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, sslconf->keyfile,
                    SSL_FILETYPE_PEM) != 1){
            logger(LOG_INFO, "OpenLI: SSL Key loading {%s} failed",
                    sslconf->keyfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        /* Make sure the key and certificate file match. */
        if (SSL_CTX_check_private_key(ctx) != 1){
            logger(LOG_INFO, "OpenLI: SSL CTX private key failed, %s and %s do not match", sslconf->keyfile, sslconf->certfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        logger(LOG_DEBUG, "OpenLI: OpenSSL CTX initialised, TLS encryption enabled.");
        logger(LOG_DEBUG, "OpenLI: Using %s, %s and %s.", sslconf->certfile,
                sslconf->keyfile, sslconf->cacertfile);

        if (sslconf->logkeyfile) {
            if (openli_ssl_keylog_hdl) {
                fclose(openli_ssl_keylog_hdl);
            }
            openli_ssl_keylog_hdl = fopen(sslconf->logkeyfile, "w");
            if (openli_ssl_keylog_hdl == NULL) {
                logger(LOG_INFO,
                        "OpenLI: unable to open file for logging TLS keys (%s): %s",
                        sslconf->logkeyfile, strerror(errno));
            } else {
                logger(LOG_DEBUG, "OpenLI: logging TLS keys to %s",
                        sslconf->logkeyfile);
            }
            SSL_CTX_set_keylog_callback(ctx, sslkeylog_cb);
        } else {
            if (openli_ssl_keylog_hdl) {
                fclose(openli_ssl_keylog_hdl);
            }
            openli_ssl_keylog_hdl = NULL;
        }

        return ctx;
    }
#else
    //takes in struct containing the CA, own cert and private key
    //if all 3 files names are null, returns null as successfully doing nothing
    //returns -1 if an error happened
    //otherwise returns a new SSL_CTX with the provided certificates using TLSv1_2
    //and enforces identity checking at handshake
    static SSL_CTX * ssl_init(openli_ssl_config_t *sslconf) {

        /* SSL library initialisation */
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_crypto_strings();
        
        /* create the SSL context */

    #if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_method());
    #else
        SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    #endif

        if (!ctx){ //check not NULL
            logger(LOG_INFO, "OpenLI: SSL_CTX creation failed");
            return NULL;
        }

        /* Enforce use of TLSv1_3 */
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

        if (SSL_CTX_load_verify_locations(ctx, sslconf->cacertfile,
                    "./") != 1){ //TODO this might want to be changed
            logger(LOG_INFO, "OpenLI: SSL CA cert loading {%s} failed",
                    sslconf->cacertfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        //enforce cheking of client/server 
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        if (SSL_CTX_use_certificate_file(ctx, sslconf->certfile,
                    SSL_FILETYPE_PEM) != 1){
            logger(LOG_INFO, "OpenLI: SSL cert loading {%s} failed",
                    sslconf->certfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, sslconf->keyfile,
                    SSL_FILETYPE_PEM) != 1){
            logger(LOG_INFO, "OpenLI: SSL Key loading {%s} failed",
                    sslconf->keyfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        /* Make sure the key and certificate file match. */
        if (SSL_CTX_check_private_key(ctx) != 1){
            logger(LOG_INFO, "OpenLI: SSL CTX private key failed, %s and %s do not match", sslconf->keyfile, sslconf->certfile);
            SSL_CTX_free(ctx);
            return NULL;
        }

        logger(LOG_DEBUG, "OpenLI: OpenSSL CTX initialised, TLS encryption enabled.");
        logger(LOG_DEBUG, "OpenLI: Using %s, %s and %s.", sslconf->certfile,
                sslconf->keyfile, sslconf->cacertfile);

        if (sslconf->logkeyfile) {
            if (openli_ssl_keylog_hdl) {
                fclose(openli_ssl_keylog_hdl);
            }
            openli_ssl_keylog_hdl = fopen(sslconf->logkeyfile, "w");
            if (openli_ssl_keylog_hdl == NULL) {
                logger(LOG_INFO,
                        "OpenLI: unable to open file for logging TLS keys (%s): %s",
                        sslconf->logkeyfile, strerror(errno));
            } else {
                logger(LOG_DEBUG, "OpenLI: logging TLS keys to %s",
                        sslconf->logkeyfile);
            }
            SSL_CTX_set_keylog_callback(ctx, sslkeylog_cb);
        } else {
            if (openli_ssl_keylog_hdl) {
                fclose(openli_ssl_keylog_hdl);
            }
            openli_ssl_keylog_hdl = NULL;
        }

        return ctx;
    }
#endif

int create_ssl_context(openli_ssl_config_t *sslconf) {

    if (sslconf->certfile && sslconf->keyfile && sslconf->cacertfile) {
        sslconf->ctx = ssl_init(sslconf);
        logger(LOG_INFO, "OpenLI: creating new SSL context for TLS sessions");
        return 0;
    }

    if (sslconf->certfile || sslconf->cacertfile || sslconf->keyfile) {
        logger(LOG_INFO, "OpenLI: incomplete TLS configuration, missing keyfile or certfile names.");
        return -1;
    }

    logger(LOG_INFO, "OpenLI: not using OpenSSL TLS for internal communications");
    return 0;
}

void free_ssl_config(openli_ssl_config_t *sslconf) {
    if (sslconf->logkeyfile) {
        free(sslconf->logkeyfile);
        sslconf->logkeyfile = NULL;
    }

    if (sslconf->certfile) {
        free(sslconf->certfile);
        sslconf->certfile = NULL;
    }

    if (sslconf->keyfile) {
        free(sslconf->keyfile);
        sslconf->keyfile = NULL;
    }

    if (sslconf->cacertfile) {
        free(sslconf->cacertfile);
        sslconf->cacertfile = NULL;
    }

    if (sslconf->ctx) {
        SSL_CTX_free(sslconf->ctx);
        sslconf->ctx = NULL;
    }

    if (openli_ssl_keylog_hdl) {
        fclose(openli_ssl_keylog_hdl);
        openli_ssl_keylog_hdl = NULL;
    }
}

int listen_ssl_socket(openli_ssl_config_t *sslconf, SSL **ssl, int newfd) {

    int err;

    if (sslconf->ctx == NULL) {
        *ssl = NULL;
        return OPENLI_SSL_CONNECT_NOSSL;
    }

    *ssl = SSL_new(sslconf->ctx);
    SSL_set_fd(*ssl, newfd);

    err = SSL_accept(*ssl);
    if (err > 0) {
        return OPENLI_SSL_CONNECT_SUCCESS;
    }

    err = SSL_get_error(*ssl, err);

    switch (err) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_CONNECT:
            return OPENLI_SSL_CONNECT_WAITING;
    }

    return OPENLI_SSL_CONNECT_FAILED;
}
int reload_ssl_config(openli_ssl_config_t *current,
        openli_ssl_config_t *newconf) {

    int changestate = 0;

    if (current->certfile == NULL && newconf->certfile != NULL) {
        current->certfile = newconf->certfile;
        newconf->certfile = NULL;
        changestate = 1;
    } else if (current->certfile != NULL && newconf->certfile == NULL) {
        free(current->certfile);
        current->certfile = NULL;
        changestate = 1;
    } else if (current->certfile && newconf->certfile) {
        if (strcmp(current->certfile, newconf->certfile) != 0) {
            free(current->certfile);
            current->certfile = newconf->certfile;
            newconf->certfile = NULL;
            changestate = 1;
        }
    }

    if (current->cacertfile == NULL && newconf->cacertfile != NULL) {
        current->cacertfile = newconf->cacertfile;
        newconf->cacertfile = NULL;
        changestate = 1;
    } else if (current->cacertfile != NULL && newconf->cacertfile == NULL) {
        free(current->cacertfile);
        current->cacertfile = NULL;
        changestate = 1;
    } else if (current->cacertfile && newconf->cacertfile) {
        if (strcmp(current->cacertfile, newconf->cacertfile) != 0) {
            free(current->cacertfile);
            current->cacertfile = newconf->cacertfile;
            newconf->cacertfile = NULL;
            changestate = 1;
        }
    }

    if (current->keyfile == NULL && newconf->keyfile != NULL) {
        current->keyfile = newconf->keyfile;
        newconf->keyfile = NULL;
        changestate = 1;
    } else if (current->keyfile != NULL && newconf->keyfile == NULL) {
        free(current->keyfile);
        current->keyfile = NULL;
        changestate = 1;
    } else if (current->keyfile && newconf->keyfile) {
        if (strcmp(current->keyfile, newconf->keyfile) != 0) {
            free(current->keyfile);
            current->keyfile = newconf->keyfile;
            newconf->keyfile = NULL;
            changestate = 1;
        }
    }

    if (current->logkeyfile == NULL && newconf->logkeyfile != NULL) {
        current->logkeyfile = newconf->logkeyfile;
        newconf->logkeyfile = NULL;
        changestate = 1;
    } else if (current->logkeyfile != NULL && newconf->logkeyfile == NULL) {
        free(current->logkeyfile);
        current->logkeyfile = NULL;
        changestate = 1;
    } else if (current->logkeyfile && newconf->logkeyfile) {
        if (strcmp(current->logkeyfile, newconf->logkeyfile) != 0) {
            free(current->logkeyfile);
            current->logkeyfile = newconf->logkeyfile;
            newconf->logkeyfile = NULL;
            changestate = 1;
        }
    }

    if (!changestate) {
        logger(LOG_INFO, "OpenLI: TLS configuration is unchanged.");
        return 0;
    }

    logger(LOG_INFO, "OpenLI: TLS configuration has changed.");

    if (current->ctx) {
        SSL_CTX_free(current->ctx);
    }
    current->ctx = newconf->ctx;
    newconf->ctx = NULL;
    return 1;
}

#define PEM_READ_SIZE 16384

int load_pem_into_memory(char *pemfile, char **memspace) {

    FILE *f = NULL;
    char *ptr;
    int result = 0;
    int totalread = 0;
    size_t totalsize = PEM_READ_SIZE;

    if (*memspace) {
        free(*memspace);
    }

    *memspace = calloc(totalsize, sizeof(char));
    ptr = *memspace;

    f = fopen(pemfile, "r");
    if (!f) {
        logger(LOG_INFO, "OpenLI: unable to open TLS .pem file %s: %s",
                pemfile, strerror(errno));
        return -1;
    }

    do {
        size_t ret;

        ret = fread(ptr, 1, PEM_READ_SIZE, f);
        if (ferror(f)) {
            logger(LOG_INFO, "OpenLI: error while reading TLS .pem file %s: %s",
                    pemfile, strerror(errno));
            result = -1;
            break;
        }

        if (ret == PEM_READ_SIZE) {
            *memspace = realloc(*memspace, totalsize + PEM_READ_SIZE);
            ptr = (*memspace) + totalsize;
            totalsize += PEM_READ_SIZE;
        }
        totalread += ret;

    } while (!feof(f));


    if (result != -1) {
        (*memspace)[totalread] = '\0';
    }

    fclose(f);
    return result;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
