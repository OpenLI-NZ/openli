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

#include <string.h>
#include <openssl/ssl.h>
#include "logger.h"
#include "openli_tls.h"

void dump_cert_info(SSL *ssl) {
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


//takes in 3 filenames for the CA, own cert and private key
//if all 3 files names are null, returns null as successfully doing nothing
//returns -1 if an error happened
//otherwise returns a new SSL_CTX with the provided certificates using TLSv1_2
//and enforces identity checking at handshake
SSL_CTX * ssl_init(const char *cacertfile, const char *certfile, const char *keyfile) {

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

    /* Enforce use of TLSv1_2 */
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    if (SSL_CTX_load_verify_locations(ctx, cacertfile, "./") != 1){ //TODO this might want to be changed
        logger(LOG_INFO, "OpenLI: SSL CA cert loading {%s} failed", cacertfile);
        SSL_CTX_free(ctx);
        return NULL;
    }

    //enforce cheking of client/server 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1){
        logger(LOG_INFO, "OpenLI: SSL cert loading {%s} failed", certfile);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1){
        logger(LOG_INFO, "OpenLI: SSL Key loading {%s} failed", keyfile);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Make sure the key and certificate file match. */
    if (SSL_CTX_check_private_key(ctx) != 1){
        logger(LOG_INFO, "OpenLI: SSL CTX private key failed, %s and %s do not match", keyfile, certfile);
        SSL_CTX_free(ctx);
        return NULL;
    }

    logger(LOG_DEBUG, "OpenLI: OpenSSL CTX initialised, TLS encryption enabled.");
    logger(LOG_DEBUG, "OpenLI: Using %s, %s and %s.", certfile, keyfile, cacertfile);

    return ctx;
}

int create_ssl_context(openli_ssl_config_t *sslconf) {

    if (sslconf->certfile && sslconf->keyfile && sslconf->cacertfile) {
        sslconf->ctx = ssl_init(sslconf->cacertfile, sslconf->certfile,
                sslconf->keyfile);
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

#define PEM_READ_SIZE 1024

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
