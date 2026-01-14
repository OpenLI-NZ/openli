# Super primitive configure script

AC_INIT([openli],[1.1.17],[shane@alcock.co.nz])

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR(src/collector/collector.c)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PREFIX_DEFAULT(/usr/local/)

AC_PROG_CC
AC_PROG_INSTALL

LT_INIT

EXTRA_LIBS=""

AC_ARG_ENABLE([mediator], AS_HELP_STRING([--disable-mediator],
        [Disable building the OpenLI mediator]))
AC_ARG_ENABLE([provisioner], AS_HELP_STRING([--disable-provisioner],
        [Disable building the OpenLI provisioner]))
AC_ARG_ENABLE([collector], AS_HELP_STRING([--disable-collector],
        [Disable building the OpenLI collector]))

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
                [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir"])

PROVISIONER_LIBS=
COLLECTOR_LIBS=
MEDIATOR_LIBS=

PROVISIONER_CFLAGS=

AC_CHECK_LIB([trace], [trace_get_uri_format],,libtrace_found=0)
AC_CHECK_LIB([yaml], [yaml_document_get_node],,libyaml_found=0)
AC_CHECK_LIB([zmq], [zmq_poll],libzmq_found=1,libzmq_found=0)
AC_CHECK_LIB([m], [pow],,libm_found=0)
AC_CHECK_LIB([ssl], [SSL_library_init],libssl_found=1,)
AC_CHECK_LIB([ssl], [OPENSSL_init_ssl],libssl11_found=1,)
AC_CHECK_LIB([crypto], [ERR_load_crypto_strings],libcrypto_found=1,)
AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_new],libcrypto_found=1,)
AC_CHECK_LIB([rabbitmq], [amqp_new_connection],rabbit_found=1,rabbit_found=0)
AC_CHECK_LIB([Judy], [JudySLGet],,libjudy_found=0)
AC_CHECK_LIB([uuid], [uuid_parse],,libuuid_found=0)

if test "x$libzmq_found" = "x1"; then
        COLLECTOR_LIBS="$COLLECTOR_LIBS -lzmq"
        MEDIATOR_LIBS="$MEDIATOR_LIBS -lzmq"
fi

if test "x$libssl11_found" = "x1"; then
        AC_DEFINE(HAVE_LIBSSL_11, 1, [defined to 1 if the system is using libssl 1.1])
fi

AC_CHECK_HEADERS([uthash.h], [uthash_avail=yes; break;])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADER(amqp.h, amqp_h_found=1, amqp_h_found=0)
AC_CHECK_HEADER(rabbitmq-c/tcp_socket.h, [amqp_h_found=1; rabbitmq_include_subdir=1;])

AC_CONFIG_FILES([Makefile src/Makefile extlib/Makefile
                extlib/libpatricia/Makefile])



AS_IF([test "x$uthash_avail" != "xyes"],
        [AC_MSG_ERROR([Required header uthash.h not found; install uthash and try again])])

if test "x$enable_collector" != "xno"; then
        AC_CHECK_LIB([tcmalloc], [tc_version],,libtcmalloc_found=0)
        AC_CHECK_LIB([z], [inflateEnd],,libz_found=0)
        if test "$libz_found" = 0; then
                AC_MSG_ERROR(Required library libz not found; use LDFLAGS to specify library location)
        fi
        AC_CHECK_LIB([osipparser2], [osip_message_init],libosip2_found=1,libosip2_found=0)
        if test "$libosip2_found" = 0; then
                AC_MSG_ERROR(Required library libosipparser2 not found; use LDFLAGS to specify library location)
        fi
        AC_CHECK_LIB([b64], [base64_decode_block],libb64_found=1,libb64_found=0)
        if test "$libb64_found" = 0; then
                AC_MSG_ERROR(Required library libb64 not found; use LDFLAGS to specify library location)
        fi
        COLLECTOR_LIBS="$COLLECTOR_LIBS -losipparser2 -lb64 -lz"
fi

if test "x$enable_provisioner" != "xno" -o "x$enable_collector" != "xno"; then
        AC_CHECK_LIB([microhttpd], [MHD_destroy_post_processor],libmicrohttpd_found=1,libmicrohttpd_found=0)
        if test "$libmicrohttpd_found" = 0; then
                AC_MSG_ERROR(Required library libmicrohttpd not found; use LDFLAGS to specify library location)
        fi

        COLLECTOR_LIBS="$COLLECTOR_LIBS -lmicrohttpd"
        PROVISIONER_LIBS="$PROVISIONER_LIBS -lmicrohttpd"
fi

if test "x$enable_provisioner" != "xno"; then
        AC_CHECK_LIB([json-c], [json_tokener_new],libjsonc_found=1,libjsonc_found=0)

        if test "$libjsonc_found" = 0; then
                AC_MSG_ERROR(Required library libjson-c not found; use LDFLAGS to specify library location)
        fi

        PROVISIONER_LIBS="$PROVISIONER_LIBS -ljson-c"

        if test "x$libssl11_found" = "x1"; then
                AC_CHECK_LIB([sqlcipher], [sqlite3_key], sqlcipher_found=1, sqlcipher_found=0)

                if test "$sqlcipher_found" = 0; then
                        AC_MSG_ERROR(Required library libsqlcipher not found; use LDFLAGS to specify library location)
                fi

		AC_DEFINE(HAVE_SQLCIPHER, 1, [defined to 1 if SQLCipher is available])
                PROVISIONER_LIBS="$PROVISIONER_LIBS -lsqlcipher"
                PROVISIONER_CFLAGS="-DSQLITE_HAS_CODEC"
        fi
fi

if test "x$enable_collector" != "xno" -o "x$enable_mediator" != "xno"; then
        AC_CHECK_LIB([wandder], [wandder_timeval_to_generalizedts],libwandder_found=1,libwandder_found=0)

        if test "$libwandder_found" = 0; then
                AC_MSG_ERROR(Required library libwandder 2.0.16 or later not found; use LDFLAGS to specify library location)
        fi


        COLLECTOR_LIBS="$COLLECTOR_LIBS -lwandder"
        MEDIATOR_LIBS="$MEDIATOR_LIBS -lwandder"
fi

if test "$libtrace_found" = 0; then
        AC_MSG_ERROR(Required library libtrace >= 4.0.27 not found; use LDFLAGS to specify library location)
fi

if test "$libssl_found" != 1 -a "$libssl11_found" != 1; then
        AC_MSG_ERROR(Required library libssl not found; use LDFLAGS to specify library location)
else
        COLLECTOR_LIBS="$COLLECTOR_LIBS -lssl"
        MEDIATOR_LIBS="$MEDIATOR_LIBS -lssl"
        PROVISIONER_LIBS="$PROVISIONER_LIBS -lssl"
fi

if test "$libcrypto_found" != 1; then
        AC_MSG_ERROR(Required library libcrypto not found; use LDFLAGS to specify library location)
else
        COLLECTOR_LIBS="$COLLECTOR_LIBS -lcrypto"
        MEDIATOR_LIBS="$MEDIATOR_LIBS -lcrypto"
        PROVISIONER_LIBS="$PROVISIONER_LIBS -lcrypto"
fi

if test "$libjudy_found" = 0; then
        AC_MSG_ERROR(Required library libjudy not found; use LDFLAGS to specify library location)
fi

if test "$libuuid_found" = 0; then
        AC_MSG_ERROR(Required library libuuid not found; use LDFLAGS to specify library location)
fi

if test "$rabbit_found" != 1; then
    AC_MSG_ERROR(Required library librabbitmq not found; use LDFLAGS to specify library location)
else
        if test "$amqp_h_found" = 0; then
                AC_MSG_ERROR(Required headers for librabbitmq not found; use CFLAGS to specify header location)
        else
                COLLECTOR_LIBS="$COLLECTOR_LIBS -lrabbitmq"
                MEDIATOR_LIBS="$MEDIATOR_LIBS -lrabbitmq"
                PROVISIONER_LIBS="$PROVISIONER_LIBS -lrabbitmq"
        fi

        if test "$rabbitmq_include_subdir" = 1; then
            AC_DEFINE(RMQC_HEADER_SUBDIR, 1, [defined to 1 if rabbitmq-c headers are in the rabbitmq-c subdirectory])
        fi

fi

if test "$libyaml_found" = 0; then
        AC_MSG_ERROR(Required library libyaml not found; use LDFLAGS to specify library location)
fi

if test "$libzmq_found" = 0; then
        AC_MSG_ERROR(Required library libzmq not found; use LDFLAGS to specify library location)
fi


AM_CONDITIONAL([BUILD_MEDIATOR], [test "x$enable_mediator" != "xno"])
AM_CONDITIONAL([BUILD_PROVISIONER], [test "x$enable_provisioner" != "xno"])
AM_CONDITIONAL([BUILD_COLLECTOR], [test "x$enable_collector" != "xno"])

AC_SUBST([ADD_LIBS])
AC_SUBST([EXTRA_LIBS])
AC_SUBST([ADD_LDFLAGS])
AC_SUBST([ADD_INCLS])
AC_SUBST([LTLIBOBJS])
AC_SUBST([COLLECTOR_LIBS])
AC_SUBST([MEDIATOR_LIBS])
AC_SUBST([PROVISIONER_LIBS])
AC_SUBST([PROVISIONER_CFLAGS])

AC_OUTPUT

# Function for reporting whether an option was set or not
reportopt() {
        if test x"$2" = xtrue -o x"$2" = xyes; then
                AC_MSG_NOTICE([$1: Yes])
        else 
                AC_MSG_NOTICE([$1: No])
        fi
}

