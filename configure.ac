# Super primitive configure script

AC_INIT(openli, 1.0.0, salcock@waikato.ac.nz)

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR(src/collector/collector.c)
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PREFIX_DEFAULT(/usr/local/)

AC_PROG_CC
AC_PROG_INSTALL

AC_PROG_LIBTOOL

EXTRA_LIBS=""

AC_ARG_ENABLE([mediator], AS_HELP_STRING([--disable-mediator],
        [Disable building the OpenLI mediator]))
AC_ARG_ENABLE([provisioner], AS_HELP_STRING([--disable-provisioner],
        [Disable building the OpenLI provisioner]))
AC_ARG_ENABLE([collector], AS_HELP_STRING([--disable-collector],
        [Disable building the OpenLI collector]))

PROVISIONER_LIBS=
COLLECTOR_LIBS=
MEDIATOR_LIBS=

AC_CHECK_LIB([trace], [trace_increment_packet_refcount],,libtrace_found=0)
AC_CHECK_LIB([yaml], [yaml_document_get_node],,libyaml_found=0)
AC_CHECK_LIB([zmq], [zmq_poll],libzmq_found=1,libzmq_found=0)
AC_CHECK_LIB([m], [pow],,libm_found=0)

if test "x$libzmq_found" = "x1"; then
        COLLECTOR_LIBS="$COLLECTOR_LIBS -lzmq"
fi


AC_CHECK_HEADERS([uthash.h], [uthash_avail=yes; break;])
AC_CHECK_HEADERS([syslog.h])

AC_CONFIG_FILES([Makefile src/Makefile extlib/Makefile
                extlib/libpatricia/Makefile])



AS_IF([test "x$uthash_avail" != "xyes"],
        [AC_MSG_ERROR([Required header uthash.h not found; install uthash and try again])])

if test "x$enable_collector" != "xno"; then
        AC_CHECK_LIB([tcmalloc], [tc_version],,libtcmalloc_found=0)
        AC_CHECK_LIB([osipparser2], [osip_message_init],libosip2_found=1,libosip2_found=0)
        if test "$libosip2_found" = 0; then
                AC_MSG_ERROR(Required library libosipparser2 not found; use LDFLAGS to specify library location)
        fi
        COLLECTOR_LIBS="$COLLECTOR_LIBS -losipparser2"
fi


if test "x$enable_collector" != "xno" -o "x$enable_mediator" != "xno"; then
        AC_CHECK_LIB([wandder], [init_wandder_encoder],libwandder_found=1,libwandder_found=0)
        if test "$libwandder_found" = 0; then
                AC_MSG_ERROR(Required library libwandder not found; use LDFLAGS to specify library location)
        fi

        AC_CHECK_LIB([Judy], [JudySLGet],libjudy_found=1,libjudy_found=0)
        if test "$libjudy_found" = 0; then
                AC_MSG_ERROR(Required library libjudy not found; use LDFLAGS to specify library location)
        fi

        COLLECTOR_LIBS="$COLLECTOR_LIBS -lJudy -lwandder"
        MEDIATOR_LIBS="$MEDIATOR_LIBS -lJudy -lwandder"
fi

if test "$libtrace_found" = 0; then
        AC_MSG_ERROR(Required library libtrace 4.0.4 not found; use LDFLAGS to specify library location)
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

AC_OUTPUT

# Function for reporting whether an option was set or not
reportopt() {
        if test x"$2" = xtrue -o x"$2" = xyes; then
                AC_MSG_NOTICE([$1: Yes])
        else 
                AC_MSG_NOTICE([$1: No])
        fi
}

