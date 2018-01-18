# Super primitive configure script

AC_INIT(openli, 0.0.1, salcock@waikato.ac.nz)

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR(src/collector.c)
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PREFIX_DEFAULT(/usr/local/)

AC_PROG_CC
AC_PROG_INSTALL

AC_PROG_LIBTOOL

EXTRA_LIBS=""

AC_CHECK_LIB([trace], [trace_pstart],,libtrace_found = 0)
AC_CHECK_LIB([wandder], [init_wandder_encoder],,libwandder_found = 0)
AC_CHECK_LIB([yaml], [yaml_document_get_node],,libyaml_found = 0)

AC_CONFIG_FILES([Makefile src/Makefile])

if test "$libtrace_found" = 0; then
        AC_MSG_ERROR(Required library libtrace not found; use LDFLAGS to specify library location)
fi

if test "$libwandder_found" = 0; then
        AC_MSG_ERROR(Required library libwandder not found; use LDFLAGS to specify library location)
fi

if test "$libyaml_found" = 0; then
        AC_MSG_ERROR(Required library libyaml not found; use LDFLAGS to specify library location)
fi


AC_SUBST([ADD_LIBS])
AC_SUBST([EXTRA_LIBS])
AC_SUBST([ADD_LDFLAGS])
AC_SUBST([ADD_INCLS])
AC_SUBST([LTLIBOBJS])

AC_OUTPUT

# Function for reporting whether an option was set or not
reportopt() {
        if test x"$2" = xtrue -o x"$2" = xyes; then
                AC_MSG_NOTICE([$1: Yes])
        else 
                AC_MSG_NOTICE([$1: No])
        fi
}

