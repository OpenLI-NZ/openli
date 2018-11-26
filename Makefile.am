SUBDIRS=extlib src
EXTRA_DIST=doc

AUTOMAKE_OPTIONS=foreign

dist_sysconf_DATA=doc/exampleconfigs/collector-example.yaml \
        doc/exampleconfigs/mediator-example.yaml \
        doc/exampleconfigs/provisioner-example.yaml

syslogdir=$(pkgdatadir)/rsyslog
dist_syslog_DATA=rsyslog/*
