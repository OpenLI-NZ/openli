SUBDIRS=extlib src
EXTRA_DIST=doc README.md

AUTOMAKE_OPTIONS=foreign

dist_sysconf_DATA=doc/exampleconfigs/collector-example.yaml \
        doc/exampleconfigs/mediator-example.yaml \
        doc/exampleconfigs/provisioner-example.yaml

syslogdir=$(pkgdatadir)/rsyslog
dist_syslog_DATA=rsyslog/*

dist_doc_DATA=doc/CollectorDoc.md doc/MediatorDoc.md doc/ProvisionerDoc.md

mandir=$(pkgdatadir)/doc/man

