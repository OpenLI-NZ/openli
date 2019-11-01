DISTCHECK_CONFIGURE_FLAGS = \
        --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

SUBDIRS=extlib src
EXTRA_DIST=doc README.md systemd/*.service

AUTOMAKE_OPTIONS=foreign

openliconfdir=$(sysconfdir)/openli
dist_openliconf_DATA=doc/exampleconfigs/collector-example.yaml \
        doc/exampleconfigs/mediator-example.yaml \
        doc/exampleconfigs/running-intercept-example.yaml \
        doc/exampleconfigs/provisioner-example.yaml

syslogdir=$(sysconfdir)/rsyslog.d/
dist_syslog_DATA=rsyslog/*

dist_doc_DATA=doc/CollectorDoc.md doc/MediatorDoc.md doc/ProvisionerDoc.md \
        doc/TLSDoc.md

mandir=$(pkgdatadir)/doc/man

if HAVE_SYSTEMD
systemdsystemunit_DATA =

if BUILD_COLLECTOR
systemdsystemunit_DATA += systemd/openli-collector.service
endif

if BUILD_PROVISIONER
systemdsystemunit_DATA += systemd/openli-provisioner.service
endif

if BUILD_MEDIATOR
systemdsystemunit_DATA += systemd/openli-mediator.service
endif

endif
