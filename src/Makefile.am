bin_PROGRAMS=

if BUILD_PROVISIONER
bin_PROGRAMS += openliprovisioner
openliprovisioner_SOURCES=provisioner/provisioner.c provisioner/provisioner.h \
		byteswap.c byteswap.h intercept.h intercept.c configparser.c \
                configparser.h util.c util.h agency.h logger.c logger.h \
		netcomms.h netcomms.c coreserver.h coreserver.c \
                collector/jenkinshash.c provisioner/updateserver.c \
                openli_tls.c openli_tls.h agency.c agency.h \
                provisioner/provisioner_client.c \
                provisioner/provisioner_client.h \
                provisioner/configwriter.c provisioner/clientupdates.c \
                provisioner/updateserver.h \
                provisioner/updateserver_jsonparsing.c \
                provisioner/updateserver_jsoncreation.c \
                provisioner/hup_reload.c

openliprovisioner_LDFLAGS = -lpthread @PROVISIONER_LIBS@
openliprovisioner_LDADD = @ADD_LIBS@
openliprovisioner_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/
endif

if BUILD_COLLECTOR
PLUGIN_SRCS=collector/accessplugins/radius.c \
                collector/accessplugins/gtp.c

bin_PROGRAMS +=openlicollector
openlicollector_SOURCES=collector/collector.c configparser.c configparser.h \
                collector/collector.h logger.c logger.h \
                collector/collector_base.h \
		collector/collector_sync.c collector/collector_sync.h \
		etsili_core.h export_buffer.h export_buffer.c \
                util.c util.h intercept.c intercept.h \
                netcomms.c netcomms.h byteswap.c byteswap.h etsili_core.c \
                collector/sipparsing.c collector/sipparsing.h \
                collector/jenkinshash.c collector/ipmmcc.c collector/ipmmcc.h \
		collector/ipmmiri.c collector/ipmmiri.h \
                collector/internetaccess.c collector/internetaccess.h \
		collector/ipcc.c collector/ipcc.h \
                coreserver.h coreserver.c collector/collector_push_messaging.c \
                collector/collector_push_messaging.h \
		collector/alushim_parser.c collector/alushim_parser.h \
                collector/ipiri.c collector/ipiri.h \
		collector/collector_sync_voip.c \
		collector/collector_sync_voip.h collector/export_shared.h \
                collector/reassembler.h collector/reassembler.c \
                collector/collector_publish.c collector/collector_publish.h \
                collector/encoder_worker.c collector/encoder_worker.h \
                collector/collector_seqtracker.c \
                collector/collector_forwarder.c collector/jmirror_parser.c \
                collector/jmirror_parser.h openli_tls.c openli_tls.h \
                collector/umtscc.h collector/umtscc.c \
                collector/umtsiri.h collector/umtsiri.c \
                $(PLUGIN_SRCS)

openlicollector_LDADD = @ADD_LIBS@ -L$(abs_top_srcdir)/extlib/libpatricia/.libs 
openlicollector_LDFLAGS=-lpthread -lpatricia @COLLECTOR_LIBS@
openlicollector_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/ -Icollector/ -I$(builddir)

endif

if BUILD_MEDIATOR
bin_PROGRAMS += openlimediator
openlimediator_SOURCES=mediator/mediator.c mediator/mediator.h \
		mediator/pcapthread.c \
                byteswap.c byteswap.h \
                configparser.c configparser.h util.c util.h \
                agency.h logger.c logger.h netcomms.c \
                netcomms.h export_buffer.c intercept.c \
                export_buffer.h etsili_core.h etsili_core.c \
                collector/jenkinshash.c openli_tls.c openli_tls.h \
                coreserver.c coreserver.h
openlimediator_LDADD = @ADD_LIBS@
openlimediator_LDFLAGS=-lpthread @MEDIATOR_LIBS@
openlimediator_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/
endif

