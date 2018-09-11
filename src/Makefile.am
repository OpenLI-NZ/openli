bin_PROGRAMS=

if BUILD_PROVISIONER
bin_PROGRAMS += openliprovisioner
openliprovisioner_SOURCES=provisioner/provisioner.c provisioner/provisioner.h \
		byteswap.c byteswap.h intercept.h intercept.c configparser.c \
                configparser.h util.c util.h agency.h logger.c logger.h \
		netcomms.h netcomms.c coreserver.h coreserver.c

openliprovisioner_LDADD = @ADD_LIBS@
openliprovisioner_LDFLAGS=-lpthread
openliprovisioner_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/
endif

if BUILD_COLLECTOR
MOSTLYCLEANFILES = internal.pb-c.c internal.pb-c.h
BUILT_SOURCES = internal.pb-c.h internal.pb-c.c

internal.pb-c.c internal.pb-c.h : Makefile
	$(PROTOC) --c_out=. collector/internal.proto

dist_noinst_DATA = collector/internal.proto
PLUGIN_SRCS=collector/accessplugins/radius.c
bin_PROGRAMS +=openlicollector
openlicollector_SOURCES=collector/collector.c configparser.c configparser.h \
                collector/collector.h logger.c logger.h \
		collector/collector_sync.c collector/collector_sync.h \
		etsili_core.h collector/collector_export.c \
                collector/collector_export.h export_buffer.h export_buffer.c \
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
		collector/collector_sync_voip.h \
                collector/reassembler.h collector/reassembler.c \
                collector/collector_publish.c collector/collector_publish.h \
                collector/internal.pb-c.c collector/internal.pb-c.h \
                $(PLUGIN_SRCS)

openlicollector_LDADD = @ADD_LIBS@ -L$(abs_top_srcdir)/extlib/libpatricia/.libs 
openlicollector_LDFLAGS=-lpthread -lpatricia @PROTOBUF_C_LIBS@
openlicollector_CFLAGS=@PROTOBUF_C_CFLAGS@ -I$(abs_top_srcdir)/extlib/libpatricia/ -Icollector/ -I$(builddir)

endif

if BUILD_MEDIATOR
bin_PROGRAMS += openlimediator
openlimediator_SOURCES=mediator/mediator.c mediator/mediator.h \
		byteswap.c byteswap.h \
                configparser.c configparser.h util.c util.h \
                agency.h logger.c logger.h netcomms.c \
                netcomms.h export_buffer.c \
                export_buffer.h etsili_core.h etsili_core.c \
                coreserver.c coreserver.h
openlimediator_LDADD = @ADD_LIBS@
openlimediator_LDFLAGS=-lpthread
openlimediator_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/
endif

bin_PROGRAMS += standaloneexporter
standaloneexporter_SOURCES=standaloneexporter.c etsili_core.h \
                collector/collector_export.c collector/collector_export.h \
                export_buffer.h export_buffer.c logger.c logger.h \
                util.c util.h intercept.c intercept.h \
                netcomms.c netcomms.h byteswap.c byteswap.h etsili_core.c \
                collector/jenkinshash.c collector/ipmmcc.c collector/ipmmcc.h \
                collector/ipmmiri.c collector/ipmmiri.h \
                collector/ipcc.c collector/ipcc.h \
                collector/ipiri.c collector/ipiri.h \
                collector/collector_publish.c collector/collector_publish.h \
                collector/internal.pb-c.c collector/internal.pb-c.h \
                coreserver.c coreserver.h 
standaloneexporter_LDADD = @ADD_LIBS@ -L$(abs_top_srcdir)/extlib/libpatricia/.libs
standaloneexporter_LDFLAGS=-lpthread -lpatricia @PROTOBUF_C_LIBS@
standaloneexporter_CFLAGS=-Icollector/ -I$(abs_top_srcdir)/extlib/libpatricia/  @PROTOBUF_C_CFLAGS@ -I$(builddir)

