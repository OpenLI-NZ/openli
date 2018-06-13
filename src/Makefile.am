bin_PROGRAMS=

PLUGIN_SRCS=accessplugins/radius.c

if BUILD_COLLECTOR
bin_PROGRAMS +=openlicollector
openlicollector_SOURCES=collector.c configparser.c configparser.h collector.h \
                logger.c logger.h collector_sync.c collector_sync.h \
                etsili_core.h collector_export.c \
                collector_export.h export_buffer.h export_buffer.c \
                util.c util.h intercept.c intercept.h netcomms.c netcomms.h \
                byteswap.c byteswap.h etsili_core.c sipparsing.c sipparsing.h \
                jenkinshash.c ipmmcc.c ipmmcc.h ipmmiri.c ipmmiri.h \
                internetaccess.c internetaccess.h ipcc.c ipcc.h coreserver.h \
                coreserver.c collector_push_messaging.c \
                collector_push_messaging.h alushim_parser.c alushim_parser.h \
                ipiri.c ipiri.h collector_sync_voip.c collector_sync_voip.h \
                $(PLUGIN_SRCS)

openlicollector_LDADD = @ADD_LIBS@
openlicollector_LDFLAGS=-lpthread
openlicollector_CFLAGS=
endif

if BUILD_PROVISIONER
bin_PROGRAMS += openliprovisioner
openliprovisioner_SOURCES=provisioner.c provisioner.h byteswap.c \
                byteswap.h intercept.h intercept.c configparser.c \
                configparser.h util.c util.h agency.h  logger.c \
                logger.h mediator.h netcomms.h netcomms.c coreserver.h \
                coreserver.c

openliprovisioner_LDADD = @ADD_LIBS@
openliprovisioner_LDFLAGS=-lpthread
openliprovisioner_CFLAGS=
endif

if BUILD_MEDIATOR
bin_PROGRAMS += openlimediator
openlimediator_SOURCES=mediator.c mediator.h byteswap.c byteswap.h \
                configparser.c configparser.h util.c util.h agency.h \
                logger.c logger.h netcomms.c netcomms.h export_buffer.c \
                export_buffer.h etsili_core.h etsili_core.c coreserver.c \
                coreserver.h
openlimediator_LDADD = @ADD_LIBS@
openlimediator_LDFLAGS=-lpthread
openlimediator_CFLAGS=
endif

