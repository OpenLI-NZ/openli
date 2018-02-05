bin_PROGRAMS=openlicollector openliprovisioner

openlicollector_SOURCES=collector.c configparser.c configparser.h collector.h \
                logger.c logger.h collector_sync.c collector_sync.h \
                etsili_const.h ipcc.h ipcc.c collector_export.c \
                collector_export.h collector_buffer.h collector_buffer.c \
                util.c util.h intercept.c intercept.h

openlicollector_LDADD = @ADD_LIBS@
openlicollector_LDFLAGS=-lpthread
openlicollector_CFLAGS=

openliprovisioner_SOURCES=provisioner.c provisioner.h byteswap.c \
                byteswap.h intercept.h intercept.c configparser.c \
                configparser.h util.c util.h agency.h  logger.c \
                logger.h

openliprovisioner_LDADD = @ADD_LIBS@
openliprovisioner_LDFLAGS=
openliprovisioner_CFLAGS=



