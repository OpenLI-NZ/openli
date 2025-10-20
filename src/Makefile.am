bin_PROGRAMS=
dist_sbin_SCRIPTS=

if BUILD_PROVISIONER
bin_PROGRAMS += openliprovisioner
openliprovisioner_SOURCES=provisioner/provisioner.c provisioner/provisioner.h \
		byteswap.c byteswap.h intercept.h intercept.c \
        util.c util.h agency.h logger.c logger.h \
		provisioner/configparser_provisioner.h \
		provisioner/configparser_provisioner.c \
		netcomms.h netcomms.c coreserver.h coreserver.c \
		configparser_common.c configparser_common.h \
                collector/jenkinshash.c provisioner/updateserver.c \
                openli_tls.c openli_tls.h agency.c agency.h \
                provisioner/provisioner_client.c \
                provisioner/provisioner_client.h \
                provisioner/configwriter.c provisioner/clientupdates.c \
                provisioner/updateserver.h \
                provisioner/updateserver_jsonparsing.c \
                provisioner/updateserver_jsoncreation.c \
                provisioner/hup_reload.c \
				provisioner/clientdb.c provisioner/integrity_sign.c \
                provisioner/intercept_timers.c provisioner/intercept_timers.h

openliprovisioner_LDFLAGS = -lpthread @PROVISIONER_LIBS@
openliprovisioner_LDADD = @ADD_LIBS@
openliprovisioner_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/ @PROVISIONER_CFLAGS@ -Werror -Wall -Wextra

dist_sbin_SCRIPTS += provisioner/authsetup/openli-prov-authsetup.sh \
                provisioner/authsetup/openli-prov-adduser.sh

endif

if BUILD_COLLECTOR
PLUGIN_SRCS=collector/accessplugins/radius.c \
                collector/accessplugins/gtp.c

bin_PROGRAMS +=openlicollector
openlicollector_SOURCES=collector/collector.c \
				collector/configparser_collector.c \
				collector/configparser_collector.h \
                collector/collector.h logger.c logger.h \
                collector/collector_base.h \
		configparser_common.c configparser_common.h \
		collector/collector_sync.c collector/collector_sync.h \
		etsili_core.h export_buffer.h export_buffer.c \
                util.c util.h intercept.c intercept.h \
                netcomms.c netcomms.h byteswap.c byteswap.h etsili_core.c \
                collector/sipparsing.c collector/sipparsing.h \
                collector/jenkinshash.c collector/ipmmcc.c collector/ipmmcc.h \
		collector/ipmmiri.h \
                collector/internetaccess.c collector/internetaccess.h \
		collector/ipcc.c collector/ipcc.h \
                coreserver.h coreserver.c collector/collector_push_messaging.c \
                collector/collector_push_messaging.h \
		collector/alushim_parser.c collector/alushim_parser.h \
		collector/cisco_parser.c collector/cisco_parser.h \
                collector/ipiri.c collector/ipiri.h \
				collector/export_shared.h \
                collector/reassembler.h collector/reassembler.c \
                collector/collector_publish.c collector/collector_publish.h \
                collector/encoder_worker.c collector/encoder_worker.h \
                collector/collector_seqtracker.c \
                collector/collector_forwarder.c collector/jmirror_parser.c \
                collector/jmirror_parser.h openli_tls.c openli_tls.h \
                collector/umtsiri.h collector/umtsiri.c \
                collector/radius_hasher.c collector/radius_hasher.h \
                collector/timed_intercept.c collector/timed_intercept.h \
                collector/email_ingest_service.c \
                collector/email_ingest_service.h \
                collector/email_worker.c collector/email_worker.h \
                collector/emailprotocols/smtp.c \
                collector/emailprotocols/imap.c \
                collector/emailprotocols/pop3.c \
                collector/emailiri.c collector/emailiri.h collector/emailcc.c \
                collector/etsiencoding/etsiencoding.h \
                collector/etsiencoding/etsiencoding.c \
                collector/etsiencoding/encryptcontainer.c \
                collector/etsiencoding/ipmmiri.c \
                collector/etsiencoding/ipmmcc.c \
                collector/etsiencoding/templating.c \
                collector/etsiencoding/epsiri.c collector/epsiri.h \
                collector/etsiencoding/epscc.c collector/epscc.h \
                collector/sip_worker.c collector/sip_worker.h \
				collector/sip_update_state.c \
                collector/gtp_worker.c collector/gtp_worker.h \
				collector/gtp.h collector/sms_masking.c \
                collector/location.c collector/location.h \
                collector/collector_util.c collector/collector_util.h \
                collector/sip_worker_redirection.c \
				collector/sip_worker_redirection.h \
				collector/x2x3_ingest.c collector/x2x3_ingest.h \
				collector/x2x3_cond_attrs.c collector/udp_sink_worker.c \
                $(PLUGIN_SRCS)

openlicollector_LDADD = @ADD_LIBS@ -L$(abs_top_srcdir)/extlib/libpatricia/.libs 
openlicollector_LDFLAGS=-lpthread -lpatricia @COLLECTOR_LIBS@
openlicollector_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/ -Icollector/ -I$(builddir) -Werror -Wall -Wextra

endif

if BUILD_MEDIATOR
bin_PROGRAMS += openlimediator
openlimediator_SOURCES=mediator/mediator.c mediator/mediator.h \
		configparser_common.c configparser_common.h \
		mediator/pcapthread.c mediator/pcapthread.h \
                mediator/handover.c mediator/handover.h \
                mediator/med_epoll.c mediator/liidmapping.c \
                mediator/liidmapping.h mediator/mediator_prov.c \
                mediator/med_epoll.h mediator/mediator_prov.h \
                mediator/coll_recv_thread.c mediator/coll_recv_thread.h \
                mediator/lea_send_thread.c mediator/lea_send_thread.h \
                mediator/mediator_rmq.c mediator/mediator_rmq.h \
                mediator/mediator_integrity_check.c \
                mediator/mediator_encryption.c \
                byteswap.c byteswap.h mediator/configparser_mediator.h \
                util.c util.h mediator/configparser_mediator.c \
                agency.h agency.c logger.c logger.h netcomms.c \
                netcomms.h export_buffer.c intercept.c \
                export_buffer.h etsili_core.h etsili_core.c \
                collector/jenkinshash.c openli_tls.c openli_tls.h \
                collector/etsiencoding/etsiencoding.h \
                collector/etsiencoding/etsiencoding.c \
                collector/etsiencoding/tripayload.c \
                collector/etsiencoding/hi1notification.c \
                collector/etsiencoding/encryptcontainer.c \
                coreserver.c coreserver.h
openlimediator_LDADD = @ADD_LIBS@
openlimediator_LDFLAGS=-lpthread @MEDIATOR_LIBS@
openlimediator_CFLAGS=-I$(abs_top_srcdir)/extlib/libpatricia/ -Icollector/etsiencoding -I$(builddir) -Werror -Wall -Wextra
endif

