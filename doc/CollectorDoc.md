## Hardware Recommendations for Collectors

OpenLI is designed to run on a typical Linux install on commodity server
hardware, such as a 1U Supermicro or similar. The actual hardware
requirements will depend on the amount of traffic you expect to be
intercepting, whether you expect to be doing VOIP and IP intercepts on
the same collector, and how much you are willing to trade off against
the possibility of a "worst case" intercept scenario (e.g. a user with
a 1Gb connection which they are flooding with 64 byte packets).

Please note that the OpenLI developers take no responsibility for any
interception failures due to underprovisioned collector hardware.

Having said that, here are some recommendations for a "typical"
collector where we define typical as having to conduct <= 3 concurrent
intercepts for users that are NOT saturating their 1Gbps connection
(and even if they are saturating them, they are using larger packets to do
so).
  * CPU: Intel Xeon or equivalent, at least 8 logical cores but preferably
         more cores if possible.
  * RAM: At least 16 GB -- more RAM will help with buffering if a
         connection to a mediator fails but won't improve speed.
  * NIC: A standard 4 port 1G NIC + an Intel DPDK-capable 10G NIC. The
         standard NIC will be used for management and capturing special
         traffic types (such as RADIUS, SIP and/or RTP).

         The DPDK NIC will be used for IP traffic capture and intercept.
         If the collector is handling VOIP intercepts only, you can
         probably manage without the DPDK NIC.

         See https://core.dpdk.org/supported/ for a list of DPDK-supported
         hardware.
  * Disk: Enough to fit a Linux install + some extra software components.
          If you are anticipating a spotty connection to the mediator(s),
          then extra disk space for buffering may be useful. SSDs are
          not required; a traditional spinning disk should be fine.

## Collector Configuration
Like all OpenLI components, the collector uses YAML as its configuration
file format. If you are unfamiliar with YAML, a decent crash course is
available [here](https://learnxinyminutes.com/docs/yaml/).

An example configuration file (with in-line documentation) can found in
`doc/exampleconfigs/collector-example.yaml`.

### Operator ID
This option should contain a string that uniquely identifies your network.
This is a mandatory field for ETSI compliance and will be used to set the
operatorIdentifier field in the ETSI header. The operator ID should be no
more than 16 characters in length.

### Network Element ID
This option should contain a string that uniquely identifies the location of
the collector within your network. While this is technically
an optional field for ETSI compliance, it is highly recommended that you set
this option. The provided value will be used to set the
networkElementIdentifier field in the ETSI header and should be no more than
16 characters in length.

### Interception Point ID
If you have multiple collectors at a single location, you can use the
Interception Point ID to assign an additional identifier to each exported
ETSI record so that the source collector can be distinguished by the
recipient LEAs. This field is optional and only necessary if the Operator
and Network Element IDs are not a unique identifier for this collector. The
Interception Point ID should be no more than 8 characters in length.

### Provisioner Socket
The provisioner address and port options describe how to connect to the
host that the OpenLI provisioner is running on. If the collector cannot
connect to the provisioner, it will not receive any intercept instructions
and will therefore sit idle. If the connection to the provisioner goes down
for some reason, the collector will periodically attempt to reconnect to it.

### Statistics Logging
This option can be used to configure the collector to log regular statistic
updates, which you can then inspect to gauge whether the collector is
functioning as expected (i.e., is it receiving packets on the capture
interface?). By default, the logging is disabled as it can be somewhat
verbose. The value you set for this option will determine the number of
minutes between statistic dumps from the collector -- setting this to zero
will disable the statistic logging altogether.


### Inputs
The inputs option is used to describe which interfaces on the collector
should be used to intercept traffic. Each interface should be expressed using
either its interface name (for non-DPDK capture) or its PCI device ID
(for DPDK capture).

You can also configure the number of processing threads that are assigned
to intercepting the packets received on that interface. High speed interfaces
( > 1Gb ) will likely need multiple processing threads. I'd suggest 1 thread
per 2Gb of expected traffic rate on the interface. Bear in mind that the
main limiting factor for performance is actually packet rate rather than
raw throughput, i.e. intercepting 500,000 64 byte packets per second is a
much higher workload than intercepting 100,000 1500 byte packets.

Finally, you can optionally choose a hashing method for your input stream
that will decide how received packets will be assigned to processing threads
within the OpenLI collector. The main use of this feature is to notify OpenLI
of inputs where the incoming traffic will be predominately RADIUS traffic and
therefore OpenLI should use a custom hashing method to ensure that all RADIUS
packets for the same user session are received by the same processing thread.
Valid values for the `hasher` option are `bidirectional` (default), `radius`
and `balanced`.

### X2/X3 Support
OpenLI collectors now support being able to receive intercepted traffic using
the X2/X3 standards (i.e. ETSI TS 102 221-2).

To enable this feature, specify the IP address and port that you want your
collector to listen on using the `x2x3inputs` configuration option. You may
specify multiple X2/X3 listeners if desired, e.g. if you wanted to scale up
your collector by adding multiple listeners and using X1 to spread your
intercept targets across them.


### Nokia Mirror Configuration
NOTE: Nokia mirrored traffic can also be handled using a UDP Sink (see below
for more information).

If you are using OpenLI to translate the intercept records produced by
Nokia / Alcatel-Lucent devices into ETSI-compliant output, any collectors that
are expected to receive mirrored copies of the Nokia intercept records need
to be able to identify which packets are encapsulated records to be
translated.

This is done by configuring the collector with a sequence of known sinks for
the Nokia intercept traffic under the 'alumirrors' top-level configuration
option. Each sequence entry is defined using two parameters:
* ip -- the IP address of the sink
* port -- the port that the sink is listening on for Nokia intercept records

Note that in this context, the sink refers to the destination IP address
and port of the mirrored Nokia traffic.

### Juniper Mirror Configuration
NOTE: JMirror traffic can also be handled using a UDP Sink (see below
for more information).

If you are using Juniper Packet Mirroring (a.k.a. JMirror) to mirror intercepted
traffic into an OpenLI collector, you will need to configure OpenLI with the
IP address and port that the mirrored traffic is being sent to so that the
collector can identify which packets are encapsulated records which need to
be stripped and encoded as ETSI-compliant records.

This is done by configuring the collector with a sequence of known sinks for
the mirrored traffic under the 'jmirrors' top-level configuration option.
Each sequence entry is defined using two parameters:
* ip -- the IP address of the sink
* port -- the port that the sink is listening on for Nokia intercept records

Note that in this context, the sink refers to the destination IP address
and port of the mirrored traffic.

### RabbitMQ Configuration
OpenLI supports the use of RabbitMQ to persist intercepted packets on the
collector which are not currently able to be sent to their corresponding
mediator (because the mediator is down or busy). The packets will be persisted
to disk by RabbitMQ, allowing OpenLI to sustain a relatively large backlog of
packets if need be.

A collector that does not use RabbitMQ will instead persist packets in memory
only. A memory backlog obviously has a much smaller amount of space available
and will be lost if the collector process is halted for any reason. Therefore,
for the best reliability, we recommend configuring your collectors and mediators
to use RabbitMQ as an intermediary.

More details on how to configure RabbitMQ for a collector can be found at
https://github.com/OpenLI-NZ/openli/wiki/Using-RabbitMQ-for-disk-backed-buffers-in-OpenLI.
A collector only requires a small amount of configuration: a username and
password that can be used to authenticate against a local RabbitMQ instance,
and a flag to inform the collector that RabbitMQ output is enabled.

### Target Identification for VOIP Intercepts
By default, OpenLI does NOT trust the "From:" field in SIP packets when it is
determining whether a SIP packet has been sent by an intercept target. This
is because this field can be spoofed by the caller and is not validated.
Instead, OpenLI relies on fields such as Proxy-Authorization and
P-Asserted-Identity which are much more reliable.

However, some VOIP deployments may not include any of the more reliable
fields and therefore outgoing calls by a target can only be recognised by
examining the "From:" field. For those cases, there is a config option
"sipallowfromident" which can be used to tell OpenLI collectors that they
should trust the SIP "From:" field and use it for target identification
purposes.

Only enable this option if you absolutely trust that the SIP "From:" fields
are not spoofed (maybe because the SIP is being generated from inside your
network) and you are unable to include any of the more reliable fields in
your SIP traffic.

### UDP Sinks
Many networking equipment vendors offer a limited lawful interception
capability on their devices that can siphon copies of traffic for a
particular network user (i.e. an intercept target) to a pre-defined destination.
These streams typically encapsulate the captured traffic in IP/UDP, and may
also include a small shim header at the beginning of the datagram payload.

OpenLI collectors can act as the destination for these UDP streams, whereby
the collector can be configured to listen on certain UDP ports for datagrams.
We call these IP/port pairs "UDP sinks". Then, in the intercept configuration,
tell OpenLI which UDP sinks will be the recipients of traffic for the target
user. Finally, when you configure the mirroring on your router/device, set the
destination to be the IP address and UDP port that you designated as the
corresponding sink on your collector.

The OpenLI collector will then assume any traffic delivered to it on the
IP address and UDP port of the specified sink(s) must belong to the target
of the associated intercept, and automatically intercept and encode each
packet accordingly.

Important notes:
 * each UDP sink on a collector can only be associated with at most one
   intercept at a time, but you may have multiple sinks attached to a single
   intercept (e.g. to handle cases where inbound and outbound traffic were
   mirrored separately).
 * UDP sinks currently only support IP intercepts, not VoIP or email
   intercepts.
 * vendmirrorid configuration is not required for IP intercepts that use UDP
   sinks, and in fact no checking of the intercept ID in the post-UDP shim
   is performed at all.
 * UDP sinks without an attached intercept will remain idle until an
   intercept is assigned to it via the provisioner.


### Configuration Syntax
All config options aside from the input configuration are standard YAML
key-value pairs, where the key is the option name and the value is your chosen
value for that option.

The basic option keys are:
* provisioneraddr   -- connect to a provisioner at this IP address
* provisionerport   -- connect to a provisioner listening on this port
* operatorid        -- set the operator ID
* networkelementid  -- set the network element ID
* interceptpointid  -- set the interception point ID
* seqtrackerthreads -- set the number of threads to use for sequence number
                       tracking (defaults to 1).
* encoderthreads    -- set the number of threads to use for encoding ETSI
                       records (defaults to 2).
* forwardingthreads -- set the number of threads to use for forwarding
                       encoded ETSI records to the mediators (defaults to 1).
* logstatfrequency  -- set the frequency (in minutes) that the collector
                       should dump detailed statistics about the collection
                       process to the logger. Defaults to 0 (no stat logging).
* sipignoresdpo     -- set to 'yes' to prevent OpenLI from using SDP O fields
                       to group multiple legs for the same VOIP call. See
                       notes below for more explanation. Defaults to 'no'.
* RMQenabled        -- a flag indicating whether RabbitMQ should be used to
                       buffer encoded ETSI records that are to be sent to the
                       mediators. Defaults to 'false'. If set to 'true', the
                       `RMQname` and `RMQpass` options must also be set.
* RMQname           -- the username to use when authenticating against a local
                       RabbitMQ instance.
* RMQpass           -- the password to use when authenticating against a local
                       RabbitMQ instance.
* sipallowfromident -- set to 'yes' to allow the SIP "From:" field to be used
                       for target identification. Defaults to "no".
* maskimapcreds     -- set to 'yes' to have OpenLI replace any clear-text or
                       base64 encoded credentials in IMAP traffic that has
                       been intercepted using an email intercept with "XXX".
                       Defaults to "yes".
* maskpop3creds     -- set to 'yes' to have OpenLI replace any clear-text
                       credentials in IMAP traffic that have been
                       intercepted using an email intercept with "XXX".
                       Defaults to "yes".
* defaultemaildomain -- during email interception, any authenticated email
                        users that do not explicitly include their domain
                        in their username will be assumed to be using the
                        address'<username>@<this domain>'.
* gtpthreads        -- set the number of threads to use for processing GTP
                       traffic (defaults to 1, can be set to zero to disable
                       GTP session tracking).
* sipthreads        -- set the number of threads to use for processing SIP
                       traffic (defaults to 1, cannot be set to zero).
* emailthreads      -- set the number of threads to use for processing email
                       traffic (defaults to 1, can be set to zero to disable
                       email interception).

Be aware that increasing the number of threads used for sequence number
tracking, encoding or forwarding can actually decrease OpenLI's performance,
especially if there are more threads active than CPU cores available on
the collector host machine. Also, OpenLI uses a number of internal threads
for message-passing and connection maintenance, which will also be
contending for CPU time. A good rule of thumb is that the total number
of input threads, sequence tracker threads, encoding threads and forwarding
threads should NOT exceed the number of CPU cores on your machine.

---

Inputs are specified as a YAML sequence with a key of `inputs:`. Each
sequence item represents a single traffic source to intercept traffic from
and must contain the following two key-value elements:
* uri              -- [a libtrace URI](https://github.com/LibtraceTeam/libtrace/wiki/Supported-Trace-Formats)
                      describing which interface to intercept packets on.
* threads          -- the number of processing threads to use with this input.
* hasher           -- the hashing method to use for this input (either
                      balanced, bidirectional or radius). Inputs that receive
                      RADIUS packets are strongly recommended to use `radius`
                      here, `bidirectional` otherwise.

---

X2/X3 inputs are also specified as a YAML sequence, using `x2x3inputs:` as
the key. Each sequence item describes a single X2/X3 listening socket that the
OpenLI collector will then create. Each X2/X3 input is limited to a single
thread, so if you want to parallelise X2/X3 ingestion then you should provide
configuration for multiple listeners and distribute the intercepts accordingly
when you use X1 to trigger the X2/X3 delivery on your network equipment.

X2/X3 inputs should include the following key-value elements:
* listenaddr       -- the IP address that the collector should listen on.
* listenport       -- the TCP port that the collector should listen on.

Note that TLS is mandatory for X2/X3 transport and we do not provide an option
to disable it. See TLSDoc.md for instructions on how to generate certificates
and enable TLS for your OpenLI collector. The certificate file that you
provide using the `tlscert` option will be offered to any devices that
connect to your collector on an X2/X3 listening socket.

---

As described above, Nokia mirrors are defined as a YAML sequence with a key
of `alumirrors:`. Each sequence item must contain the following two
key-value elements:
* ip -- the IP address of the sink
* port -- the port that the sink was listening on for Nokia intercept records

Juniper Packet Mirrors (JMirror) are defined in the same way as Nokia mirrors,
except using the key 'jmirrors:'. Each sequence item must contain the following
two key-value elements:
* ip -- the IP address of the JMirror sink
* port -- the port that the sink was listening on for mirrored traffic

We also support the Cisco equivalent, PacketCable, and the configuration to
tell the collector how to recognise traffic mirrored from a Cisco device is
very similar to the above. The sequence key in this case is called
`ciscomirrors:` and each item must contain the following two key-value
elements:

* ip -- the IP address of the device that received the mirrored traffic
* port -- the port that the sink was listening on for mirrored traffic

---

UDP sinks are defined a YAML sequence with a key of `udpsinks:`. Each sequence
item describes a single listening UDP sink instance and must contain the
following three key-value elements:
* listenaddr -- the IP address of the interface to consume UDP mirror traffic on
* listenport -- the port number to receive UDP mirror traffic on
* identifier -- an identifier string that is unique to this particular
                collector (in case another collector is also listening on the
                exact same IP address and port).


### Email interception options

When performing email interception, mail protocol sessions will be ended as
soon as the protocol "closing" command (i.e. "QUIT" for SMTP, "BYE" for IMAP)
are observed. However, OpenLI will also expire any incomplete mail protocol
sessions that have been idle for a certain number of minutes. You can
configure the idle thresholds for each mail protocol by defining a YAML sequence
with the key `emailsessiontimeouts` and then adding a sequence item for each
protocol that you wish to define a timeout for. Each sequence item should
be expressed as a key-value pair, where the key is the protocol name and the
value is the desired timeout in minutes.

The three mail protocols supported by OpenLI and their default timeout values
are:
* smtp (default is 5 minutes)
* imap (default is 30 minutes)
* pop3 (default is 10 minutes)


An email intercept target may have configured an auto-forward on any
mail that arrives in their mailbox. By default, the SMTP session for an
auto-forward may not be intercepted by OpenLI as the address of the
forwarder does not appear in the SMTP protocol messages. Instead, the
forwarder address is typically included in an RFC-822 message header within the
mail body itself, but the name of the header may differ between mail service
implementations (for instance, Sieve rules in Dovecot will add a
`X-Sieve-Redirected-From` header).

To ensure that auto-forwarding behaviour is intercepted correctly by OpenLI,
you can use the `emailforwardingheaders` configuration option to provide a
list of headers that you want OpenLI to check for the appearance of a target
email address (in addition to the normal MAIL FROM and RCPT TO checks). The
`emailforwardingheaders` option takes the form of a YAML sequence, so you
can provide multiple header names if necessary. Note that only mail content
observed for SMTP sessions will be examined for the presence of these
headers.

### Email ingestion service
Instead of intercepting email by capturing all SMTP, POP3 and/or IMAP traffic
observed on a network interface, OpenLI can also ingest email application
layer messages through an additional HTTP service that can be run on each/any
OpenLI collector.

You can then use custom plugins on your mail servers (e.g. dovecot plugins)
to generate messages in the expected format for an interceptable email session
and POST the message to the ingestion service running on a collector. The
POSTed message is sent as `multipart/form-data`, where each field in
a message is a separate part encoded as `text/plain`.

The message format itself is documented on the OpenLI wiki at
https://github.com/OpenLI-NZ/openli/wiki/Email-Ingestion-Message-Format

By default, the email ingestion service is disabled on a collector but you
can enable and configure it using the following options.

Firstly, you will need to add the `emailingest:` key to the top level of
your existing collector YAML configuration.

Then you can specify the following mapping options as values inside the
`emailingest:` key to configure the ingestion service:

* listenaddress         -- the IP address that the service should listen on.
* listenport            -- the port for the service to listen on.
* enabled               -- if set to "no", the service will be disabled. Set
                           to "yes" to enable the service.
* requiretls            -- if set to "yes", connections to the service will
                           only be permitted using HTTPS.
* authpassword          -- if set, connections to the service will be rejected
                           unless they use digest authentication and provide
                           this value as their password.

Example configuration is included in the `collector-example.yaml` config
file -- you can find this file in `doc/exampleconfigs` in the OpenLI source
tree or installed into `/etc/openli/` if you installed OpenLI using a
package.

To enable TLS on the ingestion service, you must also configure your collector
(and all other OpenLI components) to use TLS for their internal communications,
as the ingestion service will use the same certificates and keys to
establish the encrypted channel. See `doc/TLSDoc.md` for details on how to
set up TLS for OpenLI.

When using digest authentication, the username on the POST request can be
set to anything; the username is ignored by the ingestion service as long as
the provided password matches what has been set as the `authpassword`.

### SIP Ignore SDP O option
When testing OpenLI VOIP intercepts, you may discover that the IRI stream for
a given voice intercept includes some erroneous SIP packets that belong to
another call that should definitely not be part of the intercept.

If this happens to you, try adding the `sipignoresdpo` option to your
collector config and set the value to `yes`.

---

More detailed explanation (only bother if you are really curious and have
a good understanding of SIP + LI): SIP sessions that pass through SIP proxies
are said to be split into multiple "legs", where each leg is the portion of the
path between two SIP proxies / endpoints. Because each proxy is a termination
point for the session, the Call-ID (which the field we usually use to map
SIP packets to their session) changes from leg to leg. Thus, if packets from
two separate legs are intercepted by the same OpenLI collector, packets from
the first leg would be assigned to one session (based on the Call-ID assigned
by the sender of the first leg) and packets from the second leg would assigned
to a different session (again, because the Call-ID is different to that from
the first leg).

However, the ETSI LI specifications require that the interception process
recognise the two legs as being from the same session/call (despite the
Call-ID being different), and therefore should be assigned the same
communication identifier and use the same sequencing space when numbering the
IRI records. The specs suggest (in Sec 5.3.1 of ETSI TS 102 232-5) that the
intercept process can use the O field in the SDP payload to recognise different
call legs, as this should be unique but consistent across call legs (as per
RFC 4566). And thus OpenLI will indeed try to do this: if we see a SIP packet
with a new Call-ID but its SDP O identifiers match the ones we've seen for a
previous Call-ID then OpenLI considers them to be different legs for the same
call and joins the Call-IDs into a single intercepted session.

In reality, there are VOIP implementations where the values that get put in
an SDP O field are *not* unique for each call. Some implementations just hard
code some of the values, others appear to re-use them. The end result is that
the one thing OpenLI is relying on to recognise sessions that have been spread
across multiple legs is not that reliable any more.

Hence, there is now an option in OpenLI to tell a collector to not attempt
to use SDP O data to recognise other legs of a SIP session. This will prevent
OpenLI from doing exactly what Sec 5.3.1 of ETSI TS 102 232-5 wants it to do,
so each call leg will end up with its own communication identifier, but this
is a much better outcome than the overcollection that will occur if the SDP O
data is not globally unique.

In summary, if you are seeing some weird problems with SIP over-collection
on your VOIP intercepts, set `sipignoresdpo` to `yes` and the problems will
likely go away. If the LEAs give you grief about your call legs being split
across multiple communication identifiers, feel free to a) blame your VOIP
vendor for not implementing SDP O properly and b) send them a copy of this
detailed explanation as to why your intercept software is unable to join the
legs together.






