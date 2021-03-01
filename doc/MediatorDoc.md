## Mediator Configuration

Like all OpenLI components, the mediator uses YAML as its configuration
file format. If you are unfamiliar with YAML, a decent crash course is
available [here](https://learnxinyminutes.com/docs/yaml/).

An example configuration file (with in-line documentation) can found in
`doc/exampleconfigs/mediator-example.yaml`.

### Operator ID
This option should contain a string that uniquely identifies your network.
This is a mandatory field for ETSI compliance and will be used to set the
operatorIdentifier field in the ETSI header. The operator ID should be no
more than 16 characters in length. The operator ID specified here is
used to populate ETSI keep-alive messages that maintain the connection
between your mediator and the law enforcement agencies.

Ideally, the operator ID configured for your mediator(s) should match
the operator ID that you are using for your collectors.

There is also a special type of Operator ID which is used in HI1 Operations
messages that is limited to 5 characters in length -- this is an annoying
inconsistency in the ETSI standards that we cannot work around easily. This
may be set using the `altoperatorid` configuration option. If this
option is not configured, OpenLI will instead use the first 5 characters from
your regular operator ID.

### Mediator ID
Each mediator that you are running needs to be assigned a unique mediator
ID. The mediator ID should be a number between 0 and 1,000,000.

Most deployments will only have one mediator, so this shouldn't be too
difficult to keep track of. Remember your mediator ID, as you will need
it when starting an intercept.

### Listening Socket
The listen address and port options are used to describe which address and
port (on the mediator host) should listen for incoming connections from the
collector(s).

Make sure you actually choose an IP address that is assigned to the mediator
host!

### Provisioner Socket
The provisioner address and port options describe how to connect to the
host that the OpenLI provisioner is running on. If the mediator cannot
connect to the provisioner, it will not be able to announce itself as being
available and therefore no collectors will be told to connect to it. If
the provisioner goes down for some reason, the mediator will periodically
attempt to reconnect to it.

### Pcap Output
OpenLI allows intercepts to be written to disk as pcap trace files instead
of being live streamed to the requesting agency. If you wish to do this for
any intercepts, you will need to set the pcap directory option in your
mediator configuration. All pcap traces created by this mediator will be
written into this directory; by default, the filenames for the pcap traces
will include the LIID for the intercept so should be unique and easily
identifiable.

The pcap output files will be rotated every 30 minutes. If no traffic is
observed for that intercept during the 30 minute period, no output file will
be created. The rotation frequency can be configured.

The default pcap file name format is `openli_$(LIID)_$(UNIXTIMESTAMP)`. This
can be changed if necessary using the `pcapfilename` config option. The value
for this option should be a format template, much like what is used by the
`strftime()` function. All formatting tokens supported by strftime() are also
supported by this option, with the addition of '%L' (which will be replaced
with the LIID for the intercept) and '%s' (which will be replaced with the
Unix timestamp at the creation time of the file). Hence, the default template
would be expressed as `openli_%L_%s`.

By default, pcap output files are compressed using gzip compression (level 1).
Compression may be disabled by setting the compression level to 0. Higher
compression levels are also supported, although discouraged due to diminishing
returns compared with the increase in CPU load to compress at those levels.

Note: a pcap file should not be considered usable until *after* it has been
rotated -- in-progress pcap traces do not contain all of the necessary
trailers to allow them to be correctly parsed by a reader.

### RabbitMQ Configuration
If you have using RabbitMQ to reliably persist the intercepted packets that
have not yet been received by your mediator, you will need to also provide
additional configuration on your mediator to allow it to read those packets
from the RabbitMQ queue on the collector.

OpenLI supports (and recommends!) the use of SSL / TLS to authenticate with the
RabbitMQ server that is running on the collector, but you may also choose to
authenticate using the plain method with a password.

Plain authentication will require you to provide the following options in your
configuration file:

* RMQenabled       -- must be set to `true` to enable RabbitMQ support
* RMQname          -- the username to use when authenticating with RabbitMQ
* RMQpass          -- the password to use when authenticating with RabbitMQ
* RMQSSL           -- must be set to `false` to disable SSL authentication
* RMQheartbeatfreq -- time between RMQ heartbeat packets that are used to
                      detect a connection breakdown (default is 0, which
                      disables heartbeats)

SSL authentication will require you to provide the following options instead:

* RMQenabled       -- must be set to `true` to enable RabbitMQ support
* RMQname          -- the username to use when authenticating with RabbitMQ
* RMQSSL           -- must be set to `true` to enable SSL authentication
* RMQheartbeatfreq -- time between RMQ heartbeat packets that are used to
                      detect a connection breakdown (default is 0, which
                      disables heartbeats)
* tlscert          -- the file containing an SSL certificate for the mediator
* tlskey           -- the file containing an SSL key for the mediator
* tlsca            -- the file containing the SSL certificate for the CA that
                      signed your mediator certificate

See TLSDoc.md for more details on the SSL certificate files required by
OpenLI, as these will be the same certificates that you will/would use to
encrypt other inter-component messages in an OpenLI deployment.

### Configuration Syntax
All of the mediator config options are standard YAML key-value pairs, where
the key is the option name and the value is your chosen value for that option.

The supported option keys are:
* operatorid       -- set the operator ID
* altoperatorid    -- sets the operator ID for HI1 Operations messages, which
                      must be no more than 5 characters long.
* mediatorid       -- sets the mediator ID number
* provisioneraddr  -- connect to a provisioner at this IP address
* provisionerport  -- connect to a provisioner listening on this port
* listenaddr       -- listen on the interface with this address for collectors
* listenport       -- listen on this port for collectors
* pcapdirectory    -- the directory to write any pcap trace files to
* pcaprotatefreq   -- the number of minutes to wait before rotating pcap traces
* pcapcompress     -- the compression level for pcap trace files (default is 1,                       set to 0 to disable compression)
* pcapfilename     -- format template to use for naming pcap files (default is
                      `openli_%L_%s`
* RMQenabled       -- set to `true` if your collectors are using RabbitMQ
                      to buffer ETSI records destined for this mediator
* RMQname          -- the username to use when authenticating with RabbitMQ
* RMQpass          -- the password to use when authenticating with RabbitMQ
                      (required for plain auth only).
* RMQSSL           -- set to `true` to use SSL authentication instead of plain
* RMQheartbeatfreq -- time between RMQ heartbeat packets that are used to
                      detect a connection breakdown (default is 0, which
                      disables heartbeats)
* tlscert          -- the file containing an SSL certificate for the mediator
* tlskey           -- the file containing an SSL key for the mediator
* tlsca            -- the file containing the SSL certificate for the CA that
                      signed your mediator certificate

