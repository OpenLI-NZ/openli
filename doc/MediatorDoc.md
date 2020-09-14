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

### Pcap Directory
OpenLI allows intercepts to be written to disk as pcap trace files instead
of being live streamed to the requesting agency. If you wish to do this for
any intercepts, you will need to set the pcap directory option in your
mediator configuration. All pcap traces created by this mediator will be
written into this directory; filenames will include the LIID for the intercept
so should be unique and easily identifiable.

The pcap output files will be rotated every 30 minutes. If no traffic is
observed for that intercept during the 30 minute period, no output file will
be created. The rotation frequency can be configured.

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
* mediatorid       -- sets the mediator ID number
* provisioneraddr  -- connect to a provisioner at this IP address
* provisionerport  -- connect to a provisioner listening on this port
* listenaddr       -- listen on the interface with this address for collectors
* listenport       -- listen on this port for collectors
* pcapdirectory    -- the directory to write any pcap trace files to
* pcaprotatefreq   -- the number of minutes to wait before rotating pcap traces
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

