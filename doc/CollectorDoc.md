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

### Inputs
The inputs option is used to describe which interfaces should be used to
intercept traffic. Each interface should be expressed using either its
interface name (for non-DPDK capture) or its PCI device ID (for DPDK capture).

You can also configure the number of processing threads that are assigned
to intercepting the packets received on that interface. High speed interfaces
( > 1Gb ) will likely need multiple processing threads. I'd suggest 1 thread
per 2Gb of expected traffic rate on the interface. Bear in mind that the
main limiting factor for performance is actually packet rate rather than
raw throughput, i.e. intercepting 500,000 64 byte packets per second is a
much higher workload than intercepting 100,000 1500 byte packets.


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

Inputs are specified as a YAML sequence with a key of `inputs:`. Each
sequence item represents a single traffic source to intercept traffic from
and must contain the following two key-value elements:
* uri              -- [a libtrace URI](https://github.com/LibtraceTeam/libtrace/wiki/Supported-Trace-Formats)
                      describing which interface to intercept packets on.
* threads          -- the number of processing threads to use with this input.

Be aware that increasing the number of threads used for sequence number
tracking, encoding or forwarding can actually decrease OpenLI's performance,
especially if there are more threads active than CPU cores available on
the collector host machine. Also, OpenLI uses a number of internal threads
for message-passing and connection maintenance, which will also be
contending for CPU time. A good rule of thumb is that the total number
of input threads, sequence tracker threads, encoding threads and forwarding
threads should NOT exceed the number of CPU cores on your machine.




