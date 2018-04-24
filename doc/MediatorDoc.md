## Mediator Configuration

Like all OpenLI components, the mediator uses YAML as its configuration
file format. If you are unfamiliar with YAML, a decent crash course is
available [here](https://learnxinyminutes.com/docs/yaml/).

An example configuration file (with in-line documentation) can found in
`doc/exampleconfigs/mediator-example.yaml`.

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


### Configuration Syntax
All of the mediator config options are standard YAML key-value pairs, where
the key is the option name and the value is your chosen value for that option.

The supported option keys are:
* mediatorid       -- sets the mediator ID number
* provisioneraddr  -- connect to a provisioner at this IP address
* provisionerport  -- connect to a provisioner listening on this port
* listenaddr       -- listen on the interface with this address for collectors
* listenport       -- listen on this port for collectors
