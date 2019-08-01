## Encrypting OpenLI internal communications using TLS

As of version 1.0.3, OpenLI supports the use of TLS to encrypt
the internal communications between the deployed components
(i.e. provisioner, collectors and mediators). The obvious benefit
of this is that it becomes much more difficult for unauthorised
persons to discover who is the subject of an intercept or to inject
their own malicious interception instructions into an OpenLI system.

## Generating a certificate

In this example, we will be using a self-signed certificate to secure
an OpenLI deployment but you are more than welcome to substitute in a
certificate signed by a CA if you feel that is more appropriate.

If you already know how to create a self-signed certificate, feel free
to skip over this section.

First, create your own CA (replace myOpenLICA with a suitable name, if
you prefer):

    openssl req -newkey rsa:4096 -nodes -sha512 -x509 -days 3650 -nodes -subj /CN=myOpenLICA -out openli-ca-crt.pem -keyout openli-ca-key.pem


Now, create and sign a certificate for each of the OpenLI components:

    openssl genrsa -out openli-provisioner-key.pem 4096
    openssl req -new -sha256 -subj /CN=OpenLIprov -key openli-provisioner-key.pem -out openli-provisioner-csr.pem
    openssl x509 -req -days 365 -in openli-provisioner-csr.pem -CA openli-ca-crt.pem  -CAkey openli-ca-key.pem -CAcreateserial -out openli-provisioner-crt.pem

    openssl genrsa -out openli-mediator-key.pem 4096
    openssl req -new -sha256 -subj /CN=OpenLImed -key openli-mediator-key.pem -out openli-mediator-csr.pem
    openssl x509 -req -days 365 -in openli-mediator-csr.pem -CA openli-ca-crt.pem -CAkey openli-ca-key.pem -CAcreateserial -out openli-mediator-crt.pem

    openssl genrsa -out openli-collector-key.pem 4096
    openssl req -new -sha256 -subj /CN=OpenLIcol -key openli-collector-key.pem -out openli-collector-csr.pem
    openssl x509 -req -days 365 -in openli-collector-csr.pem -CA openli-ca-crt.pem -CAkey openli-ca-key.pem -CAcreateserial -out openli-collector-crt.pem

If you have planning on having multiple collectors, you may need to generate
additional certificates for each one.

Feel free to add more useful information via the `-subj` options when
creating the key request. I've just included the absolute bare minimum to
make TLS work.

Once you're done, you should probably put `openli-ca-key.pem` somewhere nice
and secure that nobody else can access (not on any of your OpenLI component
hosts, for instance!). You'll need it if you want to create more certificates
for future components.

### Putting the certificates in the right place

For each component, copy the corresponding `X-key.pem` file into `/etc/openli/`
on the host that component will be running on. Copy the `X-crt.pem` file into
`/etc/openli/`. Also copy the `openli-ca-crt.pem` file into `/etc/openli/`
onto each host running an OpenLI component.

For example, on your provisioner host you should now have the following three
files:

    /etc/openli/openli-provisioner-crt.pem
    /etc/openli/openli-ca-crt.pem
    /etc/openli/openli-provisioner-key.pem

Your mediator will have:

    /etc/openli/openli-mediator-crt.pem
    /etc/openli/openli-ca-crt.pem
    /etc/openli/openli-mediator-key.pem

Your collector will have:

    /etc/openli/openli-collector-crt.pem
    /etc/openli/openli-ca-crt.pem
    /etc/openli/openli-collector-key.pem


Make sure your keys and certificates are readable only by the user which
will be running the OpenLI components on this host. For instance, if you
have created an `openli` user to run the provisioner component:

    chown openli:openli /etc/openli/*.pem
    chmod 400 /etc/openli/openli-provisioner-key.pem
    chmod 400 /etc/openli/openli-ca-crt.pem
    chmod 400 /etc/openli/openli-provisioner-crt.pem


# Configuring OpenLI components to use the certificates

You can enable internal TLS encryption by adding the following three options
to your configuration file for each component:

 * tlscert: the location of the component's certificate file
 * tlskey:  the location of the component's key file
 * tlsca: the location of the certificate file for the CA that signed the
          certificates (i.e. openli-ca-crt.pem).

If these config options are present and the certificates are successfully
read on start-up, OpenLI will use TLS to encrypt all inter-component
messages, otherwise it will fall back to unencrypted communications.

Note that if one OpenLI component is configured to use TLS, all other
components -must- also use TLS. Any components not configured to use TLS
that attempt to connect with a component that is using TLS will have
their connection attempts dropped.

It may be desirable for performance reasons to NOT encrypt the stream of
intercepted packets sent from a collector to the mediator, while still
encrypting the remainder of the inter-component communications (such as
the intercept start and halt messages). To support this, the mediator and
collector have an additional configuration option `etsitls` -- if set to
`no` for *both* components, the connection between the two will not be
encrypted. In that case, please make sure that the path between your collectors
and mediators is entirely internal to your own network! By default, `etsitls`
is configured to have the value of `yes`.

See the example configuration files for a demonstration of these configuration
options in practice.


