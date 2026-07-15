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


Now, create and sign a certificate for each of the OpenLI components (you
should replace the `/CN=` subj argument with the hostname of the device / VM /
container that the component will be running on):

    openssl genrsa -out openli-provisioner-key.pem 4096
    openssl req -new -sha256 -subj /CN=provisioner-openli.mynetwork.net -key openli-provisioner-key.pem -out openli-provisioner-csr.pem
    openssl x509 -req -days 365 -in openli-provisioner-csr.pem -CA openli-ca-crt.pem  -CAkey openli-ca-key.pem -CAcreateserial -out openli-provisioner-crt.pem

    openssl genrsa -out openli-mediator-key.pem 4096
    openssl req -new -sha256 -subj /CN=mediator-openli.mynetwork.net -key openli-mediator-key.pem -out openli-mediator-csr.pem
    openssl x509 -req -days 365 -in openli-mediator-csr.pem -CA openli-ca-crt.pem -CAkey openli-ca-key.pem -CAcreateserial -out openli-mediator-crt.pem

    openssl genrsa -out openli-collector-key.pem 4096
    openssl req -new -sha256 -subj /CN=collector01-openli.mynetwork.net -key openli-collector-key.pem -out openli-collector-csr.pem
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


## Post-quantum cryptography

OpenSSL 3.5 (an LTS release, supported until 2030) added support for the
NIST post-quantum standards to its default provider: ML-KEM (FIPS 203) for
key exchange and ML-DSA (FIPS 204) for signatures. If you are running
OpenSSL 3.5 or later, you can use these to protect OpenLI's internal
communications against "harvest now, decrypt later" attacks, where an
adversary records your traffic today and decrypts it once a
cryptographically relevant quantum computer exists.

You do not need liboqs, the OQS provider, or any special build of OpenLI to
do this -- everything below uses stock OpenSSL. Check what you have with:

    openssl version

### Post-quantum key exchange

This is the part that matters most for harvest-now-decrypt-later, and on
OpenSSL 3.5 or later you get it for free: `X25519MLKEM768` is in OpenSSL's
default group list, so an OpenLI deployment where both ends run OpenSSL 3.5+
will already negotiate a post-quantum hybrid key exchange without any
configuration at all.

The default list also still includes classical groups, though, so a peer
that does not offer ML-KEM will quietly fall back to X25519. If you would
rather refuse such a connection than downgrade it, use the `tlsgroups`
option to name the only groups you are willing to accept:

    tlsgroups: X25519MLKEM768:SecP384r1MLKEM1024

`tlsgroups` takes an OpenSSL group list -- a `:` separated list of group
names in order of preference. Useful post-quantum names are
`X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` (each a
hybrid of ML-KEM with a classical curve, so the result is no weaker than
the classical curve alone even if ML-KEM is later broken), plus the pure
`MLKEM512`, `MLKEM768` and `MLKEM1024`. Hybrids are the conservative choice
and are what we would suggest.

Although it is described here in post-quantum terms, `tlsgroups` is a
general option: it accepts any group list your OpenSSL release
understands, including classical-only lists such as `X25519:P-384`, and
the option itself works on OpenSSL releases much older than 3.5 -- it is
only the post-quantum group names that need 3.5.

A handshake succeeds as long as both ends have at least one group in
common, so you do not have to roll this out everywhere at once. A
component restricted to `X25519MLKEM768` will still talk to a peer that
has no `tlsgroups` set at all, because OpenSSL 3.5's defaults include that
group -- so you can enable it one component at a time.

What will fail is a peer that offers no group you accept: one restricted
to a classical-only list, or one running an OpenSSL older than 3.5, which
has no ML-KEM to offer. That is the point of the option -- such a peer is
refused rather than silently downgraded -- but it does mean you should
upgrade every component to OpenSSL 3.5 before you start restricting
groups anywhere.

If OpenSSL does not recognise a name in the list -- most likely because
you are on a release older than 3.5 -- OpenLI will log an error and fail
to build an SSL context, so check the logs after changing this option.
Leaving `tlsgroups` unset keeps OpenSSL's defaults, which is the right
choice for most people.

### Post-quantum certificates

Key exchange protects the confidentiality of traffic recorded today.
Certificates are a separate question: they authenticate the components to
each other at the time of the handshake, so a quantum attacker cannot use a
future capability to retrospectively forge a signature on a handshake that
has already happened. Migrating them is therefore much less urgent than
migrating key exchange, and you may reasonably choose to leave your RSA
certificates alone for now.

If you do want ML-DSA certificates, `./createCertsPQC` in the source tree
generates a self-signed test set in the same way `createCerts` does, but
using ML-DSA-87 instead of RSA. It requires OpenSSL 3.5 or later. The
resulting certificates are used exactly like the RSA ones -- point
`tlscert`, `tlskey` and `tlsca` at them as normal.

Be aware that ML-DSA certificates are considerably larger than their RSA
equivalents (roughly 10KB against roughly 2KB), which makes the handshake
correspondingly bigger. Every component in the deployment needs to be
running OpenSSL 3.5+ before you switch, since older versions cannot verify
an ML-DSA signature at all.

# Configuring OpenLI components to use the certificates

You can enable internal TLS encryption by adding the following three options
to your configuration file for each component:

 * `tlscert`: the location of the component's certificate file
 * `tlskey`:  the location of the component's key file
 * `tlsca`: the location of the certificate file for the CA that signed the
          certificates (i.e. openli-ca-crt.pem).
 * `tlsgroups`: optional -- restricts TLS key exchange to a specific list of
          groups. See the post-quantum cryptography section above.

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


