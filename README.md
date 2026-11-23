# Keytos' RADIUS Client

A RADIUS client that can carry out the following authentication protocols:

- `mab` (MAC address authentication bypass)
- `pap`
- `eap-ms-chapv2`
- `eap-tls`
- `eap-ttls-pap`
- `eap-ttls-eap-ms-chapv2`
- `eap-ttls-eap-tls`
- `peap-ms-chapv2`

As well as `status` packets and accounting (WIP).

This is used internally at Keytos to thoroughly test [EZRADIUS](https://www.keytos.io/cloud-radius-as-a-service-for-azure-and-entra-id).
This client seeks to close the gap from existing testing clients such as [`radclient`](https://wiki.freeradius.org/config/Radclient)
and [`eapol_test`](https://manpages.debian.org/testing/eapoltest/eapol_test.8.en.html),
by first consolidating the capabilities of both tools into one, and then extending
the tool to support [RADIUS-over-TLS (RadSec)](https://datatracker.ietf.org/doc/html/rfc6614)
and simple, granular controls for Keytos' use-cases.

## Usage

To install the tool locally for use, you can run the following command

```bash
go install github.com/nnnc-org/go-radclient@latest
```

To install a specific version, replace `latest` with a version
```bash
go install github.com/nnnc-org/go-radclient@vX.X.X
```

#### With Nix

A flake is provided, so no Go toolchain needs to be installed:

```bash
# Run it directly
nix run github:nnnc-org/go-radclient -- --json auth udp "$SERVER" "$SECRET" pap \
    --username "$USER" --password "$PASS"

# Or add it to a profile
nix profile install github:nnnc-org/go-radclient
```

From a checkout, `nix develop` gives a shell with the Go toolchain,
`golangci-lint`, a C compiler for `go test -race`, plus `jq` and `openssl` for
working with the JSON output and test certificates:

```bash
nix develop
make          # build ./bin/radius-client
make test     # go test -race ./...
make checks   # fmt, vet, tidy, lint, test
```

`nix build` produces `./result/bin/radius-client`, and `nix flake check` runs
the test suite.

### Status

If the RADIUS server you are probing supports [`Status-Server`](https://datatracker.ietf.org/doc/html/rfc5997),
you can probe the server with the following commands:

```bash
# Test UDP authentication
radius-client status udp-auth $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# Test UDP accounting
radius-client status udp-acct $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# Test RADIUS TLS
radius-client status tls $RADIUS_SERVER_ENDPOINT $RADSEC_SERVER_CA_PATH $RADSEC_CLIENT_CERT_PATH
```

You can change the specific ports away from defaults if desired with the following
flags:

- `--udp-auth-port` (default is 1812)
- `--udp-acct-port` (default is 1813)
- `--tcp-port` (default is 2083)

### Authentication

All authentication protocols supported by this client can be tested against a Classic
RADIUS endpoint (unencrypted RADIUS over UDP), or over RadSec (encrypted and authenticated
RADIUS over TCP-TLS).

The following examples will assume that either of the following is exported:

```bash
# Classic RADIUS
export RADIUS_AUTH_COMMAND=radius-client authentication udp \
    $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# If you want to test RadSec (RADIUS over TCP-TLS), use:
export RADIUS_AUTH_COMMAND=radius-client authentication tls \
    $RADIUS_SERVER_ENDPOINT $RADSEC_SERVER_CA_PATH $RADSEC_CLIENT_CERT_PATH
```

If you do not need to trust the RadSec server certificate, you can append the `--radsec-unsafe`
flag. This flag will skip server authentication.

#### MAC Authentication Bypass

To test MAC authentication bypass, run the following:

```bash
$RADIUS_AUTH_COMMAND mab --mac $MAC_ADDRESS
```

#### Password-based Authentication

To test basic password authentication, you can use the following:

```bash
# Testing PAP
$RADIUS_AUTH_COMMAND pap --username $USERNAME --password $PASSWORD

# Testing MS-CHAP-V2
$RADIUS_AUTH_COMMAND eap-ms-chapv2 --username $USERNAME --password $PASSWORD
```

If you leave `--password` off, you will be prompted for it, without echo:

```bash
$ $RADIUS_AUTH_COMMAND pap --username $USERNAME
Password for alice:
```

Whether it prompts turns on one question: is there a terminal to prompt on.
It prompts in `--json` mode too, so the metrics document can be inspected
interactively without putting a password in the shell history -- the prompt
goes to stderr, so stdout still carries only the document.

With no terminal it refuses, with an explanation, rather than hanging. That is
the case that matters for a monitoring probe: a prompt there would block until
the item timed out on every run, and reading from a pipe would silently consume
input meant for something else. So an unattended probe must pass `--password`.

For password-based authentication schemes that run over an internal TLS tunnel, here
are the commands to test them:

```bash
# Testing PAP over EAP-TTLS
$RADIUS_AUTH_COMMAND eap-ttls-pap --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --username $USERNAME --password $PASSWORD

# Testing MS-CHAP-V2 over EAP-TTLS
$RADIUS_AUTH_COMMAND eap-ttls-eap-ms-chapv2 --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --username $USERNAME --password $PASSWORD

# Testing MS-CHAP-V2 over PEAP
$RADIUS_AUTH_COMMAND peap-ms-chapv2 --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --username $USERNAME --password $PASSWORD
```

#### Certificate-based Authentication

Two variants of TLS can be tested, basic EAP-TLS and EAP-TLS inside a EAP-TTLS tunnel:

```bash
# Testing EAP-TLS
$RADIUS_AUTH_COMMAND eap-tls --client-cert $CLIENT_CERT_PATH --ca-cert $SERVER_CA_CERT_PATH

# Testing EAP-TLS over EAP-TTLS
$RADIUS_AUTH_COMMAND eap-tls --tunnel-ca-cert $SERVER_CA_CERT_PATH \
    --client-cert $CLIENT_CERT_PATH --ca-cert $SERVER_CA_CERT_PATH
```

The default TLS version supported is 1.2, 1.3 is supported but has not been tested,
and it can be enabled by adding the flag `--tls-version 1.X`.

#### Checking the server certificate name

By default the server's chain is verified against `--ca-cert` (or
`--tunnel-ca-cert`) but its *name* is not checked, which is what `eapol_test`
does unless you give it `domain_suffix_match`. Pass `--server-name` to check
the name as well:

```bash
$RADIUS_AUTH_COMMAND eap-tls --client-cert $CLIENT_CERT_PATH \
    --ca-cert $SERVER_CA_CERT_PATH --server-name radius.example.org
```

The name has to be stated because there is nothing to derive it from. EAP
carries no SNI, and the address you dial is a RADIUS hop rather than the EAP
server — in a roaming federation such as eduroam you reach a top-level proxy,
whose certificate belongs to the home institution's server and so matches
neither the proxy's hostname nor its IP.

Either way the name is reported under `--json` as `name_match`; with no
`--server-name` it stays `null`, meaning unknown rather than mismatched.
`--tls-skip-hostname-check` drops the check even when a name is supplied,
leaving chain verification in place.

#### Skipping server verification

`--insecure` turns off server certificate verification at every layer. It makes
`--ca-cert` and `--tunnel-ca-cert` optional, causes the RadSec `SERVER_CA`
argument to be ignored, and implies `--radsec-unsafe`:

```bash
# Inspect a server's certificate without setting up a CA first
$RADIUS_AUTH_COMMAND peap-ms-chapv2 --insecure --username $USERNAME --password $PASSWORD
```

The server certificate is still reported in full under `--json` — subject,
serial, expiry, fingerprint, name match — which is the usual reason to reach
for the flag. What cannot be reported is validity: with no trust anchor there
is nothing to verify against, so `chain_valid` and `valid` come back as `null`
rather than `true`. Use it to look, not to monitor.

### Attributes

RADIUS servers can be configured to expect and behave differently depending on the
set of attributes sent. This can be tested and verified by defining attributes that
the client should send in every packet in the handshake, and all the attributes it
expects to receive in a successful final packet.

- `--attrs-to-send`: Define attributes to be sent in all packets sent to the server
- `--attrs-to-recv`: Define attributes that the server must send on successful handshakes

These can be used in the following format:

```bash
$RADIUS_AUTH_COMMAND $AUTHENTICATION_PROTOCOL $AUTHENTICATION_PROTOCOL_PARAMETERS \
    --attrs-to-send $ATTRIBUTE_TYPE:$ATTRIBUTE_VALUE \
    --attrs-to-recv $ATTRIBUTE_TYPE:$ATTRIBUTE_VALUE
```

> [!NOTE]
> Keep in mind that some attributes should not be sent as they may be utilized by
> the authentication protocol and will be overwritten or require different treatment,
> such as `User-Password`.

You can also send multiple attributes and expect multiple attributes. Each attribute
type cannot be defined more than once for each direction for simplicity's sake. Below
is an example of how to define multiple attributes to be sent and received in `pap`
authentication:

```bash
$RADIUS_AUTH_COMMAND pap --username test_user --password test_password \
    --attrs-to-send NAS-Identifier:fake-router \
    --attrs-to-send Framed-Protocol:PPP \
    --attrs-to-recv Framed-Protocol:PPP \
    --attrs-to-recv Service-Type:Framed \
    --attrs-to-recv Filter-Id:20
```

In the example above, the client attempts to authenticate with `pap`, sends two
additional attributes to the server, and expects three attributes from the server
in the `Access-Accept` packet.

You can view all attributes and their values can be defined in this [document](./RADIUS_ATTRIBUTES.md).

### Packet tracing

`-v` traces every packet to stderr as it goes past: the RADIUS code, identifier
and decoded attributes, and the EAP code, identifier and type carried inside
them. For the TLS based EAP types each line also names the EAP-TLS flags, the
announced handshake length and the size of the fragment, which is what a
handshake that stalls mid-exchange looks like. Repeat it (`-vv`) to add a hex
dump of every packet.

```bash
$RADIUS_AUTH_COMMAND eap-tls --client-cert $CLIENT_CERT --ca-cert $CA_CERT -v
```

```text
[   0.001] eap       --> Response id=251 len=14 type=Identity(1)
             identity = "anonymous"
[   0.001] radius    --> Access-Request id=169 len=86
             EAP-Message = 0x02fb000e01616e6f6e796d6f7573
             NAS-Identifier = "radius-client"
             User-Name = "anonymous"
[   0.112] radius    <-- Access-Challenge id=169 len=64
             EAP-Message = 0x010100061520
[   0.112] eap       <-- Request id=1 len=6 type=PEAP(25)
             flags = S (0x20)
             tls-fragment = 0 bytes
```

Lines marked `!!` are not packets but the events between them: a read that
timed out, a retransmission, a reply that answered a different request. An
inner EAP conversation inside a PEAP or EAP-TTLS tunnel is traced under
`eap-inner`, so the tunnelled exchange stays distinguishable from the outer
one.

The trace always goes to stderr, so it can be combined with `--json`, which
keeps stdout to itself. The shared secret and the password are redacted in the
trace the same way they are in the JSON document. Values passed through
`--attrs-to-send` are not: showing what was actually sent is the point of the
flag.

### JSON metrics output

Adding `--json` makes the client behave as a monitoring probe: instead of
logging text it writes a single JSON document to stdout describing the
authentication — outcome, timing, where it failed, and certificate validity and
expiry for every TLS layer in the exchange.

```bash
radius-client --json auth udp "$RADIUS_SERVER" "$SHARED_SECRET" eap-tls \
    --client-cert ./probe.pem --ca-cert ./server-ca.pem
```

```json
{
  "schema_version": 1,
  "probe": { "version": "v1.0.0", "protocol": "eap-tls", "ran": true, "duration_ms": 437.218 },
  "auth": { "success": true, "result": "accept", "response_code": "Access-Accept", "duration_ms": 388.1, "attempts": 1 },
  "radius": { "packets_sent": 12, "packets_received": 11, "jitter_total_ms": 0 },
  "tls": { "layers": { "eap": {
      "status": "observed", "version": "1.2", "handshake_duration_ms": 142.55,
      "server_cert": { "status": "observed", "valid": true, "expires_in_seconds": 29518400,
                       "subject": "CN=radius.example.com", "sha256": "9f86d081..." } } } },
  "client_cert": { "status": "observed", "valid_now": true, "expires_in_seconds": 14518400 }
}
```

Without the flag, output and exit codes are unchanged.

Two things the document is careful about:

- **Authentication success and certificate validity are separate.** A wrong
  password can follow a perfectly valid certificate. If the exchange never got
  far enough to see a certificate, its status is `unavailable` — unknown — and
  never invalid.
- **Causes are not guessed.** `auth.result` is `reject` only when an
  `Access-Reject` actually arrived. A failed handshake or a timeout is reported
  as `tls_error` or `timeout`, never as the server rejecting what we presented.

Exit codes in JSON mode: **0** when the probe ran, whatever the server said —
including a timeout, which is data. **2** only when the probe could not run,
such as a bad flag or an unreadable certificate. A probe that exits non-zero
loses its output in most monitoring systems, so a server being down must not
be reported that way.

`--json` also defaults `--min-send-jitter` and `--max-send-jitter` to `0s`,
since the usual 50ms–1s sleep before every packet would otherwise dominate the
latency figures. An explicit value is still honoured.

It currently applies to the `authentication` command; `accounting` and `status`
fail with exit code 2 rather than printing unparseable text.

- [Full field reference](./docs/json-output.md)
- [Zabbix items and triggers](./docs/zabbix.md)

### Accounting

Accounting can be tested against a Classic RADIUS endpoint and RadSec.

The following examples will assume that either of the following is exported:

```bash
# Classic RADIUS
export RADIUS_ACCT_COMMAND=radius-client accounting udp \
    $RADIUS_SERVER_ENDPOINT $SHARED_SECRET

# If you want to test RadSec (RADIUS over TCP-TLS), use:
export RADIUS_ACCT_COMMAND=radius-client accounting tls \
    $RADIUS_SERVER_ENDPOINT $RADSEC_SERVER_CA_PATH $RADSEC_CLIENT_CERT_PATH
```

An accounting request **must** contain both `Acct-Status-Type` and `Acct-Session-Id`
attributes. These are passed via the `--attrs-to-send` flag. For example:

```bash
$RADIUS_ACCT_COMMAND --attrs-to-send Acct-Status-Type:Start --attrs-to-send Acct-Session-Id:1234
```

Additional accounting values can be passed by adding the other accounting attributes,
which can be found in [the list of attributes](./RADIUS_ATTRIBUTES.md). Accounting-specific
attributes generally have a `Acct-` prefix.

## Relevant RFCs And Documents

- [RFC 2759: MS-CHAP-V2](https://datatracker.ietf.org/doc/html/rfc2759)
- [RFC 2865: RADIUS](https://datatracker.ietf.org/doc/html/rfc2865)
- [RFC 2866: RADIUS Accounting](https://datatracker.ietf.org/doc/html/rfc2866)
- [RFC 3579: RADIUS EAP](https://datatracker.ietf.org/doc/html/rfc3579)
- [RFC 3748: EAP](https://datatracker.ietf.org/doc/html/rfc3748)
- [RFC 5080: Common RADIUS Implementation Issues and Suggested Fixes](https://datatracker.ietf.org/doc/html/rfc5080)
- [RFC 5216: EAP-TLS](https://datatracker.ietf.org/doc/html/rfc5216)
- [RFC 5281: EAP-TTLS](https://datatracker.ietf.org/doc/html/rfc5281)
- [RFC 5997: Status in RADIUS](https://datatracker.ietf.org/doc/html/rfc5997)
- [RFC 8940: Session-Id Derivation for EAP-based Authentication](https://datatracker.ietf.org/doc/html/rfc8940)
- [PEAP](https://datatracker.ietf.org/doc/html/draft-josefsson-pppext-eap-tls-eap-06)
- [MAC Authentication Bypass](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/15-sy/sec-usr-aaa-15-sy-book/sec-usr-mac-auth-bypass.pdf)
