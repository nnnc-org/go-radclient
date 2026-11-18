# JSON metrics output

`--json` turns the client into a monitoring probe: instead of logging text it
writes a single JSON document to stdout describing what happened. It is
currently supported on the `authentication` command only; using it with
`accounting` or `status` fails with exit code 2 rather than printing text a
parser cannot read.

```bash
radius-client --json auth udp "$SERVER" "$SECRET" eap-tls \
    --client-cert ./probe.pem --ca-cert ./server-ca.pem
```

See [zabbix.md](./zabbix.md) for wiring this into Zabbix.

## Two guarantees worth knowing

**Authentication success and certificate validity are independent.** A wrong
password can follow a perfectly valid server certificate, so `auth.success`
being `false` says nothing about `server_cert.valid`, and vice versa. If the
exchange never got far enough to see a certificate, its status is reported as
`unavailable` — unknown — and never as invalid. A timeout is not evidence of a
certificate problem.

**Causes are not guessed.** `auth.result` is only `reject` when an
`Access-Reject` packet was actually received. A failed TLS handshake, a
timeout, or a tunnel torn down mid-exchange is reported as `tls_error` or
`timeout`, never as the server rejecting the credentials or the certificate we
presented. Likewise `peer_cert_rejected` is only `true` when the peer sent a
TLS alert that names a certificate problem, which is the one case where the
claim is proved rather than inferred.

## Reading the document

Every key documented here is **always present**. A fact that was not observed
is `null`, never omitted and never `false` — an absent key would make a
dependent item go unsupported, and a `false` would assert something that was
never measured. Timestamps are Unix seconds; durations are float milliseconds.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The probe ran. Whatever the server said is in the document, including a rejection or a timeout. |
| 2 | The probe could not run: bad flag, unreadable certificate or CA file, `--json` on an unsupported command, or a recovered internal failure. |

A server being down is **exit 0** with `auth.result: "timeout"`, because that
is data. Exit 2 means the probe itself is broken and needs an operator.

Without `--json` the original behavior is unchanged: text to stderr, exit 0 or 1.

### `probe`

| Field | Meaning |
|---|---|
| `version` | Build identity. A release tag when installed with `go install module@vX.Y.Z`, otherwise `devel-<commit>` or the value stamped by the Makefile. |
| `command`, `subcommand`, `protocol`, `transport`, `target` | What was probed. `transport` is `udp` or `radsec`. |
| `ran` | `false` only when the probe could not run, matching exit code 2. |
| `started_at`, `duration_ms` | Whole-process timing, including flag parsing and certificate loading. |
| `panic` | Set only if the probe recovered from an internal failure. |

`schema_version` sits at the top level and changes only on a breaking schema
change, so templates can gate on it independently of `probe.version`.

### `auth`

| Field | Meaning |
|---|---|
| `success` | Whether the complete authentication succeeded. |
| `result` | `accept`, `reject`, `timeout`, `tls_error`, `protocol_error`, `connection_error`, `config_error`, or `internal_error`. |
| `failure_stage` | `config`, `connection`, `tls`, `eap_negotiation`, `inner_auth`, or `radius_response`. `null` on success. |
| `error_message` | One line, secrets removed. `null` on success. |
| `response_code` | The RADIUS code actually received, e.g. `Access-Accept`. `null` if nothing arrived. |
| `duration_ms` | Sum of all attempt durations, including retries. Covers dialling, TLS and every round trip. Excludes the sleep between attempts. |
| `duration_excl_jitter_ms` | The same with the deliberate send jitter subtracted. |
| `attempts` | Number of attempts made; greater than 1 means a retry was needed. |
| `close_error` | Failure closing the session, kept separate so it cannot look like a failed authentication. |

`timeout` means nothing answered. `connection_error` means nothing is
listening, or the transport could not be established — a different problem.

> **A case worth building a trigger around.** `auth.success` can be `false`
> while `auth.response_code` is `Access-Accept`. Both the `--attrs-to-recv`
> check and the MS-MPPE session-key verification run *after* the server has
> accepted, and `result` is then `protocol_error` at stage `radius_response`.
> A trigger on `success == false` alone would read that as an outage.

### `radius`

| Field | Meaning |
|---|---|
| `packets_sent` | RADIUS datagrams written, including EAP fragments and retransmissions. |
| `packets_received` | RADIUS datagrams read. |
| `identifier_mismatches` | Replies that did not match the outstanding request. Non-zero means something answered but not to the point, which would otherwise be indistinguishable from a timeout. |
| `jitter_total_ms` | How much of the elapsed time was our own deliberate send jitter. |

### `tls.layers`

One entry per possible handshake, keyed by name so a JSONPath always refers to
the same handshake whatever the protocol:

| Layer | What it is | Used by |
|---|---|---|
| `radsec` | The RADIUS-over-TLS transport certificate | the `tls` subcommand |
| `eap` | The certificate a supplicant validates: plain EAP-TLS, or the PEAP / EAP-TTLS tunnel | `eap-tls`, `peap-*`, `eap-ttls-*` |
| `eap_inner` | An inner EAP-TLS handshake inside an EAP-TTLS tunnel | `eap-ttls-eap-tls` only |

Each layer has a `status`:

- `observed` — we handshaked and have data.
- `not_applicable` — this protocol performs no such handshake, so its absence
  says nothing. `mab`, `pap`, `eap-ms-chapv2` and `mab-eap-md5` over UDP
  terminate no TLS at all.
- `unavailable` — it should have happened but the exchange did not get that
  far. **Unknown, not broken.**

| Field | Meaning |
|---|---|
| `version` | Negotiated TLS version, e.g. `1.2`. |
| `cipher_suite` | Negotiated cipher suite name. |
| `session_resumed` | Whether the session was resumed rather than fully handshaked. Expect `false`: no session cache is configured and tunnel tickets are disabled. |
| `handshake_duration_ms` | TLS setup only. For EAP layers this necessarily includes the RADIUS round trips that carry the handshake fragments, which is the useful figure. |
| `handshake_duration_excl_jitter_ms` | The same with send jitter subtracted. |
| `handshake_error` | Why the handshake failed, if it did. |
| `alert` | Description of a TLS alert received from the peer, e.g. `bad certificate`. |
| `peer_cert_rejected` | `true` only when a received alert names a certificate problem. |
| `server_cert`, `client_cert` | Certificates seen on this layer. |

### Certificate objects

`client_cert` also appears at the top level, flattened: there is one
certificate whose expiry an operator cares about, the probe's own. It is
parsed **before dialling**, so its expiry is still reported when the server is
unreachable — which is exactly when you need the warning.

| Field | Meaning |
|---|---|
| `status` | `observed`, `not_applicable`, or `unavailable`, as above. |
| `role`, `layer` | `server` or `client`, and which handshake it came from. |
| `valid` | Chains to the configured CA, inside its validity window, and matches the expected name. **Not** "valid per the system trust store". |
| `chain_valid` | Whether a trusted chain could be built against the CA given on the command line. |
| `name_match` | Whether the certificate matches the expected server name. `null` when there was no name to check, and for client certificates. Reported even under `--tls-skip-hostname-check`: observed, not enforced. |
| `valid_now` | Whether the clock is inside `not_before`..`expires_at`. Reported separately from `chain_valid` because an expired certificate also fails chain verification, and "chain invalid" alone does not tell you why. |
| `key_match` | Client certificates only: whether the configured private key matched. `null` when the file could not be read at all, since that proves nothing about the key. |
| `verify_error` | Why chain verification failed, if it did. |
| `not_before`, `expires_at`, `expires_in_seconds` | Validity window. `expires_in_seconds` goes negative once expired. |
| `chain_expires_at` | Earliest expiry in the chain **excluding the trust anchor**, whose expiry is yours to manage rather than the server's. |
| `subject`, `issuer` | RFC 2253 distinguished names. |
| `serial` | Lowercase hex, the same value `openssl x509 -serial` prints (that prints uppercase). |
| `sha256` | Lowercase hex fingerprint of the DER, for detecting a certificate change. |
| `dns_names` | Subject alternative DNS names. |
| `chain` | Every presented certificate, leaf first, each with its own subject, issuer, serial, fingerprint, dates and `is_ca`. This is where intermediate and root details live. |

Certificate details are recorded **even when verification fails**, which is
what keeps "the server certificate expired" distinguishable from "the server
was unreachable".

### `attempts`

One entry per pass through the retry loop, each with its own `index`,
`started_at`, `duration_ms`, `duration_excl_jitter_ms`, `success`, `result`,
`failure_stage`, `error_message`, `response_code`, `packets_sent` and
`packets_received`. The top-level `auth` reflects the final attempt, except the
durations, which sum.

## Send jitter

By default the client sleeps a random 50ms–1s before *every* packet write. On
an EAP exchange of a dozen round trips that is seconds of deliberate sleep,
which would dominate any latency metric. **`--json` therefore defaults both
`--min-send-jitter` and `--max-send-jitter` to `0s`**, while still honouring
either if you pass it explicitly. Whatever jitter does occur is reported in
`radius.jitter_total_ms`, and every duration has an `_excl_jitter_ms` sibling.

## Secrets

The shared secret, `--password`, the RadSec literal secret and any value passed
via `--attrs-to-send` are replaced with `***` anywhere they would appear in the
document. The username, MAC address and target address are not treated as
secrets, because they are what makes an error diagnosable.

Secrets of six characters or more are replaced wherever they appear; shorter
ones are replaced only where they stand as a whole token, so that a two
character password cannot shred the surrounding text.
