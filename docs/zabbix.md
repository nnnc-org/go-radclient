# Monitoring with Zabbix

The `--json` document is designed for the master item / dependent item pattern:
one item runs the probe and stores the whole document, and dependent items pull
individual metrics out of it with JSONPath. The probe runs once per interval no
matter how many metrics you track.

See [json-output.md](./json-output.md) for the full field reference.

## Recommended invocation

```bash
radius-client --json --udp-timeout 2s --udp-retries 2 \
    auth udp "$RADIUS_SERVER" "$SHARED_SECRET" eap-tls \
    --client-cert /etc/zabbix/probe.pem --ca-cert /etc/zabbix/server-ca.pem
```

Keep the total runtime inside the item timeout. The worst case is roughly
`--udp-timeout` × `--udp-retries` × (`--retries` + 1), plus the TLS handshake,
so the 5s default timeout with retries can exceed a 30s item timeout once
`--retries` is involved. `--json` already drops the send jitter to zero.

Pass the shared secret from a Zabbix macro (`{$RADIUS.SECRET}`) marked as a
secret macro, not as literal text in the item key. The same goes for
`--password`, which is **required** for password-based protocols here: an item
has no terminal, so the probe cannot prompt and reports a `config_error`
instead of hanging until the item times out. Running the same command by hand
in a terminal will prompt instead, which is handy for checking a probe before
wiring it up.

Do not use `--insecure` for monitoring. It still reports certificate expiry,
but `chain_valid` and `valid` become `null` because there is no trust anchor,
so any trigger on them can never fire. Point the probe at the real CA.

## Master item

Create an **external check** or **script** item:

- Type: *External check* (or *Script*)
- Key: `radius-client[...]` with the arguments above
- Type of information: *Text*
- Update interval: `5m` for a full authentication; `1m` is reasonable for a
  cheap `pap` probe

The item stores the whole document. Nothing else is written to stdout, so no
preprocessing is needed to isolate it.

## Dependent items

Each dependent item takes one preprocessing step, *JSONPath*, and a type of
information matching the value.

| Metric | JSONPath | Type |
|---|---|---|
| Authentication succeeded | `$.auth.success` | Numeric (unsigned) |
| Result | `$.auth.result` | Character |
| Failure stage | `$.auth.failure_stage` | Character |
| Error detail | `$.auth.error_message` | Text |
| RADIUS response code | `$.auth.response_code` | Character |
| Authentication duration | `$.auth.duration_ms` | Numeric (float) |
| Attempts needed | `$.auth.attempts` | Numeric (unsigned) |
| Probe ran | `$.probe.ran` | Numeric (unsigned) |
| Probe version | `$.probe.version` | Character |
| Total probe runtime | `$.probe.duration_ms` | Numeric (float) |
| Packets sent | `$.radius.packets_sent` | Numeric (unsigned) |
| Packets received | `$.radius.packets_received` | Numeric (unsigned) |
| Identifier mismatches | `$.radius.identifier_mismatches` | Numeric (unsigned) |
| TLS version | `$.tls.layers.eap.version` | Character |
| TLS handshake duration | `$.tls.layers.eap.handshake_duration_ms` | Numeric (float) |
| Session resumed | `$.tls.layers.eap.session_resumed` | Numeric (unsigned) |
| Server cert status | `$.tls.layers.eap.server_cert.status` | Character |
| Server cert valid | `$.tls.layers.eap.server_cert.valid` | Numeric (unsigned) |
| Server cert chain valid | `$.tls.layers.eap.server_cert.chain_valid` | Numeric (unsigned) |
| Server cert name match | `$.tls.layers.eap.server_cert.name_match` | Numeric (unsigned) |
| Server cert expires at | `$.tls.layers.eap.server_cert.expires_at` | Numeric (unsigned) |
| Server cert time remaining | `$.tls.layers.eap.server_cert.expires_in_seconds` | Numeric (float) |
| Server cert fingerprint | `$.tls.layers.eap.server_cert.sha256` | Character |
| Server cert subject | `$.tls.layers.eap.server_cert.subject` | Character |
| Chain expiry (excl. anchor) | `$.tls.layers.eap.server_cert.chain_expires_at` | Numeric (unsigned) |
| Client cert time remaining | `$.client_cert.expires_in_seconds` | Numeric (float) |
| Client cert valid now | `$.client_cert.valid_now` | Numeric (unsigned) |
| Client cert key match | `$.client_cert.key_match` | Numeric (unsigned) |

Replace `eap` with `radsec` for the transport certificate on the `tls`
subcommand, or `eap_inner` for the inner handshake of `eap-ttls-eap-tls`. The
layer keys are always present, so a path never stops resolving when you change
protocol — the layer simply reports `not_applicable`.

### Booleans and nulls

JSON `true`/`false` need a second preprocessing step, *Boolean to decimal*, on
numeric items.

A field that was not observed is `null`, which will not convert to a number.
That is intentional: after a timeout, `server_cert.valid` is `null` rather than
`false`, because nothing was learned about the certificate. On those items add
*Custom on fail → Discard value*, so the last good value is retained rather
than a timeout being recorded as an invalid certificate. Gate the trigger on
`$.tls.layers.eap.server_cert.status` instead, which is always a string.

## Triggers

**The server is not answering.** Catches outages without firing on a rejected
password.

```
last(/RADIUS/radius.auth.result)="timeout" or
last(/RADIUS/radius.auth.result)="connection_error"
```

**The authentication is failing for a real reason.** `auth.success` can be
false while the server returned an `Access-Accept` — the `--attrs-to-recv`
check and the session-key verification both run after acceptance — so include
the stage rather than triggering on `success` alone.

```
last(/RADIUS/radius.auth.success)=0 and
last(/RADIUS/radius.auth.response_code)<>"Access-Accept"
```

To catch the post-acceptance cases separately:

```
last(/RADIUS/radius.auth.response_code)="Access-Accept" and
last(/RADIUS/radius.auth.success)=0
```

**The server certificate is expiring.** Warn at 30 days, high at 7.

```
last(/RADIUS/radius.server_cert.expires_in_seconds)<30*86400
```

**The probe's own certificate is expiring.** The one that is easy to forget,
and it keeps working while the server is down.

```
last(/RADIUS/radius.client_cert.expires_in_seconds)<30*86400
```

**The certificate chain stopped validating.** Gated on status so that a
timeout, which leaves validity unknown, cannot fire it.

```
last(/RADIUS/radius.server_cert.status)="observed" and
last(/RADIUS/radius.server_cert.chain_valid)=0
```

**The certificate changed.** Useful for spotting an unplanned reissue.

```
change(/RADIUS/radius.server_cert.sha256)<>0
```

**The probe itself is broken.** Distinct from a server problem, and it needs an
operator rather than a network engineer. Note that exit code 2 also makes the
master item unsupported, so Zabbix's internal triggers will report it too; this
catches it from the data side when the document does get through.

```
last(/RADIUS/radius.probe.ran)=0
```

**Authentication got slow.** Compare against the trend rather than a fixed
threshold.

```
last(/RADIUS/radius.auth.duration_ms)>3*avg(/RADIUS/radius.auth.duration_ms,7d)
```

**Retries are needed.** An early warning of packet loss, before it becomes an
outage.

```
last(/RADIUS/radius.auth.attempts)>1
```

## A note on exit codes

Zabbix marks an item unsupported and discards stdout when the command exits
non-zero. This client exits 0 whenever the probe ran, including for a timeout
or a rejection, so that data always reaches the master item. Exit code 2 is
reserved for a probe that could not run, where an unsupported item is the
correct and visible outcome — but it does mean the explanatory document is only
visible when you run the command by hand.
