/*
Copyright © 2025

Projection of collected observations into the emitted Document.

The flattening rules are a deliberate choice and are documented for template
authors:

  - auth.* reflects the final attempt, since that is the outcome the command
    returned. The exception is the durations, which sum every attempt.
  - radius.* sums all attempts; per-attempt detail stays in attempts[].
  - tls.* reports the last attempt that observed a handshake, because an expiry
    trigger wants the most recent observation.
*/
package metrics

import "time"

// Document projects everything collected so far. It is safe to call on a
// partially completed run, which is what makes emission on the panic path
// possible.
func (c *Collector) Document() Document {
	doc := Document{
		SchemaVersion: SchemaVersion,
		Attempts:      []Attempt{},
		TLS:           TLS{Layers: map[Layer]TLSLayer{}},
		ClientCert:    notApplicableCert(RoleClient),
	}
	if c == nil {
		doc.Probe.Ran = false
		doc.Auth.Result = ResultInternalError
		for _, l := range AllLayers {
			doc.TLS.Layers[l] = notApplicableLayer()
		}
		return doc
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	doc.Probe = Probe{
		Version:    c.version,
		Command:    c.command,
		Subcommand: c.subcommand,
		Protocol:   c.protocol,
		Transport:  c.transport,
		Target:     c.target,
		Ran:        c.ran,
		StartedAt:  c.start.Unix(),
		DurationMs: millis(time.Since(c.start)),
		Panic:      c.panicMsg,
	}

	var (
		totalDuration time.Duration
		totalJitter   time.Duration
	)
	for _, a := range c.attempts {
		totalDuration += a.duration
		totalJitter += a.jitter
		doc.RADIUS.PacketsSent += a.sent
		doc.RADIUS.PacketsReceived += a.received
		doc.RADIUS.IdentifierMismatches += a.idMismatch

		at := Attempt{
			Index:                a.index,
			StartedAt:            a.started.Unix(),
			DurationMs:           millis(a.duration),
			DurationExclJitterMs: millis(a.duration - a.jitter),
			Success:              a.success,
			Result:               a.result,
			ErrorMessage:         a.errMsg,
			ResponseCode:         a.responseCode,
			PacketsSent:          a.sent,
			PacketsReceived:      a.received,
		}
		if a.hasStage {
			s := a.stage
			at.FailureStage = &s
		}
		doc.Attempts = append(doc.Attempts, at)
	}
	doc.RADIUS.JitterTotalMs = millis(totalJitter)

	doc.Auth = Auth{
		DurationMs:           millis(totalDuration),
		DurationExclJitterMs: millis(totalDuration - totalJitter),
		Attempts:             len(c.attempts),
		CloseError:           c.closeErr,
	}
	switch {
	case c.panicMsg != nil:
		// The probe itself broke. Not an observation about the server.
		doc.Auth.Result = ResultInternalError
		doc.Auth.Success = false
		doc.Auth.ErrorMessage = c.panicMsg
		doc.Probe.Ran = false
	case len(c.attempts) == 0:
		doc.Auth.Result = ResultConfigError
		doc.Auth.Success = false
		doc.Auth.ErrorMessage = c.configErr
		stage := StageConfig
		doc.Auth.FailureStage = &stage
		doc.Probe.Ran = false
	default:
		last := c.attempts[len(c.attempts)-1]
		doc.Auth.Success = last.success
		doc.Auth.Result = last.result
		doc.Auth.ErrorMessage = last.errMsg
		doc.Auth.ResponseCode = last.responseCode
		if !last.success && last.hasStage {
			s := last.stage
			doc.Auth.FailureStage = &s
		}
		// A config error can surface part way into an attempt, for instance an
		// unreadable CA file. It still means the probe could not run, so it
		// must not be reported as an observation about the server.
		if last.result == ResultConfigError {
			doc.Probe.Ran = false
		}
	}

	for _, l := range AllLayers {
		doc.TLS.Layers[l] = c.projectLayerLocked(l)
	}
	if c.clientCert != nil {
		doc.ClientCert = *c.clientCert
	}
	return doc
}

func (c *Collector) projectLayerLocked(l Layer) TLSLayer {
	rec, ok := c.layers[l]
	if !ok {
		if c.expected[l] {
			// We should have handshaked here but never did, so its state is
			// unknown rather than inapplicable.
			return unavailableLayer()
		}
		return notApplicableLayer()
	}

	out := TLSLayer{
		Status:           StatusObserved,
		Version:          rec.version,
		CipherSuite:      rec.cipherSuite,
		SessionResumed:   rec.resumed,
		HandshakeError:   rec.hsError,
		Alert:            rec.alert,
		PeerCertRejected: rec.peerRejectedUs,
		ServerCert:       UnavailableCert(RoleServer),
		ClientCert:       notApplicableCert(RoleClient),
	}
	if !rec.observed {
		// The handshake was attempted but produced nothing usable.
		out.Status = StatusUnavailable
	}
	if rec.hsDuration != nil {
		d := millis(*rec.hsDuration)
		out.HandshakeDurationMs = &d
		e := millis(*rec.hsDuration - rec.hsJitter)
		out.HandshakeDurationExclJitMs = &e
	}
	if rec.serverCert != nil {
		out.ServerCert = *rec.serverCert
	}
	if rec.clientCert != nil {
		out.ClientCert = *rec.clientCert
	}
	return out
}

func unavailableLayer() TLSLayer {
	return TLSLayer{
		Status:     StatusUnavailable,
		ServerCert: UnavailableCert(RoleServer),
		ClientCert: UnavailableCert(RoleClient),
	}
}

// millis renders a duration as float milliseconds. Integers would floor a
// sub-millisecond RadSec round trip to zero.
func millis(d time.Duration) float64 {
	if d < 0 {
		d = 0
	}
	return float64(d.Microseconds()) / 1000
}
