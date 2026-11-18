package metrics

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
)

// ranCollector returns a collector with one open attempt, i.e. a probe that
// actually reached the network.
func ranCollector() *Collector {
	c := New("test")
	c.BeginAttempt(0)
	return c
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	accessReject := func(c *Collector) { c.RecordResponse(3, "Access-Reject", true) }
	accessAccept := func(c *Collector) { c.RecordResponse(2, "Access-Accept", false) }
	mismatch := func(c *Collector) { c.RecordIdentifierMismatch() }
	atStage := func(s Stage) func(*Collector) { return func(c *Collector) { c.AdvanceStage(s) } }

	tests := []struct {
		name      string
		setup     []func(*Collector)
		err       error
		wantRes   Result
		wantStage Stage
	}{
		{
			name:      "success",
			setup:     []func(*Collector){atStage(StageRadiusResponse), accessAccept},
			err:       nil,
			wantRes:   ResultAccept,
			wantStage: StageRadiusResponse,
		},
		{
			name:      "observed reject is a reject",
			setup:     []func(*Collector){atStage(StageRadiusResponse), accessReject},
			err:       errors.New("pap: authentication failed"),
			wantRes:   ResultReject,
			wantStage: StageRadiusResponse,
		},
		{
			// The core guarantee: a site may claim a rejection, but without an
			// Access-Reject on the wire we only know the response was unusable.
			name:      "claimed reject without an Access-Reject is downgraded",
			setup:     []func(*Collector){atStage(StageInnerAuth)},
			err:       Wrap(StageInnerAuth, ResultReject, errors.New("authentication failed")),
			wantRes:   ResultProtocolError,
			wantStage: StageInnerAuth,
		},
		{
			name:      "timeout",
			setup:     []func(*Collector){atStage(StageRadiusResponse)},
			err:       timeoutErr{},
			wantRes:   ResultTimeout,
			wantStage: StageRadiusResponse,
		},
		{
			// Something answered, it just did not answer this request. Calling
			// that a timeout would be a misdiagnosis.
			name:      "identifier mismatch is not a timeout",
			setup:     []func(*Collector){atStage(StageRadiusResponse), mismatch},
			err:       timeoutErr{},
			wantRes:   ResultProtocolError,
			wantStage: StageRadiusResponse,
		},
		{
			name:      "wrapped timeout with a mismatch is also downgraded",
			setup:     []func(*Collector){atStage(StageRadiusResponse), mismatch},
			err:       Wrap(StageRadiusResponse, ResultTimeout, errors.New("did not get response from server")),
			wantRes:   ResultProtocolError,
			wantStage: StageRadiusResponse,
		},
		{
			name:      "tls handshake failure",
			setup:     []func(*Collector){atStage(StageTLS)},
			err:       Wrap(StageTLS, ResultTLSError, errors.New("handshake failure")),
			wantRes:   ResultTLSError,
			wantStage: StageTLS,
		},
		{
			name:      "connection failure",
			setup:     []func(*Collector){atStage(StageConnection)},
			err:       Wrap(StageConnection, ResultConnectionError, errors.New("connection refused")),
			wantRes:   ResultConnectionError,
			wantStage: StageConnection,
		},
		{
			// An Access-Accept followed by a failed --attrs-to-recv check is a
			// protocol problem, not a rejection and not an outage.
			name:      "missing expected attributes after an accept",
			setup:     []func(*Collector){atStage(StageRadiusResponse), accessAccept},
			err:       Wrap(StageRadiusResponse, ResultProtocolError, errors.New("expected attributes were missing")),
			wantRes:   ResultProtocolError,
			wantStage: StageRadiusResponse,
		},
		{
			name:      "unwrapped error lands at the high-water stage",
			setup:     []func(*Collector){atStage(StageEAPNegotiation)},
			err:       errors.New("something unrecognized"),
			wantRes:   ResultProtocolError,
			wantStage: StageEAPNegotiation,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := ranCollector()
			for _, s := range tc.setup {
				s(c)
			}
			gotRes, gotStage := c.Classify(tc.err)
			if gotRes != tc.wantRes {
				t.Errorf("result = %q, want %q", gotRes, tc.wantRes)
			}
			if gotStage != tc.wantStage {
				t.Errorf("stage = %q, want %q", gotStage, tc.wantStage)
			}
		})
	}
}

// A failure before any attempt began is our own misconfiguration, not an
// observation about the server.
func TestClassifyBeforeProbeRanIsConfigError(t *testing.T) {
	c := New("test")
	res, stage := c.Classify(errors.New("open /nope: no such file or directory"))
	if res != ResultConfigError {
		t.Errorf("result = %q, want %q", res, ResultConfigError)
	}
	if stage != StageConfig {
		t.Errorf("stage = %q, want %q", stage, StageConfig)
	}
}

// The stage high-water mark must never move backwards, so a late generic error
// is not attributed to an early stage.
func TestStageHighWaterMarkOnlyAdvances(t *testing.T) {
	c := ranCollector()
	c.AdvanceStage(StageConnection)
	c.AdvanceStage(StageRadiusResponse)
	c.AdvanceStage(StageTLS)

	_, stage := c.Classify(errors.New("boom"))
	if stage != StageRadiusResponse {
		t.Errorf("stage = %q, want %q", stage, StageRadiusResponse)
	}
}

func TestAlertOfReceivedAlert(t *testing.T) {
	// This is the shape crypto/tls produces for an alert received from a peer.
	err := fmt.Errorf("handshake: %w", &net.OpError{
		Op:  "remote error",
		Err: errors.New("tls: bad certificate"),
	})

	a, ok := AlertOf(err)
	if !ok {
		t.Fatal("AlertOf did not recognize a received alert")
	}
	if a.Description != "bad certificate" {
		t.Errorf("description = %q, want %q", a.Description, "bad certificate")
	}
	if !a.Received || !a.CertRelated {
		t.Errorf("received = %v, certRelated = %v, want both true", a.Received, a.CertRelated)
	}
	if !PeerRejectedOurCert(err) {
		t.Error("a received bad-certificate alert does prove the peer rejected our cert")
	}
}

func TestPeerRejectedOurCertRequiresProof(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"generic handshake failure proves nothing",
			&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")},
			false,
		},
		{
			"timeout proves nothing",
			timeoutErr{},
			false,
		},
		{
			"plain error proves nothing",
			errors.New("eap tls: server sent a failure packet"),
			false,
		},
		{
			// Our own rejection of the server chain is the opposite direction
			// and must never be reported as the peer rejecting us.
			"our own verification failure proves nothing",
			&tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{}, Err: errors.New("x509: unknown authority")},
			false,
		},
		{
			"unknown CA alert is proof",
			&net.OpError{Op: "remote error", Err: errors.New("tls: unknown certificate authority")},
			true,
		},
		{
			"certificate required alert is proof",
			&net.OpError{Op: "remote error", Err: errors.New("tls: certificate required")},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PeerRejectedOurCert(tc.err); got != tc.want {
				t.Errorf("PeerRejectedOurCert = %v, want %v", got, tc.want)
			}
		})
	}
}
