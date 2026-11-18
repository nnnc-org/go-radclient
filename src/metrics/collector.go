/*
Copyright © 2025

The Collector gathers observations during a probe run and projects them into a
Document at the end.

Design notes:

  - Every method is safe on a nil receiver, so instrumentation call sites deep
    in the radius and eap packages stay one-liners with no guards, and a run
    with no collector attached behaves identically.
  - This package imports nothing from this module. That is what lets both
    radius and eap import it without an import cycle, and it is why the RADIUS
    response code arrives here as a plain uint8 plus its name.
  - Counters are per attempt and summed at projection time. TLS layer
    observations are kept at collector scope, so the last attempt that saw a
    certificate is the one reported -- an expiry trigger wants the most recent
    observation, not the first.
*/
package metrics

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"
)

// Collector accumulates probe observations.
type Collector struct {
	mu sync.Mutex

	// redactor is applied to every string that enters the document.
	redactor *Redactor

	version    string
	command    string
	subcommand string
	protocol   string
	transport  string
	target     string

	start    time.Time
	ran      bool
	panicMsg *string
	closeErr *string
	// configErr holds a failure that happened before any attempt started.
	configErr *string

	attempts []*attempt
	cur      *attempt

	layers map[Layer]*layerRec
	// expected records the layers this protocol should produce, so a layer
	// that never materialized can be reported as unavailable (unknown) rather
	// than not_applicable (nothing to know).
	expected map[Layer]bool

	clientCert      *CertInfo
	clientCertLayer Layer
}

type attempt struct {
	index      int
	started    time.Time
	duration   time.Duration
	jitter     time.Duration
	sent       int
	received   int
	idMismatch int

	stage    Stage
	hasStage bool

	responseCode *string
	// sawReject means the server explicitly rejected: an Access-Reject, or a
	// tunnelled result TLV reporting failure.
	sawReject bool

	result   Result
	errMsg   *string
	success  bool
	finished bool
}

type layerRec struct {
	observed bool

	version        *string
	cipherSuite    *string
	resumed        *bool
	hsDuration     *time.Duration
	hsJitter       time.Duration
	hsError        *string
	alert          *string
	peerRejectedUs *bool

	serverCert *CertInfo
	clientCert *CertInfo
}

// New returns a Collector. version ends up in probe.version.
func New(version string) *Collector {
	return &Collector{
		redactor: &Redactor{},
		version:  version,
		start:    time.Now(),
		layers:   make(map[Layer]*layerRec),
		expected: make(map[Layer]bool),
	}
}

// AddSecrets registers values that must never appear in the document.
func (c *Collector) AddSecrets(values ...string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.redactor.Add(values...)
}

// SetInvocation records what this run is probing.
func (c *Collector) SetInvocation(command, subcommand, protocol, transport, target string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.command, c.subcommand = command, subcommand
	c.protocol, c.transport, c.target = protocol, transport, target
}

// ExpectLayer declares that this protocol performs the given handshake. A
// declared layer that is never observed is reported as unavailable, which is
// how a timeout yields "certificate unknown" instead of "certificate invalid".
func (c *Collector) ExpectLayer(layers ...Layer) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range layers {
		c.expected[l] = true
	}
}

// BeginAttempt opens a new attempt. Everything recorded after this point is
// attributed to it.
func (c *Collector) BeginAttempt(index int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ran = true
	a := &attempt{index: index, started: time.Now()}
	c.attempts = append(c.attempts, a)
	c.cur = a
}

// FinishAttempt closes the current attempt, stamping its duration even when it
// failed. Call it from a defer so a timeout still reports elapsed time.
func (c *Collector) FinishAttempt(err error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	a := c.cur
	if a == nil || a.finished {
		c.mu.Unlock()
		return
	}
	a.duration = time.Since(a.started)
	a.finished = true
	a.success = err == nil
	if err != nil {
		a.errMsg = c.redactLocked(err.Error())
	}
	c.mu.Unlock()

	// Classify reads the state recorded above, so it runs with the lock
	// released.
	result, stage := c.Classify(err)

	c.mu.Lock()
	defer c.mu.Unlock()
	a.result = result
	if err != nil {
		a.stage = stage
		a.hasStage = true
	}
}

// SetConfigError records a failure that happened before the probe reached the
// network. It implies probe.ran == false.
func (c *Collector) SetConfigError(err error) {
	if c == nil || err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.configErr == nil {
		c.configErr = c.redactLocked(err.Error())
	}
}

// SetCloseError records a failure closing the session. It is kept apart from
// the exchange outcome so that a late close error cannot look like an
// authentication failure.
func (c *Collector) SetCloseError(err error) {
	if c == nil || err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeErr = c.redactLocked(err.Error())
}

// RecordPanic records a recovered internal failure.
func (c *Collector) RecordPanic(v any) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.panicMsg = c.redactLocked(fmt.Sprintf("%v", v))
}

// AddSent counts one RADIUS datagram written, including EAP fragments and
// retransmissions.
func (c *Collector) AddSent() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil {
		c.cur.sent++
	}
}

// AddReceived counts one RADIUS datagram read.
func (c *Collector) AddReceived() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil {
		c.cur.received++
	}
}

// AddJitter records a deliberate pre-send sleep so it can be subtracted from
// the reported latencies. Call it with the duration that will be slept, before
// sleeping.
func (c *Collector) AddJitter(d time.Duration) {
	if c == nil || d <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil {
		c.cur.jitter += d
	}
}

// RecordIdentifierMismatch counts a reply whose RADIUS identifier did not
// match the outstanding request. Such a reply otherwise looks exactly like a
// timeout to the caller, which would be a misdiagnosis.
func (c *Collector) RecordIdentifierMismatch() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil {
		c.cur.idMismatch++
	}
}

// RecordExplicitReject records a rejection the server stated outright by some
// means other than an Access-Reject: an EAP Failure, or a PEAP Extensions
// result TLV carrying Failure. Both are the server saying the authentication
// failed, so both count as proof of a rejection.
func (c *Collector) RecordExplicitReject() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil {
		c.cur.sawReject = true
	}
}

// RecordResponse records the code of a datagram read from the server. This is
// the authoritative outcome signal: it is what makes "reject" a fact rather
// than a guess at an error string.
func (c *Collector) RecordResponse(code uint8, name string, isReject bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil {
		return
	}
	n := name
	c.cur.responseCode = &n
	if isReject {
		c.cur.sawReject = true
	}
}

// AdvanceStage moves the high-water mark forward. It never moves backwards, so
// an unclassified error is attributed to the furthest point actually reached.
func (c *Collector) AdvanceStage(s Stage) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur == nil {
		return
	}
	if !c.cur.hasStage || s.rank() > c.cur.stage.rank() {
		c.cur.stage = s
		c.cur.hasStage = true
	}
}

// RecordConnectionState captures negotiated handshake parameters for a layer.
func (c *Collector) RecordConnectionState(l Layer, cs tls.ConnectionState) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.layerLocked(l)
	rec.observed = true
	rec.version = strPtr(tlsVersionName(cs.Version))
	rec.cipherSuite = strPtr(tls.CipherSuiteName(cs.CipherSuite))
	resumed := cs.DidResume
	rec.resumed = &resumed
}

// RecordServerChain stores an evaluated server certificate for a layer.
func (c *Collector) RecordServerChain(l Layer, ci CertInfo) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.layerLocked(l)
	rec.observed = true
	ci.Layer = layerPtr(l)
	ci.Role = RoleServer
	ci.VerifyError = c.redactPtrLocked(ci.VerifyError)
	rec.serverCert = &ci
}

// RecordLayerClientCert stores the certificate we presented on a layer.
func (c *Collector) RecordLayerClientCert(l Layer, ci CertInfo) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.layerLocked(l)
	ci.Layer = layerPtr(l)
	ci.Role = RoleClient
	rec.clientCert = &ci
}

// SetProbeClientCert offers a certificate for the flat client_cert object:
// the one whose expiry an operator cares about, which is the probe's own.
//
// It is set from a parse done before dialing, so certificate expiry alerting
// keeps working when the server is unreachable.
//
// A run can present more than one: a RadSec transport certificate and an EAP
// one. The highest ranked wins regardless of the order they are offered in,
// because the RadSec connection is dialed after the EAP certificate has
// already been parsed, and plain assignment let the transport certificate
// displace the one the server actually authenticates.
func (c *Collector) SetProbeClientCert(l Layer, ci CertInfo) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clientCert != nil && clientCertRank(l) <= clientCertRank(c.clientCertLayer) {
		return
	}
	ci.Layer = layerPtr(l)
	ci.Role = RoleClient
	c.clientCert = &ci
	c.clientCertLayer = l
}

// clientCertRank orders layers for the flat client_cert. The certificate the
// server authenticates us by outranks the one that merely carried the
// transport.
func clientCertRank(l Layer) int {
	switch l {
	case LayerEAPInner:
		return 2
	case LayerEAP:
		return 1
	case LayerRadSec:
		return 0
	}
	return -1
}

// HandshakeTimer measures one TLS handshake.
type HandshakeTimer struct {
	c      *Collector
	layer  Layer
	start  time.Time
	jitter time.Duration
}

// BeginHandshake starts timing a handshake on a layer.
func (c *Collector) BeginHandshake(l Layer) *HandshakeTimer {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.layerLocked(l)
	t := &HandshakeTimer{c: c, layer: l, start: time.Now()}
	if c.cur != nil {
		t.jitter = c.cur.jitter
	}
	return t
}

// Finish stops the timer and records the outcome, including any TLS alert.
// It returns err unchanged so it can be used inline.
func (t *HandshakeTimer) Finish(err error) error {
	if t == nil || t.c == nil {
		return err
	}
	c := t.c
	d := time.Since(t.start)

	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.layerLocked(t.layer)
	rec.hsDuration = &d
	if c.cur != nil {
		rec.hsJitter = c.cur.jitter - t.jitter
	}
	if err != nil {
		rec.hsError = c.redactLocked(err.Error())
		if a, ok := AlertOf(err); ok {
			rec.alert = strPtr(a.Description)
		}
		// Only ever true on proof: a received alert naming a certificate
		// problem. A generic handshake failure or a timeout says nothing
		// about what the peer thought of our certificate.
		rejected := PeerRejectedOurCert(err)
		rec.peerRejectedUs = &rejected
	} else {
		rec.observed = true
	}
	return err
}

func (c *Collector) layerLocked(l Layer) *layerRec {
	rec, ok := c.layers[l]
	if !ok {
		rec = &layerRec{}
		c.layers[l] = rec
	}
	c.expected[l] = true
	return rec
}

func (c *Collector) redactLocked(s string) *string {
	out := c.redactor.Apply(s)
	return &out
}

func (c *Collector) redactPtrLocked(s *string) *string {
	if s == nil {
		return nil
	}
	return c.redactLocked(*s)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return fmt.Sprintf("unknown(0x%04x)", v)
}

func layerPtr(l Layer) *Layer { return &l }
