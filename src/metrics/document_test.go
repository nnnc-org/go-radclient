package metrics

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

// These key sets are the contract Zabbix depends on. A dependent item whose
// JSONPath stops resolving silently goes unsupported, so a dropped or renamed
// key must fail here rather than in production.
var (
	wantTopKeys     = []string{"attempts", "auth", "client_cert", "probe", "radius", "schema_version", "tls"}
	wantProbeKeys   = []string{"command", "duration_ms", "panic", "protocol", "ran", "started_at", "subcommand", "target", "transport", "version"}
	wantAuthKeys    = []string{"attempts", "close_error", "duration_excl_jitter_ms", "duration_ms", "error_message", "failure_stage", "response_code", "result", "success"}
	wantRADIUSKeys  = []string{"identifier_mismatches", "jitter_total_ms", "packets_received", "packets_sent"}
	wantLayerKeys   = []string{"alert", "cipher_suite", "client_cert", "handshake_duration_excl_jitter_ms", "handshake_duration_ms", "handshake_error", "peer_cert_rejected", "server_cert", "session_resumed", "status", "version"}
	wantCertKeys    = []string{"chain", "chain_expires_at", "chain_valid", "dns_names", "expires_at", "expires_in_seconds", "issuer", "key_match", "layer", "name_match", "not_before", "role", "serial", "sha256", "status", "subject", "valid", "valid_now", "verify_error"}
	wantAttemptKeys = []string{"duration_excl_jitter_ms", "duration_ms", "error_message", "failure_stage", "index", "packets_received", "packets_sent", "response_code", "result", "started_at", "success"}
	wantTLSKeys     = []string{"layers"}
)

func marshalDoc(t *testing.T, doc Document) map[string]any {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func keysOf(t *testing.T, v any, path string) []string {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want an object", path, v)
	}
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func assertKeys(t *testing.T, v any, path string, want []string) {
	t.Helper()
	got := keysOf(t, v, path)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s keys =\n  %v\nwant\n  %v", path, got, want)
	}
}

func assertFullShape(t *testing.T, m map[string]any) {
	t.Helper()
	assertKeys(t, m, "$", wantTopKeys)
	assertKeys(t, m["probe"], "$.probe", wantProbeKeys)
	assertKeys(t, m["auth"], "$.auth", wantAuthKeys)
	assertKeys(t, m["radius"], "$.radius", wantRADIUSKeys)
	assertKeys(t, m["tls"], "$.tls", wantTLSKeys)
	assertKeys(t, m["client_cert"], "$.client_cert", wantCertKeys)

	layers := keysOf(t, m["tls"].(map[string]any)["layers"], "$.tls.layers")
	if strings.Join(layers, ",") != "eap,eap_inner,radsec" {
		t.Errorf("$.tls.layers keys = %v, want eap,eap_inner,radsec", layers)
	}
	for _, l := range layers {
		layer := m["tls"].(map[string]any)["layers"].(map[string]any)[l]
		assertKeys(t, layer, "$.tls.layers."+l, wantLayerKeys)
		lm := layer.(map[string]any)
		assertKeys(t, lm["server_cert"], "$.tls.layers."+l+".server_cert", wantCertKeys)
		assertKeys(t, lm["client_cert"], "$.tls.layers."+l+".client_cert", wantCertKeys)
	}
}

// A completely empty run must still emit every documented key.
func TestDocumentShapeZeroValue(t *testing.T) {
	assertFullShape(t, marshalDoc(t, New("test").Document()))
}

func TestDocumentShapeNilCollector(t *testing.T) {
	var c *Collector
	assertFullShape(t, marshalDoc(t, c.Document()))
}

// Slices must be allocated, or they marshal to null and break JSONPath array
// handling on exactly the paths a template walks.
func TestSlicesMarshalAsArraysNotNull(t *testing.T) {
	b, err := json.Marshal(New("test").Document())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, frag := range []string{`"attempts":[]`, `"chain":[]`, `"dns_names":[]`} {
		if !strings.Contains(s, frag) {
			t.Errorf("output does not contain %s; a nil slice marshalled to null", frag)
		}
	}
	if strings.Contains(s, `:null,"chain":null`) || strings.Contains(s, `"attempts":null`) {
		t.Error("a slice marshalled to null")
	}
}

func TestDocumentEapTlsSuccess(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), now.AddDate(0, 3, 0)), f.intermediate)
	clientLeaf, _ := issue(t, leafTemplate("probe@example.com", nil, now.AddDate(0, -1, 0), now.AddDate(0, 2, 0)), f.intermediate)
	keyMatch := true

	c := New("v1.2.3")
	c.SetInvocation("auth", "udp", "eap-tls", "udp", "radius.example.com")
	c.ExpectLayer(LayerEAP)
	c.SetProbeClientCert(LayerEAP, EvaluateClientCert(clientLeaf, &keyMatch, now))
	c.BeginAttempt(0)
	c.AdvanceStage(StageConnection)
	hs := c.BeginHandshake(LayerEAP)
	c.RecordConnectionState(LayerEAP, tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	})
	c.RecordServerChain(LayerEAP, EvaluateServerChain(f.chainOf(leaf), f.roots, "radius.example.com", now))
	hs.Finish(nil)
	c.AddSent()
	c.AddReceived()
	c.AdvanceStage(StageRadiusResponse)
	c.RecordResponse(2, "Access-Accept", false)
	c.FinishAttempt(nil)

	doc := c.Document()
	assertFullShape(t, marshalDoc(t, doc))

	if !doc.Auth.Success || doc.Auth.Result != ResultAccept {
		t.Errorf("auth = %v/%q, want success/accept", doc.Auth.Success, doc.Auth.Result)
	}
	if doc.Auth.FailureStage != nil {
		t.Errorf("failure_stage = %v, want nil on success", *doc.Auth.FailureStage)
	}
	if doc.Auth.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", doc.Auth.Attempts)
	}
	if !doc.Probe.Ran {
		t.Error("probe.ran should be true")
	}
	eap := doc.TLS.Layers[LayerEAP]
	if eap.Status != StatusObserved {
		t.Errorf("eap layer status = %q, want observed", eap.Status)
	}
	if eap.Version == nil || *eap.Version != "1.2" {
		t.Errorf("tls version = %v, want 1.2", eap.Version)
	}
	if eap.HandshakeDurationMs == nil {
		t.Error("handshake_duration_ms should be measured")
	}
	if eap.ServerCert.Valid == nil || !*eap.ServerCert.Valid {
		t.Error("server cert should be valid")
	}
	if doc.ClientCert.Status != StatusObserved {
		t.Errorf("client_cert status = %q, want observed", doc.ClientCert.Status)
	}
	// Layers this protocol never uses must say so, not claim a problem.
	if doc.TLS.Layers[LayerRadSec].Status != StatusNotApplicable {
		t.Errorf("radsec layer = %q, want not_applicable", doc.TLS.Layers[LayerRadSec].Status)
	}
	if doc.TLS.Layers[LayerRadSec].ServerCert.Valid != nil {
		t.Error("an unused layer must not assert certificate validity")
	}
}

// The regression that matters most: a timeout must leave certificate status
// unknown, never invalid.
func TestDocumentTimeoutLeavesCertUnknown(t *testing.T) {
	c := New("test")
	c.SetInvocation("auth", "udp", "eap-tls", "udp", "10.0.0.1")
	c.ExpectLayer(LayerEAP)
	c.BeginAttempt(0)
	c.AdvanceStage(StageConnection)
	c.AddSent()
	c.FinishAttempt(Wrap(StageRadiusResponse, ResultTimeout, timeoutErr{}))

	doc := c.Document()
	assertFullShape(t, marshalDoc(t, doc))

	if doc.Auth.Result != ResultTimeout {
		t.Errorf("result = %q, want timeout", doc.Auth.Result)
	}
	if doc.Auth.Success {
		t.Error("success should be false")
	}
	if !doc.Probe.Ran {
		t.Error("probe.ran should be true: a timeout is a real observation, not a broken probe")
	}
	sc := doc.TLS.Layers[LayerEAP].ServerCert
	if sc.Status != StatusUnavailable {
		t.Errorf("server_cert status = %q, want %q", sc.Status, StatusUnavailable)
	}
	if sc.Valid != nil {
		t.Errorf("server_cert.valid = %v, must stay unknown after a timeout", *sc.Valid)
	}
	if sc.ChainValid != nil || sc.ExpiresAt != nil {
		t.Error("nothing was observed about the certificate, so nothing may be reported")
	}
}

// A wrong password must not drag down certificate validity: they are
// independent facts and the separation is the whole point.
func TestDocumentAuthFailureKeepsCertValid(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), now.AddDate(0, 3, 0)), f.intermediate)

	c := New("test")
	c.ExpectLayer(LayerEAP)
	c.BeginAttempt(0)
	hs := c.BeginHandshake(LayerEAP)
	c.RecordServerChain(LayerEAP, EvaluateServerChain(f.chainOf(leaf), f.roots, "radius.example.com", now))
	hs.Finish(nil)
	c.AdvanceStage(StageRadiusResponse)
	c.RecordResponse(3, "Access-Reject", true)
	c.FinishAttempt(errors.New("authentication failed"))

	doc := c.Document()
	if doc.Auth.Success {
		t.Error("success should be false")
	}
	if doc.Auth.Result != ResultReject {
		t.Errorf("result = %q, want reject", doc.Auth.Result)
	}
	sc := doc.TLS.Layers[LayerEAP].ServerCert
	if sc.Valid == nil || !*sc.Valid {
		t.Error("the server certificate was valid; a failed password says nothing about it")
	}
	if doc.Auth.ResponseCode == nil || *doc.Auth.ResponseCode != "Access-Reject" {
		t.Errorf("response_code = %v, want Access-Reject", doc.Auth.ResponseCode)
	}
}

// success:false alongside an Access-Accept is a real case, and the document has
// to make it diagnosable rather than looking like an outage.
func TestDocumentAcceptWithFailedAttributeCheck(t *testing.T) {
	c := New("test")
	c.BeginAttempt(0)
	c.AdvanceStage(StageRadiusResponse)
	c.RecordResponse(2, "Access-Accept", false)
	c.FinishAttempt(Wrap(StageRadiusResponse, ResultProtocolError, errors.New("expected attributes were missing: Filter-Id")))

	doc := c.Document()
	if doc.Auth.Success {
		t.Error("success should be false")
	}
	if doc.Auth.Result != ResultProtocolError {
		t.Errorf("result = %q, want protocol_error", doc.Auth.Result)
	}
	if doc.Auth.ResponseCode == nil || *doc.Auth.ResponseCode != "Access-Accept" {
		t.Fatalf("response_code = %v, want Access-Accept so the case is diagnosable", doc.Auth.ResponseCode)
	}
	if doc.Auth.FailureStage == nil || *doc.Auth.FailureStage != StageRadiusResponse {
		t.Errorf("failure_stage = %v, want radius_response", doc.Auth.FailureStage)
	}
}

func TestDocumentConfigError(t *testing.T) {
	c := New("test")
	c.SetInvocation("auth", "udp", "eap-tls", "udp", "radius.example.com")
	c.SetConfigError(errors.New("open /nope.pem: no such file or directory"))

	doc := c.Document()
	assertFullShape(t, marshalDoc(t, doc))

	if doc.Probe.Ran {
		t.Error("probe.ran should be false")
	}
	if doc.Auth.Result != ResultConfigError {
		t.Errorf("result = %q, want config_error", doc.Auth.Result)
	}
	if doc.Auth.ErrorMessage == nil {
		t.Error("error_message should explain what was misconfigured")
	}
	if doc.Auth.Attempts != 0 || len(doc.Attempts) != 0 {
		t.Error("no attempt was made")
	}
}

func TestDocumentPanic(t *testing.T) {
	c := New("test")
	c.BeginAttempt(0)
	c.RecordPanic("runtime error: index out of range")

	doc := c.Document()
	assertFullShape(t, marshalDoc(t, doc))

	if doc.Auth.Result != ResultInternalError {
		t.Errorf("result = %q, want internal_error", doc.Auth.Result)
	}
	if doc.Probe.Ran {
		t.Error("probe.ran should be false: the probe broke rather than observing anything")
	}
	if doc.Probe.Panic == nil {
		t.Error("probe.panic should be set")
	}
}

// Durations sum across attempts, counters sum, and the final attempt decides
// the outcome.
func TestDocumentMultipleAttempts(t *testing.T) {
	c := New("test")
	for i := range 3 {
		c.BeginAttempt(i)
		c.AddSent()
		c.AddReceived()
		c.AddJitter(10 * time.Millisecond)
		c.AdvanceStage(StageRadiusResponse)
		if i == 2 {
			c.FinishAttempt(nil)
			continue
		}
		c.FinishAttempt(Wrap(StageRadiusResponse, ResultTimeout, timeoutErr{}))
	}

	doc := c.Document()
	if doc.Auth.Attempts != 3 || len(doc.Attempts) != 3 {
		t.Fatalf("attempts = %d / %d, want 3", doc.Auth.Attempts, len(doc.Attempts))
	}
	// A success that needed retries is still a success, and the retries stay
	// visible.
	if !doc.Auth.Success || doc.Auth.Result != ResultAccept {
		t.Errorf("auth = %v/%q, want success/accept from the final attempt", doc.Auth.Success, doc.Auth.Result)
	}
	if doc.RADIUS.PacketsSent != 3 || doc.RADIUS.PacketsReceived != 3 {
		t.Errorf("packets = %d/%d, want 3/3 summed", doc.RADIUS.PacketsSent, doc.RADIUS.PacketsReceived)
	}
	if doc.RADIUS.JitterTotalMs != 30 {
		t.Errorf("jitter_total_ms = %v, want 30", doc.RADIUS.JitterTotalMs)
	}
	if doc.Attempts[0].Result != ResultTimeout {
		t.Errorf("attempts[0].result = %q, want timeout", doc.Attempts[0].Result)
	}
	if doc.Auth.DurationExclJitterMs > doc.Auth.DurationMs {
		t.Error("jitter-excluded duration cannot exceed wall duration")
	}
}

// A failed EAP-TLS exchange is not evidence that the server rejected our
// client certificate, so the claim must stay false without an alert.
func TestDocumentPeerCertRejectedOnlyOnProof(t *testing.T) {
	c := New("test")
	c.ExpectLayer(LayerEAP)
	c.BeginAttempt(0)
	hs := c.BeginHandshake(LayerEAP)
	hs.Finish(errors.New("eap tls: server sent a failure packet"))
	c.FinishAttempt(Wrap(StageTLS, ResultTLSError, errors.New("eap tls: server sent a failure packet")))

	eap := c.Document().TLS.Layers[LayerEAP]
	if eap.PeerCertRejected == nil || *eap.PeerCertRejected {
		t.Error("peer_cert_rejected must be false without a certificate alert")
	}
	if eap.Alert != nil {
		t.Errorf("alert = %v, want nil when no alert was received", *eap.Alert)
	}
}

// With a received certificate alert the claim is proved and is reported.
func TestDocumentPeerCertRejectedWithProof(t *testing.T) {
	alertErr := &net.OpError{Op: "remote error", Err: errors.New("tls: certificate required")}

	c := New("test")
	c.ExpectLayer(LayerEAP)
	c.BeginAttempt(0)
	hs := c.BeginHandshake(LayerEAP)
	hs.Finish(alertErr)
	c.FinishAttempt(Wrap(StageTLS, ResultTLSError, alertErr))

	doc := c.Document()
	eap := doc.TLS.Layers[LayerEAP]
	if eap.PeerCertRejected == nil || !*eap.PeerCertRejected {
		t.Error("peer_cert_rejected should be true for a certificate-required alert")
	}
	if eap.Alert == nil || *eap.Alert != "certificate required" {
		t.Errorf("alert = %v, want \"certificate required\"", eap.Alert)
	}
	if doc.Auth.Result != ResultTLSError {
		t.Errorf("result = %q, want tls_error", doc.Auth.Result)
	}
	// The handshake never completed, so the server certificate is unknown.
	if eap.ServerCert.Status != StatusUnavailable {
		t.Errorf("server_cert status = %q, want unavailable", eap.ServerCert.Status)
	}
}
