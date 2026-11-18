package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// resetForTest restores the package-level configuration between runs.
//
// All command configuration lives in package globals and the flags are
// registered in init(), so values set by one run would otherwise leak into the
// next. The proper fix is a config struct, which is a separate refactor.
func resetForTest(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	stdout = &buf
	emitOnce = sync.Once{}
	jsonOutput = false
	collector = nil

	// Reset every registered flag to its default and clear Changed, which the
	// JSON jitter override consults.
	for _, c := range []*cobra.Command{rootCmd, authCmd, acctCmd} {
		c.Flags().VisitAll(resetFlag)
		c.PersistentFlags().VisitAll(resetFlag)
	}
	// PersistentPreRunE sets SilenceUsage on whichever command ran, so it has
	// to be cleared everywhere or one test masks the next.
	resetSilence(rootCmd)

	t.Cleanup(func() { stdout = &bytes.Buffer{} })
	return &buf
}

func resetSilence(c *cobra.Command) {
	c.SilenceUsage = false
	c.SilenceErrors = false
	for _, sub := range c.Commands() {
		resetSilence(sub)
	}
}

func resetFlag(f *pflag.Flag) {
	// A slice flag's DefValue is the literal "[]", and Set would append that as
	// an entry rather than clear it.
	if sv, ok := f.Value.(pflag.SliceValue); ok {
		_ = sv.Replace(nil)
	} else {
		_ = f.Value.Set(f.DefValue)
	}
	f.Changed = false
}

// runProbe executes the CLI in-process and returns the exit code and the
// decoded document.
func runProbe(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	buf := resetForTest(t)
	code := run(args)

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\noutput: %q", err, buf.String())
	}
	return code, doc
}

func get(t *testing.T, doc map[string]any, path ...string) any {
	t.Helper()
	var cur any = doc
	for i, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v is not an object at %q", path[:i], p)
		}
		cur, ok = m[p]
		if !ok {
			t.Fatalf("key %q missing at %v", p, path[:i])
		}
	}
	return cur
}

func TestJSONProbeAccept(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	code, doc := runProbe(t,
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "2s",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice", "--password", "hunter2",
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if got := get(t, doc, "auth", "success"); got != true {
		t.Errorf("auth.success = %v, want true", got)
	}
	if got := get(t, doc, "auth", "result"); got != "accept" {
		t.Errorf("auth.result = %v, want accept", got)
	}
	if got := get(t, doc, "auth", "response_code"); got != "Access-Accept" {
		t.Errorf("auth.response_code = %v, want Access-Accept", got)
	}
	if got := get(t, doc, "auth", "failure_stage"); got != nil {
		t.Errorf("auth.failure_stage = %v, want null on success", got)
	}
	if got := get(t, doc, "auth", "attempts"); got != float64(1) {
		t.Errorf("auth.attempts = %v, want 1", got)
	}
	if got := get(t, doc, "probe", "ran"); got != true {
		t.Errorf("probe.ran = %v, want true", got)
	}
	if got := get(t, doc, "radius", "packets_sent"); got != float64(1) {
		t.Errorf("radius.packets_sent = %v, want 1", got)
	}
	if got := get(t, doc, "radius", "packets_received"); got != float64(1) {
		t.Errorf("radius.packets_received = %v, want 1", got)
	}
	// --json zeroes the send jitter, so the latency figure is real.
	if got := get(t, doc, "radius", "jitter_total_ms"); got != float64(0) {
		t.Errorf("radius.jitter_total_ms = %v, want 0 in JSON mode", got)
	}
	if got := get(t, doc, "auth", "duration_ms").(float64); got <= 0 {
		t.Errorf("auth.duration_ms = %v, want positive", got)
	}
	// pap terminates no TLS, so the layers say so rather than claiming trouble.
	if got := get(t, doc, "tls", "layers", "eap", "status"); got != "not_applicable" {
		t.Errorf("eap layer status = %v, want not_applicable", got)
	}
	if got := get(t, doc, "client_cert", "status"); got != "not_applicable" {
		t.Errorf("client_cert.status = %v, want not_applicable", got)
	}
}

// The secret and the password must not survive into the document.
func TestJSONProbeRedactsSecrets(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessReject, false)

	buf := resetForTest(t)
	run([]string{
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "2s",
		"auth", "udp", "127.0.0.1", "supersecret123", "pap",
		"--username", "alice", "--password", "hunter2password",
	})

	out := buf.String()
	for _, secret := range []string{"supersecret123", "hunter2password"} {
		if bytes.Contains([]byte(out), []byte(secret)) {
			t.Errorf("document leaks %q", secret)
		}
	}
}

func TestJSONProbeReject(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessReject, false)

	code, doc := runProbe(t,
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "2s",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice", "--password", "wrong",
	)

	// A rejection is a successful probe of a server that said no.
	if code != 0 {
		t.Errorf("exit code = %d, want 0: the probe ran fine", code)
	}
	if got := get(t, doc, "auth", "success"); got != false {
		t.Errorf("auth.success = %v, want false", got)
	}
	if got := get(t, doc, "auth", "result"); got != "reject" {
		t.Errorf("auth.result = %v, want reject", got)
	}
	if got := get(t, doc, "auth", "response_code"); got != "Access-Reject" {
		t.Errorf("auth.response_code = %v, want Access-Reject", got)
	}
	if got := get(t, doc, "probe", "ran"); got != true {
		t.Errorf("probe.ran = %v, want true", got)
	}
	// Nothing was observed about any certificate, so nothing is claimed.
	if got := get(t, doc, "tls", "layers", "eap", "server_cert", "valid"); got != nil {
		t.Errorf("server_cert.valid = %v, want null", got)
	}
}

// The regression that matters most: a probe that times out must not report a
// certificate as invalid, and must still exit 0 so Zabbix ingests the data.
func TestJSONProbeTimeoutLeavesCertUnknown(t *testing.T) {
	srv := startFakeServer(t, "testing123", 0, false) // never answers

	code, doc := runProbe(t,
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "300ms",
		"--udp-retries", "1",
		"auth", "udp", "127.0.0.1", "testing123", "eap-tls",
		"--client-cert", testClientCertPath(t),
		"--ca-cert", testClientCertPath(t),
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0: a timeout is an observation, not a broken probe", code)
	}
	if got := get(t, doc, "auth", "result"); got != "timeout" {
		t.Errorf("auth.result = %v, want timeout", got)
	}
	if got := get(t, doc, "probe", "ran"); got != true {
		t.Errorf("probe.ran = %v, want true", got)
	}
	if got := get(t, doc, "auth", "duration_ms").(float64); got <= 0 {
		t.Error("a failed attempt must still report elapsed time")
	}
	if got := get(t, doc, "tls", "layers", "eap", "server_cert", "status"); got != "unavailable" {
		t.Errorf("server_cert.status = %v, want unavailable", got)
	}
	if got := get(t, doc, "tls", "layers", "eap", "server_cert", "valid"); got != nil {
		t.Errorf("server_cert.valid = %v, must stay unknown after a timeout", got)
	}
	// Our own certificate is parsed before dialing, so expiry alerting keeps
	// working while the server is down.
	if got := get(t, doc, "client_cert", "status"); got != "observed" {
		t.Errorf("client_cert.status = %v, want observed even on timeout", got)
	}
	if got := get(t, doc, "client_cert", "expires_in_seconds"); got == nil {
		t.Error("client_cert.expires_in_seconds must be reported even on timeout")
	}
}

func TestJSONProbeConfigError(t *testing.T) {
	code, doc := runProbe(t,
		"--json",
		"auth", "udp", "127.0.0.1", "testing123", "eap-tls",
		"--client-cert", "/nonexistent/client.pem",
		"--ca-cert", "/nonexistent/ca.pem",
	)

	if code != 2 {
		t.Errorf("exit code = %d, want 2: the probe could not run", code)
	}
	if got := get(t, doc, "probe", "ran"); got != false {
		t.Errorf("probe.ran = %v, want false", got)
	}
	if got := get(t, doc, "auth", "result"); got != "config_error" {
		t.Errorf("auth.result = %v, want config_error", got)
	}
	if got := get(t, doc, "auth", "error_message"); got == nil {
		t.Error("error_message should say what was misconfigured")
	}
	// A file we could not read says nothing about whether the key matched.
	if got := get(t, doc, "client_cert", "key_match"); got != nil {
		t.Errorf("client_cert.key_match = %v, must stay unknown", got)
	}
}

// --json on a command that does not support it must fail visibly rather than
// print text a master item cannot parse.
func TestJSONRejectedForAccounting(t *testing.T) {
	code, doc := runProbe(t,
		"--json",
		"acct", "udp", "127.0.0.1", "testing123",
	)

	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if got := get(t, doc, "auth", "result"); got != "config_error" {
		t.Errorf("auth.result = %v, want config_error", got)
	}
}

// A success that needed a retry must still read as a success, with the retries
// visible.
func TestJSONProbeRetriesAreVisible(t *testing.T) {
	srv := startFakeServer(t, "testing123", 0, false)

	code, doc := runProbe(t,
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "200ms",
		"--udp-retries", "1",
		"--retries", "2",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice", "--password", "pw",
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if got := get(t, doc, "auth", "attempts"); got != float64(3) {
		t.Errorf("auth.attempts = %v, want 3 (--retries 2 means three tries)", got)
	}
	attempts, ok := get(t, doc, "attempts").([]any)
	if !ok || len(attempts) != 3 {
		t.Fatalf("attempts array = %v, want 3 entries", get(t, doc, "attempts"))
	}
	if got := get(t, doc, "radius", "packets_sent"); got != float64(3) {
		t.Errorf("radius.packets_sent = %v, want 3 summed across attempts", got)
	}
}

// retry used to decrement the package-level flag as its loop counter, which
// left it at zero and made the function single-use.
func TestRetryDoesNotMutateGlobal(t *testing.T) {
	resetForTest(t)
	retries = 2
	collector = nil

	calls := 0
	_ = retry(func() error {
		calls++
		return nil
	})

	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
	if retries != 2 {
		t.Errorf("retries = %d, want the flag left untouched at 2", retries)
	}
}

// Text mode must keep its original exit codes.
func TestTextModeExitCodeUnchanged(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessReject, false)
	resetForTest(t)

	code := run([]string{
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "2s",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice", "--password", "wrong",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1 in text mode", code)
	}
}

// testClientCertPath writes a self-signed certificate and its key into one
// combined PEM, which is the single-file form this client expects.
func testClientCertPath(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x2a),
		Subject:               pkix.Name{CommonName: "probe@example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	var pem1 bytes.Buffer
	if err := pem.Encode(&pem1, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode certificate: %v", err)
	}
	if err := pem.Encode(&pem1, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encode key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(path, pem1.Bytes(), 0600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return path
}

// captureCobraOutput points cobra at a buffer for one run.
func captureCobraOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	return &buf
}

// A failed authentication should say what went wrong, not print the entire
// flag listing.
func TestRuntimeErrorDoesNotPrintUsage(t *testing.T) {
	srv := startFakeServer(t, "testing123", 0, false) // never answers
	resetForTest(t)
	out := captureCobraOutput(t)

	code := run([]string{
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "200ms",
		"--udp-retries", "1",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice", "--password", "pw",
	})

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if strings.Contains(out.String(), "Usage:") {
		t.Errorf("usage was printed for a runtime error:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "did not get response") {
		t.Errorf("the error itself should still be reported, got:\n%s", out.String())
	}
}

// A missing required value explains itself, so it does not need the listing
// either.
func TestMissingValueDoesNotPrintUsage(t *testing.T) {
	resetForTest(t)
	out := captureCobraOutput(t)

	code := run([]string{"auth", "udp", "127.0.0.1", "testing123", "eap-tls"})

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if strings.Contains(out.String(), "Usage:") {
		t.Errorf("usage was printed:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "missing values") {
		t.Errorf("expected the missing-value error, got:\n%s", out.String())
	}
}

// A genuine usage mistake still gets the listing, since that is when it helps.
func TestArgumentCountErrorStillPrintsUsage(t *testing.T) {
	resetForTest(t)
	out := captureCobraOutput(t)

	code := run([]string{"auth", "udp", "127.0.0.1"})

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("usage should be printed for a wrong argument count, got:\n%s", out.String())
	}
}
