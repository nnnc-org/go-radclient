package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// radsecFixture holds the files a RadSec run needs on disk.
type radsecFixture struct {
	caPath     string
	clientPath string
	serverCert tls.Certificate
	serverLeaf *x509.Certificate
}

// newRadsecFixture builds a CA, a server certificate carrying 127.0.0.1 as an
// IP SAN, and a client certificate, writing the PEM files the CLI expects.
func newRadsecFixture(t *testing.T, serverNotAfter time.Time) *radsecFixture {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RadSec Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caLeaf, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	caPath := filepath.Join(dir, "ca.pem")
	writePEM(t, caPath, [][2]any{{"CERTIFICATE", caDER}})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x5e2f),
		Subject:      pkix.Name{CommonName: "radsec.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     serverNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"radsec.example.com"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caLeaf, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	srvLeaf, err := x509.ParseCertificate(srvDER)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xc11e),
		Subject:      pkix.Name{CommonName: "probe.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caLeaf, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	cliKeyDER, err := x509.MarshalECPrivateKey(cliKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientPath := filepath.Join(dir, "client.pem")
	writePEM(t, clientPath, [][2]any{
		{"CERTIFICATE", cliDER},
		{"EC PRIVATE KEY", cliKeyDER},
	})

	return &radsecFixture{
		caPath:     caPath,
		clientPath: clientPath,
		serverLeaf: srvLeaf,
		serverCert: tls.Certificate{
			Certificate: [][]byte{srvDER},
			PrivateKey:  srvKey,
			Leaf:        srvLeaf,
		},
	}
}

func writePEM(t *testing.T, path string, blocks [][2]any) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	for _, b := range blocks {
		if err := pem.Encode(f, &pem.Block{Type: b[0].(string), Bytes: b[1].([]byte)}); err != nil {
			t.Fatalf("encode pem: %v", err)
		}
	}
}

// startRadsecServer serves RADIUS over TLS, answering each request with
// replyCode. RadSec fixes the shared secret to "radsec" (RFC 6614).
func startRadsecServer(t *testing.T, f *radsecFixture, replyCode byte) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{f.serverCert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	responder := &fakeServer{replyCode: replyCode, secret: "radsec"}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if err != nil || n < radiusHeaderLen {
						return
					}
					req := make([]byte, n)
					copy(req, buf[:n])
					if _, err := conn.Write(responder.reply(req)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// The RadSec handshake is where server certificate metrics come from on the
// tls subcommand.
func TestJSONRadsecServerCertMetrics(t *testing.T) {
	expiry := time.Now().Add(45 * 24 * time.Hour).Truncate(time.Second)
	f := newRadsecFixture(t, expiry)
	port := startRadsecServer(t, f, codeAccessAccept)

	code, doc := runProbe(t,
		"--json",
		"--tcp-port", strconv.Itoa(port),
		"--tls-timeout", "5s",
		"auth", "tls", "127.0.0.1", f.caPath, f.clientPath, "pap",
		"--username", "alice", "--password", "hunter2",
	)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; error = %v", code, get(t, doc, "auth", "error_message"))
	}
	if got := get(t, doc, "auth", "success"); got != true {
		t.Errorf("auth.success = %v, want true", got)
	}
	if got := get(t, doc, "probe", "transport"); got != "radsec" {
		t.Errorf("probe.transport = %v, want radsec", got)
	}

	layer := "radsec"
	if got := get(t, doc, "tls", "layers", layer, "status"); got != "observed" {
		t.Fatalf("radsec layer status = %v, want observed", got)
	}
	if got := get(t, doc, "tls", "layers", layer, "version"); got != "1.2" && got != "1.3" {
		t.Errorf("tls version = %v, want 1.2 or 1.3", got)
	}
	if got := get(t, doc, "tls", "layers", layer, "cipher_suite"); got == nil {
		t.Error("cipher_suite should be reported")
	}
	if got := get(t, doc, "tls", "layers", layer, "handshake_duration_ms"); got == nil {
		t.Error("handshake_duration_ms should be measured")
	}
	if got := get(t, doc, "tls", "layers", layer, "session_resumed"); got != false {
		t.Errorf("session_resumed = %v, want false", got)
	}

	sc := get(t, doc, "tls", "layers", layer, "server_cert").(map[string]any)
	if sc["status"] != "observed" {
		t.Fatalf("server_cert.status = %v, want observed", sc["status"])
	}
	for _, k := range []string{"valid", "chain_valid", "name_match", "valid_now"} {
		if sc[k] != true {
			t.Errorf("server_cert.%s = %v, want true", k, sc[k])
		}
	}
	if sc["expires_at"] != float64(expiry.Unix()) {
		t.Errorf("server_cert.expires_at = %v, want %d", sc["expires_at"], expiry.Unix())
	}
	if remaining, ok := sc["expires_in_seconds"].(float64); !ok || remaining <= 0 {
		t.Errorf("server_cert.expires_in_seconds = %v, want positive", sc["expires_in_seconds"])
	}
	if sc["serial"] != "5e2f" {
		t.Errorf("server_cert.serial = %v, want 5e2f", sc["serial"])
	}
	if sc["subject"] != "CN=radsec.example.com" {
		t.Errorf("server_cert.subject = %v", sc["subject"])
	}
	if sc["verify_error"] != nil {
		t.Errorf("server_cert.verify_error = %v, want null", sc["verify_error"])
	}
	if chain, ok := sc["chain"].([]any); !ok || len(chain) == 0 {
		t.Error("server_cert.chain should list the presented certificates")
	}

	// Our own certificate is reported flat, as the one whose expiry matters.
	if got := get(t, doc, "client_cert", "status"); got != "observed" {
		t.Errorf("client_cert.status = %v, want observed", got)
	}
	if got := get(t, doc, "client_cert", "key_match"); got != true {
		t.Errorf("client_cert.key_match = %v, want true", got)
	}
	if got := get(t, doc, "client_cert", "serial"); got != "c11e" {
		t.Errorf("client_cert.serial = %v, want c11e", got)
	}

	// pap over RadSec performs no EAP handshake of its own.
	if got := get(t, doc, "tls", "layers", "eap", "status"); got != "not_applicable" {
		t.Errorf("eap layer = %v, want not_applicable", got)
	}
}

// An expired server certificate must be reported as expired, with the dates
// intact, rather than collapsed into a bare chain failure.
func TestJSONRadsecExpiredServerCert(t *testing.T) {
	expiry := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	f := newRadsecFixture(t, expiry)
	port := startRadsecServer(t, f, codeAccessAccept)

	_, doc := runProbe(t,
		"--json",
		"--tcp-port", strconv.Itoa(port),
		"--tls-timeout", "5s",
		"--radsec-unsafe", // let the handshake complete so the cert is observable
		"auth", "tls", "127.0.0.1", f.caPath, f.clientPath, "pap",
		"--username", "alice", "--password", "hunter2",
	)

	sc := get(t, doc, "tls", "layers", "radsec", "server_cert").(map[string]any)
	if sc["status"] != "observed" {
		t.Fatalf("server_cert.status = %v, want observed: it was seen, just expired", sc["status"])
	}
	if sc["valid_now"] != false {
		t.Errorf("server_cert.valid_now = %v, want false", sc["valid_now"])
	}
	if sc["valid"] != false {
		t.Errorf("server_cert.valid = %v, want false", sc["valid"])
	}
	if remaining, ok := sc["expires_in_seconds"].(float64); !ok || remaining >= 0 {
		t.Errorf("server_cert.expires_in_seconds = %v, want negative", sc["expires_in_seconds"])
	}
	if sc["expires_at"] != float64(expiry.Unix()) {
		t.Errorf("server_cert.expires_at = %v, want %d", sc["expires_at"], expiry.Unix())
	}
	// The name still matches; it is the date that is wrong.
	if sc["name_match"] != true {
		t.Errorf("server_cert.name_match = %v, want true", sc["name_match"])
	}
}

// A CA that did not issue the server certificate is an operator mistake, and
// must not be confused with the server rejecting us.
func TestJSONRadsecUntrustedServerCert(t *testing.T) {
	f := newRadsecFixture(t, time.Now().Add(30*24*time.Hour))
	other := newRadsecFixture(t, time.Now().Add(30*24*time.Hour))
	port := startRadsecServer(t, f, codeAccessAccept)

	code, doc := runProbe(t,
		"--json",
		"--tcp-port", strconv.Itoa(port),
		"--tls-timeout", "5s",
		"auth", "tls", "127.0.0.1", other.caPath, f.clientPath, "pap",
		"--username", "alice", "--password", "hunter2",
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0: the probe ran and observed a TLS failure", code)
	}
	if got := get(t, doc, "auth", "result"); got != "tls_error" {
		t.Errorf("auth.result = %v, want tls_error", got)
	}
	if got := get(t, doc, "auth", "failure_stage"); got != "tls" {
		t.Errorf("auth.failure_stage = %v, want tls", got)
	}
	// Crucially not a rejection: no Access-Reject was ever received.
	if got := get(t, doc, "auth", "response_code"); got != nil {
		t.Errorf("auth.response_code = %v, want null", got)
	}
	if got := get(t, doc, "tls", "layers", "radsec", "handshake_error"); got == nil {
		t.Error("handshake_error should explain the failure")
	}
	// We rejected the server, so this must not claim the server rejected us.
	if got := get(t, doc, "tls", "layers", "radsec", "peer_cert_rejected"); got == true {
		t.Error("peer_cert_rejected must not be set when it was we who refused the chain")
	}
}

// --insecure drops the trust requirement so a certificate can be inspected
// without configuring a CA, which is the point of the flag. Validity then
// cannot be asserted, and must read as unknown rather than as a failure.
func TestJSONInsecureReportsCertWithoutCA(t *testing.T) {
	expiry := time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)
	f := newRadsecFixture(t, expiry)
	// A CA that did not issue the server certificate: without --insecure this
	// is the untrusted-chain case, so the handshake only succeeds because
	// verification is skipped.
	other := newRadsecFixture(t, expiry)
	port := startRadsecServer(t, f, codeAccessAccept)

	code, doc := runProbe(t,
		"--json",
		"--insecure",
		"--tcp-port", strconv.Itoa(port),
		"--tls-timeout", "5s",
		"auth", "tls", "127.0.0.1", other.caPath, f.clientPath, "pap",
		"--username", "alice", "--password", "hunter2",
	)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; error = %v", code, get(t, doc, "auth", "error_message"))
	}
	if got := get(t, doc, "auth", "success"); got != true {
		t.Errorf("auth.success = %v, want true: --insecure should let the handshake complete", got)
	}

	sc := get(t, doc, "tls", "layers", "radsec", "server_cert").(map[string]any)
	if sc["status"] != "observed" {
		t.Fatalf("server_cert.status = %v, want observed", sc["status"])
	}
	// The whole reason to use --insecure: expiry without a CA.
	if sc["expires_at"] != float64(expiry.Unix()) {
		t.Errorf("server_cert.expires_at = %v, want %d", sc["expires_at"], expiry.Unix())
	}
	if sc["subject"] != "CN=radsec.example.com" {
		t.Errorf("server_cert.subject = %v", sc["subject"])
	}
	if sc["sha256"] == nil {
		t.Error("server_cert.sha256 should be reported")
	}
	if sc["valid_now"] != true {
		t.Errorf("server_cert.valid_now = %v, want true", sc["valid_now"])
	}
	// Unknown, not false. There was no anchor to verify against, and a false
	// here would read as a broken server certificate.
	if sc["chain_valid"] != nil {
		t.Errorf("server_cert.chain_valid = %v, want null without a CA", sc["chain_valid"])
	}
	if sc["valid"] != nil {
		t.Errorf("server_cert.valid = %v, want null without a CA", sc["valid"])
	}
	if sc["verify_error"] != nil {
		t.Errorf("server_cert.verify_error = %v, want null: nothing was verified", sc["verify_error"])
	}
}

// --insecure also means the CA argument need not name a real file.
func TestJSONInsecureIgnoresCAArgument(t *testing.T) {
	f := newRadsecFixture(t, time.Now().Add(30*24*time.Hour))
	port := startRadsecServer(t, f, codeAccessAccept)

	code, doc := runProbe(t,
		"--json",
		"--insecure",
		"--tcp-port", strconv.Itoa(port),
		"--tls-timeout", "5s",
		"auth", "tls", "127.0.0.1", "/nonexistent/ca.pem", f.clientPath, "pap",
		"--username", "alice", "--password", "hunter2",
	)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; error = %v", code, get(t, doc, "auth", "error_message"))
	}
	if got := get(t, doc, "auth", "success"); got != true {
		t.Errorf("auth.success = %v, want true", got)
	}
}
