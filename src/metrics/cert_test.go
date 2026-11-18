package metrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// now is the pinned clock for every expiry assertion, so the arithmetic is
// deterministic rather than dependent on when the suite runs.
var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, tmpl *x509.Certificate, parent *ca) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := key
	issuer := tmpl
	if parent != nil {
		signer = parent.key
		issuer = parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

func caTemplate(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func leafTemplate(cn string, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(0x0a1b2c),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
	}
}

type fixture struct {
	root         *ca
	intermediate *ca
	roots        *x509.CertPool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rootCert, rootKey := issue(t, caTemplate("Test Root CA", now.AddDate(-2, 0, 0), now.AddDate(10, 0, 0)), nil)
	root := &ca{rootCert, rootKey}
	interCert, interKey := issue(t, caTemplate("Test Issuing CA", now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0)), root)
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return &fixture{root: root, intermediate: &ca{interCert, interKey}, roots: pool}
}

// chainOf builds the wire order a server presents: leaf first, then issuers.
func (f *fixture) chainOf(leaf *x509.Certificate) []*x509.Certificate {
	return []*x509.Certificate{leaf, f.intermediate.cert, f.root.cert}
}

func TestEvaluateServerChainValid(t *testing.T) {
	f := newFixture(t)
	expiry := now.AddDate(0, 3, 0)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), expiry), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), f.roots, "radius.example.com", now)

	if ci.Status != StatusObserved {
		t.Fatalf("status = %q, want %q", ci.Status, StatusObserved)
	}
	for name, got := range map[string]*bool{
		"valid":       ci.Valid,
		"chain_valid": ci.ChainValid,
		"name_match":  ci.NameMatch,
		"valid_now":   ci.ValidNow,
	} {
		if got == nil || !*got {
			t.Errorf("%s = %v, want true", name, got)
		}
	}
	if ci.VerifyError != nil {
		t.Errorf("verify_error = %q, want nil", *ci.VerifyError)
	}
	if ci.ExpiresAt == nil || *ci.ExpiresAt != expiry.Unix() {
		t.Errorf("expires_at = %v, want %d", ci.ExpiresAt, expiry.Unix())
	}
	wantRemaining := int64(expiry.Sub(now).Seconds())
	if ci.ExpiresInSeconds == nil || *ci.ExpiresInSeconds != wantRemaining {
		t.Errorf("expires_in_seconds = %v, want %d", ci.ExpiresInSeconds, wantRemaining)
	}
	if ci.Serial == nil || *ci.Serial != "0a1b2c" {
		t.Errorf("serial = %v, want 0a1b2c", ci.Serial)
	}
	if ci.SHA256 == nil || len(*ci.SHA256) != 64 {
		t.Errorf("sha256 = %v, want 64 hex chars", ci.SHA256)
	}
	if len(ci.DNSNames) != 1 || ci.DNSNames[0] != "radius.example.com" {
		t.Errorf("dns_names = %v", ci.DNSNames)
	}
}

// The trust anchor is the root we were handed locally, so including its expiry
// would raise alerts about our own CA file rather than about the server.
func TestChainExpiresAtExcludesTrustAnchor(t *testing.T) {
	f := newFixture(t)
	leafExpiry := now.AddDate(1, 0, 0)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), leafExpiry), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), f.roots, "radius.example.com", now)

	if ci.ChainExpiresAt == nil {
		t.Fatal("chain_expires_at is nil")
	}
	// Here the leaf is the earliest; the root outlives everything and must be
	// ignored even though it is in the chain.
	if *ci.ChainExpiresAt != leafExpiry.Unix() {
		t.Errorf("chain_expires_at = %d, want %d (leaf)", *ci.ChainExpiresAt, leafExpiry.Unix())
	}
	if *ci.ChainExpiresAt == f.root.cert.NotAfter.Unix() {
		t.Error("chain_expires_at picked the trust anchor")
	}
}

// An intermediate that expires before the leaf is a real operational hazard,
// so it has to be the value reported.
func TestChainExpiresAtPicksEarliestNonAnchor(t *testing.T) {
	f := newFixture(t)
	shortInterCert, shortInterKey := issue(t, caTemplate("Short Issuing CA", now.AddDate(0, -1, 0), now.AddDate(0, 2, 0)), f.root)
	shortInter := &ca{shortInterCert, shortInterKey}
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), now.AddDate(1, 0, 0)), shortInter)

	chain := []*x509.Certificate{leaf, shortInterCert, f.root.cert}
	ci := EvaluateServerChain(chain, f.roots, "radius.example.com", now)

	if ci.ChainExpiresAt == nil {
		t.Fatal("chain_expires_at is nil")
	}
	if *ci.ChainExpiresAt != shortInterCert.NotAfter.Unix() {
		t.Errorf("chain_expires_at = %d, want %d (intermediate)", *ci.ChainExpiresAt, shortInterCert.NotAfter.Unix())
	}
}

// An expired certificate fails chain verification too. The metrics must say
// which it was, or an operator only learns "chain invalid".
func TestEvaluateServerChainExpiredSeparatesValidNow(t *testing.T) {
	f := newFixture(t)
	expiry := now.AddDate(0, 0, -10)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -6, 0), expiry), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), f.roots, "radius.example.com", now)

	if ci.ValidNow == nil || *ci.ValidNow {
		t.Error("valid_now should be false for an expired leaf")
	}
	if ci.Valid == nil || *ci.Valid {
		t.Error("valid should be false for an expired leaf")
	}
	if ci.NameMatch == nil || !*ci.NameMatch {
		t.Error("name_match should still be true: the name is fine, the date is not")
	}
	if ci.ExpiresInSeconds == nil || *ci.ExpiresInSeconds >= 0 {
		t.Errorf("expires_in_seconds = %v, want negative", ci.ExpiresInSeconds)
	}
	if ci.Status != StatusObserved {
		t.Errorf("status = %q, want %q: we did see it, it is just expired", ci.Status, StatusObserved)
	}
}

func TestEvaluateServerChainNotYetValid(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, 1, 0), now.AddDate(0, 6, 0)), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), f.roots, "radius.example.com", now)

	if ci.ValidNow == nil || *ci.ValidNow {
		t.Error("valid_now should be false before NotBefore")
	}
	if ci.ExpiresInSeconds == nil || *ci.ExpiresInSeconds <= 0 {
		t.Error("a not-yet-valid cert still has time left before expiry")
	}
}

func TestEvaluateServerChainWrongName(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("other.example.com", []string{"other.example.com"}, now.AddDate(0, -1, 0), now.AddDate(0, 6, 0)), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), f.roots, "radius.example.com", now)

	if ci.NameMatch == nil || *ci.NameMatch {
		t.Error("name_match should be false")
	}
	if ci.ChainValid == nil || !*ci.ChainValid {
		t.Error("chain_valid should still be true: the chain is fine, the name is not")
	}
	if ci.Valid == nil || *ci.Valid {
		t.Error("valid should be false when the name does not match")
	}
}

// No server name to compare against means the answer is unknown, not false.
func TestEvaluateServerChainEmptyServerNameLeavesNameMatchUnknown(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), now.AddDate(0, 6, 0)), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), f.roots, "", now)

	if ci.NameMatch != nil {
		t.Errorf("name_match = %v, want nil when no server name was configured", *ci.NameMatch)
	}
	if ci.Valid == nil || !*ci.Valid {
		t.Error("valid should not be dragged down by an unknown name match")
	}
}

func TestEvaluateServerChainUnknownRoot(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), now.AddDate(0, 6, 0)), f.intermediate)

	// An empty pool stands in for "the configured CA does not issue this".
	ci := EvaluateServerChain(f.chainOf(leaf), x509.NewCertPool(), "radius.example.com", now)

	if ci.ChainValid == nil || *ci.ChainValid {
		t.Error("chain_valid should be false against an unrelated root")
	}
	if ci.VerifyError == nil {
		t.Error("verify_error should explain the failure")
	}
	// Recording on the failure path is what keeps "expired" distinguishable
	// from "unreachable".
	if ci.Subject == nil || ci.ExpiresAt == nil {
		t.Error("certificate details must still be reported when verification fails")
	}
	if len(ci.Chain) != 3 {
		t.Errorf("chain length = %d, want 3 presented certs", len(ci.Chain))
	}
}

// Regression for the panic that used to happen on certs[0] with no peer certs.
func TestEvaluateServerChainEmpty(t *testing.T) {
	ci := EvaluateServerChain(nil, x509.NewCertPool(), "radius.example.com", now)

	if ci.Status != StatusUnavailable {
		t.Errorf("status = %q, want %q", ci.Status, StatusUnavailable)
	}
	if ci.Valid != nil || ci.ChainValid != nil {
		t.Error("nothing was observed, so nothing may be asserted")
	}
	if ci.Chain == nil || ci.DNSNames == nil {
		t.Error("slices must be allocated so they marshal to [] not null")
	}
}

func TestEvaluateClientCert(t *testing.T) {
	f := newFixture(t)
	expiry := now.AddDate(0, 2, 0)
	leaf, _ := issue(t, leafTemplate("probe@example.com", nil, now.AddDate(0, -1, 0), expiry), f.intermediate)
	keyMatch := true

	ci := EvaluateClientCert(leaf, &keyMatch, now)

	if ci.Status != StatusObserved || ci.Role != RoleClient {
		t.Fatalf("status/role = %q/%q", ci.Status, ci.Role)
	}
	if ci.KeyMatch == nil || !*ci.KeyMatch {
		t.Error("key_match should be true")
	}
	if ci.ValidNow == nil || !*ci.ValidNow {
		t.Error("valid_now should be true")
	}
	if ci.ExpiresAt == nil || *ci.ExpiresAt != expiry.Unix() {
		t.Errorf("expires_at = %v, want %d", ci.ExpiresAt, expiry.Unix())
	}
	// We do not verify our own chain, so these stay unknown rather than false.
	if ci.ChainValid != nil || ci.NameMatch != nil {
		t.Error("chain_valid and name_match are not meaningful for our own cert")
	}
}

func TestEvaluateClientCertExpired(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("probe@example.com", nil, now.AddDate(-1, 0, 0), now.AddDate(0, 0, -1)), f.intermediate)
	keyMatch := true

	ci := EvaluateClientCert(leaf, &keyMatch, now)

	if ci.ValidNow == nil || *ci.ValidNow {
		t.Error("valid_now should be false")
	}
	if ci.ExpiresInSeconds == nil || *ci.ExpiresInSeconds >= 0 {
		t.Error("expires_in_seconds should be negative")
	}
}

// A missing file tells us nothing about whether the key matched, so key_match
// must stay unknown rather than claim a mismatch.
func TestEvaluateClientCertMissingLeavesKeyMatchUnknown(t *testing.T) {
	ci := EvaluateClientCert(nil, nil, now)

	if ci.Status != StatusUnavailable {
		t.Errorf("status = %q, want %q", ci.Status, StatusUnavailable)
	}
	if ci.KeyMatch != nil {
		t.Error("key_match must be unknown when the certificate could not be read")
	}
}

func TestSerialHexMatchesOpensslStyle(t *testing.T) {
	for _, tc := range []struct {
		in   *big.Int
		want string
	}{
		{big.NewInt(0x0a1b2c), "0a1b2c"},
		{big.NewInt(255), "ff"},
		{big.NewInt(0), "00"},
		{nil, "00"},
	} {
		if got := serialHex(tc.in); got != tc.want {
			t.Errorf("serialHex(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// With --insecure there is no trust anchor, so validity is unknowable. The
// observable details must still be reported: seeing a certificate's expiry
// without configuring a CA is the main reason to use that flag.
func TestEvaluateServerChainNoTrustAnchor(t *testing.T) {
	f := newFixture(t)
	expiry := now.AddDate(0, 4, 0)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -1, 0), expiry), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), nil, "radius.example.com", now)

	if ci.Status != StatusObserved {
		t.Fatalf("status = %q, want %q", ci.Status, StatusObserved)
	}
	// Unknown, not false: there is nothing to verify against.
	if ci.ChainValid != nil {
		t.Errorf("chain_valid = %v, want nil without a trust anchor", *ci.ChainValid)
	}
	if ci.Valid != nil {
		t.Errorf("valid = %v, want nil without a trust anchor", *ci.Valid)
	}
	if ci.VerifyError != nil {
		t.Errorf("verify_error = %q, want nil: no verification was attempted", *ci.VerifyError)
	}
	// Everything observable is still reported.
	if ci.ExpiresAt == nil || *ci.ExpiresAt != expiry.Unix() {
		t.Errorf("expires_at = %v, want %d", ci.ExpiresAt, expiry.Unix())
	}
	if ci.ValidNow == nil || !*ci.ValidNow {
		t.Error("valid_now is still observable without a CA")
	}
	if ci.NameMatch == nil || !*ci.NameMatch {
		t.Error("name_match is still observable without a CA")
	}
	for name, got := range map[string]*string{
		"subject": ci.Subject,
		"serial":  ci.Serial,
		"sha256":  ci.SHA256,
	} {
		if got == nil {
			t.Errorf("%s should be reported without a CA", name)
		}
	}
	if len(ci.Chain) != 3 {
		t.Errorf("chain length = %d, want the 3 presented certs", len(ci.Chain))
	}
}

// An expired certificate seen without a trust anchor still reports expired.
func TestEvaluateServerChainNoTrustAnchorExpired(t *testing.T) {
	f := newFixture(t)
	leaf, _ := issue(t, leafTemplate("radius.example.com", []string{"radius.example.com"}, now.AddDate(0, -6, 0), now.AddDate(0, 0, -5)), f.intermediate)

	ci := EvaluateServerChain(f.chainOf(leaf), nil, "radius.example.com", now)

	if ci.ValidNow == nil || *ci.ValidNow {
		t.Error("valid_now should be false for an expired leaf")
	}
	if ci.ExpiresInSeconds == nil || *ci.ExpiresInSeconds >= 0 {
		t.Errorf("expires_in_seconds = %v, want negative", ci.ExpiresInSeconds)
	}
	if ci.Valid != nil {
		t.Error("valid stays unknown without a trust anchor, even when clearly expired")
	}
}
