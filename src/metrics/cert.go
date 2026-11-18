/*
Copyright © 2025

Certificate evaluation. Pure functions over parsed certificates: no TLS
connection, no clock of their own, so they are exhaustively testable against
generated fixtures.
*/
package metrics

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"time"
)

// EvaluateServerChain describes a server certificate chain as presented on the
// wire, leaf first.
//
// chainValid, nameMatch and validNow are reported separately and deliberately:
// an expired certificate also fails chain verification, so collapsing them
// would tell an operator "chain invalid" without telling them why.
//
// serverName may be empty, in which case nameMatch is left unknown rather than
// asserted either way.
func EvaluateServerChain(chain []*x509.Certificate, roots *x509.CertPool, serverName string, now time.Time) CertInfo {
	ci := notApplicableCert(RoleServer)
	if len(chain) == 0 {
		ci.Status = StatusUnavailable
		return ci
	}
	leaf := chain[0]
	ci.Status = StatusObserved
	fillLeaf(&ci, leaf, now)

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	verified, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	chainValid := err == nil
	ci.ChainValid = &chainValid
	if err != nil {
		ci.VerifyError = strPtr(err.Error())
	}

	// crypto/tls never sets VerifyOptions.DNSName here, so the name is checked
	// only for reporting. It is reported even when hostname checking is
	// skipped: observed, not enforced.
	if serverName != "" {
		nameMatch := leaf.VerifyHostname(serverName) == nil
		ci.NameMatch = &nameMatch
	}

	valid := chainValid && derefBool(ci.ValidNow) && (ci.NameMatch == nil || *ci.NameMatch)
	ci.Valid = &valid

	// Prefer the chain the verifier built; fall back to what the peer sent.
	effective := chain
	if len(verified) > 0 {
		effective = verified[0]
	}
	ci.Chain = chainCerts(effective, now)
	if exp, ok := chainExpiry(effective, now); ok {
		ci.ChainExpiresAt = &exp
	}
	return ci
}

// EvaluateClientCert describes our own certificate. keyMatch is passed in
// rather than computed: only the loader knows whether the private key matched,
// and a missing file must leave it unknown rather than claim a mismatch.
func EvaluateClientCert(leaf *x509.Certificate, keyMatch *bool, now time.Time) CertInfo {
	ci := notApplicableCert(RoleClient)
	ci.KeyMatch = keyMatch
	if leaf == nil {
		ci.Status = StatusUnavailable
		return ci
	}
	ci.Status = StatusObserved
	fillLeaf(&ci, leaf, now)
	// A client certificate has no server name to match and no chain for us to
	// verify, so Valid reduces to "inside its validity window".
	valid := derefBool(ci.ValidNow) && (keyMatch == nil || *keyMatch)
	ci.Valid = &valid
	ci.Chain = chainCerts([]*x509.Certificate{leaf}, now)
	return ci
}

// UnavailableCert marks a certificate we expected to see but never got far
// enough to observe. Reporting unknown rather than invalid is the point: a
// timeout says nothing about the certificate.
func UnavailableCert(role string) CertInfo {
	ci := notApplicableCert(role)
	ci.Status = StatusUnavailable
	return ci
}

func fillLeaf(ci *CertInfo, leaf *x509.Certificate, now time.Time) {
	nb := leaf.NotBefore.Unix()
	na := leaf.NotAfter.Unix()
	remaining := int64(leaf.NotAfter.Sub(now).Seconds())
	validNow := !now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter)

	ci.NotBefore = &nb
	ci.ExpiresAt = &na
	ci.ExpiresInSeconds = &remaining
	ci.ValidNow = &validNow
	ci.Subject = strPtr(leaf.Subject.String())
	ci.Issuer = strPtr(leaf.Issuer.String())
	ci.Serial = strPtr(serialHex(leaf.SerialNumber))
	ci.SHA256 = strPtr(fingerprint(leaf))
	ci.DNSNames = append([]string{}, leaf.DNSNames...)
}

func chainCerts(chain []*x509.Certificate, now time.Time) []ChainCert {
	out := make([]ChainCert, 0, len(chain))
	for i, c := range chain {
		out = append(out, ChainCert{
			Index:            i,
			Subject:          c.Subject.String(),
			Issuer:           c.Issuer.String(),
			Serial:           serialHex(c.SerialNumber),
			SHA256:           fingerprint(c),
			NotBefore:        c.NotBefore.Unix(),
			ExpiresAt:        c.NotAfter.Unix(),
			ExpiresInSeconds: int64(c.NotAfter.Sub(now).Seconds()),
			IsCA:             c.IsCA,
		})
	}
	return out
}

// chainExpiry returns the earliest expiry in the chain, excluding the trust
// anchor. The anchor is the root we were handed locally, so its expiry is an
// operator problem rather than a server problem, and including it would fire
// alerts about our own CA file.
func chainExpiry(chain []*x509.Certificate, _ time.Time) (int64, bool) {
	end := len(chain)
	if end > 1 && isSelfSigned(chain[end-1]) {
		end--
	}
	if end == 0 {
		return 0, false
	}
	earliest := chain[0].NotAfter
	for _, c := range chain[1:end] {
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
	}
	return earliest.Unix(), true
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String()
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// serialHex formats a serial the way openssl x509 -serial does, which is what
// an operator will have copied out of their CA console. A decimal big.Int
// string would match nothing they can compare against.
func serialHex(n *big.Int) string {
	if n == nil {
		return "00"
	}
	b := n.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return hex.EncodeToString(b)
}

func strPtr(s string) *string { return &s }

func derefBool(b *bool) bool { return b != nil && *b }
