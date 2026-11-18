/*
Copyright © 2025

TLS alert analysis.

A received TLS alert is the only solid evidence of why a handshake died, and in
particular the only proof that the peer rejected OUR certificate rather than
the handshake failing for some other reason. Everything else is a guess, so we
do not make it.

How Go surfaces alerts (crypto/tls, go1.26):

  - An alert RECEIVED from the peer becomes
    &net.OpError{Op: "remote error", Err: alert(code)}. The alert type is
    unexported, so we match on the OpError's Op and read the description from
    its Err. Note this means tls.AlertError does NOT match a received alert on
    a normal connection.
  - tls.AlertError is used for an alert WE sent, and only on the QUIC path. It
    is matched here too, so the code keeps working if that changes.
  - A failure of OUR OWN verification of the peer chain is a
    tls.CertificateVerificationError. That is the opposite direction and must
    never be reported as the peer rejecting us; it belongs to chain_valid.
*/
package metrics

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
)

// certAlerts are the alert descriptions that name a certificate problem, i.e.
// the cases where "the peer rejected our certificate" is proved. Keys are the
// descriptions crypto/tls produces, without its "tls: " prefix.
var certAlerts = map[string]bool{
	"bad certificate":                 true,
	"unsupported certificate":         true,
	"revoked certificate":             true,
	"expired certificate":             true,
	"unknown certificate":             true,
	"unknown certificate authority":   true,
	"certificate required":            true,
	"certificate unobtainable":        true,
	"bad certificate status response": true,
	"bad certificate hash value":      true,
}

// Alert describes a TLS alert observed while handshaking.
type Alert struct {
	// Description is the human-readable alert text, e.g. "bad certificate".
	Description string
	// Received is true when the peer sent us the alert, false when it was one
	// we sent. Only a received alert says anything about what the peer thinks.
	Received bool
	// CertRelated is true when the alert names a certificate problem.
	CertRelated bool
}

// AlertOf extracts a TLS alert from a handshake error, if there was one.
func AlertOf(err error) (Alert, bool) {
	if err == nil {
		return Alert{}, false
	}

	// An alert received from the peer.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" && opErr.Err != nil {
		desc := trimTLSPrefix(opErr.Err.Error())
		return Alert{
			Description: desc,
			Received:    true,
			CertRelated: certAlerts[desc],
		}, true
	}

	// An alert we sent (QUIC transport only, today).
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		desc := trimTLSPrefix(alertErr.Error())
		return Alert{
			Description: desc,
			Received:    false,
			CertRelated: certAlerts[desc],
		}, true
	}

	return Alert{}, false
}

// PeerRejectedOurCert reports whether err proves that the peer rejected the
// certificate we presented. It requires a received alert naming a certificate
// problem: a timeout, a torn-down tunnel, or a generic handshake failure is
// not evidence, and a failure of our own chain verification is evidence of the
// opposite.
func PeerRejectedOurCert(err error) bool {
	var verr *tls.CertificateVerificationError
	if errors.As(err, &verr) {
		return false
	}
	a, ok := AlertOf(err)
	return ok && a.Received && a.CertRelated
}

func trimTLSPrefix(s string) string {
	return strings.TrimPrefix(strings.TrimPrefix(s, "remote error: "), "tls: ")
}
