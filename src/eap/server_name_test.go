package eap

import (
	"crypto/x509"
	"testing"
)

// The EAP server's certificate names the home institution's server, which is
// not the RADIUS host the client dialled. Deriving the expected name from the
// transport address therefore failed every roaming exchange -- against an IP
// literal with "doesn't contain any IP SANs", and against a hostname with a
// plain mismatch. Only a name the operator supplied is worth enforcing.
func TestHostnameEnforcedOnlyForASuppliedName(t *testing.T) {
	roots := x509.NewCertPool()

	tests := []struct {
		name              string
		serverName        string
		skipHostnameCheck bool
		rootCAs           *x509.CertPool
		want              bool
	}{
		{
			// The default: --ca-cert given, no --server-name. The chain is
			// still verified by verifyCertificateChain, which is what makes
			// skipping the name check here safe.
			name:       "no expected name",
			serverName: "",
			rootCAs:    roots,
			want:       false,
		},
		{
			name:       "expected name supplied",
			serverName: "clearpass.example.org",
			rootCAs:    roots,
			want:       true,
		},
		{
			name:              "explicitly skipped",
			serverName:        "clearpass.example.org",
			skipHostnameCheck: true,
			rootCAs:           roots,
			want:              false,
		},
		{
			// Without a trust anchor there is nothing to verify against, and
			// letting the stdlib verify would quietly fall back to the system
			// roots.
			name:       "no trust anchor",
			serverName: "clearpass.example.org",
			rootCAs:    nil,
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tt := &TLS{
				rootCAs:           tc.rootCAs,
				serverName:        tc.serverName,
				skipHostnameCheck: tc.skipHostnameCheck,
				insecure:          tc.rootCAs == nil,
			}
			if got := tt.hostnameEnforced(); got != tc.want {
				t.Errorf("hostnameEnforced() = %v, want %v", got, tc.want)
			}

			cfg := tt.baseTLSConfig()
			// InsecureSkipVerify governs only the stdlib's verification, the
			// one place the name would be enforced.
			if cfg.InsecureSkipVerify != !tc.want {
				t.Errorf("InsecureSkipVerify = %v, want %v", cfg.InsecureSkipVerify, !tc.want)
			}
			if cfg.ServerName != tc.serverName {
				t.Errorf("ServerName = %q, want %q", cfg.ServerName, tc.serverName)
			}
			// The chain is verified on every path, so a bad CA fails even when
			// the name is not checked.
			if cfg.VerifyPeerCertificate == nil {
				t.Error("VerifyPeerCertificate must be set on every path")
			}
			// Metrics are collected even on handshakes that go on to fail.
			if cfg.VerifyConnection == nil {
				t.Error("VerifyConnection must be set on every path")
			}
		})
	}
}

// Whatever each protocol adds on top, none of them may reach the wire having
// quietly dropped the trust anchor or the version pinning.
func TestBaseTLSConfigCarriesTheTrustAnchorAndVersionPinning(t *testing.T) {
	roots := x509.NewCertPool()
	tt := &TLS{rootCAs: roots, tlsVersion: 0x0303, serverName: "clearpass.example.org"}

	cfg := tt.baseTLSConfig()

	if cfg.RootCAs != roots {
		t.Error("RootCAs must be the configured pool")
	}
	if cfg.MinVersion != 0x0303 || cfg.MaxVersion != 0x0303 {
		t.Errorf("version pinning = [%#x, %#x], want both %#x", cfg.MinVersion, cfg.MaxVersion, 0x0303)
	}
}
