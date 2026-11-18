/*
Copyright © 2025

The JSON metrics document emitted by --json.

Schema rules, which Zabbix depends on:

  - Every key is always present. Unobserved tri-state facts are null pointers,
    never omitted and never false. An absent key makes a dependent item go
    unsupported; a false would assert something that was never measured.
  - Every optional sub-object carries a non-null status string, which is what
    triggers should gate on.
  - Slices are always allocated, never nil, so they marshal to [] not null.
  - Timestamps are Unix seconds. Durations are float milliseconds.
*/
package metrics

// SchemaVersion is bumped only on a breaking change to this document, so a
// Zabbix template can gate on the schema rather than on the tool version.
const SchemaVersion = 1

// Document is the whole emitted object.
type Document struct {
	SchemaVersion int       `json:"schema_version"`
	Probe         Probe     `json:"probe"`
	Auth          Auth      `json:"auth"`
	RADIUS        RADIUS    `json:"radius"`
	TLS           TLS       `json:"tls"`
	ClientCert    CertInfo  `json:"client_cert"`
	Attempts      []Attempt `json:"attempts"`
}

// Probe describes the invocation itself.
type Probe struct {
	Version    string `json:"version"`
	Command    string `json:"command"`
	Subcommand string `json:"subcommand"`
	Protocol   string `json:"protocol"`
	Transport  string `json:"transport"`
	Target     string `json:"target"`
	// Ran is false when the probe never reached the network: a config error or
	// a bad flag. Zabbix should treat ran==false as "my probe is broken",
	// not as "the server is down".
	Ran        bool    `json:"ran"`
	StartedAt  int64   `json:"started_at"`
	DurationMs float64 `json:"duration_ms"`
	// Panic is set only when the probe recovered from an internal failure.
	Panic *string `json:"panic"`
}

// Auth is the outcome of the exchange.
//
// Success is strictly independent of certificate validity: a wrong password
// can follow a perfectly valid server certificate.
//
// Note that Success can be false alongside an Access-Accept ResponseCode --
// the --attrs-to-recv check and the MS-MPPE key verification both run after
// the server has already accepted. Gate triggers on ResponseCode and
// FailureStage too, not on Success alone.
type Auth struct {
	Success              bool    `json:"success"`
	Result               Result  `json:"result"`
	FailureStage         *Stage  `json:"failure_stage"`
	ErrorMessage         *string `json:"error_message"`
	ResponseCode         *string `json:"response_code"`
	DurationMs           float64 `json:"duration_ms"`
	DurationExclJitterMs float64 `json:"duration_excl_jitter_ms"`
	Attempts             int     `json:"attempts"`
	CloseError           *string `json:"close_error"`
}

// RADIUS counts packets on the wire, summed across attempts.
type RADIUS struct {
	PacketsSent     int `json:"packets_sent"`
	PacketsReceived int `json:"packets_received"`
	// IdentifierMismatches counts replies whose RADIUS identifier did not
	// match the outstanding request. Without this, such a reply is
	// indistinguishable from a timeout.
	IdentifierMismatches int     `json:"identifier_mismatches"`
	JitterTotalMs        float64 `json:"jitter_total_ms"`
}

// TLS holds one entry per possible handshake layer, keyed by layer name so
// that a JSONPath always refers to the same handshake regardless of protocol.
type TLS struct {
	Layers map[Layer]TLSLayer `json:"layers"`
}

// TLSLayer is one handshake.
type TLSLayer struct {
	Status                     string   `json:"status"`
	Version                    *string  `json:"version"`
	CipherSuite                *string  `json:"cipher_suite"`
	SessionResumed             *bool    `json:"session_resumed"`
	HandshakeDurationMs        *float64 `json:"handshake_duration_ms"`
	HandshakeDurationExclJitMs *float64 `json:"handshake_duration_excl_jitter_ms"`
	HandshakeError             *string  `json:"handshake_error"`
	// Alert is the description of a TLS alert received from the peer, when one
	// was received. It is the only honest evidence of why a handshake died.
	Alert *string `json:"alert"`
	// PeerCertRejected is true only when the peer sent an alert that names a
	// certificate problem, which is the one case where "it rejected our
	// certificate" is proved rather than guessed.
	PeerCertRejected *bool    `json:"peer_cert_rejected"`
	ServerCert       CertInfo `json:"server_cert"`
	ClientCert       CertInfo `json:"client_cert"`
}

// CertInfo describes one certificate.
//
// Valid means: chains to the CA passed on the command line, is inside its
// validity window, and matches the expected name. It does NOT mean "valid
// according to the system trust store".
type CertInfo struct {
	Status string `json:"status"`
	Role   string `json:"role"`
	Layer  *Layer `json:"layer"`

	Valid       *bool   `json:"valid"`
	ChainValid  *bool   `json:"chain_valid"`
	NameMatch   *bool   `json:"name_match"`
	ValidNow    *bool   `json:"valid_now"`
	KeyMatch    *bool   `json:"key_match"`
	VerifyError *string `json:"verify_error"`

	NotBefore        *int64 `json:"not_before"`
	ExpiresAt        *int64 `json:"expires_at"`
	ExpiresInSeconds *int64 `json:"expires_in_seconds"`
	// ChainExpiresAt is the earliest expiry in the chain excluding the trust
	// anchor, whose expiry is ours to manage rather than the server's.
	ChainExpiresAt *int64 `json:"chain_expires_at"`

	Subject  *string  `json:"subject"`
	Issuer   *string  `json:"issuer"`
	Serial   *string  `json:"serial"`
	SHA256   *string  `json:"sha256"`
	DNSNames []string `json:"dns_names"`

	Chain []ChainCert `json:"chain"`
}

// ChainCert is one certificate as presented, leaf first.
type ChainCert struct {
	Index            int    `json:"index"`
	Subject          string `json:"subject"`
	Issuer           string `json:"issuer"`
	Serial           string `json:"serial"`
	SHA256           string `json:"sha256"`
	NotBefore        int64  `json:"not_before"`
	ExpiresAt        int64  `json:"expires_at"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
	IsCA             bool   `json:"is_ca"`
}

// Attempt is one pass through the retry loop.
type Attempt struct {
	Index                int     `json:"index"`
	StartedAt            int64   `json:"started_at"`
	DurationMs           float64 `json:"duration_ms"`
	DurationExclJitterMs float64 `json:"duration_excl_jitter_ms"`
	Success              bool    `json:"success"`
	Result               Result  `json:"result"`
	FailureStage         *Stage  `json:"failure_stage"`
	ErrorMessage         *string `json:"error_message"`
	ResponseCode         *string `json:"response_code"`
	PacketsSent          int     `json:"packets_sent"`
	PacketsReceived      int     `json:"packets_received"`
}

// notApplicableCert is the zero observation: this protocol has no such
// certificate, so nothing can be concluded from its absence.
func notApplicableCert(role string) CertInfo {
	return CertInfo{
		Status:   StatusNotApplicable,
		Role:     role,
		DNSNames: []string{},
		Chain:    []ChainCert{},
	}
}

// notApplicableLayer is the zero observation for a handshake that this
// protocol never performs.
func notApplicableLayer() TLSLayer {
	return TLSLayer{
		Status:     StatusNotApplicable,
		ServerCert: notApplicableCert(RoleServer),
		ClientCert: notApplicableCert(RoleClient),
	}
}
