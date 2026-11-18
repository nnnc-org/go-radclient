/*
Copyright © 2025

Enumerated values used in the JSON metrics document.
*/
package metrics

// Result classifies the outcome of a probe exchange. Exactly one of these ends
// up in auth.result.
type Result string

const (
	// ResultAccept means the exchange completed and the server accepted.
	ResultAccept Result = "accept"
	// ResultReject means an Access-Reject was actually received. It is never
	// inferred from an error message.
	ResultReject Result = "reject"
	// ResultTimeout means no answer arrived in time.
	ResultTimeout Result = "timeout"
	// ResultTLSError means a TLS handshake failed.
	ResultTLSError Result = "tls_error"
	// ResultProtocolError covers a response that arrived but was unusable:
	// bad authenticator, unexpected code, missing expected attributes.
	ResultProtocolError Result = "protocol_error"
	// ResultConnectionError means the transport could not be established.
	ResultConnectionError Result = "connection_error"
	// ResultConfigError means the probe never ran: bad flags, unreadable files.
	ResultConfigError Result = "config_error"
	// ResultInternalError means the probe itself broke (a recovered panic).
	ResultInternalError Result = "internal_error"
)

// Stage names how far the exchange progressed. Stages are ordered, and the
// collector keeps the furthest one reached so that an unclassified error can
// still be attributed honestly.
type Stage string

const (
	StageConfig         Stage = "config"
	StageConnection     Stage = "connection"
	StageTLS            Stage = "tls"
	StageEAPNegotiation Stage = "eap_negotiation"
	StageInnerAuth      Stage = "inner_auth"
	StageRadiusResponse Stage = "radius_response"
)

// rank orders stages for the high-water mark. Unknown stages rank lowest.
func (s Stage) rank() int {
	switch s {
	case StageConfig:
		return 0
	case StageConnection:
		return 1
	case StageTLS:
		return 2
	case StageEAPNegotiation:
		return 3
	case StageInnerAuth:
		return 4
	case StageRadiusResponse:
		return 5
	}
	return -1
}

// Observation status for an optional sub-object. Always emitted, never null,
// so a Zabbix dependent item on it can never go unsupported.
const (
	// StatusObserved means we measured it.
	StatusObserved = "observed"
	// StatusNotApplicable means this protocol has no such thing, so its
	// absence carries no information about the server.
	StatusNotApplicable = "not_applicable"
	// StatusUnavailable means it should have existed but the exchange did not
	// get far enough to see it. Explicitly not the same as invalid.
	StatusUnavailable = "unavailable"
)

// Layer names a TLS handshake within one run. A single run can terminate up to
// three of them.
type Layer string

const (
	// LayerRadSec is the RADIUS-over-TLS transport handshake.
	LayerRadSec Layer = "radsec"
	// LayerEAP is the handshake a supplicant validates: plain EAP-TLS, or the
	// PEAP/EAP-TTLS tunnel.
	LayerEAP Layer = "eap"
	// LayerEAPInner is an inner EAP-TLS handshake inside an EAP-TTLS tunnel.
	LayerEAPInner Layer = "eap_inner"
)

// AllLayers is the fixed key set emitted under tls.layers, so every documented
// JSONPath resolves regardless of protocol.
var AllLayers = []Layer{LayerRadSec, LayerEAP, LayerEAPInner}

// Certificate roles.
const (
	RoleServer = "server"
	RoleClient = "client"
)
