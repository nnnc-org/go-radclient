/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/nnnc-org/go-radclient/src/eap"
	"github.com/nnnc-org/go-radclient/src/metrics"
	"github.com/nnnc-org/go-radclient/src/radius"
	"github.com/spf13/cobra"
)

// authentication protocols
const (
	authMAB                = "mab"
	authMabEapMd5          = "mab-eap-md5"
	authPAP                = "pap"
	authEapMsCHAPv2        = "eap-ms-chapv2"
	authEapTLS             = "eap-tls"
	authEapTtlsPAP         = "eap-ttls-pap"
	authEapTtlsEapMsCHAPv2 = "eap-ttls-eap-ms-chapv2"
	authEapTtlsEapTLS      = "eap-ttls-eap-tls"
	authPeapMsCHAPv2       = "peap-ms-chapv2"
)

// required values for protocols
// no sets in go, so using maps with empty structs
var (
	requireMACAddress = map[string]struct{}{
		authMAB:       {},
		authMabEapMd5: {},
	}
	requireUsernameAndPassword = map[string]struct{}{
		authPAP:                {},
		authEapMsCHAPv2:        {},
		authEapTtlsPAP:         {},
		authEapTtlsEapMsCHAPv2: {},
		authPeapMsCHAPv2:       {},
	}
	requireClientAndCACertificate = map[string]struct{}{
		authEapTLS:        {},
		authEapTtlsEapTLS: {},
	}
	requireTunneledCACertificate = map[string]struct{}{
		authEapTtlsPAP:         {},
		authEapTtlsEapMsCHAPv2: {},
		authEapTtlsEapTLS:      {},
		authPeapMsCHAPv2:       {},
	}
)

var (
	macAddress           string
	username             string
	password             string
	anonymousUsername    string
	clientCertificate    string
	caCertificate        string
	tunnelCACertificate  string
	tlsVersion           string
	eapSendStart         bool
	tlsSkipHostnameCheck bool
)

var authCmd = &cobra.Command{
	Use:     "authentication",
	Aliases: []string{"auth"},
	Short:   "RADIUS client authentication",
	Long:    `Carry out RADIUS full client authentication sessions`,
}

var authUdpCmd = &cobra.Command{
	Use:     "udp ADDRESS SHARED_SECRET PROTOCOL",
	Short:   "RADIUS/UDP client authentication",
	Args:    cobra.ExactArgs(3),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		collector.SetInvocation("auth", "udp", args[2], "udp", args[0])
		registerSecrets(args[1])
		collector.ExpectLayer(expectedLayers(args[2])...)
		if err := preloadProbeCerts(args[2]); err != nil {
			return err
		}
		return retry(func() error {
			return auth(func() (*radius.AuthenticationSession, string, error) {
				session, err := newUDPAuthSession(args[0], args[1], udpMTUSize, sendAttributes, receiveAttributes)
				return session, args[0], err
			}, args[2])
		})
	},
}

var authTlsCmd = &cobra.Command{
	Use:     "tls ADDRESS SERVER_CA CLIENT_CERT PROTOCOL",
	Short:   "RADIUS/TLS client authentication",
	Args:    cobra.ExactArgs(4),
	PreRunE: prerun,
	RunE: func(cmd *cobra.Command, args []string) error {
		collector.SetInvocation("auth", "tls", args[3], "radsec", args[0])
		// The RadSec shared secret is fixed by RFC 6614, so there is no secret
		// positional argument on this subcommand.
		registerSecrets("")
		collector.ExpectLayer(expectedLayers(args[3])...)
		if err := preloadProbeCerts(args[3]); err != nil {
			return err
		}
		return retry(func() error {
			return auth(func() (*radius.AuthenticationSession, string, error) {
				session, err := newTLSAuthSession(args[0], args[1], args[2], sendAttributes, receiveAttributes)
				return session, args[0], err
			}, args[3])
		})
	},
}

func init() {
	authCmd.PersistentFlags().StringVar(&macAddress, "mac", "", "MAC Address")
	authCmd.PersistentFlags().StringVar(&username, "username", "", "Username")
	authCmd.PersistentFlags().StringVar(&password, "password", "", "Password")
	authCmd.PersistentFlags().StringVar(&anonymousUsername, "anonymous-username", "anonymous", "EAP anonymous username")
	authCmd.PersistentFlags().StringVar(&clientCertificate, "client-cert", "", "Client certificate")
	authCmd.PersistentFlags().StringVar(&caCertificate, "ca-cert", "", "CA certificate")
	authCmd.PersistentFlags().StringVar(&tunnelCACertificate, "tunnel-ca-cert", "", "tunnel CA certificate")
	authCmd.PersistentFlags().StringVar(&tlsVersion, "tls-version", "1.2", "TLS version underlying TLS-based protocols")
	authCmd.PersistentFlags().BoolVar(&eapSendStart, "eap-send-start", false, "EAP send EAP-Start")
	authCmd.PersistentFlags().BoolVar(&tlsSkipHostnameCheck, "tls-skip-hostname-check", false, "TLS skip Hostname check in handshake")

	// username and password are no longer required together: a missing
	// password is prompted for instead, and cobra would reject the
	// combination before we got the chance.

	authCmd.AddCommand(authUdpCmd, authTlsCmd)
}

func auth(f func() (*radius.AuthenticationSession, string, error), protocol string) error {
	session, serverName, err := f()
	if err != nil {
		slog.Error("failed to create session",
			"command", "auth",
			"protocol", protocol,
			"error", err,
		)
		return err
	}
	defer func() {
		err := session.Close()
		if err != nil {
			// Kept apart from the exchange outcome: a late close failure must
			// not read as a failed authentication.
			collector.SetCloseError(err)
			slog.Error("failed to close session",
				"command", "auth",
				"protocol", protocol,
				"error", err,
			)
		}
	}()
	err = internalAuth(session, serverName, protocol)
	if err != nil {
		slog.Error("failed authentication",
			"network", session.RemoteAddr().Network(),
			"address", session.RemoteAddr(),
			"command", "auth",
			"protocol", protocol,
			"error", err,
		)
		return err
	}
	slog.Info("successful authentication",
		"network", session.RemoteAddr().Network(),
		"address", session.RemoteAddr(),
		"command", "auth",
		"protocol", protocol,
	)
	return nil
}

func internalAuth(session *radius.AuthenticationSession, serverName, protocol string) error {
	switch protocol {
	case authMAB:
		return session.MAB(macAddress)
	case authPAP:
		return session.PAP(username, password)
	}
	if !strings.HasPrefix(protocol, "eap-") && !strings.HasPrefix(protocol, "peap-") && protocol != authMabEapMd5 {
		return fmt.Errorf("unknown protocol picked: %s", protocol)
	}
	// Scoped to this attempt: mutating the package global would leak into
	// every later retry.
	anonUsername := anonymousUsername
	if protocol == authMabEapMd5 {
		anonUsername = macAddress
	}

	eaptunnel := radius.NewEapAuthenticationTunnel(session, anonUsername)
	if eaptunnel == nil {
		return fmt.Errorf("failed to create EAP tunnel")
	}
	// nolint:errcheck // function does not return error
	defer eaptunnel.Close()
	eapsession := eap.NewSession(eaptunnel, anonUsername, eapSendStart)
	eapsession.Metrics = session.Metrics
	err := eapAuth(eapsession, serverName, protocol)
	if err != nil {
		return err
	}
	return session.VerifyEAP(eapsession.RecvKey, eapsession.SendKey)
}

func eapAuth(session *eap.Session, serverName, protocol string) error {
	switch protocol {
	case authMabEapMd5:
		return session.MD5(macAddress)
	case authEapMsCHAPv2:
		return session.MsCHAPv2(username, password)
	case authEapTLS:
		eaptls, err := eap.CreateTLS(session, caCertificate, tlsVersion, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		eaptls.SetMetrics(collector, metrics.LayerEAP)
		return eaptls.Authenticate(clientCertificate, tlsAuthenticationKeyLogFilename)
	case authEapTtlsPAP:
		eapttls, err := eap.CreateTTLS(session, tunnelCACertificate, tlsVersion, serverName, tlsTunnelKeyLogFilename, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		eapttls.SetMetrics(collector, metrics.LayerEAP)
		return eapttls.PAP(username, password)
	case authEapTtlsEapMsCHAPv2:
		eapttls, err := eap.CreateTtlsEAP(session, tunnelCACertificate, tlsVersion, serverName, tlsTunnelKeyLogFilename, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		eapttls.SetMetrics(collector, metrics.LayerEAP)
		ts := eap.NewSession(eapttls, innerIdentity(), false)
		ts.Metrics = collector
		return ts.MsCHAPv2(username, password)
	case authEapTtlsEapTLS:
		eapttls, err := eap.CreateTtlsEAP(session, tunnelCACertificate, tlsVersion, serverName, tlsTunnelKeyLogFilename, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		// Two handshakes here, reported separately: the outer tunnel and the
		// inner EAP-TLS, each with its own CA and its own certificate.
		eapttls.SetMetrics(collector, metrics.LayerEAP)
		ts := eap.NewSession(eapttls, innerIdentity(), false)
		ts.Metrics = collector
		eaptls, err := eap.CreateTLS(ts, caCertificate, tlsVersion, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		eaptls.SetMetrics(collector, metrics.LayerEAPInner)
		return eaptls.Authenticate(clientCertificate, tlsAuthenticationKeyLogFilename)
	case authPeapMsCHAPv2:
		peap, err := eap.CreatePEAP(session, tunnelCACertificate, tlsVersion, serverName, tlsTunnelKeyLogFilename, tlsSkipHostnameCheck)
		if err != nil {
			return err
		}
		peap.SetMetrics(collector, metrics.LayerEAP)
		ts := eap.NewSession(peap, innerIdentity(), true)
		ts.Metrics = collector
		return ts.MsCHAPv2(username, password)
	default:
		return fmt.Errorf("unknown protocol picked: %s", protocol)
	}
}

func prerun(cmd *cobra.Command, args []string) error {
	protocol := args[len(args)-1]
	mv := missingValues(protocol)
	if len(mv) > 0 {
		return fmt.Errorf(
			"missing values [%s] for protocol [%s]",
			strings.Join(mv, ", "),
			protocol,
		)
	}
	// Done here rather than in the run functions so that the prompt happens
	// once, before any attempt, and never between retries.
	if err := resolvePassword(protocol); err != nil {
		return err
	}
	return nil
}

func missingValues(protocol string) (mv []string) {
	if _, ok := requireMACAddress[protocol]; ok && macAddress == "" {
		mv = append(mv, "mac")
	}
	if _, ok := requireUsernameAndPassword[protocol]; ok && username == "" {
		mv = append(mv, "username")
	}
	if _, ok := requireClientAndCACertificate[protocol]; ok && clientCertificate == "" {
		mv = append(mv, "client-cert")
	}
	if !insecure {
		if _, ok := requireClientAndCACertificate[protocol]; ok && caCertificate == "" {
			mv = append(mv, "ca-cert")
		}
		if _, ok := requireTunneledCACertificate[protocol]; ok && tunnelCACertificate == "" {
			mv = append(mv, "tunnel-ca-cert")
		}
	}
	return
}

// expectedLayers names the TLS handshakes a protocol performs, so that a layer
// which never materializes can be reported as unknown rather than as not
// applicable. The distinction is what keeps a timeout from reading as an
// invalid certificate.
//
// The RadSec transport layer is declared by dialTLS instead, since it depends
// on the subcommand rather than on the protocol.
func expectedLayers(protocol string) []metrics.Layer {
	switch protocol {
	case authEapTLS, authEapTtlsPAP, authEapTtlsEapMsCHAPv2, authPeapMsCHAPv2:
		// One handshake: either plain EAP-TLS or the PEAP/TTLS tunnel. Both are
		// the certificate a supplicant validates.
		return []metrics.Layer{metrics.LayerEAP}
	case authEapTtlsEapTLS:
		// Two independent handshakes: the outer TTLS tunnel and an inner
		// EAP-TLS inside it.
		return []metrics.Layer{metrics.LayerEAP, metrics.LayerEAPInner}
	}
	// mab, mab-eap-md5, pap and eap-ms-chapv2 terminate no TLS of their own.
	return nil
}

// clientCertLayer names the handshake our own certificate is presented on.
// For EAP-TLS inside an EAP-TTLS tunnel that is the inner handshake.
func clientCertLayer(protocol string) metrics.Layer {
	if protocol == authEapTtlsEapTLS {
		return metrics.LayerEAPInner
	}
	return metrics.LayerEAP
}

// preloadProbeCerts parses our own certificate before any dialing, so that
// client_cert expiry is reported even when the server is unreachable. Warning
// ahead of the probe's own certificate expiring is the whole point of that
// metric, and it would be useless if it only worked while the server was up.
//
// A failure here is a config error: the probe never gets to run.
func preloadProbeCerts(protocol string) error {
	if _, ok := requireClientAndCACertificate[protocol]; !ok {
		return nil
	}
	_, err := loadClientCert(clientCertificate, clientCertLayer(protocol))
	return err
}

// innerIdentity is the EAP identity sent inside a PEAP or EAP-TTLS tunnel.
//
// The point of those protocols is that the real identity is only revealed
// inside the encrypted tunnel, so the anonymous identity belongs on the
// outside only. Sending it inside as well makes any server that authorizes on
// the inner identity reject the request, which it reports as a tunnelled
// failure rather than as a bad password -- a confusing way to discover a
// client bug. This matches what eapol_test does with identity versus
// anonymous_identity.
//
// Protocols with no username, such as EAP-TLS inside EAP-TTLS, fall back to
// the anonymous identity rather than sending an empty one.
func innerIdentity() string {
	if username != "" {
		return username
	}
	return anonymousUsername
}
