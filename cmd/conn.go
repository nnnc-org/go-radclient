/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nnnc-org/go-radclient/src/metrics"
	"github.com/nnnc-org/go-radclient/src/radius"
)

type statusSession interface {
	net.Conn
	Status() error
}

func dialUDP(ip string, port int) (net.Conn, error) {
	collector.AdvanceStage(metrics.StageConnection)
	d := net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		},
		Timeout: 10 * time.Second,
	}
	conn, err := d.Dial("udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, dialError(err)
	}
	return conn, nil
}

// dialError distinguishes "nothing answered in time" from "the transport could
// not be established at all", which are different problems for an operator.
func dialError(err error) error {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return metrics.Wrap(metrics.StageConnection, metrics.ResultTimeout, err)
	}
	return metrics.Wrap(metrics.StageConnection, metrics.ResultConnectionError, err)
}

func dialTLS(address, caCert, clientCert string) (*tls.Conn, error) {
	// Parsed before dialing so that certificate expiry metrics survive a server
	// that is down: a missing file is our problem, not the server's.
	rootCAs, err := loadCAPool(caCert)
	if err != nil {
		return nil, err
	}
	cert, err := loadClientCert(clientCert, metrics.LayerRadSec)
	if err != nil {
		return nil, err
	}

	collector.ExpectLayer(metrics.LayerRadSec)
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            rootCAs,
		InsecureSkipVerify: radsecUnsafe,
	}

	if !strings.ContainsRune(address, ':') {
		address = fmt.Sprintf("%s:%d", address, tcpPort)
	}
	serverName, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		serverName = address
	}

	collector.AdvanceStage(metrics.StageConnection)
	// tls.Dial completes the handshake, so this brackets all of it. The
	// redundant conn.Handshake() the previous version called afterwards is
	// gone.
	collector.AdvanceStage(metrics.StageTLS)
	hat := collector.BeginHandshake(metrics.LayerRadSec)
	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err = hat.Finish(err); err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return nil, dialError(err)
		}
		return nil, metrics.Wrap(metrics.StageTLS, metrics.ResultTLSError, err)
	}

	// With --radsec-unsafe nothing was verified and VerifiedChains is empty, so
	// the chain is evaluated here against the pinned pool either way.
	cs := conn.ConnectionState()
	collector.RecordConnectionState(metrics.LayerRadSec, cs)
	collector.RecordServerChain(metrics.LayerRadSec,
		metrics.EvaluateServerChain(cs.PeerCertificates, rootCAs, serverName, time.Now()))
	return conn, nil
}

// loadCAPool reads a CA bundle. An unreadable or non-PEM file is a config
// error: reporting it as an invalid server certificate would blame the server
// for an operator mistake.
func loadCAPool(caCert string) (*x509.CertPool, error) {
	// --insecure means there is no trust anchor, so the CA argument is not
	// read at all. A nil pool signals that to the evaluator: an empty one
	// would instead fail every chain and look like a server problem.
	if insecure {
		return nil, nil
	}
	content, err := os.ReadFile(caCert)
	if err != nil {
		return nil, metrics.Wrap(metrics.StageConfig, metrics.ResultConfigError, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(content) {
		return nil, metrics.Wrap(metrics.StageConfig, metrics.ResultConfigError,
			fmt.Errorf("no certificates found in CA file: %s", caCert))
	}
	return rootCAs, nil
}

// loadClientCert reads our own certificate and key from one combined PEM and
// records its metrics straight away.
//
// LoadX509KeyPair validates that the key matches the certificate, so success
// is what key_match reports. A file we could not read tells us nothing about
// whether they matched, so key_match stays unknown rather than claiming a
// mismatch.
func loadClientCert(path string, layer metrics.Layer) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(path, path)
	if err != nil {
		var keyMatch *bool
		if strings.Contains(err.Error(), "does not match") {
			no := false
			keyMatch = &no
		}
		ci := metrics.EvaluateClientCert(nil, keyMatch, time.Now())
		collector.SetProbeClientCert(layer, ci)
		return cert, metrics.Wrap(metrics.StageConfig, metrics.ResultConfigError, err)
	}
	keyMatch := true
	ci := metrics.EvaluateClientCert(cert.Leaf, &keyMatch, time.Now())
	collector.SetProbeClientCert(layer, ci)
	collector.RecordLayerClientCert(layer, ci)
	return cert, nil
}

func newUDPAuthSession(address, sharedSecret string, mtuSize int, sendattrs, recvattrs radius.AttributeMap) (*radius.AuthenticationSession, error) {
	conn, err := dialUDP(address, udpAuthPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if !sendattrs.ContainsType(radius.AttributeTypeNasIdentifier) {
		sendattrs.SetType(radius.AttributeTypeNasIdentifier, "radius-client")
	}
	sendattrs.SetType(radius.AttributeTypeFramedMtu, strconv.Itoa(mtuSize))
	return withAuthMetrics(radius.NewAuthenticationSession(conn, sharedSecret, udpTimeout, minWriteJitter, maxWriteJitter, udpRetries, mtuSize, sendattrs, recvattrs))
}

func newUDPAcctSession(address, sharedSecret string, mtuSize int, sendattrs, recvattrs radius.AttributeMap) (*radius.AccountingSession, error) {
	conn, err := dialUDP(address, udpAcctPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if !sendattrs.ContainsType(radius.AttributeTypeNasIdentifier) && !skipCheckAcctNasId {
		sendattrs.SetType(radius.AttributeTypeNasIdentifier, "radius-client")
	}
	sendattrs.SetType(radius.AttributeTypeFramedMtu, strconv.Itoa(mtuSize))
	return withAcctMetrics(radius.NewAccountingSession(conn, sharedSecret, udpTimeout, minWriteJitter, maxWriteJitter, udpRetries, mtuSize, sendattrs, recvattrs))
}

func newTLSAuthSession(address, serverCA, clientCer string, sendattrs, recvattrs radius.AttributeMap) (*radius.AuthenticationSession, error) {
	conn, err := dialTLS(address, serverCA, clientCer)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if !sendattrs.ContainsType(radius.AttributeTypeNasIdentifier) {
		sendattrs.SetType(radius.AttributeTypeNasIdentifier, "radius-client")
	}
	return withAuthMetrics(radius.NewAuthenticationSession(conn, "radsec", tlsTimeout, minWriteJitter, maxWriteJitter, 1, radius.DatagramMaxLen, sendattrs, recvattrs))
}

func newTLSAcctSession(address, serverCA, clientCer string, sendattrs, recvattrs radius.AttributeMap) (*radius.AccountingSession, error) {
	conn, err := dialTLS(address, serverCA, clientCer)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	if !sendattrs.ContainsType(radius.AttributeTypeNasIdentifier) && !skipCheckAcctNasId {
		sendattrs.SetType(radius.AttributeTypeNasIdentifier, "radius-client")
	}
	return withAcctMetrics(radius.NewAccountingSession(conn, "radsec", tlsTimeout, minWriteJitter, maxWriteJitter, 1, radius.DatagramMaxLen, sendattrs, recvattrs))
}

// withAuthMetrics attaches the collector to a freshly built session. Metrics is
// an exported field promoted from the embedded radius session, so attaching it
// here needs no change to any constructor signature.
func withAuthMetrics(s *radius.AuthenticationSession, err error) (*radius.AuthenticationSession, error) {
	if s != nil {
		s.Metrics = collector
	}
	return s, err
}

func withAcctMetrics(s *radius.AccountingSession, err error) (*radius.AccountingSession, error) {
	if s != nil {
		s.Metrics = collector
	}
	return s, err
}
