/*
Copyright © 2024 Keytos alan@keytos.io

Define Tunneled-TLS authentication session
*/
package eap

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"os"

	"github.com/nnnc-org/go-radclient/src/eap/diameter"
	"github.com/nnnc-org/go-radclient/src/metrics"
)

const ttlsMasterKeyLabel = "ttls keying material"

type TTLS struct {
	*TLS
	tunnelKeyLogWriter *os.File
	client             *tls.Conn
	handshakeDone      bool
}

func CreateTTLS(session *Session, caCert, tlsVersion, serverName, tlsTunnelKeyLogFilename string, tlsSkipHostnameCheck bool) (*TTLS, error) {
	t, err := internalCreateTLS(session, caCert, tlsVersion, serverName, tlsSkipHostnameCheck, TypeTTLS)
	if err != nil {
		return nil, err
	}
	tlsConfig := t.baseTLSConfig()
	tlsConfig.SessionTicketsDisabled = true
	var ttls *TTLS
	if tlsTunnelKeyLogFilename != "" {
		f, err := os.OpenFile(tlsTunnelKeyLogFilename, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		tlsConfig.KeyLogWriter = f
		ttls = &TTLS{TLS: t, tunnelKeyLogWriter: f, client: tls.Client(t, tlsConfig)}
	} else {
		ttls = &TTLS{TLS: t, client: tls.Client(t, tlsConfig)}
	}
	t.conn = ttls.client
	return ttls, nil
}

// Handshake completes the tunnel handshake explicitly, once.
//
// Without it, crypto/tls would handshake lazily inside the first client.Write
// -- in PAP below, or in TtlsEAP.Read/Write -- which leaves nothing to time
// and no clean point at which a handshake failure can be told apart from an
// inner authentication failure.
//
// It is called at first use rather than from CreateTTLS because the collector
// is attached after construction, and a handshake run before that would go
// unrecorded. Callers that write to the tunnel must call it first; it is
// idempotent.
func (tt *TTLS) Handshake() error {
	if tt.handshakeDone {
		return nil
	}
	tt.handshakeDone = true
	tt.Metrics.AdvanceStage(metrics.StageTLS)
	hat := tt.Metrics.BeginHandshake(tt.Layer)
	if err := hat.Finish(tt.client.Handshake()); err != nil {
		return metrics.Wrap(metrics.StageTLS, metrics.ResultTLSError, err)
	}
	tt.Metrics.AdvanceStage(metrics.StageInnerAuth)
	return nil
}

func (tt *TTLS) PAP(uname, pw string) error {
	if err := tt.Handshake(); err != nil {
		return err
	}
	bw := bufio.NewWriter(tt.client)
	_, err := diameter.AttributeValuePair{
		Code:  diameter.CodeUserName,
		Flags: diameter.FlagsMandatory,
		Data:  []byte(uname),
	}.WriteTo(bw)
	if err != nil {
		return err
	}
	_, err = diameter.AttributeValuePair{
		Code:  diameter.CodeUserPassword,
		Flags: diameter.FlagsMandatory,
		Data:  []byte(pw),
	}.WriteTo(bw)
	if err != nil {
		return err
	}
	err = bw.Flush()
	if err != nil {
		return err
	}

	// auth finalization
	rd := &Datagram{}
	_, err = tt.ReadDatagram(rd)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeSuccess {
		// Provisional: Classify downgrades this unless an Access-Reject was seen.
		return metrics.Wrap(metrics.StageInnerAuth, metrics.ResultReject,
			fmt.Errorf("authentication failed"))
	}
	tt.RecvKey, tt.SendKey, err = exportKeyingMaterial(tt.client, ttlsMasterKeyLabel)
	return err
}

func (tt *TTLS) Close() error {
	var err error
	tt.RecvKey, tt.SendKey, err = exportKeyingMaterial(tt.client, ttlsMasterKeyLabel)
	err = errors.Join(err, tt.TLS.Close())
	if tt.tunnelKeyLogWriter != nil {
		err = errors.Join(err, tt.tunnelKeyLogWriter.Close())
	}
	return err
}
