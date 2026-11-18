/*
Copyright © 2024 Keytos alan@keytos.io

Define Protected EAP tunnel
*/
package eap

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/nnnc-org/go-radclient/src/metrics"
)

type PEAP struct {
	*TLS
	tunnelKeyLogWriter *os.File
	client             *tls.Conn
}

func CreatePEAP(session *Session, caCert, tlsVersion, serverName, tlsTunnelKeyLogFilename string, tlsSkipHostnameCheck bool) (*PEAP, error) {
	t, err := internalCreateTLS(session, caCert, tlsVersion, tlsSkipHostnameCheck, TypePEAP)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		RootCAs:                t.rootCAs,
		MinVersion:             t.tlsVersion,
		MaxVersion:             t.tlsVersion,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     tlsSkipHostnameCheck || t.insecure,
		ServerName:             serverName,
		VerifyPeerCertificate:  t.verifyCertificateChain,
		VerifyConnection:       t.recordConnectionState,
	}
	t.serverName = serverName
	var peap *PEAP
	if tlsTunnelKeyLogFilename != "" {
		f, err := os.OpenFile(tlsTunnelKeyLogFilename, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		tlsConfig.KeyLogWriter = f
		peap = &PEAP{TLS: t, tunnelKeyLogWriter: f, client: tls.Client(t, tlsConfig)}
	} else {
		peap = &PEAP{TLS: t, client: tls.Client(t, tlsConfig)}
	}
	// Keep the same connection reachable through the embedded TLS, so that one
	// accessor serves every protocol.
	t.conn = peap.client
	return peap, nil
}

func (tt *PEAP) MaxDataSize() int {
	return 10000
}

func (tt *PEAP) Read(b []byte) (int, error) {
	n, err := tt.client.Read(b[4:])
	if err != nil {
		return n, err
	}
	// A PEAPv0 peer may send an inner EAP packet either with its four byte
	// header intact or with the header stripped, which is what this tunnel
	// sends. FreeRADIUS does both in one conversation: compressed for the
	// inner method, full headers for the identity request and for the result
	// TLV that reports a failed authentication. Assuming compression
	// unconditionally misparsed the latter, turning a plain rejection into an
	// unexpected packet type.
	if isFullEapPacket(b[4 : 4+n]) {
		copy(b, b[4:4+n])
		return n, nil
	}
	n += 4
	b[0] = byte(CodeRequest)
	b[1] = tt.identifier + 1
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	return n, nil
}

// isFullEapPacket reports whether p already carries an EAP header. The code
// must be one of the four defined values and the declared length must match
// what was actually read, which is what tells a Request carrying an identity
// apart from a bare Identity type byte: both start with 0x01, but only the
// former has a length field that agrees with the packet.
func isFullEapPacket(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	switch Code(p[0]) {
	case CodeRequest, CodeResponse, CodeSuccess, CodeFailure:
	default:
		return false
	}
	return int(binary.BigEndian.Uint16(p[2:4])) == len(p)
}

func (tt *PEAP) Write(b []byte) (int, error) {
	if len(b) == 0 {
		tt.Metrics.AdvanceStage(metrics.StageTLS)
		hat := tt.Metrics.BeginHandshake(tt.Layer)
		err := hat.Finish(tt.client.Handshake())
		if err != nil {
			return 0, metrics.Wrap(metrics.StageTLS, metrics.ResultTLSError, err)
		}
		tt.Metrics.AdvanceStage(metrics.StageInnerAuth)
		wd := tt.newDatagram(&Content{Type: tt.packetType, Data: []byte{0}})
		_, err = tt.WriteDatagram(wd)
		return 0, err
	}
	d := &Datagram{}
	err := d.Deserialize(b)
	if err != nil {
		return 0, err
	}
	return tt.client.Write(b[4:])
}

func (tt *PEAP) Close() error {
	rd := &Datagram{}
	_, err := rd.ReadFrom(tt.client)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeRequest || rd.Content.Type != TypeExtensions {
		return fmt.Errorf("peap: expected extension packet on close")
	}
	success := bytes.Equal(rd.Content.Data, []byte{0x80, 3, 0, 2, 0, 1})
	ret := byte(1)
	if !success {
		ret = 2
	}

	wd := newDatagram(&Header{Code: CodeResponse, Identifier: rd.Header.Identifier, Length: 4}, &Content{Type: TypeExtensions, Data: []byte{0x80, 3, 0, 2, 0, ret}})
	_, err = wd.WriteTo(tt.client)
	if err != nil {
		return err
	}
	_, err = tt.ReadDatagram(rd)
	if err != nil {
		return err
	}

	tt.RecvKey, tt.SendKey, err = exportKeyingMaterial(tt.client, eapMasterKeyLabel)
	if tt.tunnelKeyLogWriter != nil {
		err = errors.Join(err, tt.tunnelKeyLogWriter.Close())
	}
	return err
}

// tlvResult reads a PEAP Extensions Acknowledged-Result TLV, which is how a
// tunnelled authentication outcome is reported. ok is false when p is not one.
//
// Wire format is a 2 byte AVP type whose top two bits are the mandatory and
// reserved flags, a 2 byte length, then a 2 byte result: 1 success, 2 failure.
func tlvResult(p []byte) (success, ok bool) {
	if len(p) < 6 {
		return false, false
	}
	if binary.BigEndian.Uint16(p[0:2])&0x3fff != tlvTypeAcknowledgedResult {
		return false, false
	}
	if binary.BigEndian.Uint16(p[2:4]) != 2 {
		return false, false
	}
	switch binary.BigEndian.Uint16(p[4:6]) {
	case tlvResultSuccess:
		return true, true
	case tlvResultFailure:
		return false, true
	}
	return false, false
}

const (
	tlvTypeAcknowledgedResult = 3
	tlvResultSuccess          = 1
	tlvResultFailure          = 2
)
