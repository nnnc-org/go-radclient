/*
Copyright © 2024 Keytos alan@keytos.io

Define EAP authentication session
*/
package eap

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	"github.com/nnnc-org/go-radclient/src/metrics"
	"github.com/nnnc-org/go-radclient/src/trace"
)

type Session struct {
	Tunnel EapTunnel
	// Metrics is attached from package cmd after construction. It is promoted
	// through TLS, PEAP, TTLS and TtlsEAP, and every method on it is nil-safe.
	Metrics *metrics.Collector
	// Trace is attached from package cmd alongside Metrics and is nil unless
	// --verbose was given. TraceLayer names which EAP conversation this is, so
	// that the inner session of a tunnelled protocol is distinguishable from
	// the outer one; NewSession defaults it to the outer layer.
	Trace             *trace.Tracer
	TraceLayer        string
	EAPSendStart      bool
	AnonymousUsername string
	RecvKey, SendKey  []byte
	identifier        uint8
	lastAction        sessionLastAction
	lastErr           error
	lastReadDatagram  *Datagram
	inEncryptedTunnel bool
}

type sessionLastAction int

const (
	sessionLastActionNone sessionLastAction = iota
	sessionLastActionWriteDatagram
	sessionLastActionReadDatagram
	sessionLastActionError
)

type EapTunnel interface {
	net.Conn
	MaxDataSize() int
}

func NewSession(tunnel EapTunnel, anonymousUname string, eapSendStart bool) *Session {
	encTunnel := false
	if _, ok := tunnel.(*TtlsEAP); ok {
		encTunnel = true
	}
	if _, ok := tunnel.(*PEAP); ok {
		encTunnel = true
	}
	return &Session{
		Tunnel:            tunnel,
		TraceLayer:        trace.LayerEAP,
		EAPSendStart:      eapSendStart,
		AnonymousUsername: anonymousUname,
		identifier:        randUint8(),
		inEncryptedTunnel: encTunnel,
	}
}

func (s *Session) newHeader(c Code) *Header {
	h := &Header{
		Code:       c,
		Identifier: s.identifier,
		Length:     4,
	}
	s.identifier++
	return h
}

func (s *Session) newDatagram(cont *Content) *Datagram {
	h := s.newHeader(CodeResponse)
	return newDatagram(h, cont)
}

func (s *Session) WriteDatagram(wd *Datagram) (int, error) {
	switch s.lastAction {
	case sessionLastActionNone, sessionLastActionReadDatagram:
		break
	case sessionLastActionError:
		return 0, fmt.Errorf("eap: out of order write: invalid last action: error: %w", s.lastErr)
	default:
		s.lastErr = fmt.Errorf("eap: out of order write: invalid last action: %s", lastActionString(s.lastAction))
		s.lastAction = sessionLastActionError
		return 0, s.lastErr
	}
	s.tracePacket(trace.Sent, wd)
	n, err := wd.WriteTo(s.Tunnel)
	if err != nil {
		s.lastErr = fmt.Errorf("eap: error sending datagram: %w", err)
		s.lastAction = sessionLastActionError
		return int(n), s.lastErr
	}
	s.lastAction = sessionLastActionWriteDatagram
	return int(n), nil
}

func (s *Session) ReadDatagram(rd *Datagram) (int, error) {
	switch s.lastAction {
	case sessionLastActionNone, sessionLastActionWriteDatagram:
		break
	case sessionLastActionError:
		return 0, fmt.Errorf("eap: out of order write: invalid last action: error: %w", s.lastErr)
	default:
		s.lastErr = fmt.Errorf("eap: out of order read: invalid last action: %s", lastActionString(s.lastAction))
		s.lastAction = sessionLastActionError
		return 0, s.lastErr
	}
	n, err := rd.ReadFrom(s.Tunnel)
	if err != nil {
		s.lastErr = fmt.Errorf("eap: error receiving datagram: %w", err)
		s.lastAction = sessionLastActionError
		return int(n), s.lastErr
	}
	s.tracePacket(trace.Received, rd)
	s.lastReadDatagram = rd
	s.lastAction = sessionLastActionReadDatagram
	return int(n), nil
}

func (s *Session) WriteReadDatagram(wd *Datagram, rd *Datagram) error {
	_, err := s.WriteDatagram(wd)
	if err != nil {
		return err
	}
	_, err = s.ReadDatagram(rd)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) start(targetType Type) error {
	s.Metrics.AdvanceStage(metrics.StageEAPNegotiation)
	rd := &Datagram{}
	if s.EAPSendStart {
		_, err := s.Tunnel.Write(nil)
		if err != nil {
			return err
		}
		_, err = s.ReadDatagram(rd)
		if err != nil {
			return err
		}
		if rd.Header.Code != CodeRequest || rd.Content == nil || rd.Content.Type != TypeIdentity {
			return metrics.Wrap(metrics.StageEAPNegotiation, metrics.ResultProtocolError,
				fmt.Errorf("did not receive identity request from server"))
		}
	}

	id := &Content{
		Type: TypeIdentity,
		Data: []byte(s.AnonymousUsername),
	}
	wd := s.newDatagram(id)
	err := s.WriteReadDatagram(wd, rd)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeRequest {
		return metrics.Wrap(metrics.StageEAPNegotiation, metrics.ResultProtocolError,
			fmt.Errorf("unexpected EAP code in server response: got %s, expected %s", rd.Header.Code, CodeRequest))
	}
	if rd.Content == nil {
		return metrics.Wrap(metrics.StageEAPNegotiation, metrics.ResultProtocolError,
			fmt.Errorf("expected EAP content in request"))
	}
	if rd.Content.Type != targetType {
		nak := &Content{
			Type: TypeNAK,
			Data: []byte{byte(targetType)},
		}
		wd = s.newDatagram(nak)
		err = s.WriteReadDatagram(wd, rd)
		if err != nil {
			return err
		}
		if rd.Header.Code != CodeRequest || rd.Content == nil || rd.Content.Type != targetType {
			return metrics.Wrap(metrics.StageEAPNegotiation, metrics.ResultProtocolError,
				fmt.Errorf("got %s: failed to negotiate the target EAP type", wd.Header.Code.String()))
		}
	}
	return nil
}

func randUint8() uint8 {
	id, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		panic(err)
	}
	return uint8(id.Int64())
}

func lastActionString(la sessionLastAction) string {
	switch la {
	case sessionLastActionNone:
		return "none"
	case sessionLastActionWriteDatagram:
		return "write packet"
	case sessionLastActionReadDatagram:
		return "read packet"
	case sessionLastActionError:
		return "error"
	default:
		return "unknown"
	}
}
