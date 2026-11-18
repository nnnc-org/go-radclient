/*
Copyright © 2024 Keytos alan@keytos.io

Define MS-CHAPv2 authentication session
*/
package eap

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/nnnc-org/go-radclient/src/eap/mschapv2"
	"github.com/nnnc-org/go-radclient/src/metrics"
)

// unexpectedMsCHAPv2Packet explains a packet that arrived where an MS-CHAPv2
// one was expected.
//
// A tunnelled failure arrives as a PEAP Extensions result TLV rather than as
// an MS-CHAPv2 packet, so recognizing it is what turns the most common real
// failure -- a wrong password -- into a reported rejection instead of an
// unexplained protocol error.
func (s *Session) unexpectedMsCHAPv2Packet(rd *Datagram) error {
	// An EAP Failure carries no type and no data, so it has to be recognized
	// before the content is touched. Dereferencing it was a nil pointer panic
	// on every server that answers a bad password this way.
	if rd.Header != nil && rd.Header.Code == CodeFailure {
		s.Metrics.RecordExplicitReject()
		return metrics.Wrap(metrics.StageInnerAuth, metrics.ResultReject,
			fmt.Errorf("server sent an EAP failure"))
	}
	if rd.Content == nil {
		return fmt.Errorf("expected EAP content where an MS-CHAPv2 packet was due")
	}
	if rd.Content.Type == TypeExtensions {
		if success, ok := tlvResult(rd.Content.Data); ok && !success {
			s.Metrics.RecordExplicitReject()
			return metrics.Wrap(metrics.StageInnerAuth, metrics.ResultReject,
				fmt.Errorf("server reported a tunnelled authentication failure"))
		}
	}
	return fmt.Errorf("expected EAP packet of type MS-CHAPv2")
}

func (s *Session) MsCHAPv2(uname, pw string) error {
	err := s.start(TypeMsCHAPv2)
	if err != nil {
		return err
	}

	if s.lastReadDatagram.Content == nil || s.lastReadDatagram.Content.Type != TypeMsCHAPv2 {
		return s.unexpectedMsCHAPv2Packet(s.lastReadDatagram)
	}
	c, err := mschapv2.CreateChallengeFromBuffer(s.lastReadDatagram.Content.Data)
	if err != nil {
		return err
	}

	r := mschapv2.CreateEmptyResponse(c, uname)
	chall := mschapv2.ChallengeHash(r.PeerChallenge[:], c.Challenge[:], uname)
	pwb := mschapv2.Utf16Bytes(pw)
	pwh := mschapv2.NTPasswordHash(pwb)
	mschapv2.WriteNTResponse(r.NTResponse[:], pwh, chall)
	pwhh := mschapv2.NTPasswordHash(pwh)

	wd := s.newDatagram(&Content{Type: TypeMsCHAPv2, Data: r.ToBinary()})
	rd := &Datagram{}
	err = s.WriteReadDatagram(wd, rd)
	if err != nil {
		return err
	}

	if rd.Content == nil || rd.Content.Type != TypeMsCHAPv2 {
		return s.unexpectedMsCHAPv2Packet(rd)
	}
	request, err := mschapv2.ReadRequest(rd.Content.Data)
	if err != nil {
		return err
	}
	if request.OpCode == mschapv2.OpCodeSuccess {
		authenticator, message, err := parseSuccessMessage(request.Message)
		if err != nil {
			return err
		}
		request.Message = message
		authresp := mschapv2.AuthenticatorResponse(pwhh, r.NTResponse[:], chall)
		if subtle.ConstantTimeCompare(authenticator, authresp) == 0 {
			return fmt.Errorf("invalid success authenticator")
		}
	}

	wd = s.newDatagram(&Content{Type: TypeMsCHAPv2, Data: []byte{byte(request.OpCode)}})
	_, err = s.WriteDatagram(wd)
	if err != nil {
		return err
	}

	if s.inEncryptedTunnel {
		return s.Tunnel.Close()
	}

	_, err = s.ReadDatagram(rd)
	if err != nil {
		return err
	}
	if rd.Header.Code != CodeSuccess {
		return fmt.Errorf("authentication failed")
	}
	s.RecvKey, s.SendKey = mschapv2.SessionKeys(pwhh, r.NTResponse[:])
	return nil
}

// parseSuccessMessage reads the Message field of an MS-CHAPv2 Success packet.
//
// RFC 2759 section 8 defines it as "S=<auth string>" optionally followed by
// " M=<message>". The optional part really is optional: FreeRADIUS sends the
// authenticator alone. Requiring it, as a single Sscanf of "S=%X M=%s" does,
// fails against every such server with a bare "unexpected EOF" that says
// nothing about the cause.
func parseSuccessMessage(msg string) (authenticator []byte, message string, err error) {
	authHex := msg
	if i := strings.Index(authHex, " M="); i >= 0 {
		authHex, message = authHex[:i], authHex[i+len(" M="):]
	}
	authHex = strings.TrimPrefix(authHex, "S=")
	authenticator, err = hex.DecodeString(authHex)
	if err != nil {
		return nil, "", fmt.Errorf("invalid MS-CHAPv2 success authenticator %q: %w", authHex, err)
	}
	return authenticator, message, nil
}
