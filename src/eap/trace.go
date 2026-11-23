/*
Copyright © 2025

Rendering of EAP packets for the --verbose trace.

This is the layer a failed enrollment is usually diagnosed at: the RADIUS trace
shows an Access-Challenge carrying opaque EAP-Message attributes, while these
lines say which EAP code and type actually went past, and for the TLS based
types how the handshake was fragmented.
*/
package eap

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/nnnc-org/go-radclient/src/eap/mschapv2"
	eaptls "github.com/nnnc-org/go-radclient/src/eap/tls"
	"github.com/nnnc-org/go-radclient/src/trace"
)

// traceDataPreview caps how many payload bytes an undecoded type contributes to
// a trace line. The full bytes are available under -vv.
const traceDataPreview = 32

func (s *Session) tracePacket(dir trace.Direction, d *Datagram) {
	if !s.Trace.Enabled() || d == nil || d.Header == nil {
		return
	}
	layer := s.TraceLayer
	if layer == "" {
		layer = trace.LayerEAP
	}
	summary := fmt.Sprintf("%s id=%d len=%d", d.Header.Code, d.Header.Identifier, d.Header.Length)
	if d.Content != nil {
		summary += fmt.Sprintf(" type=%s(%d)", d.Content.Type, uint8(d.Content.Type))
	}
	p := trace.Packet{
		Layer:   layer,
		Dir:     dir,
		Summary: summary,
		Fields:  traceContentLines(d.Content),
	}
	if s.Trace.HexDump() {
		var b bytes.Buffer
		if _, err := d.WriteTo(&b); err == nil {
			p.Raw = b.Bytes()
		}
	}
	s.Trace.Packet(p)
}

// traceContentLines decodes as much of the content as can be decoded without
// guessing. An EAP Success or Failure carries none at all, which is why the
// nil case is normal rather than an error.
func traceContentLines(c *Content) []string {
	if c == nil {
		return nil
	}
	switch c.Type {
	case TypeIdentity:
		return []string{"identity = " + strconv.Quote(string(c.Data))}
	case TypeNAK:
		return []string{"desired-type = " + traceNakTypes(c.Data)}
	case TypeTLS, TypeTTLS, TypePEAP:
		return traceTLSLines(c.Data)
	case TypeMsCHAPv2:
		if len(c.Data) == 0 {
			return nil
		}
		op := mschapv2.OpCode(c.Data[0])
		return []string{fmt.Sprintf("op-code = %s(%d)", op, uint8(op))}
	case TypeExtensions:
		if success, ok := tlvResult(c.Data); ok {
			return []string{fmt.Sprintf("result-tlv = %s", tlvResultName(success))}
		}
	case TypeNotification:
		return []string{"message = " + strconv.Quote(string(c.Data))}
	}
	if len(c.Data) == 0 {
		return nil
	}
	return []string{"data = " + tracePreviewHex(c.Data)}
}

// traceTLSLines decodes the EAP-TLS framing shared by EAP-TLS, EAP-TTLS and
// PEAP: the flag byte, the total handshake length when the Length flag is set,
// and how much of the handshake this packet carries. A stalled handshake is
// almost always visible here as a fragment exchange that stops.
func traceTLSLines(b []byte) []string {
	if len(b) == 0 {
		// An empty request is how a server asks for the next fragment, and how
		// this client acknowledges one. Saying so beats an empty line.
		return []string{"(no TLS data)"}
	}
	d := eaptls.CreateDataFromBuffer(b)
	lines := []string{fmt.Sprintf("flags = %s (0x%02x)", traceTLSFlags(d.Flags), uint8(d.Flags))}
	if d.Flags&eaptls.FlagsLength != 0 {
		lines = append(lines, fmt.Sprintf("tls-message-length = %d", d.TLSMessageLength))
	}
	lines = append(lines, fmt.Sprintf("tls-fragment = %d bytes", len(d.Data)))
	if len(d.Data) > 0 {
		lines = append(lines, "tls-data = "+tracePreviewHex(d.Data))
	}
	return lines
}

// traceTLSFlags spells the flag byte the way RFC 5216 names the bits, so that a
// trace can be read next to the RFC.
func traceTLSFlags(f eaptls.Flags) string {
	var b strings.Builder
	for _, flag := range []struct {
		bit  eaptls.Flags
		name byte
	}{
		{eaptls.FlagsLength, 'L'},
		{eaptls.FlagsMore, 'M'},
		{eaptls.FlagsStart, 'S'},
	} {
		if f&flag.bit != 0 {
			b.WriteByte(flag.name)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func traceNakTypes(b []byte) string {
	if len(b) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(b))
	for _, t := range b {
		names = append(names, fmt.Sprintf("%s(%d)", Type(t), t))
	}
	return strings.Join(names, ", ")
}

func tlvResultName(success bool) string {
	if success {
		return "success"
	}
	return "failure"
}

func tracePreviewHex(b []byte) string {
	if len(b) <= traceDataPreview {
		return "0x" + hex.EncodeToString(b)
	}
	return fmt.Sprintf("0x%s... (%d bytes)", hex.EncodeToString(b[:traceDataPreview]), len(b))
}
