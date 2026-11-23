/*
Copyright © 2025

Rendering of RADIUS packets for the --verbose trace.
*/
package radius

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/nnnc-org/go-radclient/src/trace"
)

// tracePacket renders d for the packet trace. The packet is only serialized
// again when a hex dump was asked for, since nothing else needs the bytes.
//
// A received packet must be traced before its authenticator is validated:
// validResponseAndMessageAuthenticator swaps the response authenticator for
// the request one in place, so a dump taken afterwards would not be what
// arrived.
func (s *session) tracePacket(dir trace.Direction, d *Datagram) {
	if !s.Trace.Enabled() || d == nil || d.Header == nil {
		return
	}
	p := trace.Packet{
		Layer: trace.LayerRADIUS,
		Dir:   dir,
		Summary: fmt.Sprintf("%s id=%d len=%d",
			d.Header.Code, d.Header.Identifier, d.Header.Length),
		Fields: traceAttributeLines(d.Attributes),
	}
	if s.Trace.HexDump() {
		var b bytes.Buffer
		if _, err := d.WriteTo(&b); err == nil {
			p.Raw = b.Bytes()
		}
	}
	s.Trace.Packet(p)
}

func traceAttributeLines(attrs Attributes) []string {
	lines := make([]string, 0, len(attrs))
	for _, a := range attrs {
		lines = append(lines, fmt.Sprintf("%s = %s", a, traceAttributeValue(a)))
	}
	return lines
}

// traceAttributeValue renders an attribute value the way someone reading a
// trace wants to see it: text as text, a four byte attribute as a number, and
// anything else as hex. It deliberately stops there rather than decoding every
// attribute type, because a confidently wrong value in a trace costs more than
// a row of hex.
func traceAttributeValue(a *Attribute) string {
	switch {
	case len(a.Value) == 0:
		return "(empty)"
	case isPrintableASCII(a.Value):
		return strconv.Quote(string(a.Value))
	case len(a.Value) == 4:
		return fmt.Sprintf("0x%s (%d)",
			hex.EncodeToString(a.Value), binary.BigEndian.Uint32(a.Value))
	}
	return "0x" + hex.EncodeToString(a.Value)
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}
