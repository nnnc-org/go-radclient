/*
Copyright © 2025

Per-packet tracing for --verbose.

The protocol packages call into this the way they already call into metrics: a
nil *Tracer is the disabled case and every method tolerates it, so no call site
needs a conditional and tracing costs one nil check when it is off.

Everything is written to stderr. The --json document owns stdout, so a probe
can be traced and still be parsed.
*/
package trace

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/nnnc-org/go-radclient/src/metrics"
)

// Layer names the protocol a traced line belongs to. The two EAP layers are
// kept apart because a tunnelled protocol runs an inner EAP conversation of
// its own, and reading a PEAP or EAP-TTLS trace means telling the two apart.
const (
	LayerRADIUS   = "radius"
	LayerEAP      = "eap"
	LayerEAPInner = "eap-inner"
)

// fieldIndent lines decoded fields and hex dumps up under the summary they
// belong to, past the timestamp column.
const fieldIndent = "             "

// Direction is which way a packet went, as seen from this client.
type Direction int

const (
	Sent Direction = iota
	Received
)

func (d Direction) String() string {
	switch d {
	case Sent:
		return "-->"
	case Received:
		return "<--"
	}
	return "???"
}

// Packet is one traced packet: a one line summary, zero or more decoded
// fields, and optionally the bytes that went over the wire.
type Packet struct {
	Layer   string
	Dir     Direction
	Summary string
	Fields  []string
	// Raw is hex dumped when it is set. Fill it only when HexDump reports that
	// it is wanted, so that a plain -v never pays for serializing a packet
	// twice.
	Raw []byte
}

// Tracer writes the --verbose packet trace.
type Tracer struct {
	mu       sync.Mutex
	w        io.Writer
	start    time.Time
	hexDump  bool
	redactor *metrics.Redactor
}

// New returns a tracer writing to w, with timestamps relative to now. With
// hexDump set, each traced packet is followed by a dump of its bytes.
func New(w io.Writer, hexDump bool) *Tracer {
	return &Tracer{
		w:        w,
		start:    time.Now(),
		hexDump:  hexDump,
		redactor: &metrics.Redactor{},
	}
}

// AddSecrets registers values that must never appear in the trace. --verbose
// prints what went over the wire, where a credential passed through
// --attrs-to-send would otherwise be echoed in the clear.
func (t *Tracer) AddSecrets(values ...string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.redactor.Add(values...)
}

// Enabled reports whether anything is being traced. Call it before doing work
// that exists only to produce a trace.
func (t *Tracer) Enabled() bool {
	return t != nil
}

// HexDump reports whether raw packet bytes are wanted, which is -vv.
func (t *Tracer) HexDump() bool {
	return t != nil && t.hexDump
}

// Packet traces one packet.
func (t *Tracer) Packet(p Packet) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "%s %-9s %s %s\n", t.stampLocked(), p.Layer, p.Dir, t.redactor.Apply(p.Summary))
	for _, f := range p.Fields {
		b.WriteString(fieldIndent)
		b.WriteString(t.redactor.Apply(f))
		b.WriteByte('\n')
	}
	if t.hexDump && len(p.Raw) > 0 {
		writeHexDump(&b, p.Raw)
	}
	_, _ = io.WriteString(t.w, b.String())
}

// Note traces something that is not a packet of its own: a retransmission, a
// read that timed out, an answer to a request we never sent. These are the
// events that explain a gap between two packets.
func (t *Tracer) Note(layer, format string, args ...any) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	msg := t.redactor.Apply(fmt.Sprintf(format, args...))
	_, _ = fmt.Fprintf(t.w, "%s %-9s  !! %s\n", t.stampLocked(), layer, msg)
}

// stampLocked renders the time since the tracer was created. Elapsed time is
// what a trace is read for -- which exchange took the five seconds -- and an
// absolute clock would only make the lines longer.
func (t *Tracer) stampLocked() string {
	return fmt.Sprintf("[%8.3f]", time.Since(t.start).Seconds())
}

func writeHexDump(b *strings.Builder, raw []byte) {
	for line := range strings.SplitSeq(strings.TrimRight(hex.Dump(raw), "\n"), "\n") {
		b.WriteString(fieldIndent)
		b.WriteString(line)
		b.WriteByte('\n')
	}
}
