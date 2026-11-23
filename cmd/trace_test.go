package cmd

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
)

// runTraced runs the CLI in-process with the packet trace captured instead of
// written to stderr.
func runTraced(t *testing.T, args ...string) (int, string) {
	t.Helper()
	_ = resetForTest(t)
	var tbuf bytes.Buffer
	traceOut = &tbuf
	t.Cleanup(func() { traceOut = os.Stderr })
	code := run(args)
	return code, tbuf.String()
}

// papArgs is a working PAP invocation against the fake server. Anything in
// extra lands after the defaults, so a test can override one of them.
func papArgs(port int, extra ...string) []string {
	args := []string{
		"--udp-auth-port", strconv.Itoa(port),
		"--udp-timeout", "2s",
		"--min-send-jitter", "0s",
		"--max-send-jitter", "0s",
	}
	args = append(args, extra...)
	return append(args,
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice", "--password", "hunter2",
	)
}

func TestVerboseTracesBothDirections(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	code, out := runTraced(t, papArgs(srv.port(), "-v")...)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\ntrace:\n%s", code, out)
	}
	for _, want := range []string{
		"radius    --> Access-Request",
		"radius    <-- Access-Accept",
		`User-Name = "alice"`,
		`NAS-Identifier = "radius-client"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("trace is missing %q\ntrace:\n%s", want, out)
		}
	}
}

// The trace prints what went over the wire, so it has to honor the same
// redaction the JSON document does.
func TestVerboseRedactsSecrets(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	_, out := runTraced(t, papArgs(srv.port(), "-v")...)

	for _, secret := range []string{"testing123", "hunter2"} {
		if strings.Contains(out, secret) {
			t.Errorf("trace leaked %q\ntrace:\n%s", secret, out)
		}
	}
}

func TestHexDumpOnlyAtDoubleVerbose(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	_, single := runTraced(t, papArgs(srv.port(), "-v")...)
	if strings.Contains(single, "00000000  ") {
		t.Errorf("-v should not hex dump\ntrace:\n%s", single)
	}

	_, double := runTraced(t, papArgs(srv.port(), "-vv")...)
	if !strings.Contains(double, "00000000  ") {
		t.Errorf("-vv should hex dump\ntrace:\n%s", double)
	}
}

func TestNoTraceWithoutTheFlag(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	_, out := runTraced(t, papArgs(srv.port())...)

	if out != "" {
		t.Errorf("tracing is off, but got:\n%s", out)
	}
}

// A run that never reaches the network still has to leave the retransmissions
// and the timeout visible, since that is the shape of an unreachable server.
func TestVerboseShowsRetransmitAndTimeout(t *testing.T) {
	srv := startFakeServer(t, "testing123", 0, false)

	_, out := runTraced(t, papArgs(srv.port(), "-v", "--udp-timeout", "100ms")...)

	if !strings.Contains(out, "retransmitting request id=") {
		t.Errorf("trace is missing the retransmission\ntrace:\n%s", out)
	}
	if !strings.Contains(out, "no usable response") {
		t.Errorf("trace is missing the failed read\ntrace:\n%s", out)
	}
}

// --json owns stdout; the trace must not end up in the document.
func TestVerboseKeepsJSONDocumentClean(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	buf := resetForTest(t)
	var tbuf bytes.Buffer
	traceOut = &tbuf
	t.Cleanup(func() { traceOut = os.Stderr })

	code := run(append([]string{"--json", "-v"}, papArgs(srv.port())...))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Errorf("stdout is not just the document: %q", buf.String())
	}
	if !strings.Contains(tbuf.String(), "radius    --> Access-Request") {
		t.Errorf("trace did not reach stderr\ntrace:\n%s", tbuf.String())
	}
}

// The point of the trace is to show what was sent, so an attribute value given
// on the command line stays legible. The shared secret and the password do not
// (see TestVerboseRedactsSecrets), and a value registered as a secret would
// otherwise also rewrite attribute names it happens to be a substring of.
func TestVerboseShowsSentAttributes(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	_, out := runTraced(t, papArgs(srv.port(), "-v",
		"--attrs-to-send", "Called-Station-Id:00-11-22-33-44-55:eduroam",
		"--attrs-to-send", "Service-Type:Framed",
	)...)

	if !strings.Contains(out, `Called-Station-Id = "00-11-22-33-44-55:eduroam"`) {
		t.Errorf("trace masked an attribute it was asked to send\ntrace:\n%s", out)
	}
	if !strings.Contains(out, "Framed-MTU = ") {
		t.Errorf("an attribute name was rewritten by redaction\ntrace:\n%s", out)
	}
}
