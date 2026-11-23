/*
Copyright © 2025

JSON metrics output: the --json probe mode.

The document is written to stdout, exactly once per invocation, and is the only
thing on stdout. Human-readable logging stays on stderr, which Zabbix does not
read.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/nnnc-org/go-radclient/src/metrics"
)

// version is overridden at build time:
//
//	-ldflags "-X github.com/nnnc-org/go-radclient/cmd.version=v1.2.3"
//
// Left empty, the version is taken from the build info, which is what
// `go install module@vX.Y.Z` stamps.
var version = ""

var (
	jsonOutput bool
	collector  *metrics.Collector
	emitOnce   sync.Once
	// stdout is indirected so that tests can capture the document. Nothing
	// else in this program writes to stdout.
	stdout io.Writer = os.Stdout
)

// Exit codes in JSON mode. A probe that ran exits 0 whatever the server said,
// so Zabbix ingests the document and triggers on its contents. Non-zero is
// reserved for a probe that could not run, where the item should go
// unsupported and be noticed.
const (
	exitOK        = 0
	exitCannotRun = 2
)

// jsonModeRequested pre-scans argv for --json.
//
// Cobra parses flags before PersistentPreRunE, so by the time any of our own
// validation runs the flag is already bound. But an unknown flag or an
// unparseable value fails earlier than that, and those failures still have to
// produce a document, so the flag is detected without cobra's help first.
func jsonModeRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--json" || a == "--json=true" {
			return true
		}
	}
	return false
}

// probeVersion resolves probe.version.
func probeVersion() string {
	if version != "" {
		return version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := bi.Main.Version
	var revision, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
			if len(revision) > 12 {
				revision = revision[:12]
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "+dirty"
			}
		}
	}
	// A plain `go build` from a checkout reports "(devel)", which says nothing.
	// The stamped VCS revision does.
	if (v == "" || v == "(devel)") && revision != "" {
		return "devel-" + revision + dirty
	}
	if v == "" {
		return "unknown"
	}
	// A pseudo-version can already carry the suffix.
	if strings.HasSuffix(v, dirty) {
		return v
	}
	return v + dirty
}

// emit writes the document to stdout, at most once per process.
func emit() int {
	code := exitOK
	emitOnce.Do(func() {
		doc := collector.Document()
		if !doc.Probe.Ran {
			code = exitCannotRun
		}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode metrics document: %v\n", err)
			code = exitCannotRun
		}
	})
	return code
}

// setupJSONOutput applies the JSON-mode output policy: nothing but the
// document on stdout.
func setupJSONOutput() {
	// Errors still go to stderr for a human running this by hand; the
	// successful-authentication info line would just be noise.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	})))
}

// registerSecrets tells the redactor which values must never appear in the
// document. The target address, username and MAC are not secrets and stay
// readable, because they are what makes an error diagnosable.
func registerSecrets(sharedSecret string) {
	secrets := []string{
		sharedSecret,
		password,
		// RFC 6614 fixes the RadSec shared secret to this literal.
		"radsec",
	}
	collector.AddSecrets(secrets...)
	// --verbose prints the packets themselves, so it needs the same list.
	tracer.AddSecrets(secrets...)
	// A password passed through --attrs-to-send would otherwise be echoed back
	// by parseAttributes on a malformed entry.
	//
	// Deliberately not registered with the tracer. --verbose exists to show
	// the attributes that were sent, and these values came from this command
	// line in the first place, so masking them hides exactly what was asked
	// for — and because redaction is a substring replacement, a value like
	// "Framed" would also rewrite the name of every attribute containing it.
	for _, vals := range sendAttributes {
		collector.AddSecrets(vals...)
	}
}

// flattenError renders a possibly-joined error as one line. errors.Join
// separates with newlines, which would make the JSON string awkward to read in
// a Zabbix item.
func flattenError(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}
