package metrics

import (
	"fmt"
	"testing"
)

func TestRedactorReplacesRegisteredSecrets(t *testing.T) {
	r := &Redactor{}
	r.Add("s3cr3t", "hunter2", "radsec")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// The real leak path: parseAttributes echoes the raw entry, so a
			// typo'd --attrs-to-send User-Password would carry the value.
			name: "attribute entry echo",
			in:   "invalid attribute entry: User-Password:hunter2",
			want: "invalid attribute entry: User-Password:***",
		},
		{
			name: "cobra flag error echo",
			in:   `invalid argument "hunter2" for "--password" flag`,
			want: `invalid argument "***" for "--password" flag`,
		},
		{
			name: "shared secret",
			in:   "dial udp with secret s3cr3t failed",
			want: "dial udp with secret *** failed",
		},
		{
			name: "radsec literal",
			in:   "shared secret radsec rejected",
			want: "shared secret *** rejected",
		},
		{
			name: "multiple occurrences",
			in:   "s3cr3t and s3cr3t again",
			want: "*** and *** again",
		},
		{
			name: "nothing to redact",
			in:   "did not get response from server",
			want: "did not get response from server",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Apply(tc.in); got != tc.want {
				t.Errorf("Apply(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A secret that contains another must be replaced whole, not partially
// rewritten into something that still leaks the longer value.
func TestRedactorReplacesLongestFirst(t *testing.T) {
	r := &Redactor{}
	r.Add("pw", "pw-extended")

	got := r.Apply("value pw-extended here")
	if got != "value *** here" {
		t.Errorf("Apply = %q, want %q", got, "value *** here")
	}
}

func TestRedactorIgnoresEmptyAndDuplicates(t *testing.T) {
	r := &Redactor{}
	r.Add("", "x", "x")
	if len(r.values) != 1 {
		t.Errorf("values = %v, want exactly one entry", r.values)
	}
	// An empty value must not turn every character into a placeholder.
	if got := r.Apply("abc"); got != "abc" {
		t.Errorf("Apply = %q, want %q", got, "abc")
	}
}

func TestRedactorNilSafe(t *testing.T) {
	var r *Redactor
	r.Add("x")
	if got := r.Apply("x"); got != "x" {
		t.Errorf("Apply on nil redactor = %q, want passthrough", got)
	}
}

// Every string entering the document goes through the collector, so that is
// the choke point worth testing.
func TestCollectorRedactsErrorMessages(t *testing.T) {
	c := New("test")
	c.AddSecrets("hunter2")
	c.BeginAttempt(0)
	c.FinishAttempt(fmt.Errorf("invalid attribute entry: User-Password:hunter2"))

	doc := c.Document()
	if doc.Auth.ErrorMessage == nil {
		t.Fatal("error_message is nil")
	}
	if got := *doc.Auth.ErrorMessage; got != "invalid attribute entry: User-Password:***" {
		t.Errorf("error_message = %q, still leaks the secret", got)
	}
}

func TestCollectorRedactsPanicAndCloseError(t *testing.T) {
	c := New("test")
	c.AddSecrets("hunter2")
	c.BeginAttempt(0)
	c.SetCloseError(fmt.Errorf("close: hunter2"))
	c.RecordPanic("boom hunter2")

	doc := c.Document()
	if doc.Probe.Panic == nil || *doc.Probe.Panic != "boom ***" {
		t.Errorf("probe.panic = %v, want redacted", doc.Probe.Panic)
	}
	if doc.Auth.CloseError == nil || *doc.Auth.CloseError != "close: ***" {
		t.Errorf("auth.close_error = %v, want redacted", doc.Auth.CloseError)
	}
}
