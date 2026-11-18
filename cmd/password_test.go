package cmd

import (
	"strconv"
	"strings"
	"testing"
)

// withNonTerminalStdin simulates having nowhere to prompt, which is what a
// monitoring probe, a cron job or a CI runner looks like.
func withNonTerminalStdin(t *testing.T) {
	t.Helper()
	oldTerm, oldRead := stdinIsTerminal, readPassword
	stdinIsTerminal = func() bool { return false }
	readPassword = func() (string, error) {
		t.Error("readPassword must not be called when there is no terminal")
		return "", nil
	}
	t.Cleanup(func() { stdinIsTerminal, readPassword = oldTerm, oldRead })
}

// withTerminalStdin simulates an interactive terminal that types pw.
func withTerminalStdin(t *testing.T, pw string) *int {
	t.Helper()
	calls := 0
	oldTerm, oldRead := stdinIsTerminal, readPassword
	stdinIsTerminal = func() bool { return true }
	readPassword = func() (string, error) {
		calls++
		return pw, nil
	}
	t.Cleanup(func() { stdinIsTerminal, readPassword = oldTerm, oldRead })
	return &calls
}

// A probe has no terminal, so --json plus no --password must still fail fast
// rather than block until the item times out.
func TestJSONWithoutTerminalStillRefuses(t *testing.T) {
	withNonTerminalStdin(t)
	code, doc := runProbe(t,
		"--json",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice",
	)

	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if got := get(t, doc, "probe", "ran"); got != false {
		t.Errorf("probe.ran = %v, want false", got)
	}
	if got := get(t, doc, "auth", "result"); got != "config_error" {
		t.Errorf("auth.result = %v, want config_error", got)
	}
	msg, _ := get(t, doc, "auth", "error_message").(string)
	if !strings.Contains(msg, "--password") {
		t.Errorf("error_message = %q, should say to pass --password", msg)
	}
	if !strings.Contains(msg, "not a terminal") {
		t.Errorf("error_message = %q, should explain why it cannot prompt", msg)
	}
}

// Reading a password from a pipe would silently consume input meant for
// something else, so it is refused with an explanation.
func TestPasswordNotPromptedWhenStdinIsNotATerminal(t *testing.T) {
	withNonTerminalStdin(t)
	resetForTest(t)

	code := run([]string{
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1 in text mode", code)
	}
}

func TestResolvePasswordRefusals(t *testing.T) {
	tests := []struct {
		name        string
		protocol    string
		password    string
		json        bool
		wantErr     bool
		wantKeyword string
	}{
		{
			name:     "already provided",
			protocol: authPAP,
			password: "hunter2",
		},
		{
			// A certificate protocol needs no password, so nothing is asked.
			name:     "protocol needs no password",
			protocol: authEapTLS,
		},
		{
			// --json on its own no longer blocks the prompt; only the lack of
			// a terminal does.
			name:        "json mode without a terminal refuses",
			protocol:    authPAP,
			json:        true,
			wantErr:     true,
			wantKeyword: "not a terminal",
		},
		{
			name:        "non terminal refuses",
			protocol:    authEapTtlsPAP,
			wantErr:     true,
			wantKeyword: "not a terminal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withNonTerminalStdin(t)
			password = tc.password
			jsonOutput = tc.json
			t.Cleanup(func() {
				password = ""
				jsonOutput = false
			})

			err := resolvePassword(tc.protocol)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), tc.wantKeyword) {
					t.Errorf("error = %q, want it to mention %q", err, tc.wantKeyword)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if password != tc.password {
				t.Errorf("password = %q, want it left as %q", password, tc.password)
			}
		})
	}
}

// A password supplied on the command line still works, and is still redacted.
func TestPasswordFlagStillWorks(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)

	code, doc := runProbe(t,
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "2s",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice", "--password", "hunter2",
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; error = %v", code, get(t, doc, "auth", "error_message"))
	}
	if got := get(t, doc, "auth", "success"); got != true {
		t.Errorf("auth.success = %v, want true", got)
	}
}

// --username alone used to be rejected by cobra before a prompt was possible.
func TestUsernameWithoutPasswordIsNotAFlagError(t *testing.T) {
	withNonTerminalStdin(t)
	resetForTest(t)

	code := run([]string{
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice",
	})
	// It must fail for a missing password, not because the flag pair was
	// marked as required together.
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// --insecure drops the CA requirement rather than reporting a missing value.
func TestInsecureMakesCARequirementsOptional(t *testing.T) {
	t.Cleanup(func() { insecure = false })

	for _, protocol := range []string{authEapTLS, authEapTtlsEapTLS, authEapTtlsPAP, authPeapMsCHAPv2} {
		t.Run(protocol, func(t *testing.T) {
			macAddress, username, password = "", "u", "p"
			clientCertificate = "/tmp/client.pem"
			caCertificate, tunnelCACertificate = "", ""

			insecure = false
			if mv := missingValues(protocol); len(mv) == 0 {
				t.Error("without --insecure a CA should be required")
			}

			insecure = true
			if mv := missingValues(protocol); len(mv) != 0 {
				t.Errorf("with --insecure, missing values = %v, want none", mv)
			}
		})
	}
}

// PEAP and EAP-TTLS exist so the real identity only appears inside the
// tunnel. Sending the anonymous identity inside too made servers that
// authorize on it reject every request.
func TestInnerIdentity(t *testing.T) {
	t.Cleanup(func() { username, anonymousUsername = "", "anonymous" })

	username, anonymousUsername = "alice@example.com", "anonymous"
	if got := innerIdentity(); got != "alice@example.com" {
		t.Errorf("innerIdentity() = %q, want the real username", got)
	}

	// EAP-TLS inside EAP-TTLS has no username, and an empty inner identity
	// would be worse than the anonymous one.
	username = ""
	if got := innerIdentity(); got != "anonymous" {
		t.Errorf("innerIdentity() = %q, want the anonymous identity as a fallback", got)
	}
}

// The point of the change: --json no longer blocks prompting, so the metrics
// document can be inspected interactively without a password in argv.
func TestPasswordPromptedInJSONModeOnATerminal(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessAccept, false)
	calls := withTerminalStdin(t, "hunter2")

	code, doc := runProbe(t,
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "2s",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice",
	)

	if *calls != 1 {
		t.Errorf("readPassword called %d times, want exactly 1", *calls)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; error = %v", code, get(t, doc, "auth", "error_message"))
	}
	if got := get(t, doc, "auth", "success"); got != true {
		t.Errorf("auth.success = %v, want true: the typed password should have been used", got)
	}
	// The prompt goes to stderr, so the document is still the only thing on
	// stdout and still parses.
	if got := get(t, doc, "probe", "ran"); got != true {
		t.Errorf("probe.ran = %v, want true", got)
	}
}

// A typed password is a secret like any other and must not reach the document.
func TestPromptedPasswordIsRedacted(t *testing.T) {
	srv := startFakeServer(t, "testing123", codeAccessReject, false)
	withTerminalStdin(t, "typed-secret-value")

	buf := resetForTest(t)
	run([]string{
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "2s",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice",
	})

	if strings.Contains(buf.String(), "typed-secret-value") {
		t.Error("the document leaks the password that was typed at the prompt")
	}
}

// Prompting once, before any attempt, means a retry does not re-ask.
func TestPasswordPromptedOnceAcrossRetries(t *testing.T) {
	srv := startFakeServer(t, "testing123", 0, false) // never answers
	calls := withTerminalStdin(t, "hunter2")

	runProbe(t,
		"--json",
		"--udp-auth-port", strconv.Itoa(srv.port()),
		"--udp-timeout", "200ms",
		"--udp-retries", "1",
		"--retries", "2",
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice",
	)

	if *calls != 1 {
		t.Errorf("readPassword called %d times across three attempts, want 1", *calls)
	}
}

// An empty password is rejected rather than silently attempted.
func TestEmptyPromptedPasswordIsRejected(t *testing.T) {
	withTerminalStdin(t, "")
	resetForTest(t)

	code := run([]string{
		"auth", "udp", "127.0.0.1", "testing123", "pap",
		"--username", "alice",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}
