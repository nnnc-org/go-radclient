package cmd

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// withNonTerminalStdin points the terminal check at a pipe, which is what a
// cron job or a CI runner looks like.
func withNonTerminalStdin(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	old := stdinFd
	stdinFd = int(r.Fd())
	t.Cleanup(func() { stdinFd = old })
}

// Prompting from a monitoring probe would block until the item times out,
// once per interval, forever. It must be a config error instead.
func TestPasswordNotPromptedInJSONMode(t *testing.T) {
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
	if !strings.Contains(msg, "--json") {
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
			name:        "json mode refuses",
			protocol:    authPAP,
			json:        true,
			wantErr:     true,
			wantKeyword: "--json",
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
