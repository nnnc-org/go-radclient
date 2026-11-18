/*
Copyright © 2025

Interactive password entry.
*/
package cmd

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// stdinFd is indirected so tests can point the terminal check at something
// that is definitely not a terminal.
var stdinFd = int(os.Stdin.Fd())

// resolvePassword fills in the password by prompting, when the protocol needs
// one and none was given on the command line.
//
// It deliberately refuses to prompt in two cases rather than hanging:
//
//   - In --json mode. A monitoring probe runs unattended, and a prompt there
//     would block until the item times out, once per interval, forever.
//   - When stdin is not a terminal. Reading the password from a pipe would
//     silently consume input the caller may have meant for something else, and
//     a cron job with no stdin would hang.
//
// Both report what to do instead, and in JSON mode that lands in the document
// as a config error with exit code 2.
func resolvePassword(protocol string) error {
	if password != "" {
		return nil
	}
	if _, ok := requireUsernameAndPassword[protocol]; !ok {
		return nil
	}

	if jsonOutput {
		return fmt.Errorf(
			"protocol %s requires a password: pass --password, since --json cannot prompt for one",
			protocol,
		)
	}
	if !term.IsTerminal(stdinFd) {
		return fmt.Errorf(
			"protocol %s requires a password: pass --password, since stdin is not a terminal",
			protocol,
		)
	}

	// The prompt goes to stderr so that it never contaminates stdout.
	fmt.Fprintf(os.Stderr, "Password for %s: ", username)
	entered, err := term.ReadPassword(stdinFd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("could not read password: %w", err)
	}
	if len(entered) == 0 {
		return fmt.Errorf("password must not be empty")
	}

	password = string(entered)
	return nil
}
