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

var stdinFd = int(os.Stdin.Fd())

// Both indirected so tests can exercise the prompting path without a pty.
var (
	stdinIsTerminal = func() bool { return term.IsTerminal(stdinFd) }

	// readPassword reads from the terminal with echo disabled.
	readPassword = func() (string, error) {
		entered, err := term.ReadPassword(stdinFd)
		return string(entered), err
	}
)

// resolvePassword fills in the password by prompting, when the protocol needs
// one and none was given on the command line.
//
// Whether to prompt turns on one question: is there a terminal to prompt on.
// It is asked even in --json mode, so that the metrics document can be
// inspected interactively without putting a password in the shell history.
//
// With no terminal it refuses rather than hanging. That is the case that
// matters for a monitoring probe, which has no stdin: a prompt there would
// block until the item timed out, on every interval, forever. Reading from a
// pipe instead would silently consume input the caller may have meant for
// something else.
func resolvePassword(protocol string) error {
	if password != "" {
		return nil
	}
	if _, ok := requireUsernameAndPassword[protocol]; !ok {
		return nil
	}

	if !stdinIsTerminal() {
		return fmt.Errorf(
			"protocol %s requires a password: pass --password, since stdin is not a terminal to prompt on",
			protocol,
		)
	}

	// The prompt goes to stderr so that stdout carries only the JSON document
	// when that mode is in use.
	fmt.Fprintf(os.Stderr, "Password for %s: ", username)
	entered, err := readPassword()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("could not read password: %w", err)
	}
	if entered == "" {
		return fmt.Errorf("password must not be empty")
	}

	password = entered
	return nil
}
