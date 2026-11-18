/*
Copyright © 2025

Secret redaction for strings that reach the JSON document.

Nothing in the probe formats a shared secret or password into an error today,
so this is defense in depth: the values are registered up front and every
string entering the document passes through Redactor.Apply, so a future
fmt.Errorf cannot leak one.

Never format a radius session or the command-level config globals with %v/%+v;
they hold secrets that no redactor is registered for.
*/
package metrics

import (
	"sort"
	"strings"
)

// Placeholder replaces every registered secret.
const Placeholder = "***"

// Redactor replaces known secret values wherever they appear. Values are
// replaced longest-first so that a secret which contains another is not
// partially rewritten.
//
// Redaction is unconditional: a short secret will also match unrelated text.
// That is deliberate -- a garbled error message is a better outcome than a
// leaked credential.
type Redactor struct {
	values []string
}

// Add registers a secret. Empty values are ignored.
func (r *Redactor) Add(values ...string) {
	if r == nil {
		return
	}
	for _, v := range values {
		if v == "" {
			continue
		}
		if !contains(r.values, v) {
			r.values = append(r.values, v)
		}
	}
	sort.SliceStable(r.values, func(i, j int) bool {
		return len(r.values[i]) > len(r.values[j])
	})
}

// minFreeLength is the shortest secret replaced wherever it appears. Below it,
// a substring replacement does more harm than good: a one character password
// would turn "pap: did not get response" into "***a***: did not get res***onse",
// destroying the diagnostic without protecting anything that was not already
// visible. Shorter values are replaced only as whole tokens.
const minFreeLength = 6

// Apply replaces every registered secret in s.
func (r *Redactor) Apply(s string) string {
	if r == nil || s == "" {
		return s
	}
	for _, v := range r.values {
		if len(v) >= minFreeLength {
			s = strings.ReplaceAll(s, v, Placeholder)
			continue
		}
		s = replaceToken(s, v)
	}
	return s
}

// replaceToken replaces v only where it stands alone, delimited by characters
// that cannot be part of a secret-bearing token.
func replaceToken(s, v string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], v) && isTokenBoundary(s, i, i+len(v)) {
			b.WriteString(Placeholder)
			i += len(v)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isTokenBoundary(s string, start, end int) bool {
	return !isTokenByte(s, start-1) && !isTokenByte(s, end)
}

func isTokenByte(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c == '_' || c == '-' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
