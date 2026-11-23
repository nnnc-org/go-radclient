package eap

import (
	"strings"
	"testing"
)

func TestTraceContentLines(t *testing.T) {
	tests := []struct {
		name    string
		content *Content
		want    []string
	}{
		{
			// An EAP Success or Failure carries no content at all.
			name:    "no content",
			content: nil,
			want:    nil,
		},
		{
			name:    "identity",
			content: &Content{Type: TypeIdentity, Data: []byte("anonymous@example.org")},
			want:    []string{`identity = "anonymous@example.org"`},
		},
		{
			name:    "nak names the type it wants",
			content: &Content{Type: TypeNAK, Data: []byte{byte(TypeTLS)}},
			want:    []string{"desired-type = TLS(13)"},
		},
		{
			name:    "tls start",
			content: &Content{Type: TypeTLS, Data: []byte{0x20}},
			want:    []string{"flags = S (0x20)", "tls-fragment = 0 bytes"},
		},
		{
			// 0xc0 is Length|More: a first fragment announcing the whole
			// handshake size, which is what a stalled EAP-TLS trace is read for.
			name:    "fragmented tls",
			content: &Content{Type: TypeTLS, Data: []byte{0xc0, 0, 0, 0x04, 0x00, 0xaa, 0xbb}},
			want: []string{
				"flags = LM (0xc0)",
				"tls-message-length = 1024",
				"tls-fragment = 2 bytes",
				"tls-data = 0xaabb",
			},
		},
		{
			name:    "empty tls request",
			content: &Content{Type: TypeTLS, Data: nil},
			want:    []string{"(no TLS data)"},
		},
		{
			name:    "mschapv2 op code",
			content: &Content{Type: TypeMsCHAPv2, Data: []byte{0x01, 0x00}},
			want:    []string{"op-code = Challenge(1)"},
		},
		{
			name:    "unknown type falls back to hex",
			content: &Content{Type: Type(99), Data: []byte{0xde, 0xad}},
			want:    []string{"data = 0xdead"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := traceContentLines(tc.content)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d lines %q, want %d %q", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// A long payload is previewed rather than dumped in full, so that one line
// stays one line. The full bytes are what -vv is for.
func TestTracePreviewHexTruncates(t *testing.T) {
	long := make([]byte, traceDataPreview+10)
	got := tracePreviewHex(long)
	if !strings.HasSuffix(got, "... (42 bytes)") {
		t.Errorf("tracePreviewHex = %q, want a truncated preview", got)
	}
	if short := tracePreviewHex([]byte{0x01}); short != "0x01" {
		t.Errorf("tracePreviewHex = %q, want 0x01", short)
	}
}
