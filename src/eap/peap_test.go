package eap

import (
	"encoding/hex"
	"testing"
)

// The MS-CHAPv2 Success message is "S=<auth>" with an optional " M=<message>".
// FreeRADIUS omits the optional part, which used to fail the whole exchange.
func TestParseSuccessMessage(t *testing.T) {
	const auth = "E068D20538A7E51B01F9A7509EE65C0DFD6912D0"
	want, err := hex.DecodeString(auth)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	tests := []struct {
		name        string
		in          string
		wantMessage string
		wantErr     bool
	}{
		{
			// What FreeRADIUS actually sends.
			name: "authenticator only",
			in:   "S=" + auth,
		},
		{
			name:        "with an optional message",
			in:          "S=" + auth + " M=Welcome",
			wantMessage: "Welcome",
		},
		{
			name:        "message containing spaces",
			in:          "S=" + auth + " M=Password expires soon",
			wantMessage: "Password expires soon",
		},
		{
			// Lowercase hex is still hex.
			name: "lowercase authenticator",
			in:   "S=e068d20538a7e51b01f9a7509ee65c0dfd6912d0",
		},
		{
			name:    "not hex",
			in:      "S=nothexatall",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, msg, err := parseSuccessMessage(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Errorf("authenticator = %x, want %x", got, want)
			}
			if msg != tc.wantMessage {
				t.Errorf("message = %q, want %q", msg, tc.wantMessage)
			}
		})
	}
}

// A PEAPv0 peer may send an inner EAP packet with its header intact or
// stripped. FreeRADIUS does both within one conversation.
func TestIsFullEapPacket(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("fixture %q: %v", s, err)
		}
		return b
	}

	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{
			// Identity request, captured from FreeRADIUS: Request, id, len 5,
			// type Identity.
			name: "full identity request",
			in:   mustHex("01a2000501"),
			want: true,
		},
		{
			// Result TLV reporting failure, which used to be misparsed as a
			// compressed Identity because both start with 0x01.
			name: "full result tlv",
			in:   mustHex("01e9000b21800300020002"),
			want: true,
		},
		{
			// MS-CHAPv2 challenge, header stripped: starts with the type byte.
			name: "compressed mschapv2",
			in:   mustHex("1a01a3002610a58c68488caf7631dc924a176424e346"),
			want: false,
		},
		{
			// The ambiguous case: a compressed Identity response also starts
			// with 0x01, so only the length field can tell them apart.
			name: "compressed identity response",
			in:   append([]byte{0x01}, []byte("testuser")...),
			want: false,
		},
		{
			name: "too short",
			in:   []byte{0x01, 0x02},
			want: false,
		},
		{
			name: "not a valid code",
			in:   mustHex("21800300020002"),
			want: false,
		},
		{
			name: "declared length disagrees",
			in:   mustHex("01a2009901"),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFullEapPacket(tc.in); got != tc.want {
				t.Errorf("isFullEapPacket(%x) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestTLVResult(t *testing.T) {
	tests := []struct {
		name        string
		in          []byte
		wantSuccess bool
		wantOK      bool
	}{
		{
			name:        "failure",
			in:          []byte{0x80, 3, 0, 2, 0, 2},
			wantSuccess: false,
			wantOK:      true,
		},
		{
			name:        "success",
			in:          []byte{0x80, 3, 0, 2, 0, 1},
			wantSuccess: true,
			wantOK:      true,
		},
		{
			// The mandatory bit must not change how the type is read.
			name:        "without the mandatory bit",
			in:          []byte{0x00, 3, 0, 2, 0, 1},
			wantSuccess: true,
			wantOK:      true,
		},
		{
			name:   "wrong avp type",
			in:     []byte{0x80, 4, 0, 2, 0, 1},
			wantOK: false,
		},
		{
			name:   "wrong length",
			in:     []byte{0x80, 3, 0, 4, 0, 1},
			wantOK: false,
		},
		{
			name:   "unknown result value",
			in:     []byte{0x80, 3, 0, 2, 0, 9},
			wantOK: false,
		},
		{
			name:   "too short",
			in:     []byte{0x80, 3},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			success, ok := tlvResult(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && success != tc.wantSuccess {
				t.Errorf("success = %v, want %v", success, tc.wantSuccess)
			}
		})
	}
}
