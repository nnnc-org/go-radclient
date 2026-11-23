package radius

import "testing"

func TestTraceAttributeValue(t *testing.T) {
	tests := []struct {
		name string
		attr *Attribute
		want string
	}{
		{"text", newAttribute(AttributeTypeUserName, []byte("alice")), `"alice"`},
		{"empty", newAttribute(AttributeTypeEapMessage, nil), "(empty)"},
		{"integer", newAttribute(AttributeTypeFramedMtu, []byte{0, 0, 0x05, 0xdc}), "0x000005dc (1500)"},
		{"binary", newAttribute(AttributeTypeEapMessage, []byte{0x02, 0x01, 0x00}), "0x020100"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := traceAttributeValue(tc.attr); got != tc.want {
				t.Errorf("traceAttributeValue = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTraceAttributeLinesNameTheAttribute(t *testing.T) {
	lines := traceAttributeLines(Attributes{newAttribute(AttributeTypeUserName, []byte("alice"))})
	if len(lines) != 1 || lines[0] != `User-Name = "alice"` {
		t.Errorf("traceAttributeLines = %q", lines)
	}
}
