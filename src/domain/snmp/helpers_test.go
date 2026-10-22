package snmp

import (
	"testing"

	"golang.org/x/text/encoding/charmap"
)

func TestSnmpTextDecodesWindows1250(t *testing.T) {
	raw, err := charmap.Windows1250.NewEncoder().String("Kancelář Žďár")
	if err != nil {
		t.Fatal(err)
	}

	got := snmpText([]byte(raw))
	if got == nil || *got != "Kancelář Žďár" {
		t.Fatalf("snmpText = %v, want %q", deref(got), "Kancelář Žďár")
	}
}

func TestSnmpTextEmptyIsNil(t *testing.T) {
	for _, v := range []any{nil, []byte{}, ""} {
		if got := snmpText(v); got != nil {
			t.Errorf("snmpText(%#v) = %q, want nil", v, *got)
		}
	}
}

func TestSnmpTextFormatsOtherValues(t *testing.T) {
	for v, want := range map[any]string{"192.168.88.1": "192.168.88.1", 42: "42"} {
		if got := snmpText(v); got == nil || *got != want {
			t.Errorf("snmpText(%#v) = %v, want %q", v, deref(got), want)
		}
	}
}

func TestSnmpInt(t *testing.T) {
	for _, v := range []any{int(7), int64(7), uint(7), uint32(7), uint64(7)} {
		if got := snmpInt(v); got == nil || *got != 7 {
			t.Errorf("snmpInt(%T) = %v, want 7", v, got)
		}
	}

	for _, v := range []any{nil, "7", []byte{7}} {
		if got := snmpInt(v); got != nil {
			t.Errorf("snmpInt(%#v) = %d, want nil", v, *got)
		}
	}
}

func TestMacToString(t *testing.T) {
	got := macToString([]byte{0x4c, 0x5e, 0x0c, 0x01, 0xab, 0xff})
	if got == nil || *got != "4c:5e:0c:01:ab:ff" {
		t.Fatalf("macToString = %v, want 4c:5e:0c:01:ab:ff", deref(got))
	}

	for _, v := range []any{nil, []byte{}, []byte{1, 2, 3, 4, 5}, "4c:5e:0c:01:ab:ff"} {
		if got := macToString(v); got != nil {
			t.Errorf("macToString(%#v) = %q, want nil", v, *got)
		}
	}
}

func TestMaskToCIDR(t *testing.T) {
	cases := map[string]int{
		"255.255.255.0":   24,
		"255.255.255.252": 30,
		"255.255.255.255": 32,
		"0.0.0.0":         0,
		"255.0.255.0":     -1, // not contiguous
		"ffff:ffff::":     -1,
		"bogus":           -1,
	}

	for mask, want := range cases {
		if got := maskToCIDR(mask); got != want {
			t.Errorf("maskToCIDR(%q) = %d, want %d", mask, got, want)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
