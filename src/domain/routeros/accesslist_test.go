package routeros

import (
	"bytes"
	"slices"
	"testing"

	"watcher-agent/src/testutil/routerosapi"
)

// The router has the wifi package only, so the other two menus answer with an error and are passed over.
func TestRemoveFromAccessList(t *testing.T) {
	router := tlsRouter(t, routerosapi.SelfSigned(t), map[string][]map[string]string{
		"/interface/wifi/access-list": {
			{"interface": "wifi1", "mac-address": "AA:BB:CC:DD:EE:FF"},
			{"interface": "wifi2", "mac-address": "AA:BB:CC:DD:EE:FF"},
			{"interface": "wifi1", "mac-address": "11:22:33:44:55:66"},
		},
	})

	removed, err := RemoveFromAccessList(openOn(t, router), "AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatal(err)
	}

	if len(removed) != 2 || removed[0].Menu != "/interface/wifi/access-list" || removed[1].Interface != "wifi2" {
		t.Errorf("%+v", removed)
	}
	if left := router.Items("/interface/wifi/access-list"); len(left) != 1 || left[0]["mac-address"] != "11:22:33:44:55:66" {
		t.Errorf("left %v", left)
	}
	if !slices.Contains(router.Commands(), "/interface/wifiwave2/access-list/print") {
		t.Errorf("the last menu was not tried: %v", router.Commands())
	}
}

func TestParseMAC(t *testing.T) {
	for in, want := range map[string]string{
		"aa:bb:cc:dd:ee:ff":   "AA:BB:CC:DD:EE:FF",
		" AA-BB-CC-DD-EE-FF ": "AA:BB:CC:DD:EE:FF",
		"aabb.ccdd.eeff":      "AA:BB:CC:DD:EE:FF",
	} {
		if got, err := ParseMAC(in); err != nil || got != want {
			t.Errorf("ParseMAC(%q) = %q, %v", in, got, err)
		}
	}

	for _, bad := range []string{"", "nonsense", "aa:bb:cc:dd:ee:ff:00:11"} {
		if _, err := ParseMAC(bad); err == nil {
			t.Errorf("ParseMAC(%q) passed", bad)
		}
	}
}

func TestParseFingerprint(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, 32)
	colons := "AB" + string(bytes.Repeat([]byte(":AB"), 31))

	for _, in := range []string{colons, string(bytes.Repeat([]byte("ab"), 32)), " " + colons + " "} {
		if got, err := ParseFingerprint(in); err != nil || !bytes.Equal(got, want) {
			t.Errorf("ParseFingerprint(%q) = %x, %v", in, got, err)
		}
	}

	if got, err := ParseFingerprint(""); got != nil || err != nil {
		t.Errorf("empty = %x, %v", got, err)
	}

	for _, bad := range []string{"AB:CD", string(bytes.Repeat([]byte("zz"), 32))} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Errorf("ParseFingerprint(%q) passed", bad)
		}
	}
}
