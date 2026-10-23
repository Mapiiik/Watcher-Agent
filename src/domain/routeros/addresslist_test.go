package routeros

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"watcher-agent/src/testutil/routerosapi"
)

const (
	ipv4List = "/ip/firewall/address-list"
	ipv6List = "/ipv6/firewall/address-list"
)

// debtorsRouter holds a list as it may be found: written by hand in places, with a duplicate, a disabled entry, a
// dynamic one and a second list beside it.
func debtorsRouter(t *testing.T, withIPv6 bool) *routerosapi.Server {
	menus := map[string][]map[string]string{
		ipv4List: {
			{"list": "debtors", "address": "192.0.2.1", "comment": "old"},
			{"list": "debtors", "address": "192.0.2.2/32", "comment": "1002 - B"},
			{"list": "debtors", "address": "192.0.2.3", "comment": "1003 - C"},
			{"list": "debtors", "address": "192.0.2.3", "comment": "1003 - C"},
			{"list": "debtors", "address": "192.0.2.4", "comment": "1004 - D", "disabled": "true"},
			{"list": "debtors", "address": "198.51.100.0/24", "comment": "paid"},
			{"list": "debtors", "address": "192.0.2.10", "comment": "rule", "dynamic": "true"},
			{"list": "other", "address": "192.0.2.9", "comment": "not ours"},
		},
	}
	if withIPv6 {
		menus[ipv6List] = []map[string]string{
			{"list": "debtors", "address": "2001:db8::1/128", "comment": "1007 - G"},
			{"list": "debtors", "address": "2001:db8:dead::/48", "comment": "paid"},
		}
	}

	return tlsRouter(t, routerosapi.SelfSigned(t), menus)
}

func openOn(t *testing.T, router *routerosapi.Server) *Session {
	s, err := Open(testConfig(router.Port, 0), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustEntries(t *testing.T, entries ...Entry) []Entry {
	parsed, err := ParseEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func addresses(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Address)
	}
	return out
}

// addressesOn is what the list holds on the router, dynamic entries included.
func addressesOn(router *routerosapi.Server, menu, list string) []string {
	var out []string
	for _, item := range router.Items(menu) {
		if item["list"] == list {
			out = append(out, item["address"]+" "+item["comment"])
		}
	}
	slices.Sort(out)
	return out
}

func TestSyncAddressList(t *testing.T) {
	router := debtorsRouter(t, true)

	ch, err := SyncAddressList(openOn(t, router), "debtors", mustEntries(t,
		Entry{Address: "192.0.2.1", Comment: "1001 - A"},
		Entry{Address: "192.0.2.2", Comment: "1002 - B"},
		Entry{Address: "192.0.2.3/32", Comment: "1003 - C"},
		Entry{Address: "192.0.2.4", Comment: "1004 - D"},
		Entry{Address: "203.0.113.5", Comment: "1005 - E"},
		Entry{Address: "10.0.0.0/8", Comment: "1006 - F"},
		Entry{Address: "2001:db8::1", Comment: "1007 - G"},
	))
	if err != nil {
		t.Fatal(err)
	}

	if got := addresses(ch.Added); !slices.Equal(got, []string{"203.0.113.5", "10.0.0.0/8"}) {
		t.Errorf("added %v", got)
	}
	if got := addresses(ch.Updated); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.4"}) {
		t.Errorf("updated %v", got)
	}
	if got := addresses(ch.Removed); !slices.Equal(got, []string{"192.0.2.3", "198.51.100.0/24", "2001:db8:dead::/48"}) {
		t.Errorf("removed %v", got)
	}
	if ch.Unchanged != 3 {
		t.Errorf("unchanged %d", ch.Unchanged)
	}
	if ch.Removed[2].Family != FamilyIPv6 || ch.Added[0].Family != FamilyIPv4 {
		t.Errorf("families %+v %+v", ch.Removed[2], ch.Added[0])
	}

	want := []string{
		"10.0.0.0/8 1006 - F", "192.0.2.1 1001 - A", "192.0.2.10 rule", "192.0.2.2/32 1002 - B",
		"192.0.2.3 1003 - C", "192.0.2.4 1004 - D", "203.0.113.5 1005 - E",
	}
	if got := addressesOn(router, ipv4List, "debtors"); !slices.Equal(got, want) {
		t.Errorf("IPv4 list %v", got)
	}
	if got := addressesOn(router, ipv4List, "other"); !slices.Equal(got, []string{"192.0.2.9 not ours"}) {
		t.Errorf("the other list %v", got)
	}
	for _, item := range router.Items(ipv4List) {
		if item["address"] == "192.0.2.4" && item["disabled"] != "no" {
			t.Errorf("192.0.2.4 is still disabled: %v", item)
		}
	}
}

// Should a command fail half way, the list is better left blocking somebody who paid than letting a debtor through.
func TestSyncAddressListRemovesLast(t *testing.T) {
	router := debtorsRouter(t, true)

	if _, err := SyncAddressList(openOn(t, router), "debtors", mustEntries(t,
		Entry{Address: "203.0.113.5", Comment: "1005 - E"},
	)); err != nil {
		t.Fatal(err)
	}

	commands := router.Commands()
	lastAdd := slices.Index(commands, ipv4List+"/add")
	firstRemove := slices.Index(commands, ipv4List+"/remove")
	if lastAdd < 0 || firstRemove < lastAdd {
		t.Errorf("commands %v", commands)
	}
}

func TestSyncAddressListStopsAtAFailure(t *testing.T) {
	router := debtorsRouter(t, true)
	router.Fail(ipv4List+"/remove", "failure: item is in use")

	ch, err := SyncAddressList(openOn(t, router), "debtors", mustEntries(t,
		Entry{Address: "203.0.113.5", Comment: "1005 - E"},
	))

	if !errors.Is(err, ErrCommandFailed) || !strings.Contains(err.Error(), "item is in use") {
		t.Errorf("err = %v", err)
	}
	if len(ch.Added) != 1 {
		t.Errorf("what was done before the failure is lost: %+v", ch)
	}
}

func TestSyncAddressListWithoutIPv6(t *testing.T) {
	router := debtorsRouter(t, false)
	s := openOn(t, router)

	if _, err := SyncAddressList(s, "debtors", mustEntries(t, Entry{Address: "192.0.2.1", Comment: "A"})); err != nil {
		t.Errorf("only IPv4 wanted: %v", err)
	}
	if _, err := SyncAddressList(s, "debtors", mustEntries(t, Entry{Address: "2001:db8::1", Comment: "G"})); !errors.Is(err, ErrCommandFailed) {
		t.Errorf("IPv6 wanted: %v", err)
	}
}

func TestAddToAddressListLeavesTheRest(t *testing.T) {
	router := debtorsRouter(t, true)

	ch, err := AddToAddressList(openOn(t, router), "debtors", mustEntries(t,
		Entry{Address: "192.0.2.3", Comment: "MANUAL ENTRY - 1003 - C"},
		Entry{Address: "203.0.113.5", Comment: "MANUAL ENTRY - 1005 - E"},
	))
	if err != nil {
		t.Fatal(err)
	}

	// the second 192.0.2.3 goes, being one more of what is written
	if len(ch.Added) != 1 || len(ch.Updated) != 1 || len(ch.Removed) != 1 || ch.Removed[0].Address != "192.0.2.3" {
		t.Errorf("%+v", ch)
	}
	if got := addressesOn(router, ipv4List, "debtors"); !slices.Contains(got, "198.51.100.0/24 paid") {
		t.Errorf("an address that was not named went: %v", got)
	}
	for _, c := range router.Commands() {
		if strings.HasPrefix(c, ipv6List) {
			t.Errorf("IPv6 touched with nothing to write there: %v", router.Commands())
		}
	}
}

func TestRemoveFromAddressList(t *testing.T) {
	router := debtorsRouter(t, true)

	ch, err := RemoveFromAddressList(openOn(t, router), "debtors", []string{"192.0.2.3/32", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}

	if got := addresses(ch.Removed); !slices.Equal(got, []string{"192.0.2.3", "192.0.2.3", "2001:db8::1/128"}) {
		t.Errorf("removed %v", got)
	}
	if got := addressesOn(router, ipv4List, "debtors"); len(got) != 5 {
		t.Errorf("IPv4 list %v", got)
	}
}

func TestParseEntries(t *testing.T) {
	entries, err := ParseEntries([]Entry{
		{Address: "192.0.2.1", Comment: "first"},
		{Address: "192.0.2.1/32", Comment: "the same once more"},
		{Address: "2001:db8::/32", Comment: "network"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Comment != "first" || entries[0].Family != FamilyIPv4 || entries[1].Family != FamilyIPv6 {
		t.Errorf("%+v", entries)
	}

	for _, bad := range []string{"", "router.example", "192.0.2.300", "192.0.2.0/33"} {
		if _, err := ParseEntries([]Entry{{Address: bad}}); !errors.Is(err, ErrBadAddress) {
			t.Errorf("%q: %v", bad, err)
		}
		if err := CheckAddresses([]string{bad}); !errors.Is(err, ErrBadAddress) {
			t.Errorf("CheckAddresses(%q): %v", bad, err)
		}
	}
}
