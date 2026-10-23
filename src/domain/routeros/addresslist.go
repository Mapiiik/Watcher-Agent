package routeros

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Entry is one address on a firewall address list.
type Entry struct {
	Address string `json:"address"`
	Family  string `json:"family"`
	Comment string `json:"comment"`
}

// Changes is what one address list operation did on one router.
type Changes struct {
	Added     []Entry `json:"added"`
	Updated   []Entry `json:"updated"`
	Removed   []Entry `json:"removed"`
	Unchanged int     `json:"unchanged"`
}

var ErrBadAddress = errors.New("not an IP address or network")

const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

var families = []string{FamilyIPv4, FamilyIPv6}

var addressListMenus = map[string]string{
	FamilyIPv4: "/ip/firewall/address-list",
	FamilyIPv6: "/ipv6/firewall/address-list",
}

// ParseEntries checks the addresses and fills in their family. A second entry for the same network is dropped.
func ParseEntries(entries []Entry) ([]Entry, error) {
	parsed := make([]Entry, 0, len(entries))
	seen := map[netip.Prefix]bool{}

	for _, e := range entries {
		p, err := prefix(e.Address)
		if err != nil {
			return nil, err
		}
		if seen[p] {
			continue
		}
		seen[p] = true

		e.Family = family(p)
		parsed = append(parsed, e)
	}

	return parsed, nil
}

// CheckAddresses tells whether every address is one.
func CheckAddresses(addresses []string) error {
	for _, a := range addresses {
		if _, err := prefix(a); err != nil {
			return err
		}
	}
	return nil
}

// SyncAddressList makes the list hold exactly the entries, ParseEntries checked.
func SyncAddressList(s *Session, list string, entries []Entry) (Changes, error) {
	return writeAddressList(s, list, entries, true)
}

// AddToAddressList puts the entries, ParseEntries checked, on the list and leaves everything else on it.
func AddToAddressList(s *Session, list string, entries []Entry) (Changes, error) {
	return writeAddressList(s, list, entries, false)
}

// RemoveFromAddressList takes the addresses off the list.
func RemoveFromAddressList(s *Session, list string, addresses []string) (Changes, error) {
	ch := newChanges()

	targets := map[string]map[netip.Prefix]bool{}
	for _, a := range addresses {
		p, err := prefix(a)
		if err != nil {
			return ch, err
		}
		if targets[family(p)] == nil {
			targets[family(p)] = map[netip.Prefix]bool{}
		}
		targets[family(p)][p] = true
	}

	for _, fam := range families {
		if len(targets[fam]) == 0 {
			continue
		}

		rows, err := printList(s, addressListMenus[fam], list)
		if err != nil {
			return ch, err
		}

		for _, row := range rows {
			if p, err := prefix(row["address"]); err == nil && targets[fam][p] {
				if err := removeRow(s, addressListMenus[fam], fam, row, &ch); err != nil {
					return ch, err
				}
			}
		}
	}

	return ch, nil
}

func writeAddressList(s *Session, list string, entries []Entry, removeOthers bool) (Changes, error) {
	ch := newChanges()

	byFamily := map[string][]Entry{}
	for _, e := range entries {
		byFamily[e.Family] = append(byFamily[e.Family], e)
	}

	for _, fam := range families {
		if len(byFamily[fam]) == 0 && !removeOthers {
			continue
		}
		if err := writeFamily(s, fam, list, byFamily[fam], removeOthers, &ch); err != nil {
			return ch, err
		}
	}

	return ch, nil
}

func writeFamily(s *Session, fam, list string, entries []Entry, removeOthers bool, ch *Changes) error {
	menu := addressListMenus[fam]

	rows, err := printList(s, menu, list)
	if err != nil {
		// A router without IPv6 has no such menu, which matters only when something is to be written there
		if len(entries) == 0 && errors.Is(err, ErrCommandFailed) {
			return nil
		}
		return err
	}

	present := map[netip.Prefix][]map[string]string{}
	for _, row := range rows {
		if p, err := prefix(row["address"]); err == nil {
			present[p] = append(present[p], row)
		}
	}

	wanted := map[netip.Prefix]bool{}
	kept := map[string]bool{}

	for _, e := range entries {
		p, err := prefix(e.Address)
		if err != nil {
			return err
		}
		wanted[p] = true

		if len(present[p]) == 0 {
			if _, err := s.Run(menu+"/add", "=list="+list, "=address="+e.Address, "=comment="+e.Comment); err != nil {
				return err
			}
			ch.Added = append(ch.Added, e)
			continue
		}

		row := present[p][0]
		kept[row[".id"]] = true

		if row["comment"] == e.Comment && row["disabled"] != "true" {
			ch.Unchanged++
			continue
		}
		if _, err := s.Run(menu+"/set", "=.id="+row[".id"], "=comment="+e.Comment, "=disabled=no"); err != nil {
			return err
		}
		ch.Updated = append(ch.Updated, e)
	}

	// Removing comes last: a command failing half way leaves the list blocking more rather than fewer. A second
	// entry for a wanted address always goes, anything else only when the list is to hold the entries alone.
	for _, row := range rows {
		if kept[row[".id"]] {
			continue
		}
		p, err := prefix(row["address"])
		if !removeOthers && (err != nil || !wanted[p]) {
			continue
		}
		if err := removeRow(s, menu, fam, row, ch); err != nil {
			return err
		}
	}

	return nil
}

// printList reads the static entries of the list. A dynamic one was put there by a firewall rule with a timeout and
// is not the caller's to manage.
func printList(s *Session, menu, list string) ([]map[string]string, error) {
	rows, err := s.Run(menu+"/print", "?list="+list, "=.proplist=.id,address,comment,disabled,dynamic")
	if err != nil {
		return nil, err
	}

	static := rows[:0]
	for _, row := range rows {
		if row["dynamic"] != "true" {
			static = append(static, row)
		}
	}

	return static, nil
}

func removeRow(s *Session, menu, fam string, row map[string]string, ch *Changes) error {
	if _, err := s.Run(menu+"/remove", "=.id="+row[".id"]); err != nil {
		return err
	}
	ch.Removed = append(ch.Removed, Entry{Address: row["address"], Family: fam, Comment: row["comment"]})
	return nil
}

// prefix reads an address the way the firewall does: a bare address is a host prefix and a network is masked, so
// 192.0.2.1 and 192.0.2.1/32 are one entry however the router or the caller writes it.
func prefix(address string) (netip.Prefix, error) {
	if strings.Contains(address, "/") {
		p, err := netip.ParsePrefix(address)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%w: %q", ErrBadAddress, address)
		}
		return p.Masked(), nil
	}

	a, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrBadAddress, address)
	}

	return netip.PrefixFrom(a, a.BitLen()), nil
}

func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// newChanges starts with empty lists, so that the JSON answer has [] rather than null.
func newChanges() Changes {
	return Changes{Added: []Entry{}, Updated: []Entry{}, Removed: []Entry{}}
}
