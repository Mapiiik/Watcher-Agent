package routeros

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// AccessListEntry is one station removed from an access list.
type AccessListEntry struct {
	Menu       string `json:"menu"`
	Interface  string `json:"interface"`
	MACAddress string `json:"mac_address"`
}

// Access lists of the legacy wireless package and of the wifi package, the latter also under its name before
// RouterOS 7.13. A router has only some of them.
var accessListMenus = []string{
	"/interface/wireless/access-list",
	"/interface/wifi/access-list",
	"/interface/wifiwave2/access-list",
}

// ParseMAC reads a MAC address in any of the usual spellings and writes it the way RouterOS does.
func ParseMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("not a MAC address: %q", s)
	}
	return strings.ToUpper(hw.String()), nil
}

// RemoveFromAccessList takes the station, ParseMAC read, off every access list the router has, so that it has to
// be accepted again.
func RemoveFromAccessList(s *Session, mac string) ([]AccessListEntry, error) {
	removed := []AccessListEntry{}

	for _, menu := range accessListMenus {
		rows, err := s.Run(menu+"/print", "?mac-address="+mac, "=.proplist=.id,interface,mac-address")
		// a menu the router lacks answers with an error instead of entries
		if errors.Is(err, ErrCommandFailed) {
			continue
		}
		if err != nil {
			return removed, err
		}

		for _, row := range rows {
			if _, err := s.Run(menu+"/remove", "=.id="+row[".id"]); err != nil {
				return removed, err
			}
			removed = append(removed, AccessListEntry{
				Menu:       menu,
				Interface:  row["interface"],
				MACAddress: row["mac-address"],
			})
		}
	}

	return removed, nil
}
