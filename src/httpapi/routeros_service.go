package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"watcher-agent/src/domain/routeros"
	"watcher-agent/src/httphelpers"
)

// RouterOSService changes RouterOS devices over their API: the firewall address lists debtors are blocked by and
// the access lists of access points.
type RouterOSService struct {
	cfg routeros.Config
}

type AddressListRequest struct {
	Host string `json:"host"`
	List string `json:"list"`
	// What to write, for sync and add
	Entries []routeros.Entry `json:"entries"`
	// What to take off, for remove
	Addresses []string `json:"addresses"`
}

type AddressListResponse struct {
	Host      string `json:"host"`
	Transport string `json:"transport"`
	routeros.Changes
}

type AccessListRequest struct {
	Host       string `json:"host"`
	MACAddress string `json:"mac_address"`
}

type AccessListResponse struct {
	Host      string                     `json:"host"`
	Transport string                     `json:"transport"`
	Removed   []routeros.AccessListEntry `json:"removed"`
}

func NewRouterOSService(cfg routeros.Config) *RouterOSService {
	return &RouterOSService{cfg: cfg}
}

// HandleAddressListSync makes the list hold exactly the entries.
func (s *RouterOSService) HandleAddressListSync(w http.ResponseWriter, r *http.Request) {
	s.handleAddressList(w, r, "sync", routeros.SyncAddressList)
}

// HandleAddressListAdd puts the entries on the list and leaves everything else on it.
func (s *RouterOSService) HandleAddressListAdd(w http.ResponseWriter, r *http.Request) {
	s.handleAddressList(w, r, "add", routeros.AddToAddressList)
}

// HandleAddressListRemove takes the addresses off the list.
func (s *RouterOSService) HandleAddressListRemove(w http.ResponseWriter, r *http.Request) {
	if !s.configured(w) {
		return
	}

	in, ok := decodeAddressList(w, r)
	if !ok {
		return
	}
	// Missing rather than empty is a caller that sent something else
	if in.Addresses == nil {
		badRequest(w, "Parameter 'addresses' is required.")
		return
	}
	if err := routeros.CheckAddresses(in.Addresses); err != nil {
		badRequest(w, err.Error())
		return
	}

	s.runAddressList(w, r, "remove", in.Host, in.List, func(session *routeros.Session) (routeros.Changes, error) {
		return routeros.RemoveFromAddressList(session, in.List, in.Addresses)
	})
}

// HandleAccessListRemove takes a station off the access lists of an access point.
func (s *RouterOSService) HandleAccessListRemove(w http.ResponseWriter, r *http.Request) {
	if !s.configured(w) {
		return
	}

	var in AccessListRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		badRequest(w, "Invalid JSON request body.")
		return
	}
	if in.Host == "" || in.MACAddress == "" {
		badRequest(w, "Parameters 'host' and 'mac_address' are required.")
		return
	}
	mac, err := routeros.ParseMAC(in.MACAddress)
	if err != nil {
		badRequest(w, err.Error())
		return
	}

	who := []any{"client", remoteIP(r), "host", in.Host, "mac", mac}

	session, err := routeros.Open(s.cfg, in.Host)
	if err != nil {
		slog.Warn("RouterOS access list not changed", append(who, "error", err)...)
		writeRouterOSError(w, err)
		return
	}
	defer func() { _ = session.Close() }()
	who = append(who, "transport", session.Transport)

	removed, err := routeros.RemoveFromAccessList(session, mac)
	if err != nil {
		err = fmt.Errorf("%w (removed before it: %d)", err, len(removed))
		slog.Warn("RouterOS access list change failed", append(who, "error", err)...)
		writeRouterOSError(w, err)
		return
	}

	slog.Info("RouterOS access list changed", append(who, "removed", len(removed))...)
	httphelpers.WriteJSON(w, AccessListResponse{Host: in.Host, Transport: session.Transport, Removed: removed})
}

func (s *RouterOSService) handleAddressList(
	w http.ResponseWriter,
	r *http.Request,
	op string,
	write func(*routeros.Session, string, []routeros.Entry) (routeros.Changes, error),
) {
	if !s.configured(w) {
		return
	}

	in, ok := decodeAddressList(w, r)
	if !ok {
		return
	}
	// Missing rather than empty is a caller that sent something else, and a sync would read it as an empty list
	if in.Entries == nil {
		badRequest(w, "Parameter 'entries' is required.")
		return
	}
	entries, err := routeros.ParseEntries(in.Entries)
	if err != nil {
		badRequest(w, err.Error())
		return
	}

	s.runAddressList(w, r, op, in.Host, in.List, func(session *routeros.Session) (routeros.Changes, error) {
		return write(session, in.List, entries)
	})
}

// runAddressList runs the change on the router and logs what it did or why not, with who asked for it.
func (s *RouterOSService) runAddressList(
	w http.ResponseWriter,
	r *http.Request,
	op, host, list string,
	run func(*routeros.Session) (routeros.Changes, error),
) {
	who := []any{"client", remoteIP(r), "op", op, "host", host, "list", list}

	session, err := routeros.Open(s.cfg, host)
	if err != nil {
		slog.Warn("RouterOS address list not changed", append(who, "error", err)...)
		writeRouterOSError(w, err)
		return
	}
	defer func() { _ = session.Close() }()
	who = append(who, "transport", session.Transport)

	changes, err := run(session)
	if err != nil {
		err = fmt.Errorf(
			"%w (done before it: %d added, %d updated, %d removed)",
			err, len(changes.Added), len(changes.Updated), len(changes.Removed),
		)
		slog.Warn("RouterOS address list change failed", append(who, "error", err)...)
		writeRouterOSError(w, err)
		return
	}

	slog.Info("RouterOS address list changed", append(who,
		"added", addresses(changes.Added),
		"updated", addresses(changes.Updated),
		"removed", addresses(changes.Removed),
		"unchanged", changes.Unchanged,
	)...)
	httphelpers.WriteJSON(w, AddressListResponse{Host: host, Transport: session.Transport, Changes: changes})
}

// addresses lists the addresses of the entries for the log, the first 50 of them; comments name customers and stay
// out.
func addresses(entries []routeros.Entry) string {
	const most = 50
	list := make([]string, 0, min(len(entries), most))
	for _, e := range entries[:min(len(entries), most)] {
		list = append(list, e.Address)
	}
	text := strings.Join(list, " ")
	if len(entries) > most {
		text += fmt.Sprintf(" and %d more", len(entries)-most)
	}
	return text
}

func (s *RouterOSService) configured(w http.ResponseWriter) bool {
	if !s.cfg.Configured() {
		httphelpers.WriteError(
			w,
			http.StatusServiceUnavailable,
			"not_configured",
			"The RouterOS API is not configured on this agent.",
		)
		return false
	}
	return true
}

func decodeAddressList(w http.ResponseWriter, r *http.Request) (AddressListRequest, bool) {
	var in AddressListRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		badRequest(w, "Invalid JSON request body.")
		return in, false
	}
	if in.Host == "" || in.List == "" {
		badRequest(w, "Parameters 'host' and 'list' are required.")
		return in, false
	}
	return in, true
}

func badRequest(w http.ResponseWriter, msg string) {
	httphelpers.WriteError(w, http.StatusBadRequest, "bad_request", msg)
}

func writeRouterOSError(w http.ResponseWriter, err error) {
	status, code := http.StatusBadGateway, "routeros_unreachable"
	switch {
	case errors.Is(err, routeros.ErrTargetNotAllowed):
		status, code = http.StatusForbidden, "routeros_target_not_allowed"
	case errors.Is(err, routeros.ErrCertificateInvalid):
		code = "routeros_certificate_invalid"
	case errors.Is(err, routeros.ErrLoginFailed):
		code = "routeros_login_failed"
	case errors.Is(err, routeros.ErrCommandFailed):
		code = "routeros_command_failed"
	}

	httphelpers.WriteError(w, status, code, err.Error())
}
