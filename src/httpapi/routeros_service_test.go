package httpapi

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"watcher-agent/src/domain/routeros"
	"watcher-agent/src/testutil/routerosapi"
)

func routerOSRouter(t *testing.T) *routerosapi.Server {
	return routerosapi.Start(t, routerosapi.Options{
		Username: "watcher-agent",
		Password: "s3cret",
		TLS:      &tls.Config{Certificates: []tls.Certificate{routerosapi.SelfSigned(t)}},
		Menus: map[string][]map[string]string{
			"/ip/firewall/address-list": {
				{"list": "debtors", "address": "192.0.2.1", "comment": "1001 - A"},
			},
			"/ipv6/firewall/address-list": nil,
			"/interface/wireless/access-list": {
				{"interface": "wlan1", "mac-address": "AA:BB:CC:DD:EE:FF"},
			},
		},
	})
}

func routerOSConfig(port int) routeros.Config {
	return routeros.Config{
		Username: "watcher-agent",
		Password: "s3cret",
		Timeout:  2 * time.Second,
		TLSPort:  port,
	}
}

func closedTCPPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestRouterOSNotConfigured(t *testing.T) {
	svc := NewRouterOSService(routeros.Config{})

	for name, handle := range map[string]http.HandlerFunc{
		"sync":        svc.HandleAddressListSync,
		"add":         svc.HandleAddressListAdd,
		"remove":      svc.HandleAddressListRemove,
		"access list": svc.HandleAccessListRemove,
	} {
		rec := httptest.NewRecorder()
		handle(rec, httptest.NewRequest("POST", "/", jsonBody(`{"host":"127.0.0.1","list":"debtors","entries":[]}`)))

		if rec.Code != http.StatusServiceUnavailable || errorCode(t, rec) != "not_configured" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestRouterOSBadRequest(t *testing.T) {
	// nothing listens: a request that got as far as connecting would answer 502, not 400
	svc := NewRouterOSService(routerOSConfig(closedTCPPort(t)))

	for name, tc := range map[string]struct {
		handle http.HandlerFunc
		body   string
	}{
		"sync not JSON":            {svc.HandleAddressListSync, "host=127.0.0.1"},
		"sync without list":        {svc.HandleAddressListSync, `{"host":"127.0.0.1","entries":[]}`},
		"sync without entries":     {svc.HandleAddressListSync, `{"host":"127.0.0.1","list":"debtors"}`},
		"add with a bad address":   {svc.HandleAddressListAdd, `{"host":"127.0.0.1","list":"debtors","entries":[{"address":"x"}]}`},
		"remove without addresses": {svc.HandleAddressListRemove, `{"host":"127.0.0.1","list":"debtors"}`},
		"remove a bad address":     {svc.HandleAddressListRemove, `{"host":"127.0.0.1","list":"debtors","addresses":["x"]}`},
		"access list without host": {svc.HandleAccessListRemove, `{"mac_address":"AA:BB:CC:DD:EE:FF"}`},
		"access list bad MAC":      {svc.HandleAccessListRemove, `{"host":"127.0.0.1","mac_address":"x"}`},
	} {
		rec := httptest.NewRecorder()
		tc.handle(rec, httptest.NewRequest("POST", "/", jsonBody(tc.body)))

		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "bad_request" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleAddressListSync(t *testing.T) {
	router := routerOSRouter(t)
	svc := NewRouterOSService(routerOSConfig(router.Port))

	rec := httptest.NewRecorder()
	svc.HandleAddressListSync(rec, httptest.NewRequest("POST", "/api/routeros/address-list/sync", jsonBody(
		`{"host":"127.0.0.1","list":"debtors","entries":[{"address":"2001:db8::/48","comment":"1002 - B"}]}`,
	)))

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}

	added, _ := res["added"].([]any)
	removed, _ := res["removed"].([]any)
	updated, isList := res["updated"].([]any)
	if rec.Code != http.StatusOK || res["host"] != "127.0.0.1" || res["transport"] != "api-ssl" ||
		len(added) != 1 || len(removed) != 1 || !isList || len(updated) != 0 || res["unchanged"] != 0.0 {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
	if first, _ := added[0].(map[string]any); first["family"] != "ipv6" {
		t.Errorf("added %v", added)
	}
}

func TestHandleAddressListRemove(t *testing.T) {
	router := routerOSRouter(t)
	svc := NewRouterOSService(routerOSConfig(router.Port))

	rec := httptest.NewRecorder()
	svc.HandleAddressListRemove(rec, httptest.NewRequest("POST", "/api/routeros/address-list/remove",
		jsonBody(`{"host":"127.0.0.1","list":"debtors","addresses":["192.0.2.1"]}`)))

	var res AddressListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusOK || len(res.Removed) != 1 || res.Removed[0].Comment != "1001 - A" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAccessListRemove(t *testing.T) {
	router := routerOSRouter(t)
	svc := NewRouterOSService(routerOSConfig(router.Port))

	rec := httptest.NewRecorder()
	svc.HandleAccessListRemove(rec, httptest.NewRequest("POST", "/api/routeros/access-list/remove",
		jsonBody(`{"host":"127.0.0.1","mac_address":"aa-bb-cc-dd-ee-ff"}`)))

	var res AccessListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusOK || len(res.Removed) != 1 || res.Removed[0].Interface != "wlan1" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestRouterOSFailures(t *testing.T) {
	router := routerOSRouter(t)
	router.Fail("/ip/firewall/address-list/remove", "failure: item is in use")

	wrongPassword := routerOSConfig(router.Port)
	wrongPassword.Password = "wrong"

	for name, tc := range map[string]struct {
		cfg  routeros.Config
		code string
		says string
	}{
		"unreachable":     {routerOSConfig(closedTCPPort(t)), "routeros_unreachable", "api-ssl"},
		"login refused":   {wrongPassword, "routeros_login_failed", "invalid user name or password"},
		"command refused": {routerOSConfig(router.Port), "routeros_command_failed", "done before it: 1 added"},
	} {
		rec := httptest.NewRecorder()
		NewRouterOSService(tc.cfg).HandleAddressListSync(rec, httptest.NewRequest("POST", "/", jsonBody(
			`{"host":"127.0.0.1","list":"debtors","entries":[{"address":"192.0.2.2","comment":"1002 - B"}]}`,
		)))

		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusBadGateway || body["error"] != tc.code || !strings.Contains(body["message"], tc.says) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}
