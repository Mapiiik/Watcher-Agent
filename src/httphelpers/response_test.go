package httphelpers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, map[string]int{"answer": 42})

	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != "{\"answer\":42}\n" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "bad_request", "Invalid JSON request body.")

	if rec.Code != http.StatusBadRequest || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "bad_request" || body["message"] != "Invalid JSON request body." || len(body) != 2 {
		t.Errorf("body = %v", body)
	}
}

func TestWriteRouterOSError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteRouterOSError(rec, "Serial mismatch (got %s, expected %s, attempt %d)", "HE408", "HE409", 2)

	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	want := ":log error \"Watcher Agent: Serial mismatch (got HE408, expected HE409, attempt 2)\"\n"
	if rec.Body.String() != want {
		t.Errorf("body = %q, want %q", rec.Body.String(), want)
	}
}

// Text from the NMS or the device must not end the RouterOS string early.
func TestWriteRouterOSErrorEscapesArguments(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteRouterOSError(rec, "NMS provision failed: %s", "nms error 500: {\"message\":\"no \\/ route\"}\nline 2")

	want := ":log error \"Watcher Agent: NMS provision failed: nms error 500: {\\\"message\\\":\\\"no / route\\\"} line 2\"\n"
	if rec.Body.String() != want {
		t.Errorf("body = %q, want %q", rec.Body.String(), want)
	}
}

// The device imports the answer as a script, so nothing in the arguments may run there.
func TestWriteRouterOSErrorEscapesScriptSyntax(t *testing.T) {
	for in, want := range map[string]string{
		`x$[/system reset-configuration]`: `x\$[/system reset-configuration]`,
		`$serial`:                         `\$serial`,
		`a\"; /user add name=x`:           `a\\\"; /user add name=x`,
		`what?`:                           `what\?`,
		"one\r\ntwo":                      "one  two",
	} {
		rec := httptest.NewRecorder()
		WriteRouterOSError(rec, "Serial mismatch (got %s)", in)

		body := ":log error \"Watcher Agent: Serial mismatch (got " + want + ")\"\n"
		if rec.Body.String() != body {
			t.Errorf("%q: body = %q, want %q", in, rec.Body.String(), body)
		}
	}
}
