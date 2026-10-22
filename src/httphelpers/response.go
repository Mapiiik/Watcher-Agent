// Package httphelpers writes the agent's JSON answers and the RouterOS error scripts.
package httphelpers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// WriteJSON writes v as a JSON answer with status 200.
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes the JSON error {"error": code, "message": msg} with the given status.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": msg,
	})
}

// WriteRouterOSError answers a RouterOS device with a script that only logs the error. String arguments are escaped,
// so text from the NMS or the URL can neither end the string nor run a command. Write errors are only logged.
func WriteRouterOSError(w http.ResponseWriter, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain")

	escaped := make([]any, len(args))
	for i, a := range args {
		if s, ok := a.(string); ok {
			escaped[i] = escapeROS(s)
		} else {
			escaped[i] = a
		}
	}

	if _, err := fmt.Fprintf(
		w,
		":log error \"Watcher Agent: "+format+"\"\n",
		escaped...,
	); err != nil {
		log.Printf("HTTP response write failed: %v", err)
	}
}

// In a RouterOS string "\" escapes, "$" expands a variable or runs $[...] and "?" asks for help.
var rosEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, `?`, `\?`, "\r", " ", "\n", " ")

// escapeROS makes s safe inside a double-quoted RouterOS string. "\/" from JSON in NMS answers becomes "/" first.
func escapeROS(s string) string {
	return rosEscaper.Replace(strings.ReplaceAll(s, `\/`, `/`))
}
