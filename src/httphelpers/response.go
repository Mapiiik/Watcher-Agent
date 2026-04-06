package httphelpers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": msg,
	})
}

// WriteRouterOSError writes a RouterOS-compatible error response.
// Write errors are logged but not propagated.
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

func escapeROS(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, `\/`, `/`)
	return s
}
