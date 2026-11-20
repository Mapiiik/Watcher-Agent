package httphelpers

import (
	"context"
	"net/http"
)

type callerKey struct{}

// WithCaller marks the request with the name of the access its key belongs to.
func WithCaller(r *http.Request, name string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), callerKey{}, name))
}

// Caller is the name of the access the request came with, empty where it came with none.
func Caller(r *http.Request) string {
	name, _ := r.Context().Value(callerKey{}).(string)
	return name
}
