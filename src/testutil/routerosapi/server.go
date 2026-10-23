// Package routerosapi is a minimal RouterOS API server for tests. It speaks the binary protocol over TCP or TLS,
// logs one account in and keeps print, add, set and remove on menus held in memory. Like a device, it answers a
// menu it does not have with an error.
package routerosapi

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"maps"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/go-routeros/routeros/v3/proto"
)

type Options struct {
	Username string
	Password string

	// Certificate for api-ssl, nil for the plain api
	TLS *tls.Config

	// Menus the device has, such as "/ip/firewall/address-list", with their items. The server gives each an .id.
	Menus map[string][]map[string]string
}

type Server struct {
	// Port the server listens on, at 127.0.0.1
	Port int

	opts Options

	mu          sync.Mutex
	menus       map[string][]map[string]string
	nextID      int
	commands    []string
	failing     map[string]string
	connections int
}

// Start serves until the test ends.
func Start(t testing.TB, opts Options) *Server {
	t.Helper()

	var ln net.Listener
	var err error
	if opts.TLS != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", opts.TLS)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("routerosapi: %v", err)
	}

	s := &Server{
		Port:    ln.Addr().(*net.TCPAddr).Port,
		opts:    opts,
		menus:   map[string][]map[string]string{},
		failing: map[string]string{},
	}
	for menu, items := range opts.Menus {
		s.menus[menu] = []map[string]string{}
		for _, item := range items {
			s.add(menu, item)
		}
	}

	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()

	return s
}

// Items is what the menu holds now.
func (s *Server) Items(menu string) []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	items := make([]map[string]string, 0, len(s.menus[menu]))
	for _, item := range s.menus[menu] {
		items = append(items, maps.Clone(item))
	}
	return items
}

// Commands lists the commands run after login, in order.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

// Connections counts the connections accepted, logged in or not.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connections
}

// Fail makes the command answer with an error from now on.
func (s *Server) Fail(command, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing[command] = message
}

func (s *Server) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	s.mu.Lock()
	s.connections++
	s.mu.Unlock()

	r := bufio.NewReader(conn)
	w := proto.NewWriter(conn)
	loggedIn := false

	for {
		words, err := readSentence(r)
		if err != nil {
			return
		}
		if len(words) == 0 {
			continue
		}

		attrs, query := map[string]string{}, map[string]string{}
		for _, word := range words[1:] {
			switch {
			case strings.HasPrefix(word, "="):
				k, v, _ := strings.Cut(word[1:], "=")
				attrs[k] = v
			case strings.HasPrefix(word, "?"):
				k, v, _ := strings.Cut(word[1:], "=")
				query[k] = v
			}
		}

		if words[0] == "/login" {
			if attrs["name"] == s.opts.Username && attrs["password"] == s.opts.Password {
				loggedIn = true
				write(w, "!done")
			} else {
				trap(w, "invalid user name or password (6)")
			}
			continue
		}
		if !loggedIn {
			trap(w, "not logged in")
			continue
		}

		s.run(w, words[0], attrs, query)
	}
}

func (s *Server) run(w proto.Writer, command string, attrs, query map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.commands = append(s.commands, command)
	if msg, ok := s.failing[command]; ok {
		trap(w, msg)
		return
	}

	i := strings.LastIndex(command, "/")
	menu, verb := command[:i], command[i+1:]

	items, ok := s.menus[menu]
	if !ok {
		trap(w, "no such command prefix")
		return
	}

	switch verb {
	case "print":
		var props []string
		if p := attrs[".proplist"]; p != "" {
			props = strings.Split(p, ",")
		}
		for _, item := range items {
			if !matches(item, query) {
				continue
			}
			words := []string{"!re"}
			for k, v := range item {
				if props == nil || contains(props, k) {
					words = append(words, "="+k+"="+v)
				}
			}
			write(w, words...)
		}
		write(w, "!done")

	case "add":
		id := s.add(menu, attrs)
		write(w, "!done", "=ret="+id)

	case "set", "remove":
		j := s.find(menu, attrs[".id"])
		if j < 0 {
			trap(w, "no such item")
			return
		}
		if verb == "remove" {
			s.menus[menu] = append(items[:j], items[j+1:]...)
		} else {
			for k, v := range attrs {
				if k != ".id" {
					items[j][k] = v
				}
			}
		}
		write(w, "!done")

	default:
		trap(w, "no such command")
	}
}

func (s *Server) add(menu string, attrs map[string]string) string {
	s.nextID++
	item := map[string]string{"disabled": "false", "dynamic": "false"}
	maps.Copy(item, attrs)
	item[".id"] = fmt.Sprintf("*%X", s.nextID)
	s.menus[menu] = append(s.menus[menu], item)
	return item[".id"]
}

func (s *Server) find(menu, id string) int {
	for i, item := range s.menus[menu] {
		if item[".id"] == id {
			return i
		}
	}
	return -1
}

func matches(item, query map[string]string) bool {
	for k, v := range query {
		if item[k] != v {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// trap answers the way a device does, with !trap and then !done.
func trap(w proto.Writer, message string) {
	write(w, "!trap", "=message="+message)
	write(w, "!done")
}

func write(w proto.Writer, words ...string) {
	w.BeginSentence()
	for _, word := range words {
		w.WriteWord(word)
	}
	_ = w.EndSentence()
}

// readSentence reads words up to the empty one. The library's reader is the client's and rejects ?queries.
func readSentence(r *bufio.Reader) ([]string, error) {
	var words []string
	for {
		n, err := readLength(r)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return words, nil
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		words = append(words, string(b))
	}
}

func readLength(r *bufio.Reader) (int, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	var n, more int
	switch {
	case first&0x80 == 0x00:
		return int(first), nil
	case first&0xC0 == 0x80:
		n, more = int(first&0x3F), 1
	case first&0xE0 == 0xC0:
		n, more = int(first&0x1F), 2
	case first&0xF0 == 0xE0:
		n, more = int(first&0x0F), 3
	default:
		more = 4
	}

	for range more {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n = n<<8 | int(b)
	}

	return n, nil
}
