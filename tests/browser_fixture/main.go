// A loopback-only origin fixture. TLS and HTTP/2 observations come from the
// received bytes, not from a claimed user agent or a hard-coded fingerprint.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type sink struct {
	mu   sync.Mutex
	file *os.File
}

func (s *sink) emit(value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = json.NewEncoder(s.file).Encode(value)
}

type tracked struct {
	net.Conn
	mu   sync.Mutex
	data []byte
	once sync.Once
	done chan struct{}
}

func (c *tracked) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.mu.Lock()
	limit := 1024*1024 - len(c.data)
	if limit > 0 {
		c.data = append(c.data, p[:min(n, limit)]...)
	}
	c.mu.Unlock()
	return n, e
}
func (c *tracked) snapshot() []byte { c.mu.Lock(); defer c.mu.Unlock(); return bytes.Clone(c.data) }
func (c *tracked) Close() error     { e := c.Conn.Close(); c.once.Do(func() { close(c.done) }); return e }
func track(c net.Conn) *tracked     { return &tracked{Conn: c, done: make(chan struct{})} }

type tlsTracked struct {
	*tracked
	tlsConn *tls.Conn
}

func (c *tlsTracked) ConnectionState() tls.ConnectionState { return c.tlsConn.ConnectionState() }

type oneListener struct {
	c    net.Conn
	done <-chan struct{}
	used bool
}

func (l *oneListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneListener) Close() error   { return l.c.Close() }
func (l *oneListener) Addr() net.Addr { return l.c.LocalAddr() }

type observation struct {
	id         uint64
	raw, plain *tracked
	alpn       string
}
type observationKey struct{}

func h2Info(data []byte) map[string]any {
	out := map[string]any{}
	if !bytes.HasPrefix(data, []byte(http2.ClientPreface)) {
		return out
	}
	f := http2.NewFramer(nil, bytes.NewReader(data[len(http2.ClientPreface):]))
	f.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var settings [][]uint32
	var headers []any
	var connectionWindow uint32
	for {
		frame, e := f.ReadFrame()
		if e != nil {
			break
		}
		switch v := frame.(type) {
		case *http2.SettingsFrame:
			if !v.IsAck() && settings == nil {
				_ = v.ForeachSetting(func(s http2.Setting) error { settings = append(settings, []uint32{uint32(s.ID), s.Val}); return nil })
			}
		case *http2.MetaHeadersFrame:
			var fields [][]string
			for _, h := range v.Fields {
				fields = append(fields, []string{h.Name, h.Value})
			}
			headers = append(headers, map[string]any{"stream": v.StreamID, "fields": fields, "end_stream": v.StreamEnded()})
		case *http2.WindowUpdateFrame:
			if v.StreamID == 0 && len(headers) == 0 {
				connectionWindow += v.Increment
			}
		}
	}
	out["settings"] = settings
	out["headers"] = headers
	out["initial_connection_window_increment"] = connectionWindow
	return out
}

func frame(w io.Writer, opcode byte, fin bool, payload []byte) error {
	first := opcode
	if fin {
		first |= 0x80
	}
	head := []byte{first}
	switch {
	case len(payload) < 126:
		head = append(head, byte(len(payload)))
	case len(payload) <= 65535:
		head = append(head, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		head = append(head, 127)
		head = binary.BigEndian.AppendUint64(head, uint64(len(payload)))
	}
	if _, e := w.Write(head); e != nil {
		return e
	}
	_, e := w.Write(payload)
	return e
}
func readFrame(r io.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return 0, nil, e
	}
	if h[1]&128 == 0 {
		return 0, nil, fmt.Errorf("client frame was not masked")
	}
	n := uint64(h[1] & 127)
	if n == 126 {
		var b [2]byte
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, nil, e
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	}
	if n == 127 {
		var b [8]byte
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, nil, e
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 16*1024*1024 {
		return 0, nil, fmt.Errorf("frame too large")
	}
	var mask [4]byte
	if _, e := io.ReadFull(r, mask[:]); e != nil {
		return 0, nil, e
	}
	p := make([]byte, n)
	if _, e := io.ReadFull(r, p); e != nil {
		return 0, nil, e
	}
	for i := range p {
		p[i] ^= mask[i%4]
	}
	return h[0] & 15, p, nil
}
func websocket(w http.ResponseWriter, r *http.Request, out *sink) {
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP/1 WebSocket fixture", 400)
		return
	}
	conn, rw, e := h.Hijack()
	if e != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	if r.TLS != nil {
		fmt.Fprintf(rw, "X-Ech-Accepted: %t\r\n", r.TLS.ECHAccepted)
	}
	if strings.Contains(r.Header.Get("Sec-WebSocket-Protocol"), "echo") {
		fmt.Fprint(rw, "Sec-WebSocket-Protocol: echo\r\n")
	}
	fmt.Fprint(rw, "\r\n")
	if rw.Flush() != nil {
		return
	}
	if r.URL.Path == "/ws-invalid" {
		_ = frame(conn, 1, true, []byte{255, 255})
		return
	}
	if r.URL.Path == "/ws-abrupt" {
		return
	}
	if r.URL.Path == "/ws-big" {
		_ = frame(conn, 2, true, make([]byte, 65_536))
		return
	}
	if e = frame(conn, 9, true, []byte("native-ping")); e != nil {
		return
	}
	for {
		opcode, payload, e := readFrame(rw)
		if e != nil {
			return
		}
		switch opcode {
		case 1, 2:
			if r.URL.Path == "/ws-fragment" && len(payload) > 1 {
				n := len(payload) / 2
				if frame(conn, opcode, false, payload[:n]) != nil {
					return
				}
				e = frame(conn, 0, true, payload[n:])
			} else {
				e = frame(conn, opcode, true, payload)
			}
			if e != nil {
				return
			}
		case 8:
			_ = frame(conn, 8, true, payload)
			out.emit(map[string]any{"kind": "ws-close", "clean": true})
			return
		case 9:
			if frame(conn, 10, true, payload) != nil {
				return
			}
		case 10:
			out.emit(map[string]any{"kind": "ws-pong", "payload": string(payload)})
		default:
			return
		}
	}
}

func main() {
	certFile := flag.String("cert", "", "certificate")
	keyFile := flag.String("key", "", "key")
	capture := flag.String("capture", "", "capture JSONL")
	flag.Parse()
	cert, e := tls.LoadX509KeyPair(*certFile, *keyFile)
	if e != nil {
		log.Fatal(e)
	}
	file, e := os.Create(*capture)
	if e != nil {
		log.Fatal(e)
	}
	defer file.Close()
	out := &sink{file: file}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	listen := func() net.Listener {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			log.Fatal(e)
		}
		return l
	}
	plain, tlsListener, h1, echo := listen(), listen(), listen(), listen()
	port := func(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }
	var ids atomic.Uint64
	var responses atomic.Uint64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, e := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024+1))
		if e != nil {
			return
		}
		if len(body) > 16*1024*1024 {
			http.Error(w, "too large", 413)
			return
		}
		w.Header().Set("Alt-Svc", fmt.Sprintf("h3=\":%d\"; ma=60", port(tlsListener)))
		w.Header().Set("X-Protocol", r.Proto)
		w.Header().Set("X-Method", r.Method)
		if o, ok := r.Context().Value(observationKey{}).(*observation); ok {
			out.emit(map[string]any{"kind": "request", "connection": o.id, "path": r.URL.Path, "protocol": r.Proto, "alpn": o.alpn,
				"client_bytes": base64.StdEncoding.EncodeToString(o.raw.snapshot()), "http_bytes": base64.StdEncoding.EncodeToString(o.plain.snapshot()), "http2": h2Info(o.plain.snapshot())})
		}
		if r.URL.Path == "/ws-wait" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		if strings.HasPrefix(r.URL.Path, "/ws") {
			websocket(w, r, out)
			return
		}
		switch r.URL.Path {
		case "/cached":
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Header().Set("X-Fixture-Response", fmt.Sprint(responses.Add(1)))
			_, _ = w.Write(bytes.Repeat([]byte("cache"), 1024))
		case "/echo":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
		case "/redirect":
			w.Header().Set("Location", "/profile")
			w.WriteHeader(302)
		case "/redirect-cross":
			_, p, _ := net.SplitHostPort(r.Host)
			scheme := "http"
			if _, secure := r.Context().Value(observationKey{}).(*observation); secure {
				scheme = "https"
			}
			w.Header().Set("Location", scheme+"://127.0.0.1:"+p+"/profile")
			w.WriteHeader(302)
		case "/redirect-loop":
			w.Header().Set("Location", "/redirect-loop")
			w.WriteHeader(302)
		case "/cookie/set":
			w.Header().Add("Set-Cookie", "fixture=ok; Path=/; SameSite=Lax")
			_, _ = w.Write([]byte("set"))
		case "/cookie/get":
			_, _ = w.Write([]byte(r.Header.Get("Cookie")))
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			z := gzip.NewWriter(w)
			_, _ = z.Write([]byte("native decompression"))
			_ = z.Close()
		case "/stream":
			block := make([]byte, 8192)
			for i := 0; i < 64; i++ {
				for j := range block {
					block[j] = byte((i*len(block) + j) % 251)
				}
				if _, e := w.Write(block); e != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		case "/wait":
			select {
			case <-r.Context().Done():
				out.emit(map[string]any{"kind": "cancelled", "path": r.URL.Path})
			case <-time.After(2 * time.Second):
				_, _ = w.Write([]byte("late"))
			}
		case "/profile":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"protocol": r.Proto, "method": r.Method, "headers": r.Header, "host": r.Host})
		default:
			_, _ = w.Write([]byte("native origin"))
		}
	})
	go func() {
		s := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ConnContext: func(ctx context.Context, c net.Conn) context.Context { return ctx }}
		_ = s.Serve(plain)
	}()
	serve := func(l net.Listener, h2Allowed, rawEcho bool) {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				raw := track(c)
				id := ids.Add(1)
				cfg := tlsConfig.Clone()
				if !h2Allowed {
					cfg.NextProtos = []string{"http/1.1"}
				}
				secure := tls.Server(raw, cfg)
				_ = secure.SetDeadline(time.Now().Add(20 * time.Second))
				if e := secure.Handshake(); e != nil {
					out.emit(map[string]any{"kind": "tls-error", "connection": id, "error": e.Error(), "client_bytes": base64.StdEncoding.EncodeToString(raw.snapshot())})
					_ = secure.Close()
					return
				}
				alpn := secure.ConnectionState().NegotiatedProtocol
				out.emit(map[string]any{"kind": "tls", "connection": id, "alpn": alpn, "client_bytes": base64.StdEncoding.EncodeToString(raw.snapshot())})
				if rawEcho {
					_, _ = io.Copy(secure, secure)
					_ = secure.Close()
					return
				}
				p := track(secure)
				tc := &tlsTracked{tracked: p, tlsConn: secure}
				o := &observation{id: id, raw: raw, plain: p, alpn: alpn}
				ctx := context.WithValue(context.Background(), observationKey{}, o)
				if alpn == "h2" {
					s := &http2.Server{}
					s.ServeConn(tc, &http2.ServeConnOpts{Context: ctx, Handler: handler})
					_ = tc.Close()
				} else {
					s := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
					_ = s.Serve(&oneListener{c: tc, done: p.done})
				}
			}()
		}
	}
	go serve(tlsListener, true, false)
	go serve(h1, false, false)
	go serve(echo, false, true)
	udp, e := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port(tlsListener)))
	if e != nil {
		log.Fatal(e)
	}
	h3 := &http3.Server{Handler: handler, TLSConfig: tlsConfig.Clone(), IdleTimeout: 20 * time.Second}
	go func() {
		if e := h3.Serve(udp); e != nil {
			log.Print(e)
		}
	}()
	ready := map[string]any{"http_port": port(plain), "https_port": port(tlsListener), "h1_port": port(h1), "tls_port": port(echo)}
	security, stopSecurity, e := startSecurityFixtures(cert, out)
	if e != nil {
		log.Fatal(e)
	}
	defer stopSecurity()
	for name, value := range security {
		ready[name] = value
	}
	_ = json.NewEncoder(os.Stdout).Encode(ready)
	// stdin closing is also a clean stop signal for the parent test harness.
	_, _ = io.Copy(io.Discard, bufio.NewReader(os.Stdin))
	_ = h3.Close()
	_ = plain.Close()
	_ = tlsListener.Close()
	_ = h1.Close()
	_ = echo.Close()
}
