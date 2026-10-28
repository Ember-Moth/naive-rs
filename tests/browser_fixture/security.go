package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/sagernet/quic-go/http3"
	"golang.org/x/net/http2"
)

// Only the public ECHConfigList is returned to the test process. The private
// HPKE key remains in this ephemeral loopback server.
func newECHKey(id byte) (tls.EncryptedClientHelloKey, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, "", err
	}
	contents := []byte{id}
	contents = binary.BigEndian.AppendUint16(contents, 0x0020) // X25519
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(key.PublicKey().Bytes())))
	contents = append(contents, key.PublicKey().Bytes()...)
	contents = binary.BigEndian.AppendUint16(contents, 4)
	contents = binary.BigEndian.AppendUint16(contents, 1) // HKDF-SHA256
	contents = binary.BigEndian.AppendUint16(contents, 1) // AES-128-GCM
	contents = append(contents, 0)                        // maximum_name_length
	publicName := "public.ech.test"
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // extensions
	config := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)
	return tls.EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}, hex.EncodeToString(list), nil
}

func startSecurityFixtures(cert tls.Certificate, out *sink) (map[string]any, func(), error) {
	key, configList, err := newECHKey(1)
	if err != nil {
		return nil, nil, err
	}
	_, staleList, err := newECHKey(2)
	if err != nil {
		return nil, nil, err
	}
	var listeners []net.Listener
	cleanup := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}
	listen := func() (net.Listener, error) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			listeners = append(listeners, l)
		}
		return l, err
	}
	for len(listeners) < 4 {
		if _, err = listen(); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	httpsListener, h1Listener, rawListener, clearListener := listeners[0], listeners[1], listeners[2], listeners[3]
	port := func(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }
	base := &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		NextProtos:               []string{"h2", "http/1.1"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
		VerifyConnection: func(state tls.ConnectionState) error {
			out.emit(map[string]any{"kind": "security-tls", "ech_accepted": state.ECHAccepted,
				"server_name": state.ServerName, "alpn": state.NegotiatedProtocol})
			return nil
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		accepted := r.TLS != nil && r.TLS.ECHAccepted
		w.Header().Set("X-Ech-Accepted", strconv.FormatBool(accepted))
		if r.Method == "CONNECT" {
			if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
				w.Header().Set("Proxy-Authenticate", `Basic realm="fixture"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			// Echo the framed stream byte-for-byte. This exercises the client's
			// CONNECT and padding path without dialing any external target.
			w.Header().Set("padding", "fixture")
			w.WriteHeader(http.StatusOK)
			flusher := w.(http.Flusher)
			flusher.Flush()
			buffer := make([]byte, 32*1024)
			for {
				n, err := r.Body.Read(buffer)
				if n > 0 {
					if _, err := w.Write(buffer[:n]); err != nil {
						return
					}
					flusher.Flush()
				}
				if err != nil {
					return
				}
			}
		}
		if r.URL.Path == "/ws" {
			websocket(w, r, out)
			return
		}
		if r.URL.Path == "/redirect-other" {
			_, p, _ := net.SplitHostPort(r.Host)
			w.Header().Set("Location", "https://other.ech.test:"+p+"/ech")
			w.WriteHeader(http.StatusFound)
			return
		}
		name := ""
		if r.TLS != nil {
			name = r.TLS.ServerName
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ech_accepted": accepted, "server_name": name, "protocol": r.Proto})
	})
	var servers []*http.Server
	serveHTTP := func(l net.Listener, ech, h2 bool) error {
		config := base.Clone()
		if !ech {
			config.EncryptedClientHelloKeys = nil
		}
		s := &http.Server{Handler: handler, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
		if h2 {
			if err := http2.ConfigureServer(s, &http2.Server{}); err != nil {
				return err
			}
		} else {
			s.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
			s.TLSConfig.NextProtos = []string{"http/1.1"}
		}
		servers = append(servers, s)
		go func() { _ = s.ServeTLS(l, "", "") }()
		return nil
	}
	for _, entry := range []struct {
		l       net.Listener
		ech, h2 bool
	}{
		{httpsListener, true, true}, {h1Listener, true, false}, {clearListener, false, true},
	} {
		if err := serveHTTP(entry.l, entry.ech, entry.h2); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	go func() {
		for {
			c, err := rawListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				config := base.Clone()
				config.NextProtos = []string{"http/1.1"}
				secure := tls.Server(c, config)
				if secure.Handshake() != nil {
					return
				}
				_, _ = io.Copy(secure, secure)
			}()
		}
	}()
	udp, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port(httpsListener)))
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	h3 := &http3.Server{Handler: handler, TLSConfig: base.Clone(), IdleTimeout: 10 * time.Second}
	go func() { _ = h3.Serve(udp) }()
	return map[string]any{
		"ech_config": configList, "ech_stale_config": staleList,
		"ech_https_port": port(httpsListener), "ech_h1_port": port(h1Listener),
		"ech_tls_port": port(rawListener), "no_ech_port": port(clearListener),
	}, func() {
		_ = h3.Close()
		_ = udp.Close()
		for _, s := range servers {
			_ = s.Close()
		}
		cleanup()
	}, nil
}
