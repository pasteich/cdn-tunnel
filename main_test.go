package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// startEcho — локальный TCP-эхо-сервер (роль «интернета» за туннелем).
func startEcho(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

func newTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc("/t/connect", ts.handleConnect)
	mux.HandleFunc("/t/down", ts.handleDown)
	mux.HandleFunc("/t/up", ts.handleUp)
	mux.HandleFunc("/t/ups", ts.handleUpStream)
	mux.HandleFunc("/t/close", ts.handleClose)
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

// socksProxy поднимает локальный SOCKS-листенер поверх tc и возвращает адрес +
// функцию слива всех активных обработчиков (чтобы не гонять глобалы под race).
func socksProxy(t *testing.T, tc *tunnelClient) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); tc.handleSocks(c) }()
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); wg.Wait() }
}

func socksConnect(t *testing.T, proxyAddr, targetHost string, targetPort int) net.Conn {
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	c.Write([]byte{0x05, 0x01, 0x00})
	hs := make([]byte, 2)
	if _, err := io.ReadFull(c, hs); err != nil || hs[1] != 0x00 {
		t.Fatalf("socks greeting: %v %v", err, hs)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	req = append(req, targetHost...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(targetPort))
	req = append(req, pb[:]...)
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("socks connect reply: %v %v", err, rep)
	}
	return c
}

func splitAddr(t *testing.T, addr string) (string, int) {
	h, ps, _ := net.SplitHostPort(addr)
	var p int
	fmt.Sscanf(ps, "%d", &p)
	return h, p
}

func TestSocksE2E(t *testing.T) {
	st = &stats{}
	serverMethod = "both" // сервер принимает любой метод; не меняем его между кейсами
	echoHost, echoPort := splitAddr(t, startEcho(t))
	srv, hc := newTestServer(t)

	cases := []struct {
		name      string
		transport string
		method    string
		fastopen  bool
	}{
		{"chunked-post-fastopen", "chunked", "post", true},
		{"chunked-post", "chunked", "post", false},
		{"chunked-get", "chunked", "get", false},
		{"stream-fastopen", "stream", "post", true},
		{"stream", "stream", "post", false},
	}

	for _, ttc := range cases {
		t.Run(ttc.name, func(t *testing.T) {
			clientTransport, clientMethod, fastOpen = ttc.transport, ttc.method, ttc.fastopen
			tc := &tunnelClient{base: srv.URL, pool: []*http.Client{hc}}
			proxy, drain := socksProxy(t, tc)

			app := socksConnect(t, proxy, echoHost, echoPort)
			payload := []byte("сквозь-туннель-" + ttc.name)
			app.Write(payload)
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(bufio.NewReader(app), got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if string(got) != string(payload) {
				t.Fatalf("echo mismatch: got %q want %q", got, payload)
			}
			app.Close()
			drain() // дождаться завершения обработчиков перед сменой глобалов
			t.Logf("ok: %q", payload)
		})
	}
}

func TestBulkTransfer(t *testing.T) {
	st = &stats{}
	serverMethod = "both"
	echoHost, echoPort := splitAddr(t, startEcho(t))
	srv, hc := newTestServer(t)

	for _, tr := range []string{"chunked", "stream"} {
		t.Run(tr, func(t *testing.T) {
			clientTransport, clientMethod, fastOpen = tr, "post", true
			tc := &tunnelClient{base: srv.URL, pool: []*http.Client{hc}}
			proxy, drain := socksProxy(t, tc)

			app := socksConnect(t, proxy, echoHost, echoPort)
			const n = 4 << 20
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*31 + 7)
			}
			go func() { app.Write(src) }()
			got := make([]byte, n)
			if _, err := io.ReadFull(app, got); err != nil {
				t.Fatalf("[%s] read %d: %v", tr, n, err)
			}
			for i := range src {
				if got[i] != src[i] {
					t.Fatalf("[%s] mismatch at %d", tr, i)
				}
			}
			app.Close()
			drain()
			t.Logf("[%s] 4 MB прошло без искажений", tr)
		})
	}
}
