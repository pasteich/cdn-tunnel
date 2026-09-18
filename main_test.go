package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// TestUserLimit: сервер с лимитом -users пускает ровно N клиентов, следующему
// отвечает 429, а после /bye освободившийся слот достаётся новому клиенту.
func TestUserLimit(t *testing.T) {
	gate := newUserGate(2)
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc("/bye", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(gate.middleware(mux))
	defer srv.Close()

	gauge := ""
	hello := func(id string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hello", nil)
		req.Header.Set(clientHeader, id)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		gauge = resp.Header.Get(usersHeader) // «занято/лимит» для живого счётчика
		return resp.StatusCode
	}

	for _, id := range []string{"c1", "c2"} {
		if got := hello(id); got != http.StatusOK {
			t.Fatalf("клиент %s: статус %d, ожидался 200", id, got)
		}
	}
	// Повторные запросы уже пущенных клиентов слот не тратят.
	if got := hello("c1"); got != http.StatusOK {
		t.Fatalf("повторный запрос c1: статус %d, ожидался 200", got)
	}
	if got := hello("c3"); got != http.StatusTooManyRequests {
		t.Fatalf("третий клиент: статус %d, ожидался 429", got)
	}
	if gauge != "2/2" {
		t.Fatalf("заголовок %s = %q, ожидался \"2/2\"", usersHeader, gauge)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/bye", nil)
	req.Header.Set(clientHeader, "c2")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := hello("c3"); got != http.StatusOK {
		t.Fatalf("после освобождения слота: статус %d, ожидался 200", got)
	}
	if gauge != "2/2" {
		t.Fatalf("заголовок %s = %q после повторного захвата слота", usersHeader, gauge)
	}
}

// TestNoteUsers: клиент разбирает заголовок X-Tunnel-Users в счётчик.
func TestNoteUsers(t *testing.T) {
	usersMu.Lock()
	usersNow, usersLimit, usersKnown = 0, 0, false
	usersMu.Unlock()
	noteUsers("3/5")
	if n, lim := usersSnapshot(); n != 3 || lim != 5 {
		t.Fatalf("после \"3/5\" получили %d/%d", n, lim)
	}
	noteUsers("мусор")
	if n, lim := usersSnapshot(); n != 3 || lim != 5 {
		t.Fatalf("мусорный заголовок сбил счётчик: %d/%d", n, lim)
	}
}

// TestUserSeatExpires: слот протухшего клиента уходит следующему.
func TestUserSeatExpires(t *testing.T) {
	gate := newUserGate(1)
	if ok, _ := gate.admit("old", "старый", "1.2.3.4"); !ok {
		t.Fatal("первый клиент должен получить слот")
	}
	if ok, _ := gate.admit("new", "новый", "5.6.7.8"); ok {
		t.Fatal("второй клиент должен быть отклонён, пока слот занят")
	}
	gate.mu.Lock()
	gate.seats["old"].lastSeen = time.Now().Add(-seatTTL - time.Second)
	gate.mu.Unlock()
	if ok, _ := gate.admit("new", "новый", "5.6.7.8"); !ok {
		t.Fatal("после истечения seatTTL слот должен освободиться")
	}
}

// TestUserLimitE2E: два настоящих клиента против сервера с лимитом 1 —
// первый проходит рукопожатие и видит счётчик 1/1, второму сервер отказывает,
// после /bye первого слот достаётся второму.
func TestUserLimitE2E(t *testing.T) {
	st = &stats{}
	serverMethod = "both"
	clientMethod = "post"
	usersMu.Lock()
	usersNow, usersLimit, usersKnown = 0, 0, false
	usersMu.Unlock()

	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc("/bye", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/t/connect", ts.handleConnect)
	gate := newUserGate(1)
	srv := httptest.NewUnstartedServer(gate.middleware(mux))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	client := func(id string) *tunnelClient {
		hc := &http.Client{Transport: authRoundTripper{base: srv.Client().Transport, id: id}}
		return &tunnelClient{base: srv.URL, pool: []*http.Client{hc}}
	}
	a, b := client("клиент-A"), client("клиент-B")

	if err := a.hello(); err != nil {
		t.Fatalf("первый клиент не подключился: %v", err)
	}
	if n, lim := usersSnapshot(); n != 1 || lim != 1 {
		t.Fatalf("счётчик после первого клиента: %d/%d, ожидался 1/1", n, lim)
	}

	err := b.hello()
	if err == nil {
		t.Fatal("второй клиент подключился, хотя лимит 1")
	}
	if !strings.Contains(err.Error(), "максимальное число подключений") {
		t.Fatalf("ожидалась ошибка про лимит, получили: %v", err)
	}

	a.bye()
	if err := b.hello(); err != nil {
		t.Fatalf("после освобождения слота второй клиент не подключился: %v", err)
	}
	if n, lim := usersSnapshot(); n != 1 || lim != 1 {
		t.Fatalf("счётчик после смены клиента: %d/%d, ожидался 1/1", n, lim)
	}
}

// TestShareLinkRoundTrip: ссылка cdn:// разбирается обратно в те же параметры,
// в глаза не читается и не поддаётся простому base64-декоду.
func TestShareLinkRoundTrip(t *testing.T) {
	in := shareParams{
		IP: "198.51.100.10", Host: "cdn.example.org", Cred: "abc123.def456",
		Conns: 8, UDP: true, Method: "both", Transport: "chunked", Label: "дача",
	}
	link := encodeShare(in)
	if !strings.HasPrefix(link, shareScheme) {
		t.Fatalf("ссылка без схемы: %q", link)
	}
	if strings.Contains(link, "cdn.example.org") || strings.Contains(link, "abc123") {
		t.Fatalf("ссылка читается глазами: %q", link)
	}
	body := strings.TrimPrefix(link, shareScheme)
	if raw, err := base64.RawURLEncoding.DecodeString(body); err == nil {
		if strings.Contains(string(raw), "cdn.example.org") {
			t.Fatal("содержимое ссылки не зашифровано — видно после base64-декода")
		}
	}
	out, err := decodeShare(link)
	if err != nil {
		t.Fatalf("разбор ссылки: %v", err)
	}
	if out != in {
		t.Fatalf("параметры не совпали:\n получили %+v\n ожидали  %+v", out, in)
	}
	// Ссылка с подписью после # и с мусорным хвостом.
	if _, err := decodeShare(link + "#дача"); err != nil {
		t.Fatalf("ссылка с подписью не разобрана: %v", err)
	}
	if _, err := decodeShare(link + "X"); err == nil {
		t.Fatal("испорченная ссылка принята")
	}
	if _, err := decodeShare("cdn://не-ссылка"); err == nil {
		t.Fatal("мусор принят за ссылку")
	}
}

// TestRosterOnlineOffline: сервер помнит клиентов по имени и показывает, кто
// сейчас онлайн, а кто уже отключился.
func TestRosterOnlineOffline(t *testing.T) {
	st = &stats{}
	gate := newUserGate(0) // без лимита — учёт всё равно ведётся
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc(usersPath, gate.handleUsers)
	mux.HandleFunc("/bye", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(gate.middleware(mux))
	defer srv.Close()

	call := func(path, name string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, nil)
		req.Header.Set(clientHeader, "id-"+name)
		req.Header.Set(nameHeader, url.QueryEscape(name))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for _, n := range []string{"Дмитрий", "Артём"} {
		resp := call("/hello", n)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	resp := call("/bye", "Артём")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	resp = call(usersPath, "Дмитрий")
	var d usersDoc
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("список пользователей не разобран: %v (%s)", err, body)
	}
	if d.Online != 1 {
		t.Fatalf("онлайн %d, ожидался 1: %s", d.Online, body)
	}
	got := map[string]bool{}
	for _, u := range d.Users {
		got[u.Name] = u.Online
	}
	if !got["Дмитрий"] {
		t.Fatalf("Дмитрий должен быть онлайн: %s", body)
	}
	if online, ok := got["Артём"]; !ok || online {
		t.Fatalf("Артём должен остаться в списке как офлайн: %s", body)
	}
}

// TestLinkCred: удостоверение ссылки проверяется мастер-секретом сервера и не
// принимается чужим секретом.
func TestLinkCred(t *testing.T) {
	cred := issueCred("мастер-пароль")
	id, ok := checkCred("мастер-пароль", cred)
	if !ok || id == "" {
		t.Fatalf("своё удостоверение не принято: %q", cred)
	}
	if _, ok := checkCred("другой-пароль", cred); ok {
		t.Fatal("удостоверение принято чужим секретом")
	}
	if _, ok := checkCred("мастер-пароль", id+".00000000000000000000000000000000"); ok {
		t.Fatal("подделанная подпись принята")
	}
	if c := issueCred(""); c != "" {
		t.Fatalf("сервер без пароля не должен выдавать удостоверения: %q", c)
	}
}

// TestLinkBoundToDevice: ссылка закрепляется за первым устройством, второму
// сервер отвечает 409 «уже использована», а своему устройству — как обычно.
func TestLinkBoundToDevice(t *testing.T) {
	st = &stats{}
	authToken = "мастер"
	defer func() { authToken = "" }()
	cred := issueCred(authToken)

	gate := newUserGate(0)
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	srv := httptest.NewServer(authMiddleware(gate.middleware(mux)))
	defer srv.Close()

	call := func(cred, device, name string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hello", nil)
		req.Header.Set(linkHeader, cred)
		req.Header.Set(deviceHeader, device)
		req.Header.Set(nameHeader, url.QueryEscape(name))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := call(cred, "устройство-1", "Андрей"); got != http.StatusOK {
		t.Fatalf("первое устройство: статус %d, ожидался 200", got)
	}
	if got := call(cred, "устройство-2", "Артём"); got != http.StatusConflict {
		t.Fatalf("чужое устройство: статус %d, ожидался 409", got)
	}
	if got := call(cred, "устройство-1", "Андрей"); got != http.StatusOK {
		t.Fatalf("своё устройство после отказа чужому: статус %d, ожидался 200", got)
	}
	// Другая ссылка того же сервера привязывается к своему устройству свободно.
	if got := call(issueCred(authToken), "устройство-2", "Артём"); got != http.StatusOK {
		t.Fatalf("новая ссылка на втором устройстве: статус %d, ожидался 200", got)
	}
	// Подделка не проходит проверку подписи вовсе.
	if got := call("deadbeef.00000000000000000000000000000000", "устройство-3", "Чужой"); got != http.StatusForbidden {
		t.Fatalf("поддельная ссылка: статус %d, ожидался 403", got)
	}
}

// TestAdminActions: бан, кик, снятие привязки и смена лимита на ходу — и всё
// это только с мастер-паролем.
func TestAdminActions(t *testing.T) {
	st = &stats{}
	authToken = "мастер"
	defer func() { authToken = "" }()

	gate := newUserGate(2)
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}, gate: gate}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc(usersPath, gate.handleUsers)
	gate.routeAdmin(mux, ts)
	srv := httptest.NewServer(authMiddleware(gate.middleware(mux)))
	defer srv.Close()

	hello := func(name string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hello", nil)
		req.Header.Set(authHeader, authToken)
		req.Header.Set(nameHeader, url.QueryEscape(name))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	admin := func(path string, withPass bool) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if withPass {
			req.Header.Set(authHeader, authToken)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	if got := hello("Дмитрий"); got != http.StatusOK {
		t.Fatalf("hello: %d", got)
	}
	if code, _ := admin(adminPath, false); code != http.StatusForbidden {
		t.Fatalf("админка без пароля: %d, ожидался 403", code)
	}
	code, body := admin(adminPath, true)
	if code != http.StatusOK || !strings.Contains(body, "Дмитрий") {
		t.Fatalf("снимок админки: %d %s", code, body)
	}
	if _, b := admin(adminPath+"/ban?name="+url.QueryEscape("Дмитрий"), true); !strings.Contains(b, `"ok":true`) {
		t.Fatalf("бан не применился: %s", b)
	}
	if got := hello("Дмитрий"); got != http.StatusForbidden {
		t.Fatalf("забаненный клиент: %d, ожидался 403", got)
	}
	if _, b := admin(adminPath+"/unban?name="+url.QueryEscape("Дмитрий"), true); !strings.Contains(b, `"ok":true`) {
		t.Fatalf("разбан не применился: %s", b)
	}
	if got := hello("Дмитрий"); got != http.StatusOK {
		t.Fatalf("после разбана: %d, ожидался 200", got)
	}
	if _, b := admin(adminPath+"/limit?n=7", true); !strings.Contains(b, `"limit":7`) {
		t.Fatalf("лимит не сменился: %s", b)
	}
	if g := gate.gauge(); !strings.HasSuffix(g, "/7") {
		t.Fatalf("счётчик показывает %q, ожидался лимит 7", g)
	}
	if _, b := admin(adminPath+"/forget?name="+url.QueryEscape("Дмитрий"), true); !strings.Contains(b, `"ok":true`) {
		t.Fatalf("forget не сработал: %s", b)
	}
}

// TestLinkRegistry: ссылки выпускает сервер — они видны в админке ещё до
// использования, привязываются к устройству, отзываются и возвращаются.
func TestLinkRegistry(t *testing.T) {
	st = &stats{}
	authToken = "мастер"
	defer func() { authToken = "" }()

	gate := newUserGate(0)
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}, gate: gate}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	gate.routeAdmin(mux, ts)
	srv := httptest.NewServer(authMiddleware(gate.middleware(mux)))
	defer srv.Close()

	adminJSON := func(path string) map[string]any {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set(authHeader, authToken)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return m
	}
	hello := func(cred, device string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hello", nil)
		req.Header.Set(linkHeader, cred)
		req.Header.Set(deviceHeader, device)
		req.Header.Set(nameHeader, url.QueryEscape("Андрей"))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	made := adminJSON("/admin/link/new?label=" + url.QueryEscape("Андрею"))
	id, _ := made["id"].(string)
	cred, _ := made["cred"].(string)
	if id == "" || cred == "" {
		t.Fatalf("сервер не выпустил ссылку: %v", made)
	}

	// Ещё не использованная ссылка уже видна владельцу.
	doc := adminJSON(adminPath)
	links, _ := doc["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("в реестре %d ссылок, ожидалась 1: %v", len(links), doc["links"])
	}
	first, _ := links[0].(map[string]any)
	if first["label"] != "Андрею" || first["device"] != nil {
		t.Fatalf("неожиданная запись о ссылке: %v", first)
	}

	if got := hello(cred, "телефон-андрея"); got != http.StatusOK {
		t.Fatalf("первое устройство: %d", got)
	}
	if got := hello(cred, "чужой-телефон"); got != http.StatusConflict {
		t.Fatalf("чужое устройство: %d, ожидался 409", got)
	}

	// Отзыв — клиент больше не заходит; возврат — снова заходит.
	adminJSON("/admin/link/revoke?id=" + id)
	if got := hello(cred, "телефон-андрея"); got != http.StatusForbidden {
		t.Fatalf("после отзыва: %d, ожидался 403", got)
	}
	adminJSON("/admin/link/restore?id=" + id)
	if got := hello(cred, "телефон-андрея"); got != http.StatusOK {
		t.Fatalf("после возврата: %d, ожидался 200", got)
	}

	// Отвязали — можно зайти с другого устройства.
	adminJSON("/admin/link/unbind?id=" + id)
	if got := hello(cred, "новый-телефон"); got != http.StatusOK {
		t.Fatalf("после отвязки: %d, ожидался 200", got)
	}

	// Удаление убирает запись целиком, но ссылка заново регистрируется при
	// использовании — и это видно владельцу.
	adminJSON("/admin/link/delete?id=" + id)
	doc = adminJSON(adminPath)
	if links, _ := doc["links"].([]any); len(links) != 0 {
		t.Fatalf("после удаления в реестре %d ссылок", len(links))
	}
}

// TestUsersEndpointHidesTraffic: клиентам туннеля видно, кто онлайн, но не
// чужой трафик и адреса — это только для владельца в /admin.
func TestUsersEndpointHidesTraffic(t *testing.T) {
	st = &stats{}
	gate := newUserGate(0)
	gate.roster["Андрей"] = &rosterEntry{Name: "Андрей", Up: 1000, Down: 2000, Last: time.Now().Unix()}
	mux := http.NewServeMux()
	mux.HandleFunc(usersPath, gate.handleUsers)
	srv := httptest.NewServer(gate.middleware(mux))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + usersPath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "1000") || strings.Contains(string(body), "2000") {
		t.Fatalf("/users отдаёт чужой трафик: %s", body)
	}
	if !strings.Contains(string(body), "Андрей") {
		t.Fatalf("/users не показывает состав: %s", body)
	}
}
