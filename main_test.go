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
	"os"
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

// ---- доступ по ссылке ----
//
// Ниже проверяется главное свойство новой модели: пускает не подпись, а запись
// в реестре. Ссылка без записи (удалённая владельцем) мертва навсегда, сколько
// бы раз клиент ни переподключался.

// linkServer поднимает сервер с реестром и возвращает его вместе с gate.
func linkServer(t *testing.T) (*httptest.Server, *linkGate) {
	t.Helper()
	st = &stats{}
	gate := newLinkGate()
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}, gate: gate}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc("/bye", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	gate.routeAdmin(mux, ts)
	srv := httptest.NewServer(gate.middleware(mux))
	t.Cleanup(srv.Close)
	return srv, gate
}

// hello стучится в сервер удостоверением ссылки с заданного устройства.
func hello(t *testing.T, srv *httptest.Server, cred, device string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hello", nil)
	req.Header.Set(linkHeader, cred)
	req.Header.Set(deviceHeader, device)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// adminCall зовёт ручку панели мастер-ключом (или без него, если pass=false).
func adminCall(t *testing.T, srv *httptest.Server, path string, pass bool) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if pass {
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

// newLink выпускает ссылку через панель и возвращает её id и удостоверение.
func newLink(t *testing.T, srv *httptest.Server, label string) (id, cred string) {
	t.Helper()
	_, body := adminCall(t, srv, adminPath+"/link/new?label="+url.QueryEscape(label), true)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("link/new: %v (%s)", err, body)
	}
	id, _ = m["id"].(string)
	cred, _ = m["cred"].(string)
	if id == "" || cred == "" {
		t.Fatalf("сервер не выпустил ссылку: %s", body)
	}
	return id, cred
}

// TestLinkRegistryIsAuthoritative: реестр — последнее слово. Подписанная, но
// не зарегистрированная ссылка не пускает, и «вне админки» из неё не заводится.
func TestLinkRegistryIsAuthoritative(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, gate := linkServer(t)

	// Удостоверение с верной подписью, но выпущенное мимо реестра (-share).
	stray := issueCred(authToken)
	if got := hello(t, srv, stray, "чужой-телефон"); got != http.StatusForbidden {
		t.Fatalf("незарегистрированная ссылка: статус %d, ожидался 403", got)
	}
	if n := len(gate.links); n != 0 {
		t.Fatalf("в реестре завелось %d записей — ссылка не должна регистрироваться сама", n)
	}

	// Подделка с неверной подписью — тоже мимо.
	if got := hello(t, srv, "deadbeef.00000000000000000000000000000000", "х"); got != http.StatusForbidden {
		t.Fatalf("поддельная ссылка: статус %d, ожидался 403", got)
	}
}

// TestDeletedLinkStaysDead: ссылка, удалённая владельцем в панели, не пускает
// ни сразу, ни после переподключения, и обратно в реестре не появляется.
func TestDeletedLinkStaysDead(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, gate := linkServer(t)

	id, cred := newLink(t, srv, "Андрею")
	if got := hello(t, srv, cred, "телефон-андрея"); got != http.StatusOK {
		t.Fatalf("свежая ссылка: статус %d, ожидался 200", got)
	}

	adminCall(t, srv, adminPath+"/link/delete?id="+id, true)

	// Клиент ретраится — и получает отказ на каждой попытке.
	for i := 0; i < 3; i++ {
		if got := hello(t, srv, cred, "телефон-андрея"); got != http.StatusForbidden {
			t.Fatalf("попытка %d после удаления: статус %d, ожидался 403", i+1, got)
		}
	}
	if n := len(gate.links); n != 0 {
		t.Fatalf("удалённая ссылка вернулась в реестр (%d записей)", n)
	}
	// И на линии её больше нет.
	if n := len(gate.live); n != 0 {
		t.Fatalf("удалённая ссылка осталась на линии (%d)", n)
	}
	_, body := adminCall(t, srv, adminPath, true)
	if strings.Contains(body, "вне админки") {
		t.Fatalf("в панели появилась ссылка «вне админки»: %s", body)
	}
}

// TestLinkRevokeRestore: отзыв закрывает доступ, возврат открывает снова, а
// счётчики и запись при этом никуда не деваются.
func TestLinkRevokeRestore(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, _ := linkServer(t)

	id, cred := newLink(t, srv, "Андрею")
	if got := hello(t, srv, cred, "телефон"); got != http.StatusOK {
		t.Fatalf("до отзыва: %d", got)
	}
	adminCall(t, srv, adminPath+"/link/revoke?id="+id, true)
	if got := hello(t, srv, cred, "телефон"); got != http.StatusForbidden {
		t.Fatalf("после отзыва: %d, ожидался 403", got)
	}
	adminCall(t, srv, adminPath+"/link/restore?id="+id, true)
	if got := hello(t, srv, cred, "телефон"); got != http.StatusOK {
		t.Fatalf("после возврата: %d, ожидался 200", got)
	}
}

// TestLinkBoundToOneDevice: ссылка работает на одном устройстве; «Отвязать»
// освобождает её для другого.
func TestLinkBoundToOneDevice(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, _ := linkServer(t)

	id, cred := newLink(t, srv, "Андрею")
	if got := hello(t, srv, cred, "телефон-1"); got != http.StatusOK {
		t.Fatalf("первое устройство: %d", got)
	}
	if got := hello(t, srv, cred, "телефон-2"); got != http.StatusConflict {
		t.Fatalf("второе устройство: %d, ожидался 409", got)
	}
	if got := hello(t, srv, cred, "телефон-1"); got != http.StatusOK {
		t.Fatalf("своё устройство после отказа чужому: %d", got)
	}

	adminCall(t, srv, adminPath+"/link/unbind?id="+id, true)
	if got := hello(t, srv, cred, "телефон-2"); got != http.StatusOK {
		t.Fatalf("после отвязки: %d, ожидался 200", got)
	}

	// Вторая ссылка привязывается к своему устройству независимо от первой.
	_, cred2 := newLink(t, srv, "Артёму")
	if got := hello(t, srv, cred2, "телефон-3"); got != http.StatusOK {
		t.Fatalf("вторая ссылка: %d", got)
	}
}

// TestAdminNeedsMasterKey: панель открывается только мастер-ключом — ссылкой,
// даже совершенно рабочей, в неё не войти.
func TestAdminNeedsMasterKey(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, _ := linkServer(t)
	_, cred := newLink(t, srv, "Андрею")

	if code, _ := adminCall(t, srv, adminPath, false); code != http.StatusForbidden {
		t.Fatalf("панель без ключа: %d, ожидался 403", code)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+adminPath, nil)
	req.Header.Set(linkHeader, cred)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("панель по ссылке: %d, ожидался 403", resp.StatusCode)
	}
	if code, body := adminCall(t, srv, adminPath, true); code != http.StatusOK || !strings.Contains(body, "Андрею") {
		t.Fatalf("панель с ключом: %d %s", code, body)
	}
}

// TestOwnerUsesMasterKey: владелец подключается напрямую мастер-ключом, без
// ссылки и без привязки к устройству.
func TestOwnerUsesMasterKey(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, gate := linkServer(t)

	call := func(key string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hello", nil)
		req.Header.Set(authHeader, key)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := call("мастер"); got != http.StatusOK {
		t.Fatalf("владелец: %d", got)
	}
	if got := call("не-мастер"); got != http.StatusForbidden {
		t.Fatalf("неверный ключ: %d, ожидался 403", got)
	}
	// Владелец на линии есть, но ссылкой не притворяется.
	if _, ok := gate.live[ownerKey]; !ok {
		t.Fatal("владелец не учтён на линии")
	}
	if n := len(gate.links); n != 0 {
		t.Fatalf("вход владельца завёл %d ссылок", n)
	}
}

// TestLinkGoesOfflineOnBye: /bye снимает ссылку с линии сразу, не дожидаясь
// linkTTL, — панель не показывает ушедшего клиента как онлайн.
func TestLinkGoesOfflineOnBye(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, gate := linkServer(t)

	id, cred := newLink(t, srv, "Андрею")
	hello(t, srv, cred, "телефон")
	if _, ok := gate.live[id]; !ok {
		t.Fatal("ссылка не появилась на линии")
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/bye", nil)
	req.Header.Set(linkHeader, cred)
	req.Header.Set(deviceHeader, "телефон")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, ok := gate.live[id]; ok {
		t.Fatal("после /bye ссылка осталась на линии")
	}
}

// TestLinkExpires: замолчавшая ссылка уходит с линии сама через linkTTL.
func TestLinkExpires(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, gate := linkServer(t)

	id, cred := newLink(t, srv, "Андрею")
	hello(t, srv, cred, "телефон")

	gate.mu.Lock()
	gate.live[id].last = time.Now().Add(-linkTTL - time.Second)
	gate.mu.Unlock()

	gate.mu.Lock()
	gate.expireLocked(time.Now())
	_, still := gate.live[id]
	gate.mu.Unlock()
	if still {
		t.Fatal("протухшая ссылка осталась на линии")
	}
}

// TestLinkTrafficAccounting: трафик пишется на ту ссылку, по которой шёл, и
// переживает перезапуск через файл реестра.
func TestLinkTrafficAccounting(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, gate := linkServer(t)

	id, cred := newLink(t, srv, "Андрею")
	hello(t, srv, cred, "телефон")
	gate.addTraffic(id, 1000, 2000)
	gate.addTraffic(ownerKey, 500, 500) // трафик владельца ссылке не приписывается

	dir := t.TempDir()
	gate.mu.Lock()
	gate.path = dir + "/links.json"
	gate.saveLocked()
	gate.mu.Unlock()

	restored := newLinkGate()
	restored.loadLinks(dir + "/links.json")
	rec := restored.links[id]
	if rec == nil {
		t.Fatal("ссылка не пережила перезапуск")
	}
	if rec.Up != 1000 || rec.Down != 2000 {
		t.Fatalf("счётчики после перезапуска: ↑%d ↓%d, ожидалось ↑1000 ↓2000", rec.Up, rec.Down)
	}
	if rec.Device != "телефон" {
		t.Fatalf("привязка не сохранилась: %q", rec.Device)
	}
}

// TestDenyReason: клиент правильно переводит отказ сервера в STATUS-строку —
// по ней Android-обёртка решает, гасить ли VPN и что показать человеку.
func TestDenyReason(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		body   string
		cred   string // непустой — клиент подключается по ссылке
		status string
		bad    bool
	}{
		{"удалённая ссылка", http.StatusForbidden, denyUnknown, "id.mac", "linkgone", true},
		{"отозванная ссылка", http.StatusForbidden, denyRevoked, "id.mac", "linkrevoked", true},
		{"занятая ссылка", http.StatusConflict, denyUsed, "id.mac", "linkused", true},
		{"чужой сервер", http.StatusForbidden, denyForbidden, "id.mac", "linkbad", true},
		{"неверный мастер-ключ", http.StatusForbidden, denyForbidden, "", "authfail", true},
		{"всё в порядке", http.StatusOK, "hello", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			linkCred = c.cred
			defer func() { linkCred = "" }()
			got, bad := denyReason(c.code, c.body)
			if bad != c.bad {
				t.Fatalf("отказ=%v, ожидался %v", bad, c.bad)
			}
			if bad && got.status != c.status {
				t.Fatalf("STATUS %q, ожидался %q", got.status, c.status)
			}
			if bad && got.text == "" {
				t.Fatal("человеку нечего показать: текст пуст")
			}
		})
	}
}

// TestLegacyRegistryMigrates: реестр от сервера 1.x (users.json рядом)
// подхватывается один раз — уже выданные друзьям ссылки продолжают работать,
// но удалённая потом ссылка обратно не воскресает.
func TestLegacyRegistryMigrates(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"users":[{"name":"Андрей","up":10,"down":20}],` +
		`"links":[{"id":"abc123","label":"Андрею","device":"телефон","up":1000,"down":2000}]}`
	if err := os.WriteFile(dir+"/users.json", []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	// Пустой новый файл — ровно то, что оставляет openState при первом запуске.
	if err := os.WriteFile(dir+"/links.json", nil, 0o600); err != nil {
		t.Fatal(err)
	}

	g := newLinkGate()
	g.loadLinks(dir + "/links.json")
	rec := g.links["abc123"]
	if rec == nil {
		t.Fatal("ссылка из старого реестра потерялась")
	}
	if rec.Label != "Андрею" || rec.Device != "телефон" || rec.Up != 1000 {
		t.Fatalf("запись перенеслась неполно: %+v", rec)
	}
	nb, err := os.ReadFile(dir + "/links.json")
	if err != nil || !strings.Contains(string(nb), "abc123") {
		t.Fatalf("перенос не закреплён в новом файле: %v (%s)", err, nb)
	}
	// Старый файл отработал и больше не читается.
	if _, err := os.Stat(dir + "/users.json"); !os.IsNotExist(err) {
		t.Fatalf("старый реестр остался на месте: %v", err)
	}

	// Владелец удалил ссылку — после перезапуска она не должна воскреснуть.
	g2 := newLinkGate()
	g2.loadLinks(dir + "/links.json")
	if !g2.deleteLink("abc123") {
		t.Fatal("ссылка не удалилась")
	}
	g3 := newLinkGate()
	g3.loadLinks(dir + "/links.json")
	if g3.links["abc123"] != nil {
		t.Fatal("удалённая ссылка воскресла из старого реестра")
	}
}

// TestLegacyMigrationKeepsExisting: если новый реестр уже наполнен, перенос
// ничего не ломает и не дублирует.
func TestLegacyMigrationKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/users.json",
		[]byte(`{"links":[{"id":"old1","label":"старая"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/links.json",
		[]byte(`{"links":[{"id":"new1","label":"новая"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	g := newLinkGate()
	g.loadLinks(dir + "/links.json")
	if g.links["new1"] == nil || g.links["old1"] == nil {
		t.Fatalf("после переноса в реестре %d записей, ожидалось 2", len(g.links))
	}
}
