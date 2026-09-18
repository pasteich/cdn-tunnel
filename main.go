package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Туннель TCP/UDP-трафика через CDN одним файлом.
//
//	origin:  go run main.go -server
//	клиент:  go run main.go -client -ip <IP_CDN> -host <cdn.domain> -listen 127.0.0.1:8090
//
// Клиент поднимает локальный SOCKS5; трафик идёт через CDN, реальные коннекты
// делает сервер (исходящий IP = IP сервера). Транспорт: вниз — длинный chunked
// HTTP/2 поток, вверх — нумерованные POST'ы конвейером.
func main() {
	var (
		server    = flag.Bool("server", false, "режим origin-сервера туннеля")
		client    = flag.Bool("client", false, "режим локального SOCKS5-клиента")
		addr      = flag.String("addr", ":80", "адрес прослушивания сервера (режим -server)")
		listen    = flag.String("listen", "127.0.0.1:8090", "адрес локального SOCKS5 (режим -client)")
		ip        = flag.String("ip", "", "IP CDN (режим -client)")
		host      = flag.String("host", "", "Host/SNI для CDN (режим -client)")
		conns     = flag.Int("conns", 8, "число TCP-соединений к CDN (пул, убирает HoL-блокировку)")
		udp       = flag.Bool("udp", true, "включить UDP ASSOCIATE (DNS, QUIC и прочий UDP через туннель)")
		pass      = flag.String("password", "", "пароль доступа к туннелю (должен совпадать на -server и -client; пусто = без пароля)")
		stats     = flag.Bool("stats", false, "выводить машиночитаемую статистику построчно (STATS ...) вместо интерактивного HUD")
		method    = flag.String("method", "post", "метод передачи данных вверх (chunked): клиент — post|get; сервер — post|get|both")
		transport = flag.String("transport", "chunked", "транспорт апстрима: chunked (много запросов) | stream (один потоковый POST, ниже пинг; нужен CDN, пропускающий streaming request body)")
		fastopen  = flag.Bool("fastopen", true, "оптимистичный SOCKS-ответ до подтверждения connect (убирает 1 RTT на соединение)")
		window    = flag.Int("window", 32, "число одновременных up-запросов в полёте (chunked, режим post/get)")
		idle      = flag.Int("idle", 120, "таймаут простоя стрима на сервере в секундах (0 = не закрывать)")
		users     = flag.Int("users", 0, "максимум одновременно подключённых клиентов (режим -server; 0 = без лимита)")
		name      = flag.String("name", "", "имя клиента — под ним он виден в списке пользователей сервера")
		state     = flag.String("state", defaultStatePath, "файл со списком известных клиентов (режим -server; пусто = не сохранять)")
		link      = flag.String("link", "", "cdn://-ссылка с настройками подключения (режим -client; заменяет -ip/-host/-password/…)")
		device    = flag.String("device", "", "отпечаток устройства для привязки ссылки (по умолчанию определяется сам)")
		cred      = flag.String("cred", "", "удостоверение ссылки <id>.<подпись> (режим -client; альтернатива -password)")
		share     = flag.Bool("share", false, "напечатать cdn://-ссылку с текущими настройками и выйти")
	)
	flag.Parse()

	authToken = *pass
	plainStats = *stats
	fastOpen = *fastopen
	upWindow = *window
	if upWindow < 1 {
		upWindow = 1
	}
	idleTimeout = time.Duration(*idle) * time.Second
	if *users > 0 {
		maxUsers.Store(int64(*users))
	}
	clientName = cleanName(*name)
	statePath = *state
	if deviceID = strings.TrimSpace(*device); deviceID == "" {
		deviceID = localDeviceID()
	}
	linkCred = strings.TrimSpace(*cred)

	switch m := strings.ToLower(strings.TrimSpace(*method)); m {
	case "get":
		clientMethod, serverMethod = "get", "get"
	case "both":
		clientMethod, serverMethod = "post", "both" // both — только про приём на сервере
	default:
		clientMethod, serverMethod = "post", "post"
	}
	if strings.ToLower(strings.TrimSpace(*transport)) == "stream" {
		clientTransport = "stream"
	}

	// Ссылка cdn:// задаёт параметры подключения одним значением: то, что в ней
	// есть, перекрывает соответствующие флаги.
	if *link != "" {
		p, err := decodeShare(*link)
		if err != nil {
			fmt.Printf("✗ Ссылка не разобрана: %v\n", err)
			os.Exit(1)
		}
		p.applyTo(ip, host, pass, conns, udp, method, transport, &clientName)
		// Метод/транспорт из ссылки применяются уже после разбора флагов выше.
		switch strings.ToLower(strings.TrimSpace(*method)) {
		case "get":
			clientMethod, serverMethod = "get", "get"
		case "both":
			clientMethod, serverMethod = "post", "both"
		default:
			clientMethod, serverMethod = "post", "post"
		}
		clientTransport = "chunked"
		if strings.ToLower(strings.TrimSpace(*transport)) == "stream" {
			clientTransport = "stream"
		}
		authToken = *pass // у ссылок нового образца он пуст: доступ даёт linkCred
	}

	if *share {
		// В ссылку кладём не мастер-пароль, а выданное им удостоверение: оно
		// работает на одном устройстве и его не жалко отправить в мессенджер.
		fmt.Println(encodeShare(shareParams{
			IP: *ip, Host: *host, Cred: issueCred(*pass), Conns: *conns,
			UDP: *udp, Method: *method, Transport: *transport, Label: clientName,
		}))
		return
	}

	switch {
	case *server:
		runServer(*addr)
	case *client:
		runClient(*listen, *ip, *host, *conns, *udp)
	default:
		fmt.Println("укажите -server или -client")
		os.Exit(1)
	}
}

// authToken — общий секрет между клиентом и сервером. Клиент шлёт его в заголовке
// X-Tunnel-Auth на каждом запросе; сервер сверяет его в постоянное время. Пустой
// токен отключает проверку (обратная совместимость).
var authToken string

// maxUsers — сколько клиентов сервер обслуживает одновременно (-users).
// 0 — без ограничения. Меняется из админки на ходу, поэтому атомарный.
var maxUsers atomic.Int64

// clientName — имя клиента (-name). Едет на сервер в заголовке X-Tunnel-Name и
// служит ключом слота: один и тот же человек с разных запусков — один слот.
var clientName string

// linkCred — удостоверение ссылки ("<id>.<подпись>"), если клиент запущен по
// cdn://-ссылке. Едет в заголовке X-Tunnel-Link вместо мастер-пароля.
var linkCred string

// deviceID — отпечаток этого устройства: сервер привязывает к нему ссылку.
var deviceID string

// statePath — где сервер хранит список известных клиентов между перезапусками.
var statePath string

// defaultStatePath — файл состояния по умолчанию (создаётся при старте сервера;
// если каталог недоступен, сохранение просто выключается).
const defaultStatePath = "/var/lib/cdn-tunnel/users.json"

// clientID — случайный идентификатор этого запуска клиента; едет в заголовке
// X-Tunnel-Client на каждом запросе. По нему сервер считает «пользователей»:
// весь пул соединений и все стримы одного клиента занимают ровно один слот.
var clientID = randID()

// plainStats переключает вывод статистики в построчный машиночитаемый формат
// (для Android-обёртки), вместо интерактивной строки с \r.
var plainStats bool

// clientMethod — как клиент шлёт данные вверх ("post" — тело запроса, "get" —
// base64url в query). serverMethod — что принимает сервер ("post"|"get"|"both").
var (
	clientMethod = "post"
	serverMethod = "post"
)

// clientTransport — "chunked" (много up-запросов, совместимо с любым CDN) или
// "stream" (один длинный потоковый POST вверх — ниже пинг, меньше накладных, но
// требует CDN, который не буферизует тело запроса). Даун-поток всегда потоковый.
var clientTransport = "chunked"

// Тюнинг производительности.
var (
	fastOpen    = true              // оптимистичный connect (клиент)
	upWindow    = 32                // окно up-запросов в полёте (chunked)
	idleTimeout = 120 * time.Second // реап простаивающих стримов (сервер)
)

const authHeader = "X-Tunnel-Auth"

// clientHeader несёт идентификатор клиента (см. clientID) — единица учёта
// для лимита -users.
const clientHeader = "X-Tunnel-Client"

// usersHeader сервер ставит на каждый ответ: "онлайн/лимит" (например "2/5",
// лимит 0 — без ограничения). По нему клиент показывает счётчик в прямом эфире.
const usersHeader = "X-Tunnel-Users"

// nameHeader несёт имя клиента (-name) в percent-encoded виде — по нему сервер
// показывает клиента в списке пользователей.
const nameHeader = "X-Tunnel-Name"

// usersPath — ручка со списком пользователей (кто онлайн, кто офлайн).
const usersPath = "/users"

// linkHeader несёт удостоверение ссылки: "<id>.<подпись>". Подпись — HMAC от
// мастер-секрета сервера, поэтому сервер проверяет ссылку, ничего о ней заранее
// не зная, а сама ссылка мастер-пароль не содержит.
const linkHeader = "X-Tunnel-Link"

// deviceHeader несёт отпечаток устройства: к нему сервер привязывает ссылку при
// первом использовании, чтобы одной ссылкой не пользовались вдвоём.
const deviceHeader = "X-Tunnel-Device"

// Имена query-параметров для GET-режима (полезная нагрузка едет base64url в URL).
const (
	qData   = "d" // данные (up / udp send)
	qTarget = "t" // адрес назначения (connect)
	qToken  = "k" // токен (hello)
)

// methodAllowed сообщает, разрешён ли метод запроса текущей политикой сервера.
// Применяется только к «загрузочным»/управляющим ручкам; потоки вниз (/t/down,
// /u/down) всегда GET и под эту проверку не попадают.
func methodAllowed(r *http.Request) bool {
	switch serverMethod {
	case "get":
		return r.Method == http.MethodGet
	case "post":
		return r.Method == http.MethodPost
	default: // both
		return r.Method == http.MethodGet || r.Method == http.MethodPost
	}
}

// readPayload достаёт полезную нагрузку запроса: из query-параметра q
// (base64url) для GET-режима, иначе из тела запроса (POST-режим).
func readPayload(r *http.Request, q string) ([]byte, error) {
	if v := r.URL.Query().Get(q); v != "" {
		return base64.RawURLEncoding.DecodeString(v)
	}
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	return b, err
}

// helloToken — ответ должен быть "hello "+token, чтобы клиент убедился,
// что достучался именно до нашего сервера, а не до постороннего 200 от CDN.
const helloPrefix = "hello "

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// tuneConn настраивает TCP-сокет под низкую задержку и высокий BDP: без Nagle
// (мелкие интерактивные записи уходят сразу) и с увеличенными буферами.
func tuneConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(1 << 20)
		tc.SetWriteBuffer(1 << 20)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// ============================ СТАТИСТИКА / ДИСПЛЕЙ ============================

type stats struct {
	role      string
	conns     atomic.Int64 // активные соединения/стримы
	total     atomic.Int64 // всего соединений
	up        atomic.Uint64
	down      atomic.Uint64
	udpUp     atomic.Uint64
	udpDown   atomic.Uint64
	connected atomic.Bool
	rttMs     atomic.Int64 // последний измеренный RTT client↔CDN↔origin, мс
	users     atomic.Int64 // занятые слоты -users (сервер)
}

var st *stats

func human(b float64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.2f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.2f MB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1f KB", b/1e3)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}

// render рисует одну строку статуса, обновляя её на месте (без спама).
func (s *stats) render() {
	var lastUp, lastDown uint64
	last := time.Now()
	var lastQuiet time.Time
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		now := time.Now()
		dt := now.Sub(last).Seconds()
		up, down := s.up.Load(), s.down.Load()
		upRate := float64(up-lastUp) / dt
		downRate := float64(down-lastDown) / dt
		lastUp, lastDown, last = up, down, now

		// Машиночитаемый режим: одна строка в секунду, без ANSI и \r —
		// Android-обёртка парсит её для счётчика трафика.
		if plainStats {
			users, limit := s.users.Load(), maxUsers.Load()
			if s.role == "client" {
				n, lim := usersSnapshot()
				users, limit = int64(n), int64(lim)
			}
			fmt.Printf("STATS down=%d up=%d udpDown=%d udpUp=%d conns=%d total=%d downRate=%.0f upRate=%.0f rtt=%d users=%d maxusers=%d\n",
				down, up, s.udpDown.Load(), s.udpUp.Load(),
				s.conns.Load(), s.total.Load(), downRate, upRate, s.rttMs.Load(),
				users, limit)
			continue
		}

		// Под systemd/journald перерисовывать строку через \r нечем — там это
		// просто мусор в логе. Пишем короткую сводку раз в минуту.
		if !stdoutTTY {
			if now.Sub(lastQuiet) < time.Minute {
				continue
			}
			lastQuiet = now
			fmt.Printf("сводка: онлайн %d, стримов %d (всего %d) · ↓ %s (%s/s) · ↑ %s (%s/s)\n",
				s.users.Load(), s.conns.Load(), s.total.Load(),
				human(float64(down)), human(downRate), human(float64(up)), human(upRate))
			continue
		}

		dot := "\033[32m●\033[0m"
		state := "online"
		if s.role == "server" {
			state = "serving"
		}
		if !s.connected.Load() {
			dot = "\033[33m●\033[0m"
			state = "waiting"
		}
		label := "conns"
		if s.role == "server" {
			label = "streams"
		}
		rtt := ""
		if r := s.rttMs.Load(); r > 0 {
			rtt = fmt.Sprintf(" │ rtt %dms", r)
		}
		if lim := maxUsers.Load(); s.role == "server" && lim > 0 {
			rtt += fmt.Sprintf(" │ users %d/%d", s.users.Load(), lim)
		}
		line := fmt.Sprintf("%s %s │ %s %d (Σ%d) │ ↓ %s (%s/s) │ ↑ %s (%s/s) │ udp ↓%s ↑%s%s",
			dot, state,
			label, s.conns.Load(), s.total.Load(),
			human(float64(down)), human(downRate),
			human(float64(up)), human(upRate),
			human(float64(s.udpDown.Load())), human(float64(s.udpUp.Load())),
			rtt,
		)
		// перезаписать строку: \r + текст + добивка пробелами
		fmt.Printf("\r%-124s", line)
	}
}

// countWriter считает прошедшие байты в счётчик.
type countWriter struct {
	w io.Writer
	c *atomic.Uint64
}

func (cw countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.c.Add(uint64(n))
	return n, err
}

// countReader считает прочитанные байты в счётчик (для потокового апстрима).
type countReader struct {
	r io.Reader
	c *atomic.Uint64
}

func (cr *countReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.c.Add(uint64(n))
	return n, err
}

// ============================ ФРЕЙМЫ UDP ============================
// Фрейм: [2:addrLen][addr "ip:port"][2:dataLen][data]

func encodeFrame(addr string, data []byte) []byte {
	out := make([]byte, 0, 4+len(addr)+len(data))
	var ab [2]byte
	binary.BigEndian.PutUint16(ab[:], uint16(len(addr)))
	out = append(out, ab[:]...)
	out = append(out, addr...)
	var db [2]byte
	binary.BigEndian.PutUint16(db[:], uint16(len(data)))
	out = append(out, db[:]...)
	return append(out, data...)
}

func parseFrames(b []byte, fn func(addr string, data []byte)) {
	for len(b) >= 4 {
		al := int(binary.BigEndian.Uint16(b[:2]))
		if len(b) < 2+al+2 {
			return
		}
		addr := string(b[2 : 2+al])
		dl := int(binary.BigEndian.Uint16(b[2+al : 2+al+2]))
		start := 2 + al + 2
		if len(b) < start+dl {
			return
		}
		fn(addr, b[start:start+dl])
		b = b[start+dl:]
	}
}

// ============================ СЕРВЕР ============================

type stream struct {
	user      string // ключ слота клиента — кому писать трафик
	id        string
	conn      net.Conn
	down      chan []byte
	done      chan struct{}
	closeOnce sync.Once
	lastAct   atomic.Int64 // время последней активности (UnixNano) — для реапа

	upMu    sync.Mutex
	upCond  *sync.Cond
	upBuf   map[uint64][]byte
	upNext  uint64
	upStart sync.Once // ленивый старт upWriter (только для chunked-режима)
}

func (s *stream) touch() { s.lastAct.Store(time.Now().UnixNano()) }

func (s *stream) idle(d time.Duration) bool {
	return time.Since(time.Unix(0, s.lastAct.Load())) > d
}

func (s *stream) shut() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.conn.Close()
		s.upMu.Lock()
		s.upCond.Broadcast()
		s.upMu.Unlock()
		st.conns.Add(-1)
	})
}

func (s *stream) pumpTarget() {
	defer close(s.down)
	buf := make([]byte, 32*1024)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case s.down <- chunk:
			case <-s.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *stream) upWriter() {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	for {
		select {
		case <-s.done:
			return
		default:
		}
		chunk, ok := s.upBuf[s.upNext]
		if !ok {
			s.upCond.Wait()
			continue
		}
		delete(s.upBuf, s.upNext)
		s.upNext++
		s.upMu.Unlock()
		_, err := s.conn.Write(chunk)
		s.upMu.Lock()
		if err != nil {
			return
		}
	}
}

type udpSession struct {
	user      string // ключ слота клиента — кому писать трафик
	id        string
	pc        *net.UDPConn
	down      chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func (u *udpSession) shut() {
	u.closeOnce.Do(func() {
		close(u.done)
		u.pc.Close()
	})
}

func (u *udpSession) readLoop() {
	defer close(u.down)
	buf := make([]byte, 65535)
	for {
		n, addr, err := u.pc.ReadFromUDP(buf)
		if n > 0 {
			frame := encodeFrame(addr.String(), buf[:n])
			st.udpDown.Add(uint64(n))
			select {
			case u.down <- frame:
			case <-u.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ============================ ССЫЛКА cdn:// ============================

// Ссылка вида cdn://<base64url> переносит все настройки подключения одним
// значением: ей удобно делиться с друзьями, как vless://…
//
// Содержимое зашифровано AES-256-GCM, поэтому глазами в ссылке ничего не
// прочитать и случайный base64-декод ничего не даёт. Ключ общий для всех сборок
// (иначе получатель не расшифровал бы ссылку), так что это стойкая обфускация,
// а не тайна от того, у кого есть приложение: пароль туннеля по-прежнему решает,
// кого пускать на сервер.
const shareScheme = "cdn://"

// shareVersion — первый байт полезной нагрузки: формат можно менять, старые
// ссылки при этом будут отвергнуты с понятной ошибкой.
const shareVersion = 1

// shareSecret — из него выводится ключ шифрования ссылок (одинаковый в Go и в
// Android-приложении, см. ShareLink.java).
const shareSecret = "cdn-tunnel/share/v1"

// shareParams — то, что едет внутри ссылки. Мастер-пароля сервера здесь нет:
// ссылка предъявляет своё удостоверение Cred ("<id>.<подпись>"), выданное
// владельцем сервера. Pass остаётся только для ссылок старого образца.
type shareParams struct {
	IP        string `json:"ip"`
	Host      string `json:"host"`
	Cred      string `json:"cred,omitempty"`
	Pass      string `json:"pass,omitempty"`
	Conns     int    `json:"conns,omitempty"`
	UDP       bool   `json:"udp"`
	Method    string `json:"method,omitempty"`
	Transport string `json:"transport,omitempty"`
	Label     string `json:"label,omitempty"` // подпись профиля (не имя клиента)
}

// applyTo переносит параметры ссылки в разобранные флаги клиента.
func (p shareParams) applyTo(ip, host, pass *string, conns *int, udp *bool, method, transport, label *string) {
	if p.IP != "" {
		*ip = p.IP
	}
	if p.Host != "" {
		*host = p.Host
	}
	linkCred = p.Cred
	*pass = p.Pass
	if p.Conns > 0 {
		*conns = p.Conns
	}
	*udp = p.UDP
	if p.Method != "" {
		*method = p.Method
	}
	if p.Transport != "" {
		*transport = p.Transport
	}
	if *label == "" && p.Label != "" {
		*label = p.Label
	}
}

// ---- удостоверение ссылки: "<id>.<подпись>" ----
//
// Владелец сервера выпускает ссылку, подписывая случайный id мастер-секретом
// (-password). Сервер проверяет подпись тем же секретом — список выданных ссылок
// ему не нужен, — а сам мастер-секрет в ссылку не попадает. Первое устройство,
// пришедшее с таким id, к нему и привязывается.

// issueCred выпускает удостоверение для новой ссылки.
func issueCred(master string) string {
	if master == "" {
		return "" // сервер без пароля — удостоверения не нужны
	}
	b := make([]byte, 8)
	rand.Read(b)
	id := hex.EncodeToString(b)
	return id + "." + credMAC(master, id)
}

// credMAC — подпись идентификатора ссылки мастер-секретом сервера.
func credMAC(master, id string) string {
	m := hmac.New(sha256.New, []byte(master))
	m.Write([]byte("cdn-tunnel/link/v1:" + id))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// checkCred разбирает удостоверение и проверяет подпись в постоянное время.
func checkCred(master, cred string) (id string, ok bool) {
	i := strings.IndexByte(cred, '.')
	if i <= 0 || master == "" {
		return "", false
	}
	id, mac := cred[:i], cred[i+1:]
	want := credMAC(master, id)
	if subtle.ConstantTimeCompare([]byte(mac), []byte(want)) != 1 {
		return "", false
	}
	return id, true
}

// localDeviceID — отпечаток машины, на которой запущен клиент: по нему сервер
// привязывает ссылку к устройству. Берём machine-id (он стабилен и не является
// секретом сам по себе), иначе имя хоста; наружу уходит только хеш.
func localDeviceID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(b)) > 0 {
			return hashDevice(string(bytes.TrimSpace(b)))
		}
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	return hashDevice(h)
}

func hashDevice(raw string) string {
	sum := sha256.Sum256([]byte("cdn-tunnel/device/v1:" + raw))
	return hex.EncodeToString(sum[:8])
}

// shareKey выводит ключ шифрования ссылок из общего секрета.
func shareKey() []byte {
	sum := sha256.Sum256([]byte(shareSecret))
	return sum[:]
}

// encodeShare собирает ссылку: [версия][nonce][шифртекст+тег] в base64url.
func encodeShare(p shareParams) string {
	plain, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(shareKey())
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	out := make([]byte, 0, 1+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, shareVersion)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, []byte{shareVersion})
	return shareScheme + base64.RawURLEncoding.EncodeToString(out)
}

// decodeShare разбирает ссылку обратно в параметры подключения.
func decodeShare(link string) (shareParams, error) {
	var p shareParams
	s := strings.TrimSpace(link)
	if i := strings.IndexByte(s, '#'); i >= 0 { // подпись после # — только для глаз
		s = s[:i]
	}
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, shareScheme):
		s = s[len(shareScheme):]
	case strings.HasPrefix(low, "cdn:"):
		s = s[len("cdn:"):]
	}
	s = strings.TrimLeft(s, "/")
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return p, fmt.Errorf("это не похоже на cdn://-ссылку")
	}
	block, err := aes.NewCipher(shareKey())
	if err != nil {
		return p, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return p, err
	}
	if len(raw) < 1+gcm.NonceSize()+gcm.Overhead() {
		return p, fmt.Errorf("ссылка обрезана")
	}
	if raw[0] != shareVersion {
		return p, fmt.Errorf("ссылка другой версии (%d) — обновите приложение", raw[0])
	}
	nonce := raw[1 : 1+gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, raw[1+gcm.NonceSize():], []byte{shareVersion})
	if err != nil {
		return p, fmt.Errorf("ссылка повреждена или не от этой программы")
	}
	if err := json.Unmarshal(plain, &p); err != nil {
		return p, fmt.Errorf("содержимое ссылки не разобрано: %v", err)
	}
	if p.Host == "" && p.IP == "" {
		return p, fmt.Errorf("в ссылке нет адреса сервера")
	}
	return p, nil
}

// ============================ ПОЛЬЗОВАТЕЛИ ============================

// seatTTL — сколько клиент считается онлайн без единого запроса. Клиент пингует
// сервер каждые несколько секунд, так что пропуск нескольких пингов подряд
// означает, что он отвалился: слот освобождается, в списке он станет «офлайн».
const seatTTL = 45 * time.Second

// logf печатает строку журнала, не ломая однострочный HUD: тот перерисовывается
// через \r, поэтому перед выводом затираем текущую строку.
func logf(format string, args ...any) {
	if plainStats || !stdoutTTY {
		fmt.Printf(format+"\n", args...)
		return
	}
	fmt.Printf("\r\033[K"+format+"\n", args...)
}

// stdoutTTY — вывод идёт в терминал? Если нет (journald, пайп, Android), ANSI и
// возврат каретки только мусорят лог, поэтому печатаем просто строки.
var stdoutTTY = func() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

// setUsers обновляет счётчик онлайна в HUD (в тестах HUD не поднят).
func setUsers(n int) {
	if st != nil {
		st.users.Store(int64(n))
	}
}

// shortID укорачивает идентификатор для журнала. Режем по рунам: сюда попадают
// не только hex-идентификаторы, но и произвольные имена устройств.
func shortID(key string) string {
	r := []rune(key)
	if len(r) > 8 {
		return string(r[:8]) + "…"
	}
	return key
}

// cleanName приводит имя клиента к виду, пригодному для журнала и списка:
// без управляющих символов и не длиннее 32 рун. Пустое имя — клиент без -name.
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() > 64 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// seat — занятый слот: один онлайн-клиент (весь его пул соединений и стримов).
type seat struct {
	name     string
	remote   string
	link     string // id ссылки, по которой пришёл клиент ("" — по паролю)
	since    time.Time
	lastSeen time.Time
}

// rosterEntry — клиент, которого сервер видел хотя бы раз. Запись живёт и после
// отключения: в списке пользователей такой клиент показывается как «офлайн».
type rosterEntry struct {
	Name   string `json:"name"`
	Last   int64  `json:"last"`  // когда последний раз был онлайн, unix-секунды
	Seen   int64  `json:"seen"`  // сколько раз подключался
	First  int64  `json:"first"` // когда увидели впервые
	Up     uint64 `json:"up"`    // отдано клиентом за всё время, байт
	Down   uint64 `json:"down"`  // получено клиентом за всё время, байт
	Banned bool   `json:"banned,omitempty"`
}

// userView — как клиент выглядит в ответе /users.
type userView struct {
	Name   string `json:"name"`
	Online bool   `json:"online"`
	Since  int64  `json:"since,omitempty"` // онлайн с какого времени
	Last   int64  `json:"last"`            // когда видели в последний раз
	Seen   int64  `json:"seen"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
	Banned bool   `json:"banned,omitempty"`
	Device string `json:"device,omitempty"` // устройство, за которым закреплена ссылка
	Link   string `json:"link,omitempty"`   // id ссылки, если клиент пришёл по ней
	IP     string `json:"ip,omitempty"`     // адрес, пока онлайн
}

// usersDoc — ответ /users: лимит, сколько сейчас онлайн и все известные клиенты.
type usersDoc struct {
	Limit  int        `json:"limit"` // 0 — без лимита
	Online int        `json:"online"`
	Users  []userView `json:"users"`
}

// linkRec — выпущенная ссылка. Реестр ведёт сервер: владелец видит все свои
// ссылки (даже ни разу не использованные), их трафик и устройство, к которому
// ссылка привязалась, и может отозвать любую.
type linkRec struct {
	ID       string `json:"id"`
	Label    string `json:"label"`          // подпись: «Андрею», «ноут» и т.п.
	Name     string `json:"name,omitempty"` // как назвался клиент, который ей пользуется
	Created  int64  `json:"created"`
	Device   string `json:"device,omitempty"` // "" — ссылка ещё не использована
	FirstUse int64  `json:"first_use,omitempty"`
	LastUse  int64  `json:"last_use,omitempty"`
	Up       uint64 `json:"up"`
	Down     uint64 `json:"down"`
	Revoked  bool   `json:"revoked,omitempty"`
}

// serverState — то, что сервер хранит между перезапусками.
type serverState struct {
	Users []*rosterEntry `json:"users"`
	Links []*linkRec     `json:"links"`
}

// userGate считает пользователей и (если задан -users) ограничивает их число.
// Единица учёта — клиент целиком: у одного клиента пул из -conns соединений и
// десятки параллельных стримов, и всё это один пользователь. Ключ слота — имя
// (-name), а у безымянных клиентов — случайный идентификатор запуска.
type userGate struct {
	mu      sync.Mutex
	limit   int // 0 — без ограничения, только учёт
	seats   map[string]*seat
	roster  map[string]*rosterEntry // имя → когда видели последний раз
	lastLog map[string]time.Time    // троттлинг журнала отказов (клиент ретраится)
	links   map[string]*linkRec     // id ссылки → всё, что о ней известно
	path    string                  // файл состояния ("" — не сохранять)
	dirty   bool                    // есть несохранённые изменения (счётчики трафика)
}

func newUserGate(limit int) *userGate {
	return &userGate{
		limit:   limit,
		seats:   map[string]*seat{},
		roster:  map[string]*rosterEntry{},
		lastLog: map[string]time.Time{},
		links:   map[string]*linkRec{},
	}
}

// clientIP достаёт исходный адрес клиента: CDN подставляет его в X-Forwarded-For,
// иначе берём адрес самого соединения.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// seatKey определяет, кого считать одним пользователем: имя клиента, если оно
// задано (-name), иначе идентификатор запуска, а у совсем старых клиентов без
// заголовков — исходный IP. name — как показывать клиента в списке.
func seatKey(r *http.Request) (key, name, remote string) {
	remote = clientIP(r)
	id := r.Header.Get(clientHeader)
	name = cleanName(decodeName(r.Header.Get(nameHeader)))
	// Клиент по ссылке — это сама ссылка: одна ссылка = один пользователь,
	// как бы он ни назывался и с какого бы запуска ни пришёл.
	if lid, ok := checkCred(authToken, r.Header.Get(linkHeader)); ok {
		if name == "" {
			name = "ссылка-" + shortID(lid)
		}
		return "link:" + lid, name, remote
	}
	switch {
	case name != "":
		key = "name:" + strings.ToLower(name)
	case id != "":
		key, name = id, "гость-"+shortID(id)
	default:
		key, name = "ip:"+remote, "гость-"+remote
	}
	return key, name, remote
}

// issueLink выпускает новую ссылку и заносит её в реестр: владелец увидит её в
// админке сразу, ещё до того как ей кто-то воспользуется.
func (g *userGate) issueLink(label string) *linkRec {
	b := make([]byte, 8)
	rand.Read(b)
	rec := &linkRec{ID: hex.EncodeToString(b), Label: cleanName(label), Created: time.Now().Unix()}
	g.mu.Lock()
	g.links[rec.ID] = rec
	g.saveLocked()
	g.mu.Unlock()
	logf("🔗 выпущена ссылка %s%s", shortID(rec.ID), labelSuffix(rec.Label))
	return rec
}

func labelSuffix(label string) string {
	if label == "" {
		return ""
	}
	return " («" + label + "»)"
}

// useLink решает судьбу запроса по ссылке: отозвана — «revoked», занята другим
// устройством — «used», иначе привязывает (при первом использовании) и пускает.
// Ссылка, выпущенная вне админки (флагом -share), заносится в реестр на лету,
// чтобы владелец видел и мог отозвать вообще все ссылки.
func (g *userGate) useLink(linkID, device, name string) (bool, string) {
	if linkID == "" {
		return true, ""
	}
	if device == "" {
		device = "unknown" // клиент без отпечатка: привяжем хотя бы к «неизвестному»
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[linkID]
	if rec == nil {
		rec = &linkRec{ID: linkID, Label: "вне админки", Created: now.Unix()}
		g.links[linkID] = rec
	}
	if rec.Revoked {
		if last, ok := g.lastLog["rev:"+linkID]; !ok || now.Sub(last) > 5*time.Second {
			g.lastLog["rev:"+linkID] = now
			logf("⛔ ссылка %s отозвана — «%s» отклонён", shortID(linkID), name)
		}
		return false, "revoked"
	}
	if rec.Device == "" {
		rec.Device, rec.FirstUse, rec.LastUse = device, now.Unix(), now.Unix()
		rec.Name = name
		logf("🔗 ссылка %s%s привязана к устройству %s («%s»)",
			shortID(linkID), labelSuffix(rec.Label), shortID(device), name)
		g.saveLocked()
		return true, ""
	}
	if rec.Device != device {
		if last, ok := g.lastLog["link:"+linkID]; !ok || now.Sub(last) > 5*time.Second {
			g.lastLog["link:"+linkID] = now
			logf("⚠ ссылка %s%s уже привязана к другому устройству — «%s» отклонён",
				shortID(linkID), labelSuffix(rec.Label), name)
		}
		return false, "used"
	}
	rec.LastUse = now.Unix()
	if name != "" && rec.Name != name {
		rec.Name = name
		g.saveLocked()
	}
	return true, ""
}

// revokeLink отзывает ссылку: клиент по ней больше не подключится, запись
// остаётся в реестре со счётчиками. dropAll=true — удалить запись совсем.
func (g *userGate) revokeLink(id string, drop bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	if rec == nil {
		return false
	}
	if drop {
		delete(g.links, id)
	} else {
		rec.Revoked = true
	}
	for k, s := range g.seats { // отключаем того, кто сидит по этой ссылке
		if s.link == id {
			delete(g.seats, k)
		}
	}
	setUsers(len(g.seats))
	g.saveLocked()
	logf("🔗 ссылка %s %s", shortID(id), map[bool]string{true: "удалена", false: "отозвана"}[drop])
	return true
}

// restoreLink снимает отзыв: ссылка снова рабочая (устройство остаётся прежним).
func (g *userGate) restoreLink(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	if rec == nil {
		return false
	}
	rec.Revoked = false
	g.saveLocked()
	logf("🔗 ссылка %s снова активна", shortID(id))
	return true
}

// unbindLink снимает привязку к устройству, оставляя ссылку рабочей.
func (g *userGate) unbindLink(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	if rec == nil {
		return false
	}
	rec.Device, rec.FirstUse = "", 0
	g.saveLocked()
	logf("🔗 ссылка %s отвязана от устройства — можно открыть на другом", shortID(id))
	return true
}

// renameLink меняет подпись ссылки.
func (g *userGate) renameLink(id, label string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	if rec == nil {
		return false
	}
	rec.Label = cleanName(label)
	g.saveLocked()
	return true
}

// linkFor возвращает id ссылки, по которой пришёл запрос ("" — не по ссылке).
func linkFor(r *http.Request) string {
	id, _ := checkCred(authToken, r.Header.Get(linkHeader))
	return id
}

// decodeName разворачивает имя из заголовка: оно едет percent-encoded, чтобы
// кириллица и пробелы прошли через любые прокси и CDN.
func decodeName(v string) string {
	if v == "" {
		return ""
	}
	if s, err := url.QueryUnescape(v); err == nil {
		return s
	}
	return v
}

// admit продлевает уже занятый слот либо выдаёт новый. false — все слоты заняты
// живыми клиентами (только при -users > 0); запрос надо отклонить.
func (g *userGate) admit(key, name, remote string) (bool, string) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expireLocked(now)
	if e := g.roster[name]; e != nil && e.Banned {
		if last, ok := g.lastLog["ban:"+name]; !ok || now.Sub(last) > 30*time.Second {
			g.lastLog["ban:"+name] = now
			logf("⛔ «%s» (%s) заблокирован — доступ запрещён", name, remote)
		}
		return false, "banned"
	}
	if s := g.seats[key]; s != nil {
		s.lastSeen = now
		g.seeLocked(name, now, false)
		return true, ""
	}
	if g.limit > 0 && len(g.seats) >= g.limit {
		if last, ok := g.lastLog[key]; !ok || now.Sub(last) > 5*time.Second {
			g.lastLog[key] = now
			logf("⚠ отказ: достигнуто максимальное число подключений %d/%d — «%s» (%s) отклонён",
				len(g.seats), g.limit, name, remote)
		}
		return false, "limit"
	}
	link := strings.TrimPrefix(key, "link:")
	if link == key {
		link = ""
	}
	g.seats[key] = &seat{name: name, remote: remote, link: link, since: now, lastSeen: now}
	g.seeLocked(name, now, true)
	setUsers(len(g.seats))
	logf("＋ «%s» (%s) подключился — онлайн %s", name, remote, g.gaugeLocked())
	g.saveLocked()
	return true, ""
}

// touch продлевает уже занятый слот, не выдавая новый (для запросов, которые
// слот не занимают, — например опроса списка пользователей).
func (g *userGate) touch(key string) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if s := g.seats[key]; s != nil {
		s.lastSeen = now
		g.seeLocked(s.name, now, false)
	}
	g.expireLocked(now)
}

// seeLocked отмечает клиента в списке известных (онлайн он или только что был).
func (g *userGate) seeLocked(name string, now time.Time, fresh bool) {
	if name == "" {
		return
	}
	e := g.roster[name]
	if e == nil {
		e = &rosterEntry{Name: name, First: now.Unix()}
		g.roster[name] = e
	}
	e.Last = now.Unix()
	if fresh {
		e.Seen++
	}
}

// addTraffic приписывает прошедшие байты тому клиенту, чей это стрим.
// Вызывается на каждом куске данных, поэтому без записи на диск: файл состояния
// сохраняется периодически (sweep) и на подключении/отключении.
func (g *userGate) addTraffic(key string, up, down uint64) {
	if key == "" || (up == 0 && down == 0) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.seats[key]
	if s == nil {
		return
	}
	if e := g.roster[s.name]; e != nil {
		e.Up += up
		e.Down += down
	}
	if rec := g.links[s.link]; rec != nil { // сколько «съела» конкретная ссылка
		rec.Up += up
		rec.Down += down
	}
	g.dirty = true
}

// banned сообщает, заблокирован ли клиент (проверка до выдачи слота).
func (g *userGate) setBan(name string, on bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.roster[name]
	if e == nil {
		return false
	}
	e.Banned = on
	if on {
		for k, s := range g.seats { // заблокированного сразу отключаем
			if s.name == name {
				delete(g.seats, k)
			}
		}
		setUsers(len(g.seats))
	}
	g.saveLocked()
	return true
}

// kick снимает клиента с линии: слот освобождается, клиент переподключится
// (если не забанен) — удобно, чтобы согнать зависшую сессию.
func (g *userGate) kick(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	found := false
	for k, s := range g.seats {
		if s.name == name {
			delete(g.seats, k)
			found = true
		}
	}
	if found {
		setUsers(len(g.seats))
		logf("⏏ «%s» отключён администратором", name)
	}
	return found
}

// unbind снимает привязку ссылки к устройству: по id ссылки, по имени клиента
// или все сразу. Возвращает, сколько привязок снято.
func (g *userGate) unbind(linkID, name string, all bool) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for id, rec := range g.links {
		if all || (linkID != "" && id == linkID) || (name != "" && rec.Name == name) {
			rec.Device, rec.FirstUse = "", 0
			n++
		}
	}
	if n > 0 {
		logf("🔗 снято привязок ссылок: %d — можно зайти с другого устройства", n)
		g.saveLocked()
	}
	return n
}

// forget убирает клиента из списка целиком (вместе со счётчиками трафика).
func (g *userGate) forget(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.roster[name]; !ok {
		return false
	}
	delete(g.roster, name)
	for k, s := range g.seats {
		if s.name == name {
			delete(g.seats, k)
		}
	}
	for _, rec := range g.links {
		if rec.Name == name {
			rec.Device, rec.Name, rec.FirstUse = "", "", 0
		}
	}
	setUsers(len(g.seats))
	g.saveLocked()
	return true
}

// setLimit меняет лимит одновременных клиентов на ходу (без перезапуска).
func (g *userGate) setLimit(n int) {
	if n < 0 {
		n = 0
	}
	g.mu.Lock()
	g.limit = n
	g.mu.Unlock()
	maxUsers.Store(int64(n))
	logf("Лимит одновременных клиентов изменён: %d", n)
}

// expireLocked освобождает слоты клиентов, замолчавших дольше seatTTL.
func (g *userGate) expireLocked(now time.Time) {
	for k, s := range g.seats {
		if now.Sub(s.lastSeen) > seatTTL {
			delete(g.seats, k)
			g.seeLocked(s.name, s.lastSeen, false)
			logf("－ «%s» (%s) отключился (простой > %s) — онлайн %s",
				s.name, s.remote, seatTTL, g.gaugeLocked())
			g.saveLocked()
		}
	}
	for k, t := range g.lastLog {
		if now.Sub(t) > time.Minute {
			delete(g.lastLog, k)
		}
	}
	setUsers(len(g.seats))
}

// release освобождает слот по явному «прощанию» клиента (/bye) — после
// перезапуска клиент не ждёт истечения seatTTL.
func (g *userGate) release(key string) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.seats[key]
	if !ok {
		return
	}
	delete(g.seats, key)
	g.seeLocked(s.name, now, false)
	setUsers(len(g.seats))
	logf("－ «%s» (%s) отключился — онлайн %s", s.name, s.remote, g.gaugeLocked())
	g.saveLocked()
}

// gauge возвращает «онлайн/лимит» для заголовка X-Tunnel-Users (лимит 0 — без
// ограничения, клиент показывает просто число).
func (g *userGate) gauge() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gaugeLocked()
}

func (g *userGate) gaugeLocked() string {
	return fmt.Sprintf("%d/%d", len(g.seats), g.limit)
}

// doc собирает список клиентов с отметкой «онлайн/офлайн». full=true (админка)
// добавляет трафик, адреса и устройства; клиентам туннеля этого не показываем —
// им достаточно знать, кто сейчас на сервере.
func (g *userGate) doc(full bool) usersDoc {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expireLocked(now)
	online := map[string]*seat{}
	for _, s := range g.seats {
		online[s.name] = s
	}
	deviceOf := map[string]*linkRec{}
	for _, rec := range g.links {
		if rec.Name != "" && rec.Device != "" {
			deviceOf[rec.Name] = rec
		}
	}
	d := usersDoc{Limit: g.limit, Online: len(g.seats)}
	for name, e := range g.roster {
		v := userView{Name: name, Last: e.Last, Seen: e.Seen, Banned: e.Banned}
		if full {
			v.Up, v.Down = e.Up, e.Down
			if b, ok := deviceOf[name]; ok {
				v.Device, v.Link = b.Device, b.ID
			}
		}
		if s, ok := online[name]; ok {
			v.Online, v.Since, v.Last = true, s.since.Unix(), now.Unix()
			if full {
				v.IP = s.remote
				if s.link != "" {
					v.Link = s.link
				}
			}
		}
		d.Users = append(d.Users, v)
	}
	// Онлайн — сверху, дальше по свежести: список читают сверху вниз.
	sort.Slice(d.Users, func(i, j int) bool {
		if d.Users[i].Online != d.Users[j].Online {
			return d.Users[i].Online
		}
		if d.Users[i].Last != d.Users[j].Last {
			return d.Users[i].Last > d.Users[j].Last
		}
		return d.Users[i].Name < d.Users[j].Name
	})
	return d
}

// ---- сохранение списка клиентов между перезапусками сервера ----

// loadRoster поднимает список известных клиентов с диска: сервис перезапускается
// (в том числе по RuntimeMaxSec), а «офлайн»-клиенты должны остаться в списке.
func (g *userGate) loadRoster(path string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.path = path
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st serverState
	if json.Unmarshal(b, &st) != nil {
		// Файл старого образца — просто список клиентов.
		var list []*rosterEntry
		if json.Unmarshal(b, &list) != nil {
			return
		}
		st.Users = list
	}
	for _, e := range st.Users {
		if e != nil && e.Name != "" {
			g.roster[e.Name] = e
		}
	}
	for _, l := range st.Links {
		if l != nil && l.ID != "" {
			g.links[l.ID] = l
		}
	}
	logf("Состояние загружено: клиентов %d, привязанных ссылок %d (%s)", len(g.roster), len(g.links), path)
}

func (g *userGate) saveLocked() {
	if g.path == "" {
		return
	}
	stt := serverState{
		Users: make([]*rosterEntry, 0, len(g.roster)),
		Links: make([]*linkRec, 0, len(g.links)),
	}
	for _, e := range g.roster {
		stt.Users = append(stt.Users, e)
	}
	for _, l := range g.links {
		stt.Links = append(stt.Links, l)
	}
	b, err := json.Marshal(stt)
	if err != nil {
		return
	}
	tmp := g.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, g.path)
	}
}

// sweep освобождает протухшие слоты и без входящих запросов, чтобы список
// онлайна не врал, пока сервер простаивает.
func (g *userGate) sweep() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	saveEvery := 0
	for range tick.C {
		g.mu.Lock()
		g.expireLocked(time.Now())
		// Счётчики трафика сбрасываем на диск раз в полминуты, а не на каждом килобайте.
		if saveEvery++; saveEvery >= 6 && g.dirty {
			saveEvery = 0
			g.dirty = false
			g.saveLocked()
		}
		g.mu.Unlock()
	}
}

// handleUsers отдаёт список пользователей (кто онлайн, кто офлайн). Слот не
// занимает и лимитом не отклоняется: это справочная ручка для приложения.
func (g *userGate) handleUsers(w http.ResponseWriter, r *http.Request) {
	b, err := json.Marshal(g.doc(false))
	if err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Write(b)
}

// ============================ АДМИНКА ============================
//
// Ручки /admin/* — для владельца сервера: они требуют мастер-пароль (-password)
// и удостоверением ссылки не открываются. Приложение ходит в них по SSH через
// curl на localhost, поэтому наружу их светить не нужно.

const adminPath = "/admin"

// adminDoc — снимок состояния сервера для панели управления.
type adminDoc struct {
	Version  string     `json:"version"`
	Uptime   int64      `json:"uptime"` // секунд с запуска
	Limit    int        `json:"limit"`
	Online   int        `json:"online"`
	SeatTTL  int        `json:"seat_ttl"`
	Streams  int        `json:"streams"`
	UDP      int        `json:"udp"`
	Up       uint64     `json:"up"`    // всего вверх с момента запуска
	Down     uint64     `json:"down"`  // всего вниз с момента запуска
	Total    int64      `json:"total"` // всего соединений с запуска
	Method   string     `json:"method"`
	Password bool       `json:"password"` // включён ли пароль
	State    string     `json:"state"`    // файл состояния ("" — не сохраняется)
	Users    []userView `json:"users"`
	Links    []linkRec  `json:"links"`
}

// serverVersion — версия серверной части. Приложение сверяет её со своей и
// подсказывает обновить сервер, если он старее, чем ручки, которые оно зовёт.
const serverVersion = "1.4"

var serverStarted = time.Now()

// isAdmin пропускает только владельца: сверка мастер-пароля в постоянное время.
func isAdmin(r *http.Request) bool {
	if authToken == "" {
		return true // сервер без пароля — защищать нечем
	}
	got := []byte(r.Header.Get(authHeader))
	return subtle.ConstantTimeCompare(got, []byte(authToken)) == 1
}

// routeAdmin вешает ручки управления сервером.
func (g *userGate) routeAdmin(mux *http.ServeMux, ts *tunnelServer) {
	mux.HandleFunc(adminPath, func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		d := g.adminDoc(ts)
		b, err := json.Marshal(d)
		if err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	// Действия: kick / ban / unban / unbind / forget / limit.
	mux.HandleFunc(adminPath+"/", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		q := r.URL.Query()
		name := cleanName(decodeName(q.Get("name")))
		action := strings.TrimPrefix(r.URL.Path, adminPath+"/")
		res := map[string]any{"ok": true, "action": action}
		switch action {
		case "kick":
			res["ok"] = g.kick(name)
		case "ban":
			res["ok"] = g.setBan(name, true)
			g.kick(name)
		case "unban":
			res["ok"] = g.setBan(name, false)
		case "unbind":
			res["unbound"] = g.unbind(q.Get("link"), name, q.Get("all") == "1")
		case "forget":
			res["ok"] = g.forget(name)
		case "link/new":
			rec := g.issueLink(q.Get("label"))
			res["id"] = rec.ID
			res["cred"] = rec.ID + "." + credMAC(authToken, rec.ID)
			res["label"] = rec.Label
		case "link/revoke":
			res["ok"] = g.revokeLink(q.Get("id"), false)
		case "link/delete":
			res["ok"] = g.revokeLink(q.Get("id"), true)
		case "link/restore":
			res["ok"] = g.restoreLink(q.Get("id"))
		case "link/unbind":
			res["ok"] = g.unbindLink(q.Get("id"))
		case "link/rename":
			res["ok"] = g.renameLink(q.Get("id"), q.Get("label"))
		case "limit":
			n, err := strconv.Atoi(q.Get("n"))
			if err != nil {
				http.Error(w, "bad n", http.StatusBadRequest)
				return
			}
			g.setLimit(n)
			res["limit"] = n
		default:
			// Обычно это значит, что на сервере более старая сборка, чем в
			// приложении: пишем прямо, а не загадочное «unknown action».
			http.Error(w, fmt.Sprintf("unknown action %q — сервер версии %s, обновите его (Развернуть)",
				action, serverVersion), http.StatusNotFound)
			return
		}
		b, _ := json.Marshal(res)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
}

// adminDoc собирает полный снимок: список клиентов с трафиком, привязки ссылок
// и состояние самого сервера.
func (g *userGate) adminDoc(ts *tunnelServer) adminDoc {
	d := adminDoc{
		Version:  serverVersion,
		Uptime:   int64(time.Since(serverStarted).Seconds()),
		SeatTTL:  int(seatTTL / time.Second),
		Method:   serverMethod,
		Password: authToken != "",
		State:    statePath,
	}
	if st != nil {
		d.Up, d.Down, d.Total = st.up.Load(), st.down.Load(), st.total.Load()
	}
	if ts != nil {
		ts.mu.Lock()
		d.Streams, d.UDP = len(ts.streams), len(ts.udp)
		ts.mu.Unlock()
	}
	users := g.doc(true)
	d.Limit, d.Online, d.Users = users.Limit, users.Online, users.Users
	g.mu.Lock()
	for _, rec := range g.links {
		d.Links = append(d.Links, *rec)
	}
	g.mu.Unlock()
	// Свежие сверху: сначала по последнему использованию, потом по дате выпуска.
	sort.Slice(d.Links, func(i, j int) bool {
		a, b := d.Links[i], d.Links[j]
		if a.LastUse != b.LastUse {
			return a.LastUse > b.LastUse
		}
		return a.Created > b.Created
	})
	return d
}

// middleware считает пользователей и, при -users > 0, отклоняет лишних.
// Корень "/" слот не занимает: он отвечает всем, чтобы сервер выглядел обычным
// origin для CDN и сканеров.
func (g *userGate) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}
		key, name, remote := seatKey(r)
		switch r.URL.Path {
		case "/bye":
			g.release(key)
			w.Header().Set(usersHeader, g.gauge())
			next.ServeHTTP(w, r)
			return
		case usersPath:
			g.touch(key) // опрос списка продлевает слот, но не занимает новый
			w.Header().Set(usersHeader, g.gauge())
			next.ServeHTTP(w, r)
			return
		}
		// Админка — не клиент туннеля: слот не занимает и под лимит не попадает.
		if r.URL.Path == adminPath || strings.HasPrefix(r.URL.Path, adminPath+"/") {
			next.ServeHTTP(w, r)
			return
		}
		// Ссылка работает на одном устройстве и может быть отозвана владельцем.
		if lid := linkFor(r); lid != "" {
			if ok, why := g.useLink(lid, r.Header.Get(deviceHeader), name); !ok {
				w.Header().Set(usersHeader, g.gauge())
				if why == "revoked" {
					http.Error(w, "link revoked", http.StatusForbidden)
				} else {
					http.Error(w, "link already used on another device", http.StatusConflict)
				}
				return
			}
		}
		ok, why := g.admit(key, name, remote)
		// Счётчик едет на любом ответе, в том числе на отказе: клиент показывает
		// его в прямом эфире, не опрашивая сервер отдельной ручкой.
		w.Header().Set(usersHeader, g.gauge())
		switch {
		case ok:
		case why == "banned":
			http.Error(w, "banned", http.StatusForbidden)
			return
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, fmt.Sprintf("user limit %d/%d", g.limit, g.limit), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type tunnelServer struct {
	mu      sync.Mutex
	streams map[string]*stream
	udp     map[string]*udpSession
	gate    *userGate // учёт трафика по клиентам (может быть nil в тестах)
}

// bill приписывает байты клиенту, которому принадлежит стрим.
func (t *tunnelServer) bill(user string, up, down uint64) {
	if t.gate != nil {
		t.gate.addTraffic(user, up, down)
	}
}

func runServer(addr string) {
	st = &stats{role: "server"}
	st.connected.Store(true)
	gate := newUserGate(int(maxUsers.Load()))
	gate.loadRoster(openState(statePath))
	ts := &tunnelServer{
		streams: make(map[string]*stream),
		udp:     make(map[string]*udpSession),
		gate:    gate,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc("/t/connect", ts.handleConnect)
	mux.HandleFunc("/t/down", ts.handleDown)
	mux.HandleFunc("/t/up", ts.handleUp)
	mux.HandleFunc("/t/ups", ts.handleUpStream)
	mux.HandleFunc("/t/close", ts.handleClose)
	mux.HandleFunc("/u/open", ts.handleUDPOpen)
	mux.HandleFunc("/u/down", ts.handleUDPDown)
	mux.HandleFunc("/u/send", ts.handleUDPSend)
	mux.HandleFunc("/u/close", ts.handleUDPClose)
	// Клиент зовёт /bye при завершении — слот -users освобождается сразу.
	mux.HandleFunc("/bye", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tunnel server ok\n"))
	})

	// Учёт пользователей включён всегда (список «кто онлайн»), а -users при
	// значении > 0 ещё и ограничивает их число.
	mux.HandleFunc(usersPath, gate.handleUsers)
	gate.routeAdmin(mux, ts)
	var handler http.Handler = gate.middleware(mux)
	go gate.sweep()
	if maxUsers.Load() > 0 {
		fmt.Printf("Лимит одновременных клиентов: %d (слот освобождается через %s простоя или по /bye)\n", maxUsers.Load(), seatTTL)
	} else {
		fmt.Println("Лимит клиентов не задан (-users 0) — подключиться может любое число клиентов.")
	}
	// Проверка пароля — снаружи учёта: чужак с неверным паролем не должен
	// попадать в список пользователей и отнимать слот.
	if authToken != "" {
		handler = authMiddleware(handler)
		fmt.Println("Доступ защищён паролем (-password): клиенты без верного пароля будут отклонены (403).")
	} else {
		fmt.Println("ВНИМАНИЕ: пароль не задан (-password пуст) — туннель открыт для всех, кто знает адрес.")
	}
	fmt.Printf("Приём данных вверх методом: %s (транспорт stream/chunked определяется клиентом)\n", serverMethod)
	if idleTimeout > 0 {
		go ts.reaper()
		fmt.Printf("Реап простаивающих стримов: %s\n", idleTimeout)
	}

	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	fmt.Printf("Туннель-сервер слушает %s\n", addr)
	go st.render()
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("\nошибка сервера: %v\n", err)
		os.Exit(1)
	}
}

// openState готовит файл состояния: создаёт каталог и проверяет, что туда можно
// писать. Если нельзя (нет прав, только чтение) — возвращает "", и сервер просто
// работает без сохранения списка между перезапусками.
func openState(path string) string {
	if path == "" {
		return ""
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Printf("Список клиентов не сохраняется (%v)\n", err)
		return ""
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Printf("Список клиентов не сохраняется (%v)\n", err)
		return ""
	}
	f.Close()
	return path
}

// authMiddleware требует верный пароль в заголовке X-Tunnel-Auth на всех путях,
// кроме корня "/" (он отдаёт безобидный текст — так сервер выглядит как обычный
// origin для CDN и случайных сканеров). Сравнение — в постоянное время, чтобы
// не утекала длина/содержимое пароля через тайминг.
func authMiddleware(next http.Handler) http.Handler {
	want := []byte(authToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}
		got := []byte(r.Header.Get(authHeader))
		okPass := subtle.ConstantTimeCompare(got, want) == 1
		// Клиент по ссылке мастер-пароля не знает: он предъявляет удостоверение
		// ссылки, подписанное этим же паролем.
		_, okLink := checkCred(authToken, r.Header.Get(linkHeader))
		if !okPass && !okLink {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := readPayload(r, qToken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(helloPrefix + string(body)))
}

func (t *tunnelServer) getStream(id string) *stream {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams[id]
}

func (t *tunnelServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	body, _ := readPayload(r, qTarget)
	target := string(body)
	if id == "" || target == "" {
		http.Error(w, "id and target required", http.StatusBadRequest)
		return
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	tuneConn(conn)
	owner, _, _ := seatKey(r)
	s := &stream{user: owner, id: id, conn: conn, down: make(chan []byte, 1024), done: make(chan struct{}), upBuf: make(map[uint64][]byte)}
	s.upCond = sync.NewCond(&s.upMu)
	s.touch()
	t.mu.Lock()
	t.streams[id] = s
	t.mu.Unlock()
	st.conns.Add(1)
	st.total.Add(1)
	go s.pumpTarget()
	// upWriter (реассемблер chunked-режима) стартует лениво — в stream-режиме он
	// не нужен, данные вверх пишутся напрямую в handleUpStream.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("connected"))
}

// handleUpStream — апстрим stream-режима: одно длинное тело POST копируется
// напрямую в цель. Нет нумерации/реассемблера/окна — порядок держит сам поток.
func (t *tunnelServer) handleUpStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s := t.getStream(r.URL.Query().Get("id"))
	if s == nil {
		http.Error(w, "no stream", http.StatusNotFound)
		return
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			s.touch()
			st.up.Add(uint64(n))
			t.bill(s.user, uint64(n), 0)
			if _, werr := s.conn.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	r.Body.Close()
	w.WriteHeader(http.StatusOK)
}

// reaper периодически закрывает стримы/UDP-сессии, простаивающие дольше idleTimeout.
func (t *tunnelServer) reaper() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for range tick.C {
		var dead []*stream
		t.mu.Lock()
		for id, s := range t.streams {
			if s.idle(idleTimeout) {
				dead = append(dead, s)
				delete(t.streams, id)
			}
		}
		t.mu.Unlock()
		for _, s := range dead {
			s.shut()
		}
	}
}

func (t *tunnelServer) handleDown(w http.ResponseWriter, r *http.Request) {
	s := t.getStream(r.URL.Query().Get("id"))
	if s == nil {
		http.Error(w, "no stream", http.StatusNotFound)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case chunk, more := <-s.down:
			if !more {
				return
			}
			if _, err := w.Write(chunk); err != nil {
				return
			}
			st.down.Add(uint64(len(chunk)))
			t.bill(s.user, 0, uint64(len(chunk)))
			s.touch()
			flusher.Flush()
		}
	}
}

func (t *tunnelServer) handleUp(w http.ResponseWriter, r *http.Request) {
	s := t.getStream(r.URL.Query().Get("id"))
	if s == nil {
		http.Error(w, "no stream", http.StatusNotFound)
		return
	}
	if !methodAllowed(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
	if err != nil {
		http.Error(w, "bad seq", http.StatusBadRequest)
		return
	}
	body, _ := readPayload(r, qData)
	st.up.Add(uint64(len(body)))
	t.bill(s.user, uint64(len(body)), 0)
	s.touch()
	s.upStart.Do(func() { go s.upWriter() }) // ленивый старт реассемблера
	s.upMu.Lock()
	s.upBuf[seq] = body
	s.upCond.Signal()
	s.upMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (t *tunnelServer) handleClose(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if s := t.getStream(id); s != nil {
		s.shut()
		t.mu.Lock()
		delete(t.streams, id)
		t.mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func (t *tunnelServer) udpGet(id string) *udpSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.udp[id]
}

func (t *tunnelServer) handleUDPOpen(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		http.Error(w, "udp listen failed", http.StatusBadGateway)
		return
	}
	pc.SetReadBuffer(4 << 20)
	pc.SetWriteBuffer(4 << 20)
	owner, _, _ := seatKey(r)
	u := &udpSession{user: owner, id: id, pc: pc, down: make(chan []byte, 4096), done: make(chan struct{})}
	t.mu.Lock()
	t.udp[id] = u
	t.mu.Unlock()
	st.conns.Add(1)
	st.total.Add(1)
	go u.readLoop()
	w.WriteHeader(http.StatusOK)
}

func (t *tunnelServer) handleUDPDown(w http.ResponseWriter, r *http.Request) {
	u := t.udpGet(r.URL.Query().Get("id"))
	if u == nil {
		http.Error(w, "no udp session", http.StatusNotFound)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame, more := <-u.down:
			if !more {
				return
			}
			if _, err := w.Write(frame); err != nil {
				return
			}
			t.bill(u.user, 0, uint64(len(frame)))
			flusher.Flush()
		}
	}
}

func (t *tunnelServer) handleUDPSend(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u := t.udpGet(r.URL.Query().Get("id"))
	if u == nil {
		http.Error(w, "no udp session", http.StatusNotFound)
		return
	}
	body, _ := readPayload(r, qData)
	parseFrames(body, func(addr string, data []byte) {
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return
		}
		u.pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
		u.pc.WriteToUDP(data, ua)
		st.udpUp.Add(uint64(len(data)))
		t.bill(u.user, uint64(len(data)), 0)
	})
	w.WriteHeader(http.StatusOK)
}

func (t *tunnelServer) handleUDPClose(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	t.mu.Lock()
	u := t.udp[id]
	delete(t.udp, id)
	t.mu.Unlock()
	if u != nil {
		u.shut()
		st.conns.Add(-1)
	}
	w.WriteHeader(http.StatusOK)
}

// ============================ КЛИЕНТ ============================

type tunnelClient struct {
	pool []*http.Client // пул независимых TCP/h2-соединений к CDN
	rr   atomic.Uint32  // round-robin счётчик
	base string
	udp  bool
}

// pick выбирает следующий клиент из пула (round-robin).
// Разные SOCKS-соединения едут по разным TCP-путям — нет общей HoL-блокировки.
func (tc *tunnelClient) pick() *http.Client {
	return tc.pool[int(tc.rr.Add(1))%len(tc.pool)]
}

func cdnClient(ip, host string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
			if err == nil {
				tuneConn(c) // без Nagle + большие буферы на канале к CDN
			}
			return c, err
		},
		TLSClientConfig:     &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}},
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		IdleConnTimeout:     5 * time.Minute,
		WriteBufferSize:     64 * 1024,
		ReadBufferSize:      64 * 1024,
		MaxIdleConnsPerHost: 4,
	}
	return &http.Client{Transport: authRoundTripper{base: tr, id: clientID}}
}

// authRoundTripper добавляет заголовок с паролем на каждый исходящий запрос.
// Так пароль проставляется единообразно и для hc.Post, и для hc.Do — не нужно
// трогать каждый вызов по отдельности.
type authRoundTripper struct {
	base http.RoundTripper
	id   string // значение X-Tunnel-Client (по умолчанию — clientID этого запуска)
}

func (a authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if authToken != "" {
		r.Header.Set(authHeader, authToken)
	}
	if linkCred != "" {
		r.Header.Set(linkHeader, linkCred)
		r.Header.Set(deviceHeader, deviceID) // к нему сервер привяжет ссылку
	}
	id := a.id
	if id == "" {
		id = clientID
	}
	r.Header.Set(clientHeader, id) // единица учёта для лимита -users
	if clientName != "" {
		// Кириллица и пробелы в заголовке — только percent-encoded.
		r.Header.Set(nameHeader, url.QueryEscape(clientName))
	}
	resp, err := a.base.RoundTrip(r)
	if resp != nil {
		noteUsers(resp.Header.Get(usersHeader))
	}
	return resp, err
}

// Последнее известное состояние лимита на сервере ("занято/лимит"). Приходит
// заголовком на каждом ответе, поэтому под нагрузкой обновляется мгновенно.
var (
	usersMu    sync.Mutex
	usersNow   int
	usersLimit int
	usersKnown bool
)

// noteUsers разбирает заголовок X-Tunnel-Users и, если число подключённых
// изменилось, печатает событие: строку USERS n/m для Android-обёртки или
// человекочитаемую строку в терминал.
func noteUsers(h string) {
	i := strings.IndexByte(h, '/')
	if i <= 0 {
		return
	}
	n, err1 := strconv.Atoi(h[:i])
	lim, err2 := strconv.Atoi(h[i+1:])
	if err1 != nil || err2 != nil {
		return
	}
	usersMu.Lock()
	changed := !usersKnown || n != usersNow || lim != usersLimit
	prev := usersNow
	first := !usersKnown
	usersNow, usersLimit, usersKnown = n, lim, true
	usersMu.Unlock()
	if !changed {
		return
	}
	if plainStats {
		fmt.Printf("USERS %d/%d\n", n, lim) // машиночитаемо для Android-обёртки
		return
	}
	switch {
	case first:
		logf("👥 пользователей на сервере: %d/%d", n, lim)
	case n > prev:
		logf("👥 подключился ещё один клиент — %d/%d", n, lim)
	default:
		logf("👥 клиент отключился — %d/%d", n, lim)
	}
}

// usersSnapshot — текущее «занято/лимит» для строки статистики.
func usersSnapshot() (n, limit int) {
	usersMu.Lock()
	defer usersMu.Unlock()
	return usersNow, usersLimit
}

func runClient(listen, ip, host string, conns int, udp bool) {
	if ip == "" || host == "" {
		fmt.Println("✗ Не задан сервер: укажите -ip и -host либо -link cdn://…")
		os.Exit(1)
	}
	st = &stats{role: "client"}
	if conns < 1 {
		conns = 1
	}
	tc := &tunnelClient{base: "https://" + host, udp: udp}
	for i := 0; i < conns; i++ {
		tc.pool = append(tc.pool, cdnClient(ip, host))
	}

	// hello-рукопожатие: убеждаемся, что достучались именно до нашего сервера.
	upDesc := clientTransport
	if clientTransport == "chunked" {
		upDesc = "chunked/" + clientMethod
	}
	fmt.Printf("Подключение к серверу через CDN %s (Host %s), апстрим: %s, fastopen=%v...\n", ip, host, upDesc, fastOpen)
	if err := tc.hello(); err != nil {
		fmt.Printf("✗ Не удалось подключиться: %v\n", err)
		fmt.Println("  Проверьте, что сервер запущен (go run main.go -server), IP/host и пароль верны.")
		os.Exit(1)
	}
	fmt.Println("✓ Успешно подключено к серверу")
	if clientName != "" {
		fmt.Printf("Имя клиента: %s\n", clientName)
	}
	fmt.Println("STATUS linked") // машиночитаемо для Android-обёртки

	// stream-транспорт требует CDN, не буферизующего тело запроса. Проверяем и,
	// если CDN буферизует, автоматически откатываемся на chunked — иначе VPN
	// просто «висел» бы без трафика вниз.
	if clientTransport == "stream" {
		fmt.Println("Проверяю потоковый апстрим (stream) через CDN…")
		if tc.streamWorks() {
			fmt.Println("✓ stream работает через этот CDN")
		} else {
			clientTransport = "chunked"
			fmt.Println("✗ CDN буферизует тело запроса — откат на chunked")
			fmt.Println("STATUS stream-fallback")
		}
	}

	go tc.keepWarm()    // тёплый пул + периодический замер RTT
	go tc.watchRoster() // список пользователей и счётчик онлайна в прямом эфире

	// По Ctrl-C / SIGTERM прощаемся с сервером, чтобы занятый слот (-users)
	// освободился сразу, а не через seatTTL.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		tc.bye()
		fmt.Println()
		os.Exit(0)
	}()

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Printf("✗ Не удалось открыть SOCKS5 на %s: %v\n", listen, err)
		os.Exit(1)
	}
	fmt.Printf("SOCKS5 прокси: %s\n\n", listen)
	st.connected.Store(true)
	go st.render()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go tc.handleSocks(conn)
	}
}

// doReq отправляет запрос клиент→сервер с необязательной нагрузкой выбранным
// методом: POST кладёт нагрузку в тело, GET — base64url в query-параметр
// payloadParam. Заголовок с паролем добавляет authRoundTripper.
func (tc *tunnelClient) doReq(ctx context.Context, hc *http.Client, path string, q url.Values, payloadParam string, payload []byte) (*http.Response, error) {
	u := tc.base + path
	if clientMethod == "get" {
		if payload != nil {
			q.Set(payloadParam, base64.RawURLEncoding.EncodeToString(payload))
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		return hc.Do(req)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return hc.Do(req)
}

func (tc *tunnelClient) hello() error {
	token := randID()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := tc.doReq(ctx, tc.pool[0], "/hello", url.Values{}, qToken, []byte(token))
	if err != nil {
		return fmt.Errorf("сервер недоступен (%v)", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		if strings.Contains(string(body), "link revoked") {
			fmt.Println("STATUS linkrevoked") // машиночитаемо для Android-обёртки
			return fmt.Errorf("эта ссылка отозвана владельцем сервера — попросите новую")
		}
		if strings.Contains(string(body), "banned") {
			fmt.Println("STATUS banned") // машиночитаемо для Android-обёртки
			return fmt.Errorf("доступ закрыт: клиент «%s» заблокирован владельцем сервера", clientName)
		}
		fmt.Println("STATUS authfail")
		return fmt.Errorf("неверный пароль (сервер вернул 403 forbidden)")
	}
	if resp.StatusCode == http.StatusConflict {
		fmt.Println("STATUS linkused") // машиночитаемо для Android-обёртки
		return fmt.Errorf("эта ссылка уже использована на другом устройстве — попросите новую")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		fmt.Println("STATUS userlimit") // машиночитаемо для Android-обёртки
		return fmt.Errorf("на сервере достигнуто максимальное число подключений (%s) — попробуйте позже",
			strings.TrimSpace(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер вернул статус %d", resp.StatusCode)
	}
	if string(body) != helloPrefix+token {
		return fmt.Errorf("неверный ответ — это точно наш сервер?")
	}
	st.rttMs.Store(time.Since(start).Milliseconds())
	return nil
}

// keepWarm держит соединения пула тёплыми (не платим TLS+slow-start после
// простоя) и периодически меряет RTT через /hello. Крошечный GET на «/» каждого
// клиента предотвращает закрытие idle-соединения и разогревает CDN-путь.
func (tc *tunnelClient) keepWarm() {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for range tick.C {
		// RTT-проба на pool[0].
		token := randID()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		start := time.Now()
		if resp, err := tc.doReq(ctx, tc.pool[0], "/hello", url.Values{}, qToken, []byte(token)); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusConflict {
				logf("⚠ ссылка занята другим устройством")
				fmt.Println("STATUS linkused")
			} else if resp.StatusCode == http.StatusTooManyRequests {
				// Слот отобрали (сервер перезапущен или лимит уменьшили).
				logf("⚠ сервер отклонил запрос: достигнуто максимальное число подключений")
				fmt.Println("STATUS userlimit")
			} else {
				st.rttMs.Store(time.Since(start).Milliseconds())
			}
		}
		cancel()
		// Разогреть остальные соединения пула.
		for i := 1; i < len(tc.pool); i++ {
			c, cc := context.WithTimeout(context.Background(), 8*time.Second)
			if resp, err := tc.doReq(c, tc.pool[i], "/hello", url.Values{}, qToken, []byte("ka")); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			cc()
		}
	}
}

// watchRoster раз в несколько секунд забирает у сервера список пользователей
// (кто онлайн, кто офлайн) и печатает его при каждом изменении: строкой
// ROSTER {json} для Android-обёртки или человекочитаемо в терминал. Счётчик
// «онлайн/лимит» приезжает заголовком на этом же запросе.
func (tc *tunnelClient) watchRoster() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	last := ""
	for range tick.C {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		resp, err := tc.doReq(ctx, tc.pool[0], usersPath, url.Values{}, "", nil)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusNotFound {
			logf("Сервер старой версии — список пользователей недоступен")
			return
		}
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var d usersDoc
		if json.Unmarshal(body, &d) != nil {
			continue
		}
		sig := rosterSignature(d)
		if sig == last {
			continue // ничего не изменилось — не шумим
		}
		last = sig
		if plainStats {
			fmt.Printf("ROSTER %s\n", string(body)) // машиночитаемо для Android-обёртки
			continue
		}
		logf("👥 %s", rosterSummary(d))
	}
}

// rosterSignature — отпечаток состава списка (без меняющихся отметок времени),
// чтобы печатать только настоящие изменения: кто-то подключился или отключился.
func rosterSignature(d usersDoc) string {
	parts := make([]string, 0, len(d.Users))
	for _, u := range d.Users {
		flag := "0"
		if u.Online {
			flag = "1"
		}
		parts = append(parts, u.Name+":"+flag)
	}
	sort.Strings(parts)
	return fmt.Sprintf("%d/%d|%s", d.Online, d.Limit, strings.Join(parts, ","))
}

// rosterSummary — однострочная сводка списка для терминала.
func rosterSummary(d usersDoc) string {
	var on, off []string
	for _, u := range d.Users {
		if u.Online {
			on = append(on, u.Name)
		} else {
			off = append(off, u.Name)
		}
	}
	limit := "без лимита"
	if d.Limit > 0 {
		limit = fmt.Sprintf("лимит %d", d.Limit)
	}
	out := fmt.Sprintf("онлайн %d (%s)", d.Online, limit)
	if len(on) > 0 {
		out += ": " + strings.Join(on, ", ")
	}
	if len(off) > 0 {
		out += " · офлайн: " + strings.Join(off, ", ")
	}
	return out
}

// bye сообщает серверу, что клиент уходит, — тот освобождает слот -users.
func (tc *tunnelClient) bye() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if resp, err := tc.doReq(ctx, tc.pool[0], "/bye", url.Values{}, "", nil); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (tc *tunnelClient) connect(hc *http.Client, id, target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := tc.doReq(ctx, hc, "/t/connect", url.Values{"id": {id}}, qTarget, []byte(target))
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connect status %d", resp.StatusCode)
	}
	return nil
}

func (tc *tunnelClient) up(hc *http.Client, id string, seq uint64, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := url.Values{"id": {id}, "seq": {strconv.FormatUint(seq, 10)}}
	resp, err := tc.doReq(ctx, hc, "/t/up", q, qData, data)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("up status %d", resp.StatusCode)
	}
	return nil
}

func (tc *tunnelClient) closeStream(hc *http.Client, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := tc.doReq(ctx, hc, "/t/close", url.Values{"id": {id}}, "", nil)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (tc *tunnelClient) relay(hc *http.Client, conn net.Conn, br io.Reader, id string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Вниз: длинный потоковый ответ (одинаково в обоих транспортах).
	go func() {
		defer conn.Close()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tc.base+"/t/down?id="+id, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		io.Copy(countWriter{conn, &st.down}, resp.Body)
	}()

	if clientTransport == "stream" {
		tc.relayUpStream(ctx, hc, br, id)
	} else {
		tc.relayUpChunked(hc, br, id)
	}
	tc.closeStream(hc, id)
	cancel()
}

// relayUpStream — апстрим одним длинным POST: тело запроса читается прямо из
// приложения. Нет нумерации/окна/реассемблера — порядок держит сам поток.
// Требует CDN, пропускающего streaming request body (иначе сервер не увидит
// байты до закрытия — используйте transport=chunked).
func (tc *tunnelClient) relayUpStream(ctx context.Context, hc *http.Client, br io.Reader, id string) {
	body := io.NopCloser(&countReader{r: br, c: &st.up})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tc.base+"/t/ups?id="+id, body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// streamWorks проверяет, пропускает ли CDN потоковый апстрим (streaming request
// body). Открывает стрим к известному хосту, шлёт HTTP-запрос потоковым телом и
// ждёт любой байт вниз. Если CDN буферизует тело запроса — ответ не придёт и
// вернётся false (тогда клиент откатывается на chunked).
func (tc *tunnelClient) streamWorks() bool {
	hc := tc.pool[0]
	id := randID()
	if err := tc.connect(hc, id, "connectivitycheck.gstatic.com:80"); err != nil {
		return true // проверить не смогли — не отключаем stream
	}
	defer tc.closeStream(hc, id)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	gotDown := make(chan bool, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tc.base+"/t/down?id="+id, nil)
		resp, err := hc.Do(req)
		if err != nil {
			gotDown <- false
			return
		}
		defer resp.Body.Close()
		b := make([]byte, 1)
		n, _ := resp.Body.Read(b)
		gotDown <- n > 0
	}()

	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n"))
		<-ctx.Done()
		pw.Close()
	}()
	upReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, tc.base+"/t/ups?id="+id, pr)
	upReq.Header.Set("Content-Type", "application/octet-stream")
	go func() {
		if resp, err := hc.Do(upReq); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	select {
	case ok := <-gotDown:
		return ok
	case <-ctx.Done():
		return false
	}
}

// relayUpChunked — апстрим множеством нумерованных запросов с окном в полёте.
func (tc *tunnelClient) relayUpChunked(hc *http.Client, br io.Reader, id string) {
	// В GET-режиме данные едут в URL (base64url) — держим кусок маленьким.
	upChunk := 64 * 1024
	if clientMethod == "get" {
		upChunk = 4 * 1024
	}
	sem := make(chan struct{}, upWindow)
	var wg sync.WaitGroup
	var upErr atomic.Bool
	var seq uint64
	for {
		buf := make([]byte, upChunk)
		n, err := br.Read(buf)
		if n > 0 {
			if upErr.Load() {
				break
			}
			st.up.Add(uint64(n))
			sem <- struct{}{}
			wg.Add(1)
			go func(s uint64, data []byte) {
				defer wg.Done()
				defer func() { <-sem }()
				if e := tc.up(hc, id, s, data); e != nil {
					upErr.Store(true)
				}
			}(seq, buf[:n])
			seq++
		}
		if err != nil {
			break
		}
	}
	wg.Wait()
}

// ============================ SOCKS5 ============================

func socksReply(status byte) []byte {
	return []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

func (tc *tunnelClient) handleSocks(conn net.Conn) {
	defer conn.Close()
	tuneConn(conn) // без Nagle — мелкие интерактивные записи уходят сразу
	br := bufio.NewReader(conn)

	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	nm, err := br.ReadByte()
	if err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(nm)); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00})

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	cmd, atyp := hdr[1], hdr[3]

	var host string
	switch atyp {
	case 0x01:
		a := make([]byte, 4)
		if _, err := io.ReadFull(br, a); err != nil {
			return
		}
		host = net.IP(a).String()
	case 0x03:
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		d := make([]byte, l)
		if _, err := io.ReadFull(br, d); err != nil {
			return
		}
		host = string(d)
	case 0x04:
		a := make([]byte, 16)
		if _, err := io.ReadFull(br, a); err != nil {
			return
		}
		host = net.IP(a).String()
	default:
		conn.Write(socksReply(0x08))
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))

	hc := tc.pick()

	switch cmd {
	case 0x01: // CONNECT
	case 0x03: // UDP ASSOCIATE
		if !tc.udp {
			// UDP выключен → браузер уходит на TCP-fallback (QUIC → HTTP/2 по TCP).
			conn.Write(socksReply(0x07))
			return
		}
		tc.handleUDPAssociate(conn, hc)
		return
	default:
		conn.Write(socksReply(0x07))
		return
	}

	id := randID()
	if fastOpen {
		// Оптимистично: сразу отвечаем «успех», чтобы приложение начало слать
		// первые байты (ClientHello и т.п.) не дожидаясь RTT на connect. Эти
		// байты копятся в буфере сокета и relay их прочитает. Если connect
		// провалится — соединение просто рвётся (для веба это редко и дёшево).
		conn.Write(socksReply(0x00))
		if err := tc.connect(hc, id, target); err != nil {
			return
		}
	} else {
		if err := tc.connect(hc, id, target); err != nil {
			conn.Write(socksReply(0x04))
			return
		}
		conn.Write(socksReply(0x00))
	}
	st.conns.Add(1)
	st.total.Add(1)
	defer st.conns.Add(-1)
	tc.relay(hc, conn, br, id)
}

// ============================ SOCKS5 UDP ASSOCIATE ============================

func (tc *tunnelClient) udpOpen(hc *http.Client, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := tc.doReq(ctx, hc, "/u/open", url.Values{"id": {id}}, "", nil)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("udp open status %d", resp.StatusCode)
	}
	return nil
}

func (tc *tunnelClient) udpSend(hc *http.Client, id string, frame []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := tc.doReq(ctx, hc, "/u/send", url.Values{"id": {id}}, qData, frame)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func (tc *tunnelClient) udpClose(hc *http.Client, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := tc.doReq(ctx, hc, "/u/close", url.Values{"id": {id}}, "", nil)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (tc *tunnelClient) handleUDPAssociate(conn net.Conn, hc *http.Client) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		conn.Write(socksReply(0x01))
		return
	}
	defer relay.Close()
	relay.SetReadBuffer(4 << 20)
	relay.SetWriteBuffer(4 << 20)
	la := relay.LocalAddr().(*net.UDPAddr)
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(la.Port >> 8), byte(la.Port)})

	id := randID()
	if err := tc.udpOpen(hc, id); err != nil {
		return
	}
	defer tc.udpClose(hc, id)
	st.conns.Add(1)
	st.total.Add(1)
	defer st.conns.Add(-1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var appAddr atomic.Pointer[net.UDPAddr]

	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tc.base+"/u/down?id="+id, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		h := make([]byte, 2)
		for {
			if _, err := io.ReadFull(resp.Body, h); err != nil {
				return
			}
			al := binary.BigEndian.Uint16(h)
			addr := make([]byte, al)
			if _, err := io.ReadFull(resp.Body, addr); err != nil {
				return
			}
			if _, err := io.ReadFull(resp.Body, h); err != nil {
				return
			}
			dl := binary.BigEndian.Uint16(h)
			data := make([]byte, dl)
			if _, err := io.ReadFull(resp.Body, data); err != nil {
				return
			}
			if aa := appAddr.Load(); aa != nil {
				relay.WriteToUDP(buildSocksUDP(string(addr), data), aa)
				st.udpDown.Add(uint64(len(data)))
			}
		}
	}()

	go func() {
		io.Copy(io.Discard, conn)
		cancel()
		relay.SetReadDeadline(time.Now())
	}()

	// Апстрим датаграмм: батчинг микро-окном + конвейер без ожидания.
	// UDP не требует порядка, поэтому копим пачку ~2мс/32КБ и шлём параллельно —
	// это убирает RTT-на-пакет и делает QUIC-через-TCP пригодным для видео.
	sendCh := make(chan []byte, 2048)
	go tc.udpBatcher(hc, id, sendCh)

	buf := make([]byte, 65535)
	for {
		n, aaddr, err := relay.ReadFromUDP(buf)
		if n > 0 {
			appAddr.Store(aaddr)
			if tgt, data, ok := parseSocksUDP(buf[:n]); ok {
				st.udpUp.Add(uint64(len(data)))
				frame := encodeFrame(tgt, data)
				select {
				case sendCh <- frame:
				default: // переполнение — роняем датаграмму (нормально для UDP)
				}
			}
		}
		if err != nil {
			close(sendCh)
			return
		}
	}
}

// udpBatcher копит датаграммы и шлёт их пачками, до inflight POST'ов в полёте.
func (tc *tunnelClient) udpBatcher(hc *http.Client, id string, in <-chan []byte) {
	maxBatch := 60 * 1024
	if clientMethod == "get" {
		maxBatch = 4 * 1024 // GET: датаграммы едут в URL — короткие пачки
	}
	const (
		window   = 4 * time.Millisecond
		inflight = 48
	)
	sem := make(chan struct{}, inflight)
	ticker := time.NewTicker(window)
	defer ticker.Stop()
	var batch []byte

	flush := func() {
		if len(batch) == 0 {
			return
		}
		b := batch
		batch = nil
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			tc.udpSend(hc, id, b)
		}()
	}

	for {
		select {
		case f, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = append(batch, f...)
			if len(batch) >= maxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func parseSocksUDP(p []byte) (target string, data []byte, ok bool) {
	if len(p) < 4 || p[2] != 0 {
		return "", nil, false
	}
	atyp := p[3]
	i := 4
	var host string
	switch atyp {
	case 0x01:
		if len(p) < i+6 {
			return "", nil, false
		}
		host = net.IP(p[i : i+4]).String()
		i += 4
	case 0x03:
		if len(p) < i+1 {
			return "", nil, false
		}
		l := int(p[i])
		i++
		if len(p) < i+l+2 {
			return "", nil, false
		}
		host = string(p[i : i+l])
		i += l
	case 0x04:
		if len(p) < i+18 {
			return "", nil, false
		}
		host = net.IP(p[i : i+16]).String()
		i += 16
	default:
		return "", nil, false
	}
	port := binary.BigEndian.Uint16(p[i : i+2])
	i += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), p[i:], true
}

func buildSocksUDP(src string, data []byte) []byte {
	host, portStr, _ := net.SplitHostPort(src)
	port, _ := strconv.Atoi(portStr)
	out := []byte{0, 0, 0}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		out = append(out, 0x01)
		out = append(out, ip.To4()...)
	case ip != nil:
		out = append(out, 0x04)
		out = append(out, ip.To16()...)
	default:
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	out = append(out, pb[:]...)
	return append(out, data...)
}
