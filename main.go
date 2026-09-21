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
	"errors"
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
		state     = flag.String("state", defaultStatePath, "файл реестра выпущенных ссылок (режим -server; пусто = не сохранять)")
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
		p.applyTo(ip, host, pass, conns, udp, method, transport)
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
			UDP: *udp, Method: *method, Transport: *transport,
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

// linkCred — удостоверение ссылки ("<id>.<подпись>"), если клиент запущен по
// cdn://-ссылке. Едет в заголовке X-Tunnel-Link вместо мастер-пароля.
var linkCred string

// deviceID — отпечаток этого устройства: сервер привязывает к нему ссылку.
var deviceID string

// statePath — где сервер хранит реестр выпущенных ссылок между перезапусками.
var statePath string

// defaultStatePath — файл реестра по умолчанию (создаётся при старте сервера;
// если каталог недоступен, сохранение просто выключается).
const defaultStatePath = "/var/lib/cdn-tunnel/links.json"

// clientID — случайный идентификатор этого запуска клиента; едет в заголовке
// X-Tunnel-Client. Сервер его не использует для доступа (доступ решает ссылка),
// он нужен только чтобы различать запросы одного запуска в журналах.
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

// clientHeader несёт идентификатор запуска клиента (см. clientID).
const clientHeader = "X-Tunnel-Client"

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
	online    atomic.Int64 // сколько ссылок сейчас на линии (сервер)
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
			fmt.Printf("STATS down=%d up=%d udpDown=%d udpUp=%d conns=%d total=%d downRate=%.0f upRate=%.0f rtt=%d\n",
				down, up, s.udpDown.Load(), s.udpUp.Load(),
				s.conns.Load(), s.total.Load(), downRate, upRate, s.rttMs.Load())
			continue
		}

		// Под systemd/journald перерисовывать строку через \r нечем — там это
		// просто мусор в логе. Пишем короткую сводку раз в минуту.
		if !stdoutTTY {
			if now.Sub(lastQuiet) < time.Minute {
				continue
			}
			lastQuiet = now
			fmt.Printf("сводка: на линии %d, стримов %d (всего %d) · ↓ %s (%s/s) · ↑ %s (%s/s)\n",
				s.online.Load(), s.conns.Load(), s.total.Load(),
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
		if s.role == "server" {
			rtt += fmt.Sprintf(" │ на линии %d", s.online.Load())
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
	Label     string `json:"label,omitempty"` // подпись профиля, для показа в приложении
}

// applyTo переносит параметры ссылки в разобранные флаги клиента.
func (p shareParams) applyTo(ip, host, pass *string, conns *int, udp *bool, method, transport *string) {
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
}

// ---- удостоверение ссылки: "<id>.<подпись>" ----
//
// Владелец сервера выпускает ссылку, подписывая случайный id мастер-секретом
// (-password); сам секрет в ссылку не попадает. Подпись доказывает, что ссылку
// выпустил владелец, но доступ даёт не она, а запись в реестре сервера: пускают
// только ссылки, которые там есть и не отозваны (см. linkGate.useLink).
// Первое устройство, пришедшее с таким id, к нему и привязывается.

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

// ============================ ССЫЛКИ ============================

// linkTTL — сколько молчания клиента считается отключением. Клиент пингует
// сервер каждые 15 секунд, так что это три пропущенных пинга подряд.
const linkTTL = 45 * time.Second

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

// setOnline обновляет счётчик «на линии» в HUD (в тестах HUD не поднят).
func setOnline(n int) {
	if st != nil {
		st.online.Store(int64(n))
	}
}

// shortID укорачивает идентификатор для журнала. Режем по рунам: сюда попадают
// не только hex-идентификаторы, но и произвольные отпечатки устройств.
func shortID(key string) string {
	r := []rune(key)
	if len(r) > 8 {
		return string(r[:8]) + "…"
	}
	return key
}

// cleanName приводит подпись ссылки к виду, пригодному для журнала и панели:
// без управляющих символов и не длиннее 64 байт.
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

// ============================ ДОСТУП ============================
//
// Единственная сущность — ссылка cdn://. Реестр ссылок на сервере авторитетен:
// подключиться можно только по той ссылке, которая в реестре есть и не отозвана.
// Подпись удостоверения (HMAC мастер-ключа) лишь подтверждает, что ссылку
// выпускал владелец этого сервера; доступа сама по себе она не даёт. Поэтому
// удалённая в панели ссылка мертва навсегда — переподключением её не воскресить.
//
// Владелец сервера ходит напрямую по мастер-ключу, ссылка ему не нужна.

// linkRec — выпущенная ссылка: всё, что сервер помнит о ней между перезапусками.
type linkRec struct {
	ID       string `json:"id"`
	Label    string `json:"label"`   // подпись: «Андрею», «ноут» и т.п.
	Created  int64  `json:"created"` // когда выпущена, unix-секунды
	Device   string `json:"device,omitempty"`
	FirstUse int64  `json:"first_use,omitempty"`
	LastUse  int64  `json:"last_use,omitempty"`
	Up       uint64 `json:"up"`   // отдано по ссылке за всё время, байт
	Down     uint64 `json:"down"` // получено по ссылке за всё время, байт
	Revoked  bool   `json:"revoked,omitempty"`
}

// linkView — ссылка в ответе панели: запись из реестра плюс то, что известно
// только сейчас, — на линии ли она и с какого адреса.
type linkView struct {
	linkRec
	Online bool   `json:"online,omitempty"`
	Since  int64  `json:"since,omitempty"` // на линии с какого времени
	IP     string `json:"ip,omitempty"`
}

// live — соединение, идущее прямо сейчас.
type live struct {
	ip    string
	since time.Time
	last  time.Time
}

// serverState — то, что сервер хранит между перезапусками.
type serverState struct {
	Links []*linkRec `json:"links"`
}

// ownerKey — под этим ключом учитывается владелец, вошедший по мастер-ключу.
// Не из hex-алфавита, поэтому с идентификатором ссылки не столкнётся.
const ownerKey = "owner"

// linkGate — реестр ссылок и учёт тех, кто сейчас на линии.
type linkGate struct {
	mu      sync.Mutex
	links   map[string]*linkRec  // id ссылки → всё, что о ней известно
	live    map[string]*live     // id ссылки (или ownerKey) → живое соединение
	lastLog map[string]time.Time // троттлинг журнала отказов: клиент ретраится
	path    string               // файл состояния ("" — не сохранять)
	dirty   bool                 // есть несохранённые счётчики трафика
}

func newLinkGate() *linkGate {
	return &linkGate{
		links:   map[string]*linkRec{},
		live:    map[string]*live{},
		lastLog: map[string]time.Time{},
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

// Причины отказа: едут клиенту в теле ответа, он переводит их в STATUS-строки.
const (
	denyForbidden = "forbidden"     // ни мастер-ключа, ни верной подписи ссылки
	denyUnknown   = "link unknown"  // ссылки нет в реестре — удалена владельцем
	denyRevoked   = "link revoked"  // ссылка отозвана
	denyUsed      = "link occupied" // ссылка занята другим устройством
)

// isOwner сверяет мастер-ключ в постоянное время. Сервер без пароля защищать
// нечем: там владелец — кто угодно.
func isOwner(r *http.Request) bool {
	if authToken == "" {
		return true
	}
	got := []byte(r.Header.Get(authHeader))
	return subtle.ConstantTimeCompare(got, []byte(authToken)) == 1
}

// admit — единственная точка, решающая судьбу запроса. Возвращает ключ учёта
// (по нему пишется трафик) и, при отказе, его причину.
func (g *linkGate) admit(r *http.Request) (key string, ok bool, why string) {
	if isOwner(r) {
		g.seen(ownerKey, clientIP(r))
		return ownerKey, true, ""
	}
	id, signed := checkCred(authToken, r.Header.Get(linkHeader))
	if !signed {
		return "", false, denyForbidden
	}
	return g.useLink(id, r.Header.Get(deviceHeader), clientIP(r))
}

// billKey — ключ учёта запроса без побочных эффектов: им подписываются стримы,
// чтобы трафик лёг на нужную ссылку. Запрос к этому моменту уже пропущен admit.
func billKey(r *http.Request) string {
	if isOwner(r) {
		return ownerKey
	}
	id, _ := checkCred(authToken, r.Header.Get(linkHeader))
	return id
}

// useLink сверяет ссылку с реестром и, если всё в порядке, отмечает её живой.
// Последнее слово здесь за реестром: верной подписи мало, запись должна быть.
func (g *linkGate) useLink(id, device, ip string) (string, bool, string) {
	if device == "" {
		device = "unknown" // клиент без отпечатка: привяжем хотя бы к «неизвестному»
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	switch {
	case rec == nil:
		// Ссылку удалили в панели (или выпустил другой сервер): доступа нет, и
		// заново запись не заводится — иначе удаление ничего бы не значило.
		g.denyLog(now, "gone:"+id, "⛔ ссылка %s удалена — отказ (%s)", shortID(id), ip)
		return "", false, denyUnknown
	case rec.Revoked:
		g.denyLog(now, "rev:"+id, "⛔ %s отозвана — отказ (%s)", linkTitle(rec), ip)
		return "", false, denyRevoked
	case rec.Device == "":
		rec.Device, rec.FirstUse, rec.LastUse = device, now.Unix(), now.Unix()
		logf("🔗 %s привязана к устройству %s", linkTitle(rec), shortID(device))
		g.saveLocked()
	case rec.Device != device:
		g.denyLog(now, "dev:"+id, "⚠ %s занята другим устройством — отказ (%s)", linkTitle(rec), ip)
		return "", false, denyUsed
	default:
		rec.LastUse = now.Unix()
	}
	g.seenLocked(id, ip)
	return id, true, ""
}

// linkTitle — как называть ссылку в журнале: по подписи, если владелец её дал.
func linkTitle(rec *linkRec) string {
	if rec.Label != "" {
		return "ссылка «" + rec.Label + "»"
	}
	return "ссылка " + shortID(rec.ID)
}

// titleLocked — название ключа учёта для журнала.
func (g *linkGate) titleLocked(key string) string {
	if key == ownerKey {
		return "владелец"
	}
	if rec := g.links[key]; rec != nil {
		return linkTitle(rec)
	}
	return "ссылка " + shortID(key)
}

// denyLog пишет отказ не чаще раза в 5 секунд на причину: отклонённый клиент
// ретраится, и без троттлинга журнал заливает одинаковыми строками.
func (g *linkGate) denyLog(now time.Time, key, format string, args ...any) {
	if last, ok := g.lastLog[key]; ok && now.Sub(last) < 5*time.Second {
		return
	}
	g.lastLog[key] = now
	logf(format, args...)
}

// seen отмечает клиента живым (обёртка seenLocked под замком).
func (g *linkGate) seen(key, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seenLocked(key, ip)
}

// seenLocked заводит запись о соединении при первом запросе и продлевает её на
// каждом следующем.
func (g *linkGate) seenLocked(key, ip string) {
	now := time.Now()
	g.expireLocked(now)
	if l := g.live[key]; l != nil {
		l.last, l.ip = now, ip
		return
	}
	g.live[key] = &live{ip: ip, since: now, last: now}
	setOnline(len(g.live))
	logf("＋ подключение: %s (%s) — на линии %d", g.titleLocked(key), ip, len(g.live))
}

// expireLocked снимает с линии тех, кто замолчал дольше linkTTL.
func (g *linkGate) expireLocked(now time.Time) {
	for k, l := range g.live {
		if now.Sub(l.last) > linkTTL {
			delete(g.live, k)
			logf("－ отключение: %s (простой > %s) — на линии %d", g.titleLocked(k), linkTTL, len(g.live))
		}
	}
	for k, t := range g.lastLog {
		if now.Sub(t) > time.Minute {
			delete(g.lastLog, k)
		}
	}
	setOnline(len(g.live))
}

// release снимает клиента с линии по его явному «прощанию» (/bye): после
// перезапуска клиента панель не ждёт истечения linkTTL.
func (g *linkGate) release(key string) {
	if key == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.live[key]; !ok {
		return
	}
	title := g.titleLocked(key)
	delete(g.live, key)
	setOnline(len(g.live))
	logf("－ отключение: %s — на линии %d", title, len(g.live))
}

// addTraffic приписывает прошедшие байты ссылке, по которой пришёл клиент.
// Вызывается на каждом куске данных, поэтому без записи на диск: состояние
// сбрасывает sweep раз в полминуты. Трафик владельца ссылке не принадлежит.
func (g *linkGate) addTraffic(key string, up, down uint64) {
	if key == "" || key == ownerKey || (up == 0 && down == 0) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if rec := g.links[key]; rec != nil {
		rec.Up += up
		rec.Down += down
		g.dirty = true
	}
}

// ---- управление ссылками (из панели) ----

// issueLink выпускает ссылку и сразу заносит её в реестр: владелец видит её в
// панели ещё до того, как ей кто-то воспользуется.
func (g *linkGate) issueLink(label string) *linkRec {
	b := make([]byte, 8)
	rand.Read(b)
	rec := &linkRec{ID: hex.EncodeToString(b), Label: cleanName(label), Created: time.Now().Unix()}
	g.mu.Lock()
	g.links[rec.ID] = rec
	g.saveLocked()
	g.mu.Unlock()
	logf("🔗 выпущена %s", linkTitle(rec))
	return rec
}

// setRevoked отзывает ссылку или возвращает её в строй. Отозванная остаётся в
// реестре со счётчиками, но клиент по ней получает отказ.
func (g *linkGate) setRevoked(id string, on bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	if rec == nil {
		return false
	}
	rec.Revoked = on
	if on {
		g.dropLiveLocked(id)
	}
	g.saveLocked()
	if on {
		logf("🔗 %s отозвана — доступ закрыт", linkTitle(rec))
	} else {
		logf("🔗 %s снова активна", linkTitle(rec))
	}
	return true
}

// deleteLink стирает ссылку из реестра: доступ по ней закрыт навсегда, потому
// что сервер пускает только то, что в реестре есть.
func (g *linkGate) deleteLink(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	if rec == nil {
		return false
	}
	delete(g.links, id)
	g.dropLiveLocked(id)
	g.saveLocked()
	logf("🔗 %s удалена — доступ по ней закрыт навсегда", linkTitle(rec))
	return true
}

// dropLiveLocked снимает с линии того, кто сидит по этой ссылке.
func (g *linkGate) dropLiveLocked(id string) {
	if _, ok := g.live[id]; !ok {
		return
	}
	delete(g.live, id)
	setOnline(len(g.live))
}

// kickLink снимает клиента с линии, оставляя ссылку рабочей: он переподключится
// сам — удобно, чтобы согнать зависшую сессию.
func (g *linkGate) kickLink(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.live[id]; !ok {
		return false
	}
	title := g.titleLocked(id)
	g.dropLiveLocked(id)
	logf("⏏ сброшено с линии администратором: %s", title)
	return true
}

// unbindLink снимает привязку к устройству: ссылку можно открыть на другом.
func (g *linkGate) unbindLink(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.links[id]
	if rec == nil {
		return false
	}
	rec.Device, rec.FirstUse = "", 0
	g.dropLiveLocked(id)
	g.saveLocked()
	logf("🔗 %s отвязана от устройства — можно открыть на другом", linkTitle(rec))
	return true
}

// unbindAll снимает привязки со всех ссылок сразу.
func (g *linkGate) unbindAll() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for id, rec := range g.links {
		if rec.Device == "" {
			continue
		}
		rec.Device, rec.FirstUse = "", 0
		g.dropLiveLocked(id)
		n++
	}
	if n > 0 {
		g.saveLocked()
		logf("🔗 снято привязок: %d", n)
	}
	return n
}

// renameLink меняет подпись ссылки.
func (g *linkGate) renameLink(id, label string) bool {
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

// view собирает реестр для панели: на линии — сверху, дальше по свежести.
func (g *linkGate) view() (out []linkView, online int) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expireLocked(now)
	for id, rec := range g.links {
		v := linkView{linkRec: *rec}
		if l := g.live[id]; l != nil {
			v.Online, v.Since, v.IP, v.LastUse = true, l.since.Unix(), l.ip, now.Unix()
		}
		out = append(out, v)
	}
	online = len(g.live)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Online != b.Online {
			return a.Online
		}
		if a.LastUse != b.LastUse {
			return a.LastUse > b.LastUse
		}
		return a.Created > b.Created
	})
	return out, online
}

// ---- сохранение реестра между перезапусками ----

// loadLinks поднимает реестр с диска: сервис перезапускается (в том числе по
// RuntimeMaxSec), а выпущенные ссылки и их счётчики должны пережить это.
func (g *linkGate) loadLinks(path string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.path = path
	if path == "" {
		return
	}
	// openState создаёт файл при старте, так что пустой файл — норма.
	if b, err := os.ReadFile(path); err == nil {
		g.addLinksLocked(b)
	}
	logf("Реестр загружен: ссылок %d (%s)", len(g.links), path)
	g.migrateLegacyLocked(path)
}

// migrateLegacyLocked переносит ссылки из реестра сервера версии 1.x: тот
// хранил их вместе со списком клиентов в users.json. Перенос одноразовый —
// старый файл сразу переименовывается. Иначе удалённая владельцем ссылка
// воскресала бы при каждом перезапуске, а это ровно то, от чего мы ушли.
func (g *linkGate) migrateLegacyLocked(path string) {
	legacy := filepath.Join(filepath.Dir(path), "users.json")
	if legacy == path {
		return
	}
	b, err := os.ReadFile(legacy)
	if err != nil {
		return
	}
	added := g.addLinksLocked(b)
	if added > 0 {
		g.saveLocked()
		logf("Перенесено ссылок из реестра прежней версии: %d (%s)", added, legacy)
	}
	// Файл отработал — убираем, чтобы он больше никогда не участвовал в загрузке.
	if os.Rename(legacy, legacy+".migrated") == nil && added == 0 {
		logf("Реестр прежней версии (%s) пуст — отложен", legacy)
	}
}

// addLinksLocked добавляет в реестр ссылки из JSON, не трогая уже известные.
// Возвращает, сколько записей добавилось.
func (g *linkGate) addLinksLocked(b []byte) int {
	if len(bytes.TrimSpace(b)) == 0 {
		return 0
	}
	var stt serverState
	if json.Unmarshal(b, &stt) != nil {
		return 0
	}
	n := 0
	for _, l := range stt.Links {
		if l == nil || l.ID == "" || g.links[l.ID] != nil {
			continue
		}
		g.links[l.ID] = l
		n++
	}
	return n
}

func (g *linkGate) saveLocked() {
	if g.path == "" {
		return
	}
	stt := serverState{Links: make([]*linkRec, 0, len(g.links))}
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

// sweep снимает с линии протухших и без входящих запросов, чтобы панель не
// врала, пока сервер простаивает, и сбрасывает счётчики трафика на диск.
func (g *linkGate) sweep() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	saveEvery := 0
	for range tick.C {
		g.mu.Lock()
		g.expireLocked(time.Now())
		// Счётчики пишем раз в полминуты, а не на каждом килобайте.
		if saveEvery++; saveEvery >= 6 && g.dirty {
			saveEvery = 0
			g.dirty = false
			g.saveLocked()
		}
		g.mu.Unlock()
	}
}

// ============================ ПАНЕЛЬ ============================
//
// Ручки /admin/* — для владельца сервера: они требуют мастер-ключ (-password) и
// удостоверением ссылки не открываются. Приложение ходит в них по SSH через
// curl на localhost, поэтому наружу их светить не нужно.

const adminPath = "/admin"

// adminDoc — снимок состояния сервера для панели управления.
type adminDoc struct {
	Version  string     `json:"version"`
	Uptime   int64      `json:"uptime"` // секунд с запуска
	Online   int        `json:"online"` // сколько сейчас на линии
	LinkTTL  int        `json:"link_ttl"`
	Streams  int        `json:"streams"`
	UDP      int        `json:"udp"`
	Up       uint64     `json:"up"`    // всего вверх с момента запуска
	Down     uint64     `json:"down"`  // всего вниз с момента запуска
	Total    int64      `json:"total"` // всего соединений с запуска
	Method   string     `json:"method"`
	Password bool       `json:"password"` // задан ли мастер-ключ
	State    string     `json:"state"`    // файл реестра ("" — не сохраняется)
	Links    []linkView `json:"links"`
}

// serverVersion — версия серверной части. Приложение сверяет её со своей и
// подсказывает обновить сервер, если он старее, чем ручки, которые оно зовёт.
const serverVersion = "2.0"

var serverStarted = time.Now()

// adminDoc собирает полный снимок: реестр ссылок и состояние самого сервера.
func (g *linkGate) adminDoc(ts *tunnelServer) adminDoc {
	d := adminDoc{
		Version:  serverVersion,
		Uptime:   int64(time.Since(serverStarted).Seconds()),
		LinkTTL:  int(linkTTL / time.Second),
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
	d.Links, d.Online = g.view()
	return d
}

// routeAdmin вешает ручки управления. Мастер-ключ уже проверен в middleware.
func (g *linkGate) routeAdmin(mux *http.ServeMux, ts *tunnelServer) {
	mux.HandleFunc(adminPath, func(w http.ResponseWriter, r *http.Request) {
		b, err := json.Marshal(g.adminDoc(ts))
		if err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	mux.HandleFunc(adminPath+"/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		id := q.Get("id")
		action := strings.TrimPrefix(r.URL.Path, adminPath+"/")
		res := map[string]any{"ok": true, "action": action}
		switch action {
		case "link/new":
			rec := g.issueLink(q.Get("label"))
			res["id"] = rec.ID
			res["cred"] = rec.ID + "." + credMAC(authToken, rec.ID)
			res["label"] = rec.Label
		case "link/revoke":
			res["ok"] = g.setRevoked(id, true)
		case "link/restore":
			res["ok"] = g.setRevoked(id, false)
		case "link/delete":
			res["ok"] = g.deleteLink(id)
		case "link/unbind":
			if q.Get("all") == "1" {
				res["unbound"] = g.unbindAll()
			} else {
				res["ok"] = g.unbindLink(id)
			}
		case "link/kick":
			res["ok"] = g.kickLink(id)
		case "link/rename":
			res["ok"] = g.renameLink(id, q.Get("label"))
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

// denyReply отвечает отказом. Причина едет текстом: клиент по ней печатает
// STATUS-строку, которую читает Android-обёртка.
func denyReply(w http.ResponseWriter, why string) {
	code := http.StatusForbidden
	if why == denyUsed {
		code = http.StatusConflict
	}
	http.Error(w, why, code)
}

// middleware решает доступ к каждому запросу и ведёт учёт. Корень "/" открыт
// всем: сервер должен выглядеть обычным origin для CDN и сканеров.
func (g *linkGate) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}
		// Панель — только мастер-ключ: удостоверением ссылки не открывается и
		// на линии не учитывается, это не клиент туннеля.
		if r.URL.Path == adminPath || strings.HasPrefix(r.URL.Path, adminPath+"/") {
			if !isOwner(r) {
				http.Error(w, denyForbidden, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		key, ok, why := g.admit(r)
		if !ok {
			denyReply(w, why)
			return
		}
		if r.URL.Path == "/bye" {
			g.release(key)
		}
		next.ServeHTTP(w, r)
	})
}

type tunnelServer struct {
	mu      sync.Mutex
	streams map[string]*stream
	udp     map[string]*udpSession
	gate    *linkGate // учёт трафика по ссылкам (может быть nil в тестах)
}

// bill приписывает байты ссылке, которой принадлежит стрим.
func (t *tunnelServer) bill(key string, up, down uint64) {
	if t.gate != nil {
		t.gate.addTraffic(key, up, down)
	}
}

func runServer(addr string) {
	st = &stats{role: "server"}
	st.connected.Store(true)
	gate := newLinkGate()
	gate.loadLinks(openState(statePath))
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
	// Клиент зовёт /bye при завершении — ссылка сразу уходит с линии.
	mux.HandleFunc("/bye", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tunnel server ok\n"))
	})

	gate.routeAdmin(mux, ts)
	// middleware — единственная проверка доступа: мастер-ключ владельца либо
	// ссылка, которая есть в реестре и не отозвана.
	var handler http.Handler = gate.middleware(mux)
	go gate.sweep()
	if authToken != "" {
		fmt.Printf("Доступ: мастер-ключ владельца или выпущенная ссылка (ссылка уходит с линии через %s молчания или по /bye).\n", linkTTL)
	} else {
		fmt.Println("ВНИМАНИЕ: мастер-ключ не задан (-password пуст) — туннель открыт для всех, кто знает адрес, и ссылки выпускать нечем.")
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
		fmt.Printf("Реестр ссылок не сохраняется (%v)\n", err)
		return ""
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Printf("Реестр ссылок не сохраняется (%v)\n", err)
		return ""
	}
	f.Close()
	return path
}

// authMiddleware требует верный пароль в заголовке X-Tunnel-Auth на всех путях,
// кроме корня "/" (он отдаёт безобидный текст — так сервер выглядит как обычный
// origin для CDN и случайных сканеров). Сравнение — в постоянное время, чтобы
// не утекала длина/содержимое пароля через тайминг.
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
	s := &stream{user: billKey(r), id: id, conn: conn, down: make(chan []byte, 1024), done: make(chan struct{}), upBuf: make(map[uint64][]byte)}
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
	u := &udpSession{user: billKey(r), id: id, pc: pc, down: make(chan []byte, 4096), done: make(chan struct{})}
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
	r.Header.Set(clientHeader, id)
	return a.base.RoundTrip(r)
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

	go tc.keepWarm() // тёплый пул + периодический замер RTT

	// По Ctrl-C / SIGTERM прощаемся с сервером, чтобы ссылка ушла с линии
	// сразу, а не через linkTTL.
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

// deny — как показать отказ сервера: строкой STATUS для Android-обёртки и
// человеку в терминал.
type deny struct {
	status string
	text   string
}

// denyReason переводит ответ сервера в причину отказа. Сервер присылает её
// текстом (см. denyReply), и это единственное место, где она разбирается.
func denyReason(code int, body string) (deny, bool) {
	switch {
	case code == http.StatusConflict || strings.Contains(body, denyUsed):
		return deny{"linkused", "ссылка уже используется на другом устройстве — попросите владельца отвязать её или выдать новую"}, true
	case code != http.StatusForbidden:
		return deny{}, false
	case strings.Contains(body, denyUnknown):
		return deny{"linkgone", "этой ссылки больше нет на сервере — владелец её удалил, попросите новую"}, true
	case strings.Contains(body, denyRevoked):
		return deny{"linkrevoked", "ссылка отозвана владельцем сервера — попросите новую"}, true
	}
	if linkCred != "" {
		return deny{"linkbad", "сервер не принял ссылку — возможно, она выпущена для другого сервера"}, true
	}
	return deny{"authfail", "неверный мастер-ключ (сервер вернул 403)"}, true
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
	if why, bad := denyReason(resp.StatusCode, string(body)); bad {
		fmt.Println("STATUS " + why.status) // машиночитаемо для Android-обёртки
		return errors.New(why.text)
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
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			tail := string(b)
			// Владелец мог удалить или отозвать ссылку уже после подключения:
			// замечаем это здесь и сообщаем обёртке, чтобы та погасила VPN.
			if why, bad := denyReason(resp.StatusCode, tail); bad {
				logf("⚠ %s", why.text)
				fmt.Println("STATUS " + why.status)
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

// bye сообщает серверу, что клиент уходит, — ссылка сразу уходит с линии.
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
