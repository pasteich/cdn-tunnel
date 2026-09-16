package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Туннель TCP/UDP-трафика через CDN одним файлом.
//
//	origin:  go run main.go -server
//	клиент:  go run main.go -client -ip 151.236.109.225 -host u8t.fun -listen 127.0.0.1:8090
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
		ip        = flag.String("ip", "151.236.109.225", "IP CDN (режим -client)")
		host      = flag.String("host", "u8t.fun", "Host/SNI для CDN (режим -client)")
		conns     = flag.Int("conns", 8, "число TCP-соединений к CDN (пул, убирает HoL-блокировку)")
		udp       = flag.Bool("udp", true, "включить UDP ASSOCIATE (DNS, QUIC и прочий UDP через туннель)")
		pass      = flag.String("password", "", "пароль доступа к туннелю (должен совпадать на -server и -client; пусто = без пароля)")
		stats     = flag.Bool("stats", false, "выводить машиночитаемую статистику построчно (STATS ...) вместо интерактивного HUD")
		method    = flag.String("method", "post", "метод передачи данных вверх (chunked): клиент — post|get; сервер — post|get|both")
		transport = flag.String("transport", "chunked", "транспорт апстрима: chunked (много запросов) | stream (один потоковый POST, ниже пинг; нужен CDN, пропускающий streaming request body)")
		fastopen  = flag.Bool("fastopen", true, "оптимистичный SOCKS-ответ до подтверждения connect (убирает 1 RTT на соединение)")
		window    = flag.Int("window", 32, "число одновременных up-запросов в полёте (chunked, режим post/get)")
		idle      = flag.Int("idle", 120, "таймаут простоя стрима на сервере в секундах (0 = не закрывать)")
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

type tunnelServer struct {
	mu      sync.Mutex
	streams map[string]*stream
	udp     map[string]*udpSession
}

func runServer(addr string) {
	st = &stats{role: "server"}
	st.connected.Store(true)
	ts := &tunnelServer{
		streams: make(map[string]*stream),
		udp:     make(map[string]*udpSession),
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tunnel server ok\n"))
	})

	var handler http.Handler = mux
	if authToken != "" {
		handler = authMiddleware(mux)
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
		if subtle.ConstantTimeCompare(got, want) != 1 {
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
	s := &stream{id: id, conn: conn, down: make(chan []byte, 1024), done: make(chan struct{}), upBuf: make(map[uint64][]byte)}
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
	u := &udpSession{id: id, pc: pc, down: make(chan []byte, 4096), done: make(chan struct{})}
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
	return &http.Client{Transport: authRoundTripper{base: tr}}
}

// authRoundTripper добавляет заголовок с паролем на каждый исходящий запрос.
// Так пароль проставляется единообразно и для hc.Post, и для hc.Do — не нужно
// трогать каждый вызов по отдельности.
type authRoundTripper struct{ base http.RoundTripper }

func (a authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if authToken != "" {
		r.Header.Set(authHeader, authToken)
	}
	return a.base.RoundTrip(r)
}

func runClient(listen, ip, host string, conns int, udp bool) {
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
		fmt.Println("STATUS authfail") // машиночитаемо для Android-обёртки
		return fmt.Errorf("неверный пароль (сервер вернул 403 forbidden)")
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
			st.rttMs.Store(time.Since(start).Milliseconds())
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
