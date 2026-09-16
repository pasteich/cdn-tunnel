# CDN Tunnel — Android-обёртка

VPN-приложение, которое заворачивает **весь трафик телефона** через туннель из
`../main.go` (режим `-client`): SOCKS5 → HTTP/2 через CDN → ваш `-server`.

## Как устроено
```
Приложения телефона
   │ весь трафик (IPv4/IPv6)
   ▼
VpnService (TUN 10.0.0.2 / fd00::2)
   ▼  tun2socks (libgojni.so, встроен через gomobile AAR)
   ▼  SOCKS5 CONNECT + DNS-over-TCP
libtun.so  = ../main.go -client  (SOCKS5 на 127.0.0.1:<порт>)
   ▼  HTTP/2 к CDN, заголовок X-Tunnel-Auth: <пароль>
CDN (ip:443, SNI=host) ──► ваш -server ──► интернет
```
- Пароль передаётся клиентом (`-password`) и проверяется сервером. Неверный
  пароль → сервер отвечает **403**, клиент печатает `STATUS authfail` и выходит,
  VPN не поднимается.
- Трафик самого приложения к CDN исключён из VPN (`addDisallowedApplication`),
  поэтому петли нет.
- Счётчик трафика: клиент печатает `STATS down=… up=…` каждые 0.5с (флаг `-stats`),
  сервис их парсит и показывает на вкладке «Трафик».

## Поля (сохраняются между запусками)
Вкладка **Туннель**: IP сервера CDN, Host/SNI, Пароль, локальный порт SOCKS,
conns, **Транспорт (chunked/stream)**, **Метод (post/get)**, переключатель UDP;
в «Дополнительно» — DNS, MTU, **Fast Open**, блок IPv6, debug-лог.
Вкладка **Трафик** показывает ↓/↑ (всего и скорость), UDP, соединения и **пинг (RTT)**.

### Транспорт и оптимизации (снижение пинга/роста скорости)
- **chunked** (по умолчанию) — апстрим множеством запросов; работает через любой CDN.
- **stream** — апстрим одним потоковым POST (ниже пинг, меньше накладных), но
  требует CDN, не буферизующего тело запроса. Клиент сам это проверяет при старте
  и при буферизации **автоматически откатывается на chunked** (в логе `STATUS stream-fallback`).
- **Fast Open** — оптимистичный SOCKS-ответ, убирает 1 RTT на каждое соединение.
- Плюс всегда включено: тёплый пул + замер RTT, TCP_NODELAY и большие буферы,
  окно из 32 up-запросов, реап простаивающих стримов на сервере.

### Метод передачи: post / get
Данные вверх (и управляющие запросы) можно слать двумя способами:
- **post** — тело запроса (по умолчанию, максимальная скорость, куски по 64 КБ);
- **get** — полезная нагрузка едет base64url в query-строке URL (куски по 4 КБ,
  чтобы уложиться в лимит длины URL). Полезно там, где CDN/WAF режет или кэширует
  POST иначе, чем GET.

Метод на клиенте (в приложении) и на сервере должен совпадать — либо запустите
сервер с `-method both`, тогда он принимает оба:
```bash
./tunnel -server -password parol123 -method both   # принимает post и get
./tunnel -server -password parol123 -method get     # принимает только get (405 на post)
```
Потоки вниз (`/t/down`, `/u/down`) всегда GET независимо от режима.

## Сборка
```bash
source ~/android-dev/env.sh        # JDK17 + SDK + gradle + platform-tools в PATH

# 1) собрать бинарник туннеля (libtun.so) из ../main.go (CGO обязателен для DNS):
NDK=$ANDROID_HOME/ndk/26.3.11579264
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang
( cd .. && CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$CC" \
    go build -trimpath -ldflags "-s -w" \
    -o android/app/src/main/jniLibs/arm64-v8a/libtun.so . )

# 2) собрать APK:
gradle :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```
`t2smobile.aar` (tun2socks) уже лежит в `app/libs/`. Пересобирать его нужно
только при изменении `~/android-dev/t2smobile/t2s.go`.

Собрано и протестировано: Redmi (rubypro), Android 14, только arm64-v8a.
