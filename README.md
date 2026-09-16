# CDN Tunnel

Туннель TCP/UDP-трафика через CDN одним Go-файлом + Android-обёртка (VPN).

Клиент поднимает локальный **SOCKS5**; трафик идёт через CDN (TLS+HTTP/2, SNI),
реальные исходящие коннекты делает сервер (исходящий IP = IP сервера).
Вниз — длинный потоковый ответ, вверх — chunked-запросы (или потоковый `stream`).

## Сборка
```bash
go build -o tunnel .
```

## Сервер (origin, за CDN)
```bash
./tunnel -server -addr :80 -password 123456 -method both
```

## Клиент (локальный SOCKS5)
```bash
./tunnel -client -ip <CDN_IP> -host <cdn.domain> -password 123456 \
         -listen 127.0.0.1:8090
# затем: curl --socks5-hostname 127.0.0.1:8090 https://api.ipify.org
```

## Ключевые флаги
| Флаг | Назначение |
|------|-----------|
| `-password` | общий секрет (заголовок `X-Tunnel-Auth`, сверка в постоянное время; пусто = без пароля) |
| `-method` | клиент: `post`\|`get`; сервер: `post`\|`get`\|`both` (что принимать) |
| `-transport` | `chunked` (любой CDN) \| `stream` (один потоковый POST вверх, ниже пинг; при буферизующем CDN — авто-откат на chunked) |
| `-fastopen` | оптимистичный SOCKS-ответ (−1 RTT на соединение) |
| `-conns` | число TCP/h2-соединений к CDN (пул) |
| `-udp` | UDP ASSOCIATE (DNS/QUIC/прочий UDP) |
| `-window` | окно up-запросов в полёте (chunked) |
| `-idle` | таймаут простоя стрима на сервере, сек |
| `-stats` | машиночитаемый вывод `STATS ...` (для Android-обёртки) |

## Транспорт и безопасность
- TLS есть только на участке **клиент → CDN**; CDN → origin — обычный HTTP:80.
- Пароль защищает доступ: без верного пароля любой путь, кроме `/`, отдаёт **403**.
- `stream`/WebSocket-полнодуплекс требует CDN, не буферизующего тело запроса.

## Android-обёртка
Полноценное VPN-приложение (весь трафик телефона через туннель) — см.
[`android/README.md`](android/README.md). Собранное протестировано на Android 14 (arm64).

## Тесты
```bash
go test -race .   # SOCKS end-to-end во всех транспортах + 4 МБ целостность
```
