#!/usr/bin/env bash
# Собирает Go-часть, которую упаковывает APK:
#   jniLibs/arm64-v8a/libtun.so      — клиент туннеля (main.go -client), CGO обязателен для DNS
#   assets/server/cdn-tunnel-amd64   — серверная часть для VPS (её заливает автодеплой)
#   assets/server/cdn-tunnel-arm64
#
# Вызывается из Gradle перед сборкой APK: иначе легко забыть пересобрать бинари
# после правок main.go и увезти на сервер устаревшую сборку.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"

if ! command -v go >/dev/null 2>&1; then
  echo "build-go: go не найден — оставляю уже собранные бинари как есть" >&2
  exit 0
fi

sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
cc=""
for d in "$sdk"/ndk/*/toolchains/llvm/prebuilt/linux-x86_64/bin; do
  [ -x "$d/aarch64-linux-android24-clang" ] && cc="$d/aarch64-linux-android24-clang"
done

if [ -n "$cc" ]; then
  echo "build-go: libtun.so (android/arm64)"
  ( cd "$root" && CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$cc" \
      go build -trimpath -ldflags "-s -w" \
      -o android/app/src/main/jniLibs/arm64-v8a/libtun.so . )
else
  echo "build-go: NDK не найден — libtun.so не пересобран" >&2
fi

echo "build-go: серверные бинари (linux amd64/arm64)"
( cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
    -o android/app/src/main/assets/server/cdn-tunnel-amd64 . )
( cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" \
    -o android/app/src/main/assets/server/cdn-tunnel-arm64 . )
echo "build-go: готово"
