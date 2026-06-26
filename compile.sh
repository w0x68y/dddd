#!/usr/bin/env bash
set -euo pipefail

LDFLAGS='-s -w'
GOCACHE="${GOCACHE:-/private/tmp/dddd-go-build-cache}"
export GOCACHE

if [[ -z "${GO_BIN:-}" ]]; then
	if command -v go1.20.14 >/dev/null 2>&1; then
		GO_BIN="$(command -v go1.20.14)"
	elif [[ -x "$HOME/go/bin/go1.20.14" ]]; then
		GO_BIN="$HOME/go/bin/go1.20.14"
	else
		echo "go1.20.14 not found. Install it or run: GO_BIN=/path/to/go1.20.x bash compile.sh" >&2
		exit 1
	fi
fi

GO_VERSION="$("$GO_BIN" version)"
if [[ "$GO_VERSION" != *"go1.20."* ]]; then
	echo "compile.sh requires Go 1.20.x, got: $GO_VERSION" >&2
	echo "Use: GO_BIN=/path/to/go1.20.x bash compile.sh" >&2
	exit 1
fi

echo "Using $GO_VERSION"

build() {
	local goos="$1"
	local goarch="$2"
	local output="$3"
	local pack="${4:-false}"

	echo "Building $output ($goos/$goarch)"
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "$GO_BIN" build -ldflags="$LDFLAGS" -trimpath -o "$output" main.go

	if [[ "$pack" == "true" ]]; then
		if command -v upx >/dev/null 2>&1; then
			upx -9 "$output"
		else
			echo "upx not found, skip packing $output" >&2
		fi
	fi
}

build windows amd64 dddd64.exe true
build windows 386 dddd.exe true
build linux amd64 dddd_linux64 true
build linux arm64 dddd_linux_arm64
build darwin amd64 dddd_darwin64
build darwin arm64 dddd_darwin_arm64
