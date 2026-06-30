BIN     := bin/fivem-ebpf
GO      ?= go
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all vmlinux generate build install clean tidy release-amd64 release-arm64 release

all: build

vmlinux: bpf/vmlinux.h

bpf/vmlinux.h:
	scripts/gen-vmlinux.sh

generate: bpf/vmlinux.h
	$(GO) generate ./...

tidy:
	$(GO) mod tidy

build: generate
	mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/fivem-ebpf

install: build
	install -m 0755 $(BIN) /usr/local/bin/fivem-ebpf

release-amd64: generate
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/fivem-ebpf-linux-amd64 ./cmd/fivem-ebpf

release-arm64: generate
	mkdir -p dist
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/fivem-ebpf-linux-arm64 ./cmd/fivem-ebpf

release: release-amd64 release-arm64

clean:
	rm -rf bin dist
	rm -f bpf/vmlinux.h
	rm -f internal/loader/fivem*_bpfel*.go internal/loader/fivem*_bpfel*.o
