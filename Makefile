BIN         := bin/fivem-ebpf
GO          ?= go
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX      ?= /usr/local
DESTDIR     ?=
LDFLAGS     := -X main.version=$(VERSION)
REL_LDFLAGS := -s -w $(LDFLAGS)
GENERATED   := internal/loader/fivemxdp_bpfel.go internal/loader/fivemsockops_bpfel.go
UNAME_S     := $(shell uname -s)

.PHONY: all vmlinux generate build check fmt vet test lint install uninstall clean tidy release release-amd64 release-arm64

all: build

ifneq ($(UNAME_S),Linux)
bpf/vmlinux.h:
	@echo "BPF code generation needs Linux; run make inside the dev VM, see the README" >&2
	@exit 1
else
bpf/vmlinux.h:
	scripts/gen-vmlinux.sh
endif

vmlinux: bpf/vmlinux.h

$(GENERATED): bpf/vmlinux.h bpf/fivem_xdp.bpf.c bpf/fivem_sockops.bpf.c bpf/shared/maps.h bpf/shared/stats.h internal/loader/gen.go
	$(GO) generate ./...

generate: $(GENERATED)

tidy:
	$(GO) mod tidy

build: $(GENERATED)
	mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/fivem-ebpf

check: fmt vet test lint

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "$$out"; echo "run gofmt -w ."; exit 1; fi

vet: $(GENERATED)
	$(GO) vet ./...

test: $(GENERATED)
	$(GO) test ./...

lint: $(GENERATED)
	golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 ./...

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/fivem-ebpf

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/fivem-ebpf

release-amd64: $(GENERATED)
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags "$(REL_LDFLAGS)" -o dist/fivem-ebpf-linux-amd64 ./cmd/fivem-ebpf

release-arm64: $(GENERATED)
	mkdir -p dist
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags "$(REL_LDFLAGS)" -o dist/fivem-ebpf-linux-arm64 ./cmd/fivem-ebpf

release: release-amd64 release-arm64

clean:
	rm -rf bin dist
	rm -f bpf/vmlinux.h
	rm -f internal/loader/fivem*_bpfel*.go internal/loader/fivem*_bpfel*.o
