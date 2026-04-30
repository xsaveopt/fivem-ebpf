package core

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../bpf" dispatcherXDP ../../bpf/core/dispatcher_xdp.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../bpf" dispatcherSockops ../../bpf/core/dispatcher_sockops.bpf.c
