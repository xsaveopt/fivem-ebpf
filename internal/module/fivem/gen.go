package fivem

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../../bpf" fivemXDP ../../../bpf/modules/fivem/xdp.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../../bpf" fivemSockops ../../../bpf/modules/fivem/sockops.bpf.c
