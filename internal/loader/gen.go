package loader

//go:generate go tool bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../bpf" fivemXDP ../../bpf/fivem_xdp.bpf.c
//go:generate go tool bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -I../../bpf" fivemSockops ../../bpf/fivem_sockops.bpf.c
