package loader

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const bpfFSMagic = 0xcafe4a11

func checkBPFFS(path string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	if uint32(st.Type) != bpfFSMagic {
		return fmt.Errorf("pin path %s is not on a bpf filesystem: mount one with "+
			"`mount -t bpf bpffs /sys/fs/bpf`", path)
	}
	return nil
}
