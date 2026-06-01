package pinpath

import "path/filepath"

const DefaultRoot = "/sys/fs/bpf/gameshield"

func Core(root string) string {
	return filepath.Join(root, "core")
}

func Module(root, name string) string {
	return filepath.Join(root, "modules", name)
}
