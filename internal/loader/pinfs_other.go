//go:build !linux

package loader

import "errors"

func checkBPFFS(string) error {
	return errors.New("fivem-ebpf only runs on Linux")
}
