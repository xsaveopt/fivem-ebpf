//go:build !linux

package bpfmaps

import "errors"

func BootTimeNS() (uint64, error) {
	return 0, errors.New("CLOCK_BOOTTIME is only available on Linux")
}
