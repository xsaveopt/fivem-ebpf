// Package pinpath centralizes the gameshield pin-path layout so daemon,
// modules, and CLI agree on where things live without copying string
// literals across packages.
package pinpath

import "path/filepath"

const DefaultRoot = "/sys/fs/bpf/gameshield"

// Core returns the directory for shared dispatcher state:
//
//	<root>/core
func Core(root string) string {
	return filepath.Join(root, "core")
}

// Module returns the directory for a module's private maps:
//
//	<root>/modules/<name>
func Module(root, name string) string {
	return filepath.Join(root, "modules", name)
}
