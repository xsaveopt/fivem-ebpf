package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func capture(t *testing.T, dst **os.File, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := *dst
	*dst = w
	defer func() { *dst = orig }()

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()

	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

var flagParsers = map[string]func(args []string) (string, error){
	"clear":   func(a []string) (string, error) { o, err := parseClearFlags(a); return o.pinPath, err },
	"dump":    func(a []string) (string, error) { o, err := parseDumpFlags(a); return o.pinPath, err },
	"health":  func(a []string) (string, error) { o, err := parseHealthFlags(a); return o.pinPath, err },
	"info":    func(a []string) (string, error) { o, err := parseInfoFlags(a); return o.pinPath, err },
	"inspect": func(a []string) (string, error) { o, err := parseInspectFlags(a); return o.pinPath, err },
	"stats":   func(a []string) (string, error) { o, err := parseStatsFlags(a); return o.pinPath, err },
	"top":     func(a []string) (string, error) { o, err := parseTopFlags(a); return o.pinPath, err },
	"unpin":   func(a []string) (string, error) { o, err := parseUnpinFlags(a); return o.pinPath, err },
}

func TestEverySubcommandDefaultsToTheStandardPinPath(t *testing.T) {
	for name, parse := range flagParsers {
		got, err := parse(nil)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != defaultPinPath {
			t.Errorf("%s pin path = %q, want %q", name, got, defaultPinPath)
		}
	}
}

func TestEverySubcommandAcceptsPinPath(t *testing.T) {
	for name, parse := range flagParsers {
		for _, spelling := range [][]string{
			{"--pin-path", "/run/bpf/fivem"},
			{"-pin-path", "/run/bpf/fivem"},
			{"--pin-path=/run/bpf/fivem"},
		} {
			got, err := parse(spelling)
			if err != nil {
				t.Errorf("%s %v: %v", name, spelling, err)
				continue
			}
			if got != "/run/bpf/fivem" {
				t.Errorf("%s %v gave pin path %q", name, spelling, got)
			}
		}
	}
}

func TestEverySubcommandRejectsAnUnknownFlag(t *testing.T) {
	capture(t, &os.Stderr, func() {
		for name, parse := range flagParsers {
			if _, err := parse([]string{"--no-such-flag"}); err == nil {
				t.Errorf("%s accepted --no-such-flag", name)
			}
		}
	})
}

func TestEverySubcommandReportsHelpAsErrHelp(t *testing.T) {
	capture(t, &os.Stderr, func() {
		for name, parse := range flagParsers {
			_, err := parse([]string{"-h"})
			if !errors.Is(err, flag.ErrHelp) {
				t.Errorf("%s -h gave %v, want flag.ErrHelp so the command exits 0", name, err)
			}
		}
	})
}

func TestParseDumpFlags(t *testing.T) {
	o, err := parseDumpFlags(nil)
	if err != nil {
		t.Fatalf("parseDumpFlags: %v", err)
	}
	if o.which != "whitelist" {
		t.Errorf("--map default = %q, want whitelist", o.which)
	}
	o, err = parseDumpFlags([]string{"--map", "all"})
	if err != nil {
		t.Fatalf("parseDumpFlags: %v", err)
	}
	if o.which != "all" {
		t.Errorf("--map = %q", o.which)
	}
}

func TestParseClearFlags(t *testing.T) {
	o, err := parseClearFlags(nil)
	if err != nil {
		t.Fatalf("parseClearFlags: %v", err)
	}
	if o.which != "whitelist" || o.ip != "" {
		t.Errorf("defaults = (%q, %q), want (whitelist, empty)", o.which, o.ip)
	}
	o, err = parseClearFlags([]string{"--map", "health", "--ip", "192.0.2.7"})
	if err != nil {
		t.Fatalf("parseClearFlags: %v", err)
	}
	if o.which != "health" || o.ip != "192.0.2.7" {
		t.Errorf("parsed = (%q, %q)", o.which, o.ip)
	}
}

func TestParseHealthFlags(t *testing.T) {
	o, err := parseHealthFlags(nil)
	if err != nil {
		t.Fatalf("parseHealthFlags: %v", err)
	}
	if o.all {
		t.Error("--all defaults to true, so health would list every tracked IP")
	}
	o, err = parseHealthFlags([]string{"--all"})
	if err != nil {
		t.Fatalf("parseHealthFlags: %v", err)
	}
	if !o.all {
		t.Error("--all did not set the flag")
	}
}

func TestParseStatsFlags(t *testing.T) {
	o, err := parseStatsFlags(nil)
	if err != nil {
		t.Fatalf("parseStatsFlags: %v", err)
	}
	if o.asJSON || o.watch != 0 {
		t.Errorf("defaults = (%v, %s), want (false, 0)", o.asJSON, o.watch)
	}
	o, err = parseStatsFlags([]string{"--json", "--watch", "2s"})
	if err != nil {
		t.Fatalf("parseStatsFlags: %v", err)
	}
	if !o.asJSON || o.watch != 2*time.Second {
		t.Errorf("parsed = (%v, %s)", o.asJSON, o.watch)
	}
	capture(t, &os.Stderr, func() {
		if _, err := parseStatsFlags([]string{"--watch", "soon"}); err == nil {
			t.Error("--watch accepted a value that is not a duration")
		}
	})
}

func TestParseInspectFlagsTakesTheAddressPositionally(t *testing.T) {
	o, err := parseInspectFlags([]string{"--watch", "1s", "198.51.100.4"})
	if err != nil {
		t.Fatalf("parseInspectFlags: %v", err)
	}
	if o.addr != "198.51.100.4" || o.watch != time.Second {
		t.Errorf("parsed = (%q, %s)", o.addr, o.watch)
	}
	o, err = parseInspectFlags(nil)
	if err != nil {
		t.Fatalf("parseInspectFlags: %v", err)
	}
	if o.addr != "" {
		t.Errorf("addr = %q with no argument, want empty so inspect prints its usage", o.addr)
	}
}

func TestParseTopFlags(t *testing.T) {
	o, err := parseTopFlags(nil)
	if err != nil {
		t.Fatalf("parseTopFlags: %v", err)
	}
	if o.which != "open-count" || o.n != 10 || o.reason != "" {
		t.Errorf("defaults = (%q, %d, %q)", o.which, o.n, o.reason)
	}
	o, err = parseTopFlags([]string{"--map", "drop-history", "-n", "3", "--reason", "udp_ratelimit"})
	if err != nil {
		t.Fatalf("parseTopFlags: %v", err)
	}
	if o.which != "drop-history" || o.n != 3 || o.reason != "udp_ratelimit" {
		t.Errorf("parsed = (%q, %d, %q)", o.which, o.n, o.reason)
	}
}

func TestParseUnpinFlagsRequiresConfirmation(t *testing.T) {
	o, err := parseUnpinFlags(nil)
	if err != nil {
		t.Fatalf("parseUnpinFlags: %v", err)
	}
	if o.yes {
		t.Error("--yes defaults to true, so unpin would wipe the pin directory unprompted")
	}
}

func TestResolveMapTargets(t *testing.T) {
	all, err := resolveMapTargets("all")
	if err != nil {
		t.Fatalf("resolveMapTargets(all): %v", err)
	}
	if len(all) != len(bpfmaps.PerIP) {
		t.Errorf("all resolved to %d maps, want %d", len(all), len(bpfmaps.PerIP))
	}
	for cli, pinned := range bpfmaps.CLIName {
		got, err := resolveMapTargets(cli)
		if err != nil {
			t.Errorf("resolveMapTargets(%q): %v", cli, err)
			continue
		}
		if len(got) != 1 || got[0] != pinned {
			t.Errorf("resolveMapTargets(%q) = %v, want [%s]", cli, got, pinned)
		}
	}
	for _, bad := range []string{"", "tcp_whitelist", "everything"} {
		if _, err := resolveMapTargets(bad); err == nil {
			t.Errorf("resolveMapTargets(%q) accepted an unknown map", bad)
		}
	}
}

func TestUnpinRemovesThePinDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fivem")
	if err := os.MkdirAll(filepath.Join(dir, "tcp_whitelist"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	out := capture(t, &os.Stdout, func() {
		cmdUnpin([]string{"--pin-path", dir, "--yes"})
	})

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("pin directory still present after unpin --yes: %v", err)
	}
	if !strings.Contains(out, "removed "+dir) {
		t.Errorf("unpin printed %q", out)
	}
}

func TestUnpinOnAnAbsentDirectoryIsNotAnError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never-created")
	out := capture(t, &os.Stdout, func() {
		cmdUnpin([]string{"--pin-path", dir, "--yes"})
	})
	if !strings.Contains(out, "removed "+dir) {
		t.Errorf("unpin printed %q", out)
	}
}

func TestUsageListsEverySubcommand(t *testing.T) {
	out := capture(t, &os.Stderr, func() { usage() })
	for _, sub := range []string{
		"run", "info", "stats", "top", "inspect", "dump", "health", "clear", "unpin",
	} {
		if !strings.Contains(out, "fivem-ebpf "+sub) {
			t.Errorf("usage does not document the %s subcommand", sub)
		}
	}
	if !strings.Contains(out, bpfmaps.CLINamesHelp) {
		t.Error("usage does not list the map names")
	}
	if !strings.Contains(out, defaultPinPath) {
		t.Error("usage does not mention the default pin path")
	}
}

func TestRunDaemonRejectsAnOutOfRangePort(t *testing.T) {
	for _, arg := range []string{"0", "65536", "70000"} {
		err := runDaemon([]string{"--port", arg})
		if err == nil {
			t.Errorf("--port %s was accepted", arg)
			continue
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("--port %s: %v", arg, err)
		}
	}
}

func TestRunDaemonRejectsAnOutOfRangeHealthThreshold(t *testing.T) {
	err := runDaemon([]string{"--health-threshold", "4294967296"})
	if err == nil {
		t.Fatal("--health-threshold 4294967296 was accepted, so it would wrap to 0")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error = %v", err)
	}
}

func TestLimitDesc(t *testing.T) {
	for _, tc := range []struct {
		rate, burst uint64
		unit, want  string
	}{
		{1500, 4500, "/s", "1500/s burst 4500"},
		{6, 3, "/min", "6/min burst 3"},
		{0, 4500, "/s", "DISABLED"},
		{1500, 0, "/s", "DISABLED"},
		{0, 0, "/s", "DISABLED"},
	} {
		if got := limitDesc(tc.rate, tc.unit, tc.burst); got != tc.want {
			t.Errorf("limitDesc(%d, %q, %d) = %q, want %q", tc.rate, tc.unit, tc.burst, got, tc.want)
		}
	}
}

func TestEnabledDesc(t *testing.T) {
	if enabledDesc(true) != "enabled" || enabledDesc(false) != "disabled" {
		t.Errorf("enabledDesc gave (%q, %q)", enabledDesc(true), enabledDesc(false))
	}
}

func TestIsLoopback(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9464", true},
		{"localhost:9464", true},
		{"[::1]:9464", true},
		{"0.0.0.0:9464", false},
		{"192.0.2.10:9464", false},
		{":9464", false},
		{"127.0.0.1", false},
		{"", false},
	} {
		if got := isLoopback(tc.addr); got != tc.want {
			t.Errorf("isLoopback(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
