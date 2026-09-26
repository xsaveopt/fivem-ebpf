package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func daemonPinPath(t *testing.T) string {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil || uint32(st.Type) != 0xcafe4a11 {
		t.Skip("no bpf filesystem at /sys/fs/bpf")
	}
	dir, err := os.MkdirTemp("/sys/fs/bpf", "fivem-test-")
	if err != nil {
		t.Skipf("cannot write to the bpf filesystem: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func daemonCgroup(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no cgroup information: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", rest)
		}
	}
	t.Skip("not in a cgroup v2 hierarchy")
	return ""
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func requireDaemonPrivileges(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs BPF privileges: %v", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("running the daemon needs root")
	}
}

func startDaemon(t *testing.T, args ...string) <-chan error {
	t.Helper()
	quietLog(t)
	done := make(chan error, 1)
	go func() { done <- runDaemon(args) }()
	return done
}

func get(t *testing.T, url string) (int, string, error) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func waitHealthy(t *testing.T, base string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			skipIfUnprivileged(t, err)
			t.Fatalf("daemon exited before serving: %v", err)
		default:
		}
		if code, body, err := get(t, base+"/health"); err == nil && code == http.StatusOK && body == "up" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("daemon never reported healthy")
}

func stopDaemon(t *testing.T, done <-chan error) error {
	t.Helper()
	guard := make(chan os.Signal, 16)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)
	deadline := time.After(20 * time.Second)
	for {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("signal: %v", err)
		}
		select {
		case err := <-done:
			return err
		case <-deadline:
			t.Fatal("runDaemon did not return after SIGTERM")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestRunDaemonServesMetricsAndAPIThenStopsOnSIGTERM(t *testing.T) {
	requireDaemonPrivileges(t)
	pin := daemonPinPath(t)
	addr := freeAddr(t)
	base := "http://" + addr

	done := startDaemon(t,
		"--iface", "lo",
		"--port", "30126",
		"--pin-path", pin,
		"--cgroup", daemonCgroup(t),
		"--metrics-addr", addr,
		"--udp-rate", "700",
		"--map-size-interval", "1s",
	)
	waitHealthy(t, base, done)

	code, body, err := get(t, base+"/metrics")
	if err != nil || code != http.StatusOK {
		t.Fatalf("/metrics: %d %v", code, err)
	}
	if !strings.Contains(body, "fivem_") {
		t.Errorf("/metrics has no fivem_ series:\n%s", body)
	}

	code, body, err = get(t, base+"/api/info")
	if err != nil || code != http.StatusOK {
		t.Fatalf("/api/info: %d %v %s", code, err, body)
	}
	var info struct {
		Iface    string          `json:"iface"`
		Port     uint16          `json:"port"`
		PinPath  string          `json:"pin_path"`
		XDPMode  string          `json:"xdp_mode"`
		Attached map[string]bool `json:"attached"`
		Limits   apiLimits       `json:"limits"`
	}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("decode /api/info: %v", err)
	}
	if info.Iface != "lo" || info.Port != 30126 || info.PinPath != pin || info.XDPMode == "" {
		t.Errorf("/api/info = %+v", info)
	}
	if !info.Attached["xdp"] || !info.Attached["sockops"] {
		t.Errorf("attached = %v", info.Attached)
	}
	if info.Limits.UDPRatePerSec != 700 || info.Limits.WhitelistTTL != 10*time.Minute {
		t.Errorf("limits = %+v, want the flag values", info.Limits)
	}

	code, body, _ = get(t, base+"/")
	if code != http.StatusOK || !strings.Contains(body, "/api/state") || !strings.Contains(body, "/metrics") {
		t.Errorf("index: %d %q", code, body)
	}
	if code, _, _ := get(t, base+"/nope"); code != http.StatusNotFound {
		t.Errorf("/nope: status %d, want 404", code)
	}

	err = stopDaemon(t, done)
	if err != nil {
		t.Errorf("runDaemon returned %v after SIGTERM, want nil", err)
	}
	if _, _, err := get(t, base+"/health"); err == nil {
		t.Error("the HTTP server still answers after shutdown")
	}
	if _, err := os.Stat(filepath.Join(pin, "tcp_whitelist")); err != nil {
		t.Errorf("the pinned maps did not survive shutdown: %v", err)
	}
}

func TestRunDaemonFailsWhenTheMetricsAddressIsTaken(t *testing.T) {
	requireDaemonPrivileges(t)
	pin := daemonPinPath(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := startDaemon(t,
		"--iface", "lo",
		"--pin-path", pin,
		"--cgroup", daemonCgroup(t),
		"--metrics-addr", ln.Addr().String(),
	)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runDaemon returned nil with its metrics address taken")
		}
		skipIfUnprivileged(t, err)
		if !strings.Contains(err.Error(), "metrics server") {
			t.Errorf("error = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runDaemon kept running without its metrics server")
	}

	again := freeAddr(t)
	done = startDaemon(t,
		"--iface", "lo",
		"--pin-path", pin,
		"--cgroup", daemonCgroup(t),
		"--metrics-addr", again,
	)
	waitHealthy(t, "http://"+again, done)
	if err := stopDaemon(t, done); err != nil {
		t.Errorf("restarted daemon: %v", err)
	}
}

func TestRunDaemonReportsALoadFailure(t *testing.T) {
	quietLog(t)
	err := runDaemon([]string{"--iface", "fivemtest0", "--pin-path", t.TempDir()})
	if err == nil {
		t.Fatal("runDaemon succeeded on an interface that does not exist")
	}
	if strings.HasPrefix(err.Error(), "rlimit:") {
		t.Skipf("needs BPF privileges: %v", err)
	}
	if !strings.Contains(err.Error(), "load:") || !strings.Contains(err.Error(), "fivemtest0") {
		t.Errorf("error = %v", err)
	}
}
