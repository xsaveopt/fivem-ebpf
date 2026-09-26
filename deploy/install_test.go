package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type installEnv struct {
	t       *testing.T
	root    string
	release string
	etc     string
	prefix  string
	sysd    string
	pinDir  string
	env     []string
}

func requireInstallHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("install.sh only runs on Linux")
	}
	for _, p := range []string{"/sys/kernel/btf/vmlinux", "/sys/fs/cgroup/cgroup.controllers"} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("host lacks %s, which install.sh checks for", p)
		}
	}
	rel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Skipf("unknown kernel release: %v", err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(rel)), ".", 3)
	major, _ := strconv.Atoi(parts[0])
	minor := 0
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if major < 5 || (major == 5 && minor < 17) {
		t.Skip("kernel older than install.sh accepts")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func newInstallEnv(t *testing.T) *installEnv {
	t.Helper()
	requireInstallHost(t)
	root := t.TempDir()
	e := &installEnv{
		t:       t,
		root:    root,
		release: filepath.Join(root, "release"),
		etc:     filepath.Join(root, "etc", "fivem-ebpf"),
		prefix:  filepath.Join(root, "prefix"),
		sysd:    filepath.Join(root, "systemd"),
		pinDir:  filepath.Join(root, "bpf", "default-pins"),
	}

	script := readFile(t, "install.sh")
	writeFile(t, filepath.Join(e.release, "install.sh"), script, 0o755)
	writeFile(t, filepath.Join(e.release, "config.example"), readFile(t, "config.example"), 0o644)
	writeFile(t, filepath.Join(e.release, "fivem-ebpf"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFile(t, filepath.Join(e.release, "fivem-ebpf.service"), "[Unit]\n", 0o644)
	writeFile(t, filepath.Join(e.release, "fivem-ebpf-dashboard.json"), "{}\n", 0o644)
	writeFile(t, filepath.Join(e.release, "fivem-ebpf-ips-dashboard.json"), "{}\n", 0o644)
	if err := os.MkdirAll(e.sysd, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	bin := filepath.Join(root, "bin")
	writeFile(t, filepath.Join(bin, "id"), "#!/bin/sh\necho 0\n", 0o755)
	writeFile(t, filepath.Join(bin, "mount"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFile(t, filepath.Join(bin, "journalctl"), "#!/bin/sh\nexit 0\n", 0o755)
	writeFile(t, filepath.Join(bin, "systemctl"),
		"#!/bin/sh\necho \"$*\" >> \""+filepath.Join(root, "systemctl.log")+"\"\n"+
			"case \"$1\" in is-active) exit 3 ;; esac\nexit 0\n", 0o755)

	e.env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"PREFIX="+e.prefix,
		"SYSD_DIR="+e.sysd,
		"ETC_DIR="+e.etc,
		"PIN_DIR="+e.pinDir,
	)
	return e
}

func (e *installEnv) config() string { return filepath.Join(e.etc, "config") }

func (e *installEnv) writeConfig(content string) {
	e.t.Helper()
	writeFile(e.t, e.config(), content, 0o644)
}

func (e *installEnv) pinnedDir(name string) string {
	e.t.Helper()
	dir := filepath.Join(e.root, "bpf", name)
	writeFile(e.t, filepath.Join(dir, "tcp_whitelist"), "", 0o600)
	return dir
}

func (e *installEnv) run(args ...string) string {
	e.t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(e.release, "install.sh")}, args...)...)
	cmd.Env = e.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("install.sh %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func configValues(content string) map[string][]string {
	out := map[string][]string{}
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, val, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		out[key] = append(out[key], val)
	}
	return out
}

func exampleKeys(t *testing.T) []string {
	t.Helper()
	var keys []string
	for line := range strings.SplitSeq(readFile(t, "config.example"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, _ := strings.Cut(line, "=")
		keys = append(keys, key)
	}
	return keys
}

func addedKeys(out string) map[string]bool {
	keys := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.HasPrefix(line, "added new config keys") {
			continue
		}
		_, list, _ := strings.Cut(line, "):")
		for _, k := range strings.Fields(list) {
			keys[k] = true
		}
	}
	return keys
}

func TestInstallFreshCopiesTheExampleConfig(t *testing.T) {
	e := newInstallEnv(t)
	out := e.run()

	if got, want := readFile(t, e.config()), readFile(t, "config.example"); got != want {
		t.Error("a fresh install did not copy config.example verbatim")
	}
	if !strings.Contains(out, "EDIT "+e.config()) {
		t.Errorf("a fresh install did not ask for the config to be edited:\n%s", out)
	}
	for _, p := range []string{
		filepath.Join(e.prefix, "bin", "fivem-ebpf"),
		filepath.Join(e.sysd, "fivem-ebpf.service"),
		filepath.Join(e.etc, "grafana", "fivem-ebpf-dashboard.json"),
		filepath.Join(e.etc, "grafana", "fivem-ebpf-ips-dashboard.json"),
	} {
		if !exists(p) {
			t.Errorf("%s was not installed", strings.TrimPrefix(p, e.root))
		}
	}
}

func TestInstallMergeAddsOnlyMissingKeys(t *testing.T) {
	e := newInstallEnv(t)
	e.writeConfig("IFACE=ens5\nPORT=30130\nUDP_RATE=900\n")
	out := e.run()

	got := configValues(readFile(t, e.config()))
	for key, want := range map[string]string{"IFACE": "ens5", "PORT": "30130", "UDP_RATE": "900"} {
		if vals := got[key]; len(vals) != 1 || vals[0] != want {
			t.Errorf("%s = %v, want the operator's %q kept once", key, vals, want)
		}
	}
	example := configValues(readFile(t, "config.example"))
	for _, key := range exampleKeys(t) {
		if len(got[key]) != 1 {
			t.Errorf("%s appears %d times, want once", key, len(got[key]))
			continue
		}
		if key != "IFACE" && key != "PORT" && key != "UDP_RATE" && got[key][0] != example[key][0] {
			t.Errorf("added %s = %q, want the default %q", key, got[key][0], example[key][0])
		}
	}
	added := addedKeys(out)
	if !added["UDP_BURST"] || !added["PIN_PATH"] {
		t.Errorf("the merge did not list what it added:\n%s", out)
	}
	for _, key := range []string{"IFACE", "PORT", "UDP_RATE"} {
		if added[key] {
			t.Errorf("the merge lists %s as added although it was already set", key)
		}
	}
	if strings.Contains(out, "EDIT ") {
		t.Errorf("an upgrade asked for the config to be edited as if it were new:\n%s", out)
	}
}

func TestInstallMergeLeavesACompleteConfigAlone(t *testing.T) {
	e := newInstallEnv(t)
	var b strings.Builder
	for _, key := range exampleKeys(t) {
		b.WriteString(key + "=custom\n")
	}
	e.writeConfig(b.String())
	out := e.run()

	if got := readFile(t, e.config()); got != b.String() {
		t.Errorf("a complete config was modified:\n%s", got)
	}
	if strings.Contains(out, "added new config keys") {
		t.Errorf("the merge reported additions to a complete config:\n%s", out)
	}
}

func TestInstallMergeStartsAddedKeysOnTheirOwnLine(t *testing.T) {
	e := newInstallEnv(t)
	e.writeConfig("IFACE=ens5\nDROP_HISTORY=false")
	e.run()

	got := configValues(readFile(t, e.config()))
	if vals := got["DROP_HISTORY"]; len(vals) != 1 || vals[0] != "false" {
		t.Errorf("DROP_HISTORY = %v, want the operator's false kept intact", vals)
	}
	if vals := got["PORT"]; len(vals) != 1 {
		t.Errorf("PORT = %v, want the added default on a line of its own", vals)
	}
}

func TestInstallMergeRecognisesIndentedKeys(t *testing.T) {
	e := newInstallEnv(t)
	e.writeConfig("  UDP_RATE=900\nIFACE=ens5\n")
	e.run()

	vals := configValues(readFile(t, e.config()))["UDP_RATE"]
	if len(vals) != 1 || vals[0] != "900" {
		t.Errorf("UDP_RATE = %v, want only the operator's indented 900, since a later default would override it", vals)
	}
}

func TestInstallClearsThePinDirectoryFromTheConfig(t *testing.T) {
	for name, line := range map[string]func(dir string) string{
		"plain":            func(dir string) string { return "PIN_PATH=" + dir },
		"double quoted":    func(dir string) string { return "PIN_PATH=\"" + dir + "\"" },
		"indented":         func(dir string) string { return "   PIN_PATH=" + dir },
		"trailing spaces":  func(dir string) string { return "PIN_PATH=" + dir + "   " },
		"single quoted":    func(dir string) string { return "PIN_PATH='" + dir + "'" },
		"after a previous": func(dir string) string { return "PIN_PATH=/nonexistent-fivem-test\nPIN_PATH=" + dir },
	} {
		t.Run(name, func(t *testing.T) {
			e := newInstallEnv(t)
			custom := e.pinnedDir("custom")
			fallback := e.pinnedDir("default-pins")
			e.writeConfig("IFACE=ens5\n" + line(custom) + "\n")
			out := e.run()

			if exists(custom) {
				t.Errorf("the configured pin directory was not cleared:\n%s", out)
			}
			if !exists(fallback) {
				t.Error("the fallback pin directory was cleared instead of the configured one")
			}
			if !strings.Contains(out, "pin path:   "+custom+"\n") {
				t.Errorf("the summary does not report the configured pin path:\n%s", out)
			}
		})
	}
}

func TestInstallFallsBackToPinDirWithoutAConfiguredPath(t *testing.T) {
	for name, cfg := range map[string]string{
		"no config":       "",
		"no PIN_PATH key": "IFACE=ens5\n",
		"empty PIN_PATH":  "IFACE=ens5\nPIN_PATH=\n",
		"commented out":   "IFACE=ens5\n# PIN_PATH=/nonexistent-fivem-test\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := newInstallEnv(t)
			fallback := e.pinnedDir("default-pins")
			if cfg != "" {
				e.writeConfig(cfg)
			}
			out := e.run()
			if exists(fallback) {
				t.Errorf("PIN_DIR was not cleared:\n%s", out)
			}
			if !strings.Contains(out, "pin path:   "+fallback+"\n") {
				t.Errorf("the summary does not report PIN_DIR:\n%s", out)
			}
		})
	}
}

func TestUninstallRemovesTheConfiguredPinDirectory(t *testing.T) {
	e := newInstallEnv(t)
	e.run()
	custom := e.pinnedDir("custom")
	fallback := e.pinnedDir("default-pins")
	e.writeConfig("PIN_PATH=" + custom + "\n")

	e.run("--uninstall")
	if exists(custom) {
		t.Error("uninstall left the configured pin directory behind")
	}
	if !exists(fallback) {
		t.Error("uninstall removed PIN_DIR although the config names another path")
	}
	if exists(e.etc) {
		t.Error("uninstall kept the config directory without --keep-config")
	}
	for _, p := range []string{filepath.Join(e.prefix, "bin", "fivem-ebpf"), filepath.Join(e.sysd, "fivem-ebpf.service")} {
		if exists(p) {
			t.Errorf("uninstall left %s", strings.TrimPrefix(p, e.root))
		}
	}
}

func TestUninstallKeepConfigStillClearsThePins(t *testing.T) {
	e := newInstallEnv(t)
	e.run()
	custom := e.pinnedDir("custom")
	e.writeConfig("PIN_PATH=" + custom + "\n")

	out := e.run("--uninstall", "--keep-config")
	if exists(custom) {
		t.Error("uninstall --keep-config left the configured pin directory behind")
	}
	if !exists(e.config()) {
		t.Error("uninstall --keep-config removed the config")
	}
	if !strings.Contains(out, "kept "+e.etc) {
		t.Errorf("output = %s", out)
	}
}
