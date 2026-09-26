package main

import (
	"os"
	"strings"
	"testing"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

func TestPrintHealthFailsWithoutPinnedMaps(t *testing.T) {
	if err := printHealth("/nonexistent-pin-path", false); err == nil {
		t.Error("printHealth succeeded with no pinned maps")
	}
}

func TestMapEntryCountFailsWithoutPinnedMaps(t *testing.T) {
	n, err := mapEntryCount("/nonexistent-pin-path", bpfmaps.Whitelist)
	if err == nil {
		t.Error("mapEntryCount succeeded with no pinned maps")
	}
	if n != -1 {
		t.Errorf("count = %d, want -1 on failure", n)
	}
}

func TestBlacklistedNowFailsWithoutPinnedMaps(t *testing.T) {
	n, err := blacklistedNow("/nonexistent-pin-path")
	if err == nil {
		t.Error("blacklistedNow succeeded with no pinned maps")
	}
	if n != -1 {
		t.Errorf("count = %d, want -1 on failure", n)
	}
}

func TestCmdDumpReportsAnUnopenableMap(t *testing.T) {
	var stdout string
	stderr := capture(t, &os.Stderr, func() {
		stdout = capture(t, &os.Stdout, func() {
			cmdDump([]string{"--pin-path", "/nonexistent-pin-path", "--map", "open-count"})
		})
	})
	if stdout != "" {
		t.Errorf("a single-map dump printed %q to stdout", stdout)
	}
	if !strings.HasPrefix(stderr, "dump: open "+bpfmaps.OpenCount+":") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCmdDumpAllHeadsEveryMap(t *testing.T) {
	var stdout string
	stderr := capture(t, &os.Stderr, func() {
		stdout = capture(t, &os.Stdout, func() {
			cmdDump([]string{"--pin-path", "/nonexistent-pin-path", "--map", "all"})
		})
	})
	for _, name := range bpfmaps.PerIP {
		if !strings.Contains(stdout, "== "+name+" ==\n") {
			t.Errorf("no section header for %s in:\n%s", name, stdout)
		}
	}
	if got := strings.Count(stderr, "dump: "); got != len(bpfmaps.PerIP) {
		t.Errorf("got %d errors, want one per map:\n%s", got, stderr)
	}
}

func TestCmdInfoWithAnEmptyPinDirectory(t *testing.T) {
	dir := t.TempDir()
	var stdout string
	stderr := capture(t, &os.Stderr, func() {
		stdout = capture(t, &os.Stdout, func() {
			cmdInfo([]string{"--pin-path", dir})
		})
	})
	if !strings.Contains(stdout, "fivem-ebpf "+version+"\n") {
		t.Errorf("no version line in:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  pin path: "+dir+"\n") {
		t.Errorf("no pin path line in:\n%s", stdout)
	}
	if !strings.Contains(stderr, "open "+bpfmaps.Stats+":") {
		t.Errorf("the missing stats map was not reported: %q", stderr)
	}
	if strings.Contains(stdout, "tcp: ") {
		t.Errorf("a stats summary was printed without a stats map:\n%s", stdout)
	}
	for _, name := range bpfmaps.PerIP {
		if !strings.Contains(stdout, name) {
			t.Errorf("%s missing from the populations:\n%s", name, stdout)
		}
	}
	if strings.Contains(stdout, "(blacklisted)") {
		t.Errorf("a blacklist count was printed without a health map:\n%s", stdout)
	}
}
