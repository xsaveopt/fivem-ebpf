package bpfmaps

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func parseEnum(t *testing.T, path, prefix string) map[string]int {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(`(?m)^\s*(` + prefix + `[A-Z0-9_]+)\s*=\s*(\d+)\s*,`)
	out := map[string]int{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		v, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("%s: %v", m[1], err)
		}
		out[m[1]] = v
	}
	if len(out) == 0 {
		t.Fatalf("%s: found no %s members", path, prefix)
	}
	return out
}

func TestStatEnumMatchesLabels(t *testing.T) {
	members := parseEnum(t, "../../bpf/shared/stats.h", "STAT_")

	if got, ok := members["STAT_MAX"]; !ok || got != StatMax {
		t.Fatalf("STAT_MAX is %d in stats.h, StatMax is %d in Go", got, StatMax)
	}
	delete(members, "STAT_MAX")

	if len(members) != StatMax {
		t.Errorf("stats.h declares %d slots, StatLabels has %d", len(members), StatMax)
	}
	seen := make([]bool, StatMax)
	for name, slot := range members {
		if slot < 0 || slot >= StatMax {
			t.Errorf("%s = %d, outside StatLabels", name, slot)
			continue
		}
		want := strings.ToLower(strings.TrimPrefix(name, "STAT_"))
		if got := StatLabels[slot]; got != want {
			t.Errorf("slot %d: stats.h has %s so the label should be %q, StatLabels has %q",
				slot, name, want, got)
		}
		seen[slot] = true
	}
	for i, ok := range seen {
		if !ok {
			t.Errorf("StatLabels[%d] = %q has no matching stats.h member", i, StatLabels[i])
		}
	}
}

func TestDropReasonEnumMatchesNames(t *testing.T) {
	members := parseEnum(t, "../../bpf/shared/maps.h", "DROP_REASON_")

	if len(members) != NumDropReasons {
		t.Fatalf("maps.h declares %d drop reasons, NumDropReasons is %d", len(members), NumDropReasons)
	}
	for name, idx := range members {
		if idx < 0 || idx >= NumDropReasons {
			t.Errorf("%s = %d, outside DropReasonNames", name, idx)
			continue
		}
		want := strings.ToLower(strings.TrimPrefix(name, "DROP_REASON_"))
		if got := DropReasonNames[idx]; got != want {
			t.Errorf("index %d: maps.h has %s so the name should be %q, DropReasonNames has %q",
				idx, name, want, got)
		}
	}
}

func TestNumDropReasonsMatchesDefine(t *testing.T) {
	src, err := os.ReadFile("../../bpf/shared/maps.h")
	if err != nil {
		t.Fatalf("read maps.h: %v", err)
	}
	m := regexp.MustCompile(`#define\s+NUM_DROP_REASONS\s+(\d+)`).FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("maps.h has no NUM_DROP_REASONS define")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if n != NumDropReasons {
		t.Errorf("NUM_DROP_REASONS is %d in maps.h, NumDropReasons is %d in Go", n, NumDropReasons)
	}
}
