package bpfmaps

import "testing"

func TestStatLabelsComplete(t *testing.T) {
	seen := map[string]int{}
	for i, lbl := range StatLabels {
		if lbl == "" {
			t.Errorf("StatLabels[%d] is empty, so a stat slot would report under no name", i)
			continue
		}
		if prev, dup := seen[lbl]; dup {
			t.Errorf("StatLabels[%d] and [%d] are both %q", prev, i, lbl)
		}
		seen[lbl] = i
	}
}

func TestDropReasonNamesComplete(t *testing.T) {
	seen := map[string]int{}
	for i, name := range DropReasonNames {
		if name == "" {
			t.Errorf("DropReasonNames[%d] is empty", i)
			continue
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("DropReasonNames[%d] and [%d] are both %q", prev, i, name)
		}
		seen[name] = i
	}
}

func TestCLINameCoversEveryPerIPMap(t *testing.T) {
	byPinned := map[string]bool{}
	for _, pinned := range CLIName {
		byPinned[pinned] = true
	}
	for _, name := range PerIP {
		if !byPinned[name] {
			t.Errorf("%s is in PerIP but no --map value resolves to it", name)
		}
	}
	if len(CLIName) != len(PerIP) {
		t.Errorf("CLIName has %d entries, PerIP has %d", len(CLIName), len(PerIP))
	}
}
