package main

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/xsaveopt/fivem-ebpf/internal/bpfmaps"
)

type fakeEntry struct {
	key [4]byte
	val any
}

type fakeMap struct {
	entries []fakeEntry
	iterErr error
}

func (f *fakeMap) Iterate() bpfmaps.Iterator { return &fakeIter{m: f} }

func (f *fakeMap) Lookup(key, valueOut any) error {
	k := *key.(*[4]byte)
	for _, e := range f.entries {
		if e.key == k {
			assign(valueOut, e.val)
			return nil
		}
	}
	return errors.New("not found")
}

type fakeIter struct {
	m *fakeMap
	i int
}

func (it *fakeIter) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.m.entries) {
		return false
	}
	e := it.m.entries[it.i]
	it.i++
	*keyOut.(*[4]byte) = e.key
	assign(valueOut, e.val)
	return true
}

func (it *fakeIter) Err() error { return it.m.iterErr }

func assign(dst, src any) {
	reflect.ValueOf(dst).Elem().Set(reflect.ValueOf(src))
}

func TestAgeSecondsDoesNotUnderflow(t *testing.T) {
	const now = 1_000_000_000_000

	if got := ageSeconds(now, now+5_000_000_000); got != 0 {
		t.Errorf("a timestamp 5s in the future gave age %d, want 0", got)
	}
	if got := ageSeconds(now, 0); got != 1000 {
		t.Errorf("ageSeconds(now, 0) = %d, want 1000", got)
	}
	if got := ageSeconds(now, now); got != 0 {
		t.Errorf("ageSeconds(now, now) = %d, want 0", got)
	}
	if got := ageSeconds(0, math.MaxUint64); got < 0 {
		t.Errorf("ageSeconds clamped to %d, want a non-negative value", got)
	}
}

func TestParseTopN(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 10, false},
		{"5", 5, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
		{"999999", maxTopRows, false},
	} {
		got, err := parseTopN(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseTopN(%q) = %d, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTopN(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseTopN(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseIPv4Key(t *testing.T) {
	key, err := parseIPv4Key("192.0.2.7")
	if err != nil {
		t.Fatalf("parseIPv4Key: %v", err)
	}
	if key != [4]byte{192, 0, 2, 7} {
		t.Errorf("key = %v, want [192 0 2 7]", key)
	}
	if ipv4Str(key) != "192.0.2.7" {
		t.Errorf("round trip gave %q", ipv4Str(key))
	}
	for _, bad := range []string{"", "999.1.1.1", "2001:db8::1", "not-an-ip"} {
		if _, err := parseIPv4Key(bad); err == nil {
			t.Errorf("parseIPv4Key(%q) accepted an invalid address", bad)
		}
	}
}

func TestDropReasonIndex(t *testing.T) {
	if idx, err := dropReasonIndex(""); err != nil || idx != -1 {
		t.Errorf("empty reason gave (%d, %v), want (-1, nil)", idx, err)
	}
	idx, err := dropReasonIndex("udp_ratelimit")
	if err != nil {
		t.Fatalf("dropReasonIndex: %v", err)
	}
	if bpfmaps.DropReasonNames[idx] != "udp_ratelimit" {
		t.Errorf("index %d resolves to %q", idx, bpfmaps.DropReasonNames[idx])
	}
	if _, err := dropReasonIndex("ratelimit"); err == nil {
		t.Error("dropReasonIndex accepted the Prometheus label instead of the drop-history name")
	}
}

func TestCountMapEmitsZeroCounts(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: uint64(0)},
		{key: [4]byte{10, 0, 0, 2}, val: uint64(3)},
	}}
	rec := httptest.NewRecorder()
	handleCountMap(m)(rec, httptest.NewRequest(http.MethodGet, "/api/open-count", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d rows, want 2", len(out))
	}
	if _, ok := out[0]["count"]; !ok {
		t.Error("a zero count was omitted from the JSON")
	}
}

func TestAbortedIterationIsAnError(t *testing.T) {
	m := &fakeMap{
		entries: []fakeEntry{{key: [4]byte{10, 0, 0, 1}, val: uint64(1)}},
		iterErr: errors.New("iteration aborted"),
	}
	rec := httptest.NewRecorder()
	handleCountMap(m)(rec, httptest.NewRequest(http.MethodGet, "/api/open-count", nil))
	if rec.Code == http.StatusOK {
		t.Errorf("a truncated listing returned 200 with body %s", rec.Body)
	}
}

func TestTopRowsRanksAndTruncates(t *testing.T) {
	m := &fakeMap{entries: []fakeEntry{
		{key: [4]byte{10, 0, 0, 1}, val: uint64(1)},
		{key: [4]byte{10, 0, 0, 2}, val: uint64(9)},
		{key: [4]byte{10, 0, 0, 3}, val: uint64(5)},
	}}
	rows, err := topRows(m, "count", 0, 2, -1, false)
	if err != nil {
		t.Fatalf("topRows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].IP != "10.0.0.2" || rows[1].IP != "10.0.0.3" {
		t.Errorf("rows out of order: %s then %s", rows[0].IP, rows[1].IP)
	}
	if rows[0].Display != "" {
		t.Errorf("the HTTP path built a display string: %q", rows[0].Display)
	}
}

func TestTopRowsPropagatesIterationError(t *testing.T) {
	m := &fakeMap{
		entries: []fakeEntry{{key: [4]byte{10, 0, 0, 1}, val: uint64(1)}},
		iterErr: errors.New("iteration aborted"),
	}
	if _, err := topRows(m, "count", 0, 10, -1, false); err == nil {
		t.Error("topRows swallowed an aborted iteration")
	}
}
