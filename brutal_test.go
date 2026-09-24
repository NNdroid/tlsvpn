package main

import (
	"errors"
	"reflect"
	"testing"
)

type fakeBrutalSocket struct {
	congestion  string
	version     uint32
	versionErr  error
	setAlgoErr  error
	setParamErr error
	getParamErr error
	params      []byte
	algoCalls   []string
}

func (f *fakeBrutalSocket) setCongestion(v string) error {
	f.algoCalls = append(f.algoCalls, v)
	if f.setAlgoErr != nil && v == "brutal" {
		return f.setAlgoErr
	}
	f.congestion = v
	return nil
}
func (f *fakeBrutalSocket) getCongestion() (string, error) { return f.congestion, nil }
func (f *fakeBrutalSocket) getVersion() (uint32, error)    { return f.version, f.versionErr }
func (f *fakeBrutalSocket) setParams(v []byte) error {
	if f.setParamErr != nil {
		return f.setParamErr
	}
	f.params = append([]byte(nil), v...)
	return nil
}
func (f *fakeBrutalSocket) getParams(size int) ([]byte, error) {
	if f.getParamErr != nil {
		return nil, f.getParamErr
	}
	if len(f.params) != size {
		return nil, errors.New("no params")
	}
	return append([]byte(nil), f.params...), nil
}

func TestBrutalParamABIAndVersionFallback(t *testing.T) {
	v2 := &fakeBrutalSocket{congestion: "cubic", version: brutalV2Version}
	legacy8, _ := brutalMbpsToBps(8)
	got := configureTCPBrutal(v2, 30, legacy8, 42)
	if !got.Applied || got.RateMbps != 30 || got.GroupID != 42 || len(v2.params) != 20 {
		t.Fatalf("v2 group apply = %+v, params=%d bytes", got, len(v2.params))
	}
	rate, gain, group, err := decodeBrutalParams(v2.params)
	if err != nil || rate != 30 || gain != 20 || group != 42 {
		t.Fatalf("v2 params decoded as rate=%d gain=%d group=%d err=%v", rate, gain, group, err)
	}

	v1 := &fakeBrutalSocket{congestion: "cubic", versionErr: errBrutalNoVersion}
	got = configureTCPBrutal(v1, 30, legacy8, 42)
	if !got.Applied || got.RateMbps != 8 || got.GroupID != 0 || len(v1.params) != 12 {
		t.Fatalf("v1 fallback = %+v, params=%d bytes", got, len(v1.params))
	}
}

func TestBrutalLockedRuleAndRollback(t *testing.T) {
	locked := &fakeBrutalSocket{
		congestion: "brutal", version: brutalV2Version,
		setAlgoErr: errBrutalLocked, setParamErr: errBrutalLocked,
	}
	params, _ := encodeBrutalParams(125, 15, 7, true)
	locked.params = params
	legacy8, _ := brutalMbpsToBps(8)
	got := configureTCPBrutal(locked, 30, legacy8, 42)
	if !got.Applied || !got.RuleManaged || got.RateMbps != 125 || got.CwndGain != 15 || got.GroupID != 7 {
		t.Fatalf("locked rule must be treated as active and read back: %+v", got)
	}

	lockedUnreadable := &fakeBrutalSocket{
		congestion: "brutal", version: brutalV2Version,
		setAlgoErr: errBrutalLocked, setParamErr: errBrutalLocked, getParamErr: errBrutalLocked,
	}
	got = configureTCPBrutal(lockedUnreadable, 30, legacy8, 42)
	if !got.Applied || !got.RuleManaged || got.RateMbps != 0 || got.GroupID != 0 || got.Error == "" {
		t.Fatalf("unreadable locked rule must not report the requested rate as actual: %+v", got)
	}

	failed := &fakeBrutalSocket{congestion: "cubic", version: brutalV2Version, setParamErr: errors.New("bad params")}
	got = configureTCPBrutal(failed, 30, legacy8, 42)
	if got.Applied || got.Error == "" {
		t.Fatalf("bad params unexpectedly applied: %+v", got)
	}
	if !reflect.DeepEqual(failed.algoCalls, []string{"brutal", "cubic"}) || failed.congestion != "cubic" {
		t.Fatalf("congestion algorithm not rolled back: calls=%v current=%s", failed.algoCalls, failed.congestion)
	}
}

func TestSplitLegacyBrutalRatePreservesTotal(t *testing.T) {
	for _, tc := range []struct {
		total uint64
		conns int
	}{{30, 4}, {2, 4}, {1, 1}, {101, 8}} {
		var sum uint64
		for i := 0; i < tc.conns; i++ {
			sum += splitLegacyBrutalRate(tc.total, tc.conns, i)
		}
		if sum != tc.total {
			t.Fatalf("split total=%d conns=%d summed to %d", tc.total, tc.conns, sum)
		}
	}
	if splitLegacyBrutalRate(2, 4, 2) != 0 {
		t.Fatal("zero-share legacy connection must stay unshaped instead of exceeding total")
	}
	var bpsSum uint64
	for i := 0; i < 4; i++ {
		bpsSum += splitLegacyBrutalRateBps(2, 4, i)
	}
	wantBps, _ := brutalMbpsToBps(2)
	if bpsSum != wantBps {
		t.Fatalf("byte-exact v1 split summed to %d B/s, want %d", bpsSum, wantBps)
	}
}

func TestBrutalRateBoundsAndGroupDomain(t *testing.T) {
	if _, err := brutalMbpsToBps(maxBrutalRateMbps); err != nil {
		t.Fatalf("maximum valid rate rejected: %v", err)
	}
	if _, err := brutalMbpsToBps(maxBrutalRateMbps + 1); err == nil {
		t.Fatal("rate above upstream kernel maximum accepted")
	}
	a := brutalGroupID("client", "same")
	b := brutalGroupID("server", "same")
	if a == 0 || b == 0 || a == b || a != brutalGroupID("client", "same") {
		t.Fatalf("group domain/stability broken: client=%d server=%d", a, b)
	}
}
