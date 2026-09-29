package main

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestTLSBatchCorkCoalescesBurstAndUncorksOnce(t *testing.T) {
	var mu sync.Mutex
	var calls []bool
	c := newTLSBatchCorkForTest(1440, 20*time.Millisecond, func(on bool) error {
		mu.Lock()
		calls = append(calls, on)
		mu.Unlock()
		return nil
	})
	defer c.Close()

	c.BeforeWrite(900)
	time.Sleep(5 * time.Millisecond)
	c.BeforeWrite(900) // conservative MSS progress starts a fresh tail deadline

	time.Sleep(8 * time.Millisecond)
	mu.Lock()
	gotEarly := append([]bool(nil), calls...)
	mu.Unlock()
	if !reflect.DeepEqual(gotEarly, []bool{true}) {
		t.Fatalf("premature uncork calls=%v want [true]", gotEarly)
	}

	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := append([]bool(nil), calls...)
		mu.Unlock()
		if reflect.DeepEqual(got, []bool{true, false}) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	got := append([]bool(nil), calls...)
	mu.Unlock()
	t.Fatalf("timer did not uncork once: calls=%v", got)
}

func TestTLSBatchCorkDoesNotExtendTinyOldTailForever(t *testing.T) {
	var mu sync.Mutex
	var calls []bool
	c := newTLSBatchCorkForTest(1440, 15*time.Millisecond, func(on bool) error {
		mu.Lock()
		calls = append(calls, on)
		mu.Unlock()
		return nil
	})
	defer c.Close()

	c.BeforeWrite(100)
	for i := 0; i < 4; i++ {
		time.Sleep(2 * time.Millisecond)
		c.BeforeWrite(100)
	}
	deadline := time.Now().Add(80 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := append([]bool(nil), calls...)
		mu.Unlock()
		if len(got) >= 2 && got[0] && !got[1] {
			return
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	got := append([]bool(nil), calls...)
	mu.Unlock()
	t.Fatalf("tiny writes kept old cork indefinitely: calls=%v", got)
}

func TestTLSBatchCorkCloseUncorks(t *testing.T) {
	var mu sync.Mutex
	var calls []bool
	c := newTLSBatchCorkForTest(1440, time.Second, func(on bool) error {
		mu.Lock()
		calls = append(calls, on)
		mu.Unlock()
		return nil
	})
	c.BeforeWrite(1500)
	c.Close()
	mu.Lock()
	got := append([]bool(nil), calls...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []bool{true, false}) {
		t.Fatalf("Close calls=%v want [true false]", got)
	}
}

func TestTLSBatchCorkFailureFallsBackWithoutRetryStorm(t *testing.T) {
	calls := 0
	c := newTLSBatchCorkForTest(1440, time.Second, func(bool) error {
		calls++
		return errTestCorkUnsupported
	})
	c.BeforeWrite(1500)
	c.BeforeWrite(1500)
	c.Close()
	if calls != 1 {
		t.Fatalf("setCork calls=%d want 1 after disabling failed optimization", calls)
	}
}

type corkTestError string

func (e corkTestError) Error() string { return string(e) }

const errTestCorkUnsupported = corkTestError("unsupported")
