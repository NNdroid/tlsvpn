//go:build linux

package main

import (
	"fmt"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestTapQueuesOpenFailureAndFallback(t *testing.T) {
	for _, err := range []error{syscall.EINVAL, syscall.EOPNOTSUPP, syscall.EPERM, syscall.EMFILE} {
		t.Run(err.Error(), func(t *testing.T) {
			q := newTestTapQueue()
			calls := 0
			got, e := openTapQueues("tap-test", 4, false, func(c water.Config) (io.ReadWriteCloser, error) {
				calls++
				if calls == 1 {
					if !c.MultiQueue || c.Name != "tap-test" {
						t.Fatal("wrong flags/name")
					}
					return q, nil
				}
				if calls == 2 {
					return nil, fmt.Errorf("ioctl: %w", err)
				}
				if c.MultiQueue || q.closed.Load() != 1 {
					t.Fatal("fallback before cleanup or wrong flags")
				}
				return newTestTapQueue(), nil
			})
			fallback := err == syscall.EINVAL || err == syscall.EOPNOTSUPP
			if (e == nil) != fallback {
				t.Fatalf("fallback=%t err=%v", fallback, e)
			}
			if q.closed.Load() != 1 {
				t.Fatal("partial open leaked fd")
			}
			if got != nil {
				_ = got.Close()
			}
		})
	}
}

// Explicit opt-in is a hard gate in CI: unavailable privileges cannot become
// a green skipped test. Real traffic is validated by the namespace harness.
func TestTapQueuesRealKernelLifecycle(t *testing.T) {
	if os.Getenv("TLSVPN_TEST_REAL_TAP") != "1" {
		t.Skip("set TLSVPN_TEST_REAL_TAP=1 for privileged kernel test")
	}
	for _, count := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			name := fmt.Sprintf("tmq%d_%d", os.Getpid(), count)
			q, err := openConfiguredTap(&Config{Tap: name, TapQueues: count, TapMultiQueue: true})
			if err != nil {
				t.Fatal(err)
			}
			defer q.Close()
			mq, ok := q.(*tapQueues)
			if !ok || len(mq.queues) != count {
				t.Fatal("kernel test silently fell back")
			}
			link, err := netlink.LinkByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if err = netlink.LinkSetUp(link); err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{}, count)
			stop := runTapReaders(q, func(r io.Reader) {
				started <- struct{}{}
				b := make([]byte, 2048)
				for {
					if _, err := r.Read(b); err != nil {
						return
					}
				}
			})
			for i := 0; i < count; i++ {
				<-started
			}
			done := make(chan struct{})
			go func() { stop(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("kernel fd Close did not unblock reads")
			}
			if _, err := netlink.LinkByName(name); err == nil {
				t.Fatal("nonpersistent device survived final fd Close")
			}
		})
	}
}
