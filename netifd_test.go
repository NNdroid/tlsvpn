package main

import (
	"sync/atomic"
	"testing"
)

func TestNetifdLinkNotificationsAreAggregateAndIdempotent(t *testing.T) {
	oldUp, oldDown := netifdLinkUpFn, netifdLinkDownFn
	defer func() {
		netifdLinkUpFn = oldUp
		netifdLinkDownFn = oldDown
	}()

	var upCalls, downCalls int
	netifdLinkUpFn = func(iface, device, v4, v6, gw4, gw6 string) error {
		upCalls++
		if iface != "vpn" || device != "tvpn-vpn" {
			t.Fatalf("unexpected netifd identity: %q %q", iface, device)
		}
		return nil
	}
	netifdLinkDownFn = func(iface, device string) error {
		downCalls++
		return nil
	}

	c := &Client{
		interfaceManager: "netifd",
		netifdInterface:  "vpn",
		tapName:           "tvpn-vpn",
	}

	atomic.StoreInt32(&c.liveConns, 1)
	if err := c.notifyNetifdUp("10.0.0.2/24", "fd00::2/64", "10.0.0.1", "fd00::1"); err != nil {
		t.Fatal(err)
	}
	if err := c.notifyNetifdUp("10.0.0.2/24", "fd00::2/64", "10.0.0.1", "fd00::1"); err != nil {
		t.Fatal(err)
	}
	if upCalls != 1 {
		t.Fatalf("identical multipath handshakes must collapse to one update, got %d", upCalls)
	}

	if err := c.notifyNetifdUp("10.0.0.3/24", "fd00::3/64", "10.0.0.1", "fd00::1"); err != nil {
		t.Fatal(err)
	}
	if upCalls != 2 {
		t.Fatalf("address change must refresh netifd, got %d up calls", upCalls)
	}

	// A transient 1 -> 0 observation must not publish DOWN when another
	// backend has already recovered before the state lock is acquired.
	atomic.StoreInt32(&c.liveConns, 1)
	if err := c.notifyNetifdDown(); err != nil {
		t.Fatal(err)
	}
	if downCalls != 0 {
		t.Fatalf("live aggregate connection must suppress stale DOWN, got %d", downCalls)
	}

	atomic.StoreInt32(&c.liveConns, 0)
	if err := c.notifyNetifdDown(); err != nil {
		t.Fatal(err)
	}
	if downCalls != 1 {
		t.Fatalf("last backend loss must publish one DOWN, got %d", downCalls)
	}
	if err := c.notifyNetifdDown(); err != nil {
		t.Fatal(err)
	}
	if downCalls != 1 {
		t.Fatalf("duplicate DOWN must be idempotent, got %d", downCalls)
	}
}
