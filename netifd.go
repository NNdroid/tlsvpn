package main

import (
	"fmt"
	"strings"
	"sync/atomic"
)

type netifdLinkState struct {
	up   bool
	v4   string
	v6   string
	gw4  string
	gw6  string
}

func sameNetifdLinkState(a netifdLinkState, v4, v6, gw4, gw6 string) bool {
	return a.up && a.v4 == v4 && a.v6 == v6 && a.gw4 == gw4 && a.gw6 == gw6
}

func (c *Client) usesNetifd() bool {
	return c.interfaceManager == "netifd"
}

func (c *Client) notifyNetifdUp(v4, v6, gw4, gw6 string) error {
	if !c.usesNetifd() {
		return nil
	}
	if strings.TrimSpace(c.netifdInterface) == "" {
		return fmt.Errorf("client.interface_manager=netifd requires TLSVPN_NETIFD_INTERFACE")
	}

	c.netifdMu.Lock()
	defer c.netifdMu.Unlock()
	if sameNetifdLinkState(c.netifdState, v4, v6, gw4, gw6) {
		return nil
	}

	// Serialize helper execution across multipath handshakes. Without holding
	// this lock two connections can both observe the old state and race two
	// netifd updates for the same interface.
	if err := netifdLinkUp(c.netifdInterface, c.tapName, v4, v6, gw4, gw6); err != nil {
		return err
	}

	c.netifdState = netifdLinkState{
		up: true, v4: v4, v6: v6, gw4: gw4, gw6: gw6,
	}
	return nil
}

func (c *Client) notifyNetifdDown() error {
	if !c.usesNetifd() {
		return nil
	}

	c.netifdMu.Lock()
	defer c.netifdMu.Unlock()
	if !c.netifdState.up {
		return nil
	}
	// A reconnect may have incremented liveConns after the disconnecting
	// backend observed 1 -> 0 but before it acquired this lock. Do not publish
	// a stale DOWN after connectivity has already recovered.
	if atomic.LoadInt32(&c.liveConns) != 0 {
		return nil
	}

	if err := netifdLinkDown(c.netifdInterface, c.tapName); err != nil {
		return err
	}

	c.netifdState = netifdLinkState{}
	return nil
}
