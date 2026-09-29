package main

import "net"

// Unwrap lets socket-level helpers reach the accepted TCP connection through
// the prefix-replay wrapper used by protocol sniffing on the server side.
func (c *PrefixConn) Unwrap() net.Conn {
	if c == nil {
		return nil
	}
	return c.Conn
}
