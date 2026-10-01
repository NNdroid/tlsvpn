//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func tcpObservationError(err error) string {
	if errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return "unsupported"
	}
	return "read_failed: " + err.Error()
}
func readTCPSocketSnapshot(conn *net.TCPConn, proxy bool) *tcpSocketSnapshot {
	s := newTCPSnapshot(conn, proxy)
	if conn == nil {
		s.Unavailable["socket"] = "no_tcp_socket"
		return s
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		s.Unavailable["socket"] = tcpObservationError(err)
		return s
	}
	err = raw.Control(func(fd uintptr) {
		for _, opt := range []struct {
			key               string
			level, option     int
			boolean, unsigned bool
		}{
			{"nodelay", unix.IPPROTO_TCP, unix.TCP_NODELAY, true, false},
			{"cork", unix.IPPROTO_TCP, unix.TCP_CORK, true, false},
			{"quickack", unix.IPPROTO_TCP, unix.TCP_QUICKACK, true, false},
			{"keepalive", unix.SOL_SOCKET, unix.SO_KEEPALIVE, true, false},
			{"keepidle_sec", unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, false, false},
			{"keepintvl_sec", unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, false, false},
			{"keepcnt", unix.IPPROTO_TCP, unix.TCP_KEEPCNT, false, false},
			{"sndbuf_bytes", unix.SOL_SOCKET, unix.SO_SNDBUF, false, false},
			{"rcvbuf_bytes", unix.SOL_SOCKET, unix.SO_RCVBUF, false, false},
			{"mss_bytes", unix.IPPROTO_TCP, unix.TCP_MAXSEG, false, false},
			{"user_timeout_ms", unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, false, true},
			{"notsent_lowat_bytes", unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, false, true},
			{"mark", unix.SOL_SOCKET, unix.SO_MARK, false, true},
		} {
			value, e := unix.GetsockoptInt(int(fd), opt.level, opt.option)
			if e != nil {
				s.Unavailable[opt.key] = tcpObservationError(e)
				continue
			}
			if opt.boolean {
				s.Values[opt.key] = value != 0
			} else if opt.unsigned {
				s.Values[opt.key] = uint64(uint32(value))
			} else {
				s.Values[opt.key] = value
			}
		}
		congestion, e := unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
		if e != nil {
			s.Unavailable["congestion"] = tcpObservationError(e)
		} else {
			s.Values["congestion"] = congestion
		}
		// Keep the kernel-returned optlen. New x/sys structs on older OpenWrt
		// kernels otherwise turn absent tail fields into misleading zeros.
		b := make([]byte, 512)
		n := uint32(len(b))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_INFO, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)), 0)
		if errno != 0 {
			s.Unavailable["tcp_info"] = tcpObservationError(errno)
			return
		}
		if n > uint32(len(b)) {
			n = uint32(len(b))
		}
		decodeTCPInfo(s, b[:n])
	})
	if err != nil {
		s.Values = map[string]interface{}{}
		s.Unavailable = map[string]string{"socket": tcpObservationError(err)}
	}
	return s
}
func decodeTCPInfo(s *tcpSocketSnapshot, b []byte) {
	var info unix.TCPInfo
	fields := []struct {
		key    string
		offset uintptr
		size   int
	}{
		{"rtt_us", unsafe.Offsetof(info.Rtt), 4}, {"rttvar_us", unsafe.Offsetof(info.Rttvar), 4}, {"rto_us", unsafe.Offsetof(info.Rto), 4},
		{"snd_mss_bytes", unsafe.Offsetof(info.Snd_mss), 4}, {"rcv_mss_bytes", unsafe.Offsetof(info.Rcv_mss), 4}, {"pmtu_bytes", unsafe.Offsetof(info.Pmtu), 4},
		{"cwnd_segments", unsafe.Offsetof(info.Snd_cwnd), 4}, {"unacked_segments", unsafe.Offsetof(info.Unacked), 4}, {"retrans_segments", unsafe.Offsetof(info.Retrans), 4},
		{"total_retrans", unsafe.Offsetof(info.Total_retrans), 4}, {"notsent_bytes", unsafe.Offsetof(info.Notsent_bytes), 4},
		{"delivery_rate_Bps", unsafe.Offsetof(info.Delivery_rate), 8}, {"pacing_rate_Bps", unsafe.Offsetof(info.Pacing_rate), 8},
		{"busy_us", unsafe.Offsetof(info.Busy_time), 8}, {"rwnd_limited_us", unsafe.Offsetof(info.Rwnd_limited), 8}, {"sndbuf_limited_us", unsafe.Offsetof(info.Sndbuf_limited), 8},
		{"bytes_retrans", unsafe.Offsetof(info.Bytes_retrans), 8}, {"snd_wnd_bytes", unsafe.Offsetof(info.Snd_wnd), 4},
	}
	for _, f := range fields {
		offset := int(f.offset)
		if offset+f.size > len(b) {
			s.Unavailable[f.key] = "unsupported_short_tcp_info"
			continue
		}
		v := uint64(binary.NativeEndian.Uint32(b[offset:]))
		if f.size == 8 {
			v = binary.NativeEndian.Uint64(b[offset:])
		}
		s.Values[f.key] = v
		if f.key == "pacing_rate_Bps" && v == ^uint64(0) {
			s.Values[f.key] = "unlimited"
		}
	}
	if len(b) > 0 {
		states := map[byte]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}
		s.Values["state"] = states[b[0]]
	}
	if len(b) > 1 {
		states := []string{"Open", "Disorder", "CWR", "Recovery", "Loss"}
		if int(b[1]) < len(states) {
			s.Values["ca_state"] = states[b[1]]
		}
	}
	if len(b) > 5 {
		flags := b[5]
		for _, opt := range []struct {
			key  string
			mask byte
		}{{"timestamps", 1}, {"sack", 2}, {"window_scaling", 4}, {"ecn", 8}} {
			s.Values[opt.key] = flags&opt.mask != 0
		}
	}
	if len(b) > 6 {
		snd, rcv := b[6]&15, b[6]>>4
		if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
			snd, rcv = rcv, snd
		}
		s.Values["snd_wscale"] = snd
		s.Values["rcv_wscale"] = rcv
	}
	if len(b) > 7 {
		mask := byte(1)
		if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
			mask = 128
		}
		s.Values["delivery_app_limited"] = b[7]&mask != 0
	}
}
