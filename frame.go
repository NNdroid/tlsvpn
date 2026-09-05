package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"strings"
	"sync"
)

// ======================= 内存池与带有序列号的成帧协议 =======================
type VPNFrame struct {
	Seq  uint32
	Data []byte
}

var framePool = sync.Pool{
	New: func() any { return make([]byte, 32*1024) },
}

func getFrame() []byte { return framePool.Get().([]byte) }
func putFrame(b []byte) {
	if cap(b) >= 1500 && cap(b) <= 65536 {
		framePool.Put(b[:cap(b)])
	}
}

// cloneFrame 深拷贝一帧负载（优先取池缓冲），供逐后端独立所有权使用
func cloneFrame(data []byte) []byte {
	if data == nil {
		return nil
	}
	buf := getFrame()
	if len(data) > cap(buf) {
		putFrame(buf)
		dst := make([]byte, len(data))
		copy(dst, data)
		return dst
	}
	dst := buf[:len(data)]
	copy(dst, data)
	return dst
}

// freeFrames 释放一批帧的缓冲（所有权归调用方时使用）
func freeFrames(batch []VPNFrame) {
	for i := range batch {
		if batch[i].Data != nil {
			putFrame(batch[i].Data)
			batch[i].Data = nil
		}
	}
}

func getPaddingLength(dataLen int) int {
	if dataLen == 0 {
		return 100 + mathrand.IntN(201)
	}
	if dataLen < 200 {
		return 300 + mathrand.IntN(200)
	} else if dataLen < 800 {
		return 100 + mathrand.IntN(200)
	} else {
		return mathrand.IntN(100)
	}
}

// appendPaddedFrame 10 字节头部 [4B len][2B padLen][4B seq]
//
// ic 为内层加密器：nil 表示明文；seq=0 的控制/握手帧恒不加密（协议约定，
// 接收端以此区分校验帧与握手帧）。GCM 模式密文后附 16B 标签，线路
// dataLen = 明文长 + tagLen；ic.tagLen() 用于一次性预留缓冲，避免中途扩容。
func appendPaddedFrame(buf []byte, vf VPNFrame, ic *innerCipher) []byte {
	dataLen := 0
	if vf.Data != nil {
		dataLen = len(vf.Data)
	}
	encTag := 0
	if ic != nil && vf.Seq != 0 && dataLen > 0 {
		encTag = ic.tagLen()
	}
	padLen := getPaddingLength(dataLen)

	// 1. 一次性算出需要的整包新增长度
	needed := 10 + dataLen + encTag + padLen
	startIdx := len(buf)

	// 2. 检查容量，不够则一次性扩容，防多次 append 扩容崩溃
	if cap(buf)-startIdx < needed {
		newCap := cap(buf) * 2
		if newCap < startIdx+needed {
			newCap = startIdx + needed
		}
		newBuf := make([]byte, startIdx, newCap)
		copy(newBuf, buf)
		buf = newBuf
	}

	// 改变 slice 的长度属性
	buf = buf[:startIdx+needed]

	// 3. 原址绝对下标写入头信息（dataLen 为线路负载长度，含 GCM 标签）
	binary.BigEndian.PutUint32(buf[startIdx:startIdx+4], uint32(dataLen+encTag))
	binary.BigEndian.PutUint16(buf[startIdx+4:startIdx+6], uint16(padLen))
	binary.BigEndian.PutUint32(buf[startIdx+6:startIdx+10], vf.Seq)

	// 4. 拷贝数据负载并加密
	if dataLen > 0 {
		payloadStart := startIdx + 10
		copy(buf[payloadStart:payloadStart+dataLen], vf.Data)

		if ic != nil && vf.Seq != 0 {
			ic.sealInPlace(buf[payloadStart:payloadStart+dataLen+encTag], dataLen, vf.Seq, uint32(dataLen+encTag))
		}
	}

	// 5. 填补混淆填充
	if padLen > 0 {
		padStart := startIdx + 10 + dataLen + encTag
		offset := mathrand.IntN(RandomPoolSize - padLen)
		copy(buf[padStart:padStart+padLen], randomPool[offset:offset+padLen])
	}

	return buf
}

// writeStreamFrame 发送无需去重的控制帧
func writeStreamFrame(w io.Writer, frame []byte) error {
	streamBuf := getFrame()[:0]
	streamBuf = appendPaddedFrame(streamBuf, VPNFrame{Seq: 0, Data: frame}, nil)
	_, err := w.Write(streamBuf)
	putFrame(streamBuf[:cap(streamBuf)])
	return err
}

func generatePadding(min, max int) string {
	length := mathrand.IntN(max-min+1) + min
	offset := mathrand.IntN(RandomPoolSize - length)
	return hex.EncodeToString(randomPool[offset : offset+length])
}

// ======================= 流式帧扫描器 (读取 10 字节头) =======================
type FrameScanner struct {
	r      io.Reader
	buf    []byte
	offset int
}

func NewFrameScanner(r io.Reader) *FrameScanner {
	return &FrameScanner{r: r, buf: make([]byte, 0, 70*1024)}
}

func (fs *FrameScanner) ReadFrame() ([]byte, uint32, error) {
	const HeaderSize = 10
	const MaxDataLength = 65535 * 2

	for {
		available := len(fs.buf) - fs.offset

		if available >= HeaderSize {
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			seq := binary.BigEndian.Uint32(fs.buf[fs.offset+6 : fs.offset+10])
			totalLen := dataLen + padLen

			if dataLen > MaxDataLength {
				fs.buf = fs.buf[:0]
				fs.offset = 0
				return nil, 0, fmt.Errorf("invalid frame data length: %d", dataLen)
			}

			if available >= HeaderSize+totalLen {
				if dataLen == 0 {
					fs.offset += HeaderSize + totalLen
					continue // 忽略空包
				}

				var frame []byte
				temp := getFrame()
				if dataLen > cap(temp) {
					putFrame(temp)
					frame = make([]byte, dataLen)
				} else {
					frame = temp[:dataLen]
				}

				copy(frame, fs.buf[fs.offset+HeaderSize:fs.offset+HeaderSize+dataLen])
				fs.offset += HeaderSize + totalLen
				return frame, seq, nil
			}
		}

		if fs.offset > 0 && (fs.offset == len(fs.buf) || fs.offset > 16384) {
			remaining := len(fs.buf) - fs.offset
			if remaining > 0 {
				copy(fs.buf, fs.buf[fs.offset:])
			}
			fs.buf = fs.buf[:remaining]
			fs.offset = 0
		}

		tailStart := len(fs.buf)
		requiredCap := tailStart + 2048

		available = len(fs.buf) - fs.offset
		if available >= HeaderSize {
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			if fs.offset+HeaderSize+dataLen+padLen > requiredCap {
				requiredCap = fs.offset + HeaderSize + dataLen + padLen
			}
		}

		if cap(fs.buf) < requiredCap {
			newCap := cap(fs.buf) * 2
			if newCap < requiredCap {
				newCap = requiredCap
			}
			newBuf := make([]byte, len(fs.buf), newCap)
			copy(newBuf, fs.buf)
			fs.buf = newBuf
		}

		fs.buf = fs.buf[:cap(fs.buf)]
		n, err := fs.r.Read(fs.buf[tailStart:])
		fs.buf = fs.buf[:tailStart+n]

		if err != nil {
			if n == 0 || (err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection")) {
				return nil, 0, err
			}
		}
	}
}

// ======================= 协议结构 =======================
type HandshakeReq struct {
	ClientID string `json:"client_id"`
	PSK      string `json:"psk"`
	MAC      string `json:"mac,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Padding  string `json:"padding,omitempty"`
	BrutalTx uint64 `json:"brutal_tx,omitempty"`
	BrutalRx uint64 `json:"brutal_rx,omitempty"`
	FEC      bool   `json:"fec,omitempty"`
	FecGroup int    `json:"fec_group,omitempty"`
	Encrypt  bool   `json:"encrypt,omitempty"`
	// EncAlgo：本端支持的最高内层加密算法（位集，bit1=GCM）。
	// 旧版 Go/Rust 不发送本字段 → 0（legacy CTR）。
	EncAlgo int `json:"enc_algo,omitempty"`
}

type MacBinding struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

type HandshakeResp struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	SessionID string `json:"session_id,omitempty"`
	ClientID  string `json:"client_id"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	GwV4      string `json:"gw_v4,omitempty"`
	GwV6      string `json:"gw_v6,omitempty"`
	Padding   string `json:"padding,omitempty"`
	BrutalTx  uint64 `json:"brutal_tx,omitempty"`
	BrutalRx  uint64 `json:"brutal_rx,omitempty"`
	FEC       bool   `json:"fec,omitempty"`
	FecGroup  int    `json:"fec_group,omitempty"`
	Encrypt   bool   `json:"encrypt,omitempty"`
	// EncAlgo：协商选定的算法（0=legacy CTR，2=GCM）。仅当双方都支持
	// GCM 时为 2；此时 EncSalt 为 c2s 方向盐（客户端加密/服务端解密），
	// EncSalt2 为 s2c 方向盐（服务端加密/客户端解密）。
	EncAlgo  int    `json:"enc_algo,omitempty"`
	EncSalt  string `json:"enc_salt,omitempty"`  // hex(8B)：客户端→服务端方向
	EncSalt2 string `json:"enc_salt2,omitempty"` // hex(8B)：服务端→客户端方向
}
