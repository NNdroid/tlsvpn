package main

import (
	"testing"
	"unsafe"
)

// TestAlignProbe386 回归测试：所有经 sync/atomic（atomic.AddUint64/LoadUint64
// 或 atomic.Uint64 类型）访问的 64 位计数字段必须在 8 字节边界上。32 位平台
// （386/arm/mips，见 crosscompile_test.go 发布矩阵）只保证结构体首字段的 8 字节
// 对齐，结构体中部的裸 uint64 字段偏移 4-mod-8，运行时 atomic 操作直接 panic
// （数据面首包即崩）。字段必须用 atomic.Uint64 类型（内嵌 align64 保证对齐）。
// 新增 64 位原子计数字段时把它加进探针列表。
func TestAlignProbe386(t *testing.T) {
	type ent struct {
		name string
		off  uintptr
	}
	var ents []ent
	add := func(name string, off uintptr) { ents = append(ents, ent{name, off}) }
	var cs ClientSession
	add("ClientSession.TxBytes", unsafe.Offsetof(cs.TxBytes))
	add("ClientSession.RxBytes", unsafe.Offsetof(cs.RxBytes))
	add("ClientSession.TxPackets", unsafe.Offsetof(cs.TxPackets))
	add("ClientSession.RxPackets", unsafe.Offsetof(cs.RxPackets))
	var ci connInfo
	add("connInfo.txBytes", unsafe.Offsetof(ci.txBytes))
	add("connInfo.rxBytes", unsafe.Offsetof(ci.rxBytes))
	add("connInfo.txPackets", unsafe.Offsetof(ci.txPackets))
	add("connInfo.rxPackets", unsafe.Offsetof(ci.rxPackets))
	add("connInfo.brutalTx", unsafe.Offsetof(ci.brutalTx))
	add("connInfo.brutalRx", unsafe.Offsetof(ci.brutalRx))
	add("connInfo.epoch", unsafe.Offsetof(ci.epoch))
	var c Client
	add("Client.TxBytes", unsafe.Offsetof(c.TxBytes))
	add("Client.RxBytes", unsafe.Offsetof(c.RxBytes))
	add("Client.TxPackets", unsafe.Offsetof(c.TxPackets))
	add("Client.RxPackets", unsafe.Offsetof(c.RxPackets))
	var cci clientConnInfo
	add("clientConnInfo.txBytes", unsafe.Offsetof(cci.txBytes))
	add("clientConnInfo.rxBytes", unsafe.Offsetof(cci.rxBytes))
	add("clientConnInfo.retries", unsafe.Offsetof(cci.retries))
	var ap AsyncPort
	add("AsyncPort.dropped", unsafe.Offsetof(ap.dropped))
	bad := 0
	for _, e := range ents {
		aligned := e.off%8 == 0
		if !aligned {
			bad++
		}
		t.Logf("%-28s off=%d align8=%v", e.name, e.off, aligned)
	}
	if bad > 0 {
		t.Errorf("%d fields NOT 8-byte aligned on this arch", bad)
	}
}
