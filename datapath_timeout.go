package main

import "time"

// 数据面超时参数。
//
// 这些超时决定"对端消失"的检测速度：健康连接每 keepaliveInterval 收到一次对端
// 应用层心跳，读超时须显著大于心跳间隔以容忍一次心跳丢失；写超时检测阻塞写
// （socket 发送缓冲满且对端不再读取），对正在承载流量的死连接能更快发现。
//
// 历史值读超时 16s / 写超时 11s 会把半开连接留在调度器里近 16 秒，期间调度器
// 持续把数据分给死路径（最多 N-1/N 丢失），表现为"3 条断开后网络就断了"。
// 收敛到 8s / 3s 后，活跃死连接约 3s 内、空闲死连接约 8s 内被踢出调度器。
const (
	// keepaliveInterval 双向应用层心跳间隔（空帧）。
	keepaliveInterval = 4 * time.Second

	// datapathReadTimeout 数据面读超时。须大于 keepaliveInterval 且能容忍
	// 一次心跳丢失（4s 间隔 + 容忍一次 = 8s），同时把"对端静默"的检测窗口
	// 压到 8s，让半开/死连接尽快被踢出调度器，避免幸存路径被死路径拖垮。
	datapathReadTimeout = 8 * time.Second

	// datapathWriteTimeout 数据面单次写超时。单批 <= maxTLSWriteBatchBytes
	// （12 KiB），在任意可用带宽（> ~32 Kbps）下都能在 3s 内完成；超时意味着
	// socket 发送缓冲已满且对端停止读取——即连接已死/半开。对正在承载流量的
	// 死连接，写超时是比读超时更快的检测手段（缓冲填满后约 3s 即被踢出）。
	datapathWriteTimeout = 3 * time.Second
)
