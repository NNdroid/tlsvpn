from pathlib import Path

path = Path('client.go')
text = path.read_text()
old = '''\t// 初始化重排缓冲区：当包按序理顺后，统一写入 c.tap\n\tc.rxReorder = NewReorderBuffer(func(orderedFrame []byte) {\n\t\tif _, werr := c.tap.Write(orderedFrame); werr != nil {\n\t\t\t// 旧实现静默丢弃错误：TAP 故障时表现为\"隧道在线但本机不通\"\n\t\t\tn := c.tapWriteErrs.Add(1)\n\t\t\tif n == 1 || n%1000 == 0 {\n\t\t\t\tlog.Warnf(\"[Client] TAP write failed #%d: %v\", n, werr)\n\t\t\t}\n\t\t}\n\t})\n'''
new = '''\t// v2 只在单物理连接时把 RX/reorder 与阻塞 TAP write 解耦。旧 real-TAP\n\t// 实验显示 conns=1 有正收益信号，而 conns=2/4 的额外 channel/goroutine\n\t// 调度会抵消收益；多连接因此继续保留直接 TAP 交付路径。\n\treportTapWriteErr := func(werr error) {\n\t\tn := c.tapWriteErrs.Add(1)\n\t\tif n == 1 || n%1000 == 0 {\n\t\t\tlog.Warnf(\"[Client] TAP write failed #%d: %v\", n, werr)\n\t\t}\n\t}\n\tif cl.Conns == 1 {\n\t\ttapDelivery := newOwnedTapDelivery(ctx, c.tap, asyncTapDeliveryQueue, reportTapWriteErr)\n\t\tc.rxReorder = NewOwnedReorderBuffer(tapDelivery.EnqueueOwned)\n\t} else {\n\t\tc.rxReorder = NewReorderBuffer(func(orderedFrame []byte) {\n\t\t\tif _, werr := c.tap.Write(orderedFrame); werr != nil {\n\t\t\t\treportTapWriteErr(werr)\n\t\t\t}\n\t\t})\n\t}\n'''
if old not in text:
    raise SystemExit('target reorder block not found; branch may have drifted')
text = text.replace(old, new, 1)
path.write_text(text)
