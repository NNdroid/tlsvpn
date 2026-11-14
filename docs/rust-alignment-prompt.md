# tlsvpn-rs 对齐 tlsvpn (Go) 协议 — 任务提示词

> ⚠️ **已过期 — 历史档案，不要再照着实现。** Rust 移植阶段的任务原文，保留
> 原样以便追溯当时定了什么；其中多条规格已被后续代码淘汰：
>
> - **AES-CTR 回退路径已移除。** 现在只有一种内层算法（GCM），所谓"强度下限"
>   退化成一道开关（`crypto.go` 的 `minEncNone` / `minEncGCM`）。
> - **`min_enc`**：只接受 `""`、`"any"`、`"gcm"`；`"ctr"` / `"legacy"` 已非法
>   （Go `config.go:393-397`，Rust `src/main.rs:387`）。
> - **`pad_mode`**：只接受 `""`、`"off"`、`"bucket"`；`"legacy"` 已非法
>   （Go `config.go:398-402`，Rust `src/crypto.rs:168`）。
> - **`enc_algo` 强弱协商与"新客户端 ↔ 旧服务端"降级语义已不存在。** 客户端
>   硬拒绝任何非 GCM 的协商结果（`client.go:1052`）。
> - 项目明确不兼容旧版本协议，本文的"任意混搭互通"目标已废止。
>
> 权威来源是两侧实现代码本身，以及 `testdata/protocol_golden.json`。

> 使用方法：把本文件全文作为任务发给实现 tlsvpn-rs 的 agent。要求它先读完
> `testdata/protocol_golden.json`（Go 侧生成的黄金向量）再动手；分阶段实现并
> 按各阶段验收标准自测。**所有字节序、常量、字段名以本提示词为准，与 Go 代码
> `frame.go`/`fec.go`/`crypto.go` 保持逐字节一致。**

---

## 背景

Go 版 tlsvpn 新增了四项协议能力，全部通过握手 JSON 字段**增量协商**。
Rust 端需要对齐，使新旧版本任意混搭都能互通：

1. **XOR 奇偶校验 FEC**（替代旧的"逐帧向所有连接复制"）
2. **AES-256-GCM 内层加密**（替代旧的 AES-CTR 异或；带会话盐与完整性校验）
3. **心跳帧语义变更**（0 长帧不再被静默吞掉，用于刷新读超时）
4. **web.bind=tunnel 面板绑定**（可选，仅 Rust 实现了面板时需要）

未协商时全部回退旧行为——所以 Rust 端可以先做握手字段透传（最低要求），
再逐步实现 FEC/GCM 本体。

（见文末"追加"一节：Go 侧后来又加了 `session_token`、`pad_mode`、`min_enc`
三项，其中前两项与线协议有关，需要同步。）

## 阶段 0（最低要求，半天）：握手字段透传

只改握手结构体，不改任何行为：

- `HandshakeReq` 增加 `fec_group: u32`（serde `#[serde(default)]`，缺省 0）与
  `enc_algo: u32`（同样 default 0）。
- `HandshakeResp` 增加上述两字段 + `enc_salt: String` + `enc_salt2: String`
  （全部 `#[serde(default)]`，缺省空串）。
- 收到请求时：若 `req.fec_group >= 2` 且你想启用 XOR FEC，则响应回带
  `fec_group`（clamp 到 2..=64）；若 `req.enc_algo >= 2` 且你想启用 GCM，则
  响应回带 `enc_algo=2` 和两个随机盐（hex 编码 8 字节）。
- **什么都不实现时**：直接回显 `fec_group=0`/`enc_algo=0`（或不带这些字段），
  对端自动回退旧模式，互通不受影响。这是安全底线。

验收：Go(Rust 服务端，旧行为) ↔ 新 Go 客户端互跑 e2e 全绿（Go 客户端日志出现
"falling back"字样）；Go 服务端 ↔ Rust 客户端同理。

## 阶段 1：握手 JSON 字段名契约（必须与 Go 完全一致）

serde 字段名（snake_case）：

```
client_id  psk  mac  ipv4  ipv6  padding  brutal_tx  brutal_rx
fec  fec_group  encrypt  enc_algo            (Req)
success  message  session_id  client_id  ipv4  ipv6  gw_v4  gw_v6
padding  brutal_tx  brutal_rx  fec  fec_group  encrypt  enc_algo
enc_salt  enc_salt2                            (Resp)
```

所有 `omitempty` 等价字段（mac/ipv4/ipv6/padding/brutal_tx/brutal_rx/fec/
fec_group/encrypt/enc_algo/enc_salt/enc_salt2）序列化时零值必须省略，
Resp 的 `success/message/client_id/ipv4/ipv6` 恒出现。

`rtt_probe`（Req 与 Resp 都有，见"追加 G"）是**协商字段**、同样 `omitempty`，
但 Go 客户端**恒发 `true`**——声明能力不违反"零值省略"约定，因为 Go 端该值
永远非零。Rust 侧未实现时不要发该字段，语义等价于 `false`；两侧取交集，
任一为 `false` 即不产生 `0x03`/`0x04` 流量。

验收：跑 Go 仓库 `go test -run TestHandshake`——它锁定了字段名集合与
omitempty 行为；Rust 侧用同样断言写测试。

## 阶段 2：AES-256-GCM 内层加密

密钥派生（与 golden vectors 逐字节一致，不得更改）：

```
key   = SHA256( PSK + "_enc_key" )   // 32 字节 AES-256
legacy_iv = SHA256( PSK + "_enc_iv" )[0..16]
```

GCM 参数（c2s 与 s2c **各一个方向**的盐，盐互不相同）：

```
salt  = 8 字节随机（每次建会话时 crypto_rand 生成；c2s 用 resp.enc_salt，
        s2c 用 resp.enc_salt2；发起方在响应里同时下发两个方向）
nonce = seq(4B 大端) || salt(8B)          // 12 字节
aad   = wire_len(4B 大端) || seq(4B 大端) // wire_len = 密文长+16B 标签
密文  = AES-256-GCM(key, nonce).seal(明文, aad)，线路负载 = 密文+16B 标签
```

线帧格式（10 字节头不变）：

```
[4B data_len 大端][2B pad_len 大端][4B seq 大端][data_len 字节负载][pad_len 字节填充]
data_len 含 GCM 标签（明文长 + 16）；seq==0 的帧（心跳/握手）不加密
```

兼容回退：`enc_algo=0` 时沿用旧 AES-CTR（即 legacy_iv 前 12 字节作 IV 基底、
低 4 字节放 seq 大端，整 IV 做 CTR 计数器异或）——这段已有实现保持不动。

盐生命周期：**每个会话一对新盐**（服务端每次建会话生成；重启即换）。同盐下
seq 严格递增不复用；seq 回绕前必须先换盐。

验收：
1. `go test -run TestGenerateGoldenVectors -update-golden` 在 Go 侧生成后，
   Rust 侧解析 `testdata/protocol_golden.json` 校验密钥派生、legacy 向量、
   帧头布局逐字节一致；
2. Rust 服务端 + Go 客户端以 `encrypt=true` 建链，两端日志均出现
   `EncAlgo=2`，e2e 隧道 up；
3. 故意翻转 1 字节密文 → 接收端丢弃该帧并打 debug 日志（不得 panic）。

## 阶段 3：XOR 奇偶校验 FEC

协商：客户端请求 `fec_group=K`（2..=64，默认 4），服务端响应回带相同 K。
`fec=true` 且 `fec_group>=2` → XOR 模式；响应缺 `fec_group` 或 <2 →
回退旧复制模式。

分组与线格式：

```
会话数据帧 seq 从 1 起连续编号（0 = 心跳/控制帧，不参与 FEC）。
分组起点固定满足 start ≡ 1 (mod K)，无需端间同步即可算出：start = seq - ((seq-1) % K)
每凑满 K 个数据帧生成 1 个校验帧；校验帧 seq=0（不加密头字段），
线路负载：
  [1B 0xFE 魔数][4B group_start 大端][1B K][K×4B 成员明文长度 大端][异或载荷]
异或载荷 = K 个成员【明文】负载的逐字节异或，按最长成员对齐（短帧高位补零）；
encrypt 开启时对异或载荷加密（seq 用 group_start，AAD 的 wire_len = 载荷长+16GCM 标签），
即整帧 = 6B 描述 + K*4B 长度表 + 加密后的异或载荷(+16B 标签)
校验帧广播到所有物理连接（每连接一份副本）；数据帧仍按 MinRTT 单路发送。
```

解码规则：

```
数据帧到达：按 start=seq-((seq-1)%K) 归组，异或进累加器，gotMask 记位
校验帧到达：异或载荷解密（GCM 失败→整组放弃）；组内恰好缺 1 帧 →
  recovered = parity[i] ^ acc[i]（i < 缺失帧长度；acc 短于它时先零扩展），
  以原 seq 注入重排缓冲；缺 ≥2 帧 → 不可恢复，等待或放弃
同组终结（恢复/全员到齐/淘汰）后记住 start，吸收多连接广播的重复校验帧
在途组上限 512、超限淘汰 start 最老者（不拉黑 start）；done 缓存 64 项
```

接收端收到**0 长数据帧必须忽略且不得占用分组槽位**（Go 侧 a2701e4 修复的
对齐问题：发送端零长帧不消耗 seq）。

验收：
1. Rust 侧单测：K=4 丢组内单帧恢复（含组首帧丢失——它会把待定组起点锚错，
   必须靠校验帧的 group_start 对齐）、丢 2 帧不产出伪造帧、异盐校验帧被拒；
2. Rust 服务端 ↔ Go 客户端 `-fec -fec-group 4` 建链，两端日志
   `XOR FEC negotiated: K=4`，e2e 隧道 up；
3. 极端测试：校验帧先于其成员到达也要正确（乱序宽容）。

## 阶段 4：心跳帧语义（必做，防 30 秒断连）

线协议层：收到 `data_len==0` 的帧时**返回给调用方**（Go 语义为
`frame=nil, seq, err=nil`），由读循环刷新 30 秒读超时。不得在扫描器内部
静默 `continue`——那是 Go 版已修复的 bug（空闲隧道每 30 秒被误杀重连）。
发送侧 keepalive 维持 4 秒一次的 0 长帧。

## 阶段 5（可选）：web.bind=tunnel

若 Rust 版有面板：配置 `web.bind = "tunnel"` 时仅监听隧道 IP——服务端为
地址池网关 IPv4+IPv6（各一个 listener），客户端为首次握手分配的 IP；用
2 秒轮询的 rebind 循环跟随 IP/证书/认证变化，先开新 listener 再关旧的。

## 通用约束

- seq==0 永远不加密（心跳/校验帧识别依赖此约定）；握手帧也是 seq=0 且以
  `{` 开头，不会与 0xFE 魔数混淆。
- 所有 multi-byte 整数一律大端（golden vectors 的 FrameHeaders 向量锁定）。
- 错误帧（GCM 失败、校验帧描述符自洽性不过、异盐）一律静默丢弃 + debug 日志，
  禁止 panic 或关闭连接。
- 每阶段完成后跑仓库 e2e：`scripts/e2e_test.sh`（组 C/D 是跨语言组）。

## 验收总标准

1. `go test ./...`（Go 侧）与 Rust 侧全部测试通过；
2. `scripts/e2e_test.sh` 组 A–F 全绿，其中组 C（Go 服务端 ↔ Rust 客户端）
   与组 D（Rust 服务端 ↔ Go 客户端）在两侧都启用 `fec/encrypt` 的新参数
   后仍互通；
3. 黄金向量测试两侧逐字节一致；
4. 新旧混搭矩阵（Rust 新 ↔ Go 旧、Rust 旧 ↔ Go 新）全部回退模式互通。

---

# 追加：Go 侧新增的三项（2026-09）

## 追加 A：`session_token`（握手双向字段，可选）

服务端配置 `server.session_token = true` 时，握手**响应**新增
`session_token`（hex 字符串，`#[serde(default)]`，缺省空串）。它是
`hex(HMAC-SHA256(pskKey, b"session-token-v1" || session_id))`——**只在该
会话自己的 TLS 连接里下发**，所以持有 PSK、能凭 (MAC, PSK) 算出
`client_id` 的冒充者仍然拿不到令牌。

客户端收到后必须保存，并在**重连同一 client_id** 的握手机制请求里通过
`session_token`（同样是 `#[serde(default)]` 空串）回带。服务端校验失败就
拒绝接管在线会话并断开该连接。

安全语义（务必按此实现，否则该特性形同虚设）：
- 校验必须发生在"接管既有会话 / 销毁旧连接"之前；
- 校验失败不要走抗探测的焦油坑，直接断开（与 PSK 失败的处理保持一致）；
- 旧客户端回带空串。所以默认值必须是 **false**，否则升级后所有旧客户端
  的重连会被拒绝。这是刻意设计的 opt-in。

验收：Go 测试 `TestSessionToken` 锁定了令牌算法与失败条件，Rust 侧写同向
测试。e2e 中用两台同 MAC 客户端互踢验证。

## 追加 B：`pad_mode`（本地配置，影响线路字节）

> ⚠️ **已过期**：`legacy` 档位连同 AES-CTR 回退一起移除了，现在只接受
> `""` / `"off"` / `"bucket"`。下面的 `legacy` 描述仅作历史参考。

混淆填充不再是唯一的"随机填充"策略，可配置为 `legacy | bucket | off`
（默认 `bucket`）。三者的线路长度语义：

- `off`：`padLen = 0`。
- `legacy`：旧语义，入参是**线路负载长度**（明文长 + GCM 16B 标签）：
  `wireLen==0 → 100..=300`；`<200 → 300..=499`；`<800 → 100..=299`；
  否则 `0..=99`。
- `bucket`：把小帧填充到固定桶 `128,256,384,512,768,1024,1280,1600,2048,4096`
  （`frame.go` 的 `padBuckets`；取第一个 `>= wireLen` 的桶，差值即 padLen）；
  `wireLen <= 0` 不填充；超过最大桶（4096）的 jumbo 帧只加 `0..=99` 随机填充。

**与 Go 旧实现的关键差异**：填充长度现在按 `wireLen`（含 GCM 标签）计算，
不是按明文长。旧 Go 是按明文长。所以开启 GCM 后同一个包的 padLen 会变大
16 左右，Rust 侧若已实现 legacy 也要按 `wireLen` 算，否则两侧 pad 区间错位。

配置字段名 `pad_mode`（顶层），面板 `save_apply` 可热更。

## 追加 C：`min_enc`（纯本地策略，无线协议影响）

> ⚠️ **已过期**：取值现在是 `""` / `"any"` / `"gcm"`，`"ctr"` 和 `"legacy"`
> 都已非法（Go `config.go:277`，Rust `src/main.rs:387`），因为只有一种内层
> 算法（GCM）了。强度序 `none < ctr < gcm` 同样不再成立。下文仅作历史参考。

顶层配置 `min_enc`，取值 `"" | "ctr" | "legacy" | "gcm"`。强度序
`none(0) < ctr(1) < gcm(2)`。语义：
- 服务端：握手请求声明的 `enc_algo` 强度低于下限则拒绝（`enc_algo=0/1`
  视作 CTR，`2` 视作 GCM，其它未知值一律按 CTR 算，**不要**用数值大小比较
  ——旧代码正是用 `>=` 比出来的 bug）。
- 客户端：服务端协商出的 `enc_algo` 低于下限则视为握手失败、进入重连。
- 要求 `encrypt = true` 才允许配置（校验层强制）。

这一项只影响本进程行为，Rust 侧无需同步线协议，但对齐语义可避免配置误用。

## 追加 D：FEC 尾组行为（无协议变化，纯澄清）

编码器**从不冲刷不满 K 的分组**，解码端**必须拒绝成员数不足 K 的校验帧**。
原因：解码端用 `seq` 的算术对齐把数据帧归组（组起点 `start ≡ 1 mod K`，
数据帧 seq 从 1 起连续），这个边界无法随帧协商。一旦接受一个只有 `m < K`
个成员的分组的校验帧，该 `start` 被标记为已终结，紧随其后的帧会全部被算进
这个已终结组而直接丢弃——静默批量丢包。因此宁可丢掉那个尾组（退化为容忍
丢失，由 TCP 重传兜底），也不能容忍归组错位。

如果 Rust 端 FEC 已实现，确认这两点：
1. 编码端 `flush` 只在组满 K 帧时触发；
2. 解码端对 `start == 0 || k != K || (start-1) % K != 0` 的校验帧直接返回。

## 追加 E：`enc_algo=3`（GCM-v2，协商式密钥分离）—— 已于 2026-09-19 双侧实现

背景：Go 与 Rust 的 GCM（算法 2）与 legacy CTR 共用同一派生密钥
`sha256(psk + "_enc_key")`——同一把 AES 密钥既当 GCM 的 GHASH 子密钥又当
CTR 密钥流，属分层混用。**直接改算法 2 的派生是破坏性变更**（两端都声明
支持 GCM 时协商仍成功，但标签全败 = 静默黑洞），所以用新算法值协商：

- 新常量 `enc_algo = 3`（GCM-v2）：线路格式与 2 完全一致
  （nonce = seq(4BE)‖salt(8B)、AAD = wireLen(4BE)‖seq(4BE)、16B 标签），
  **唯一区别**是密钥派生标签：`sha256(psk + "_enc_key_gcm_v2")`。
- 客户端：`enc_algo` 声明改为 3（Go `clientEncAlgoSupport` /
  Rust `CLIENT_ENC_ALGO_SUPPORT`）。服务端响应 3 → 用 v2 标签；
  响应 2 → 用旧标签。
- 服务端：请求 3 → v2；请求 2 → 旧派生（旧客户端不受影响）；
  请求 0/其它 → legacy CTR。
- `min_enc`：强度档不变，2 与 3 都算 GCM 档。
- 混搭语义：新客户端 ↔ 旧服务端 = 双方回退 legacy CTR（安全降级，
  绝不黑洞）；旧客户端 ↔ 新服务端 = GCM-v1 不变；两端同升 = GCM-v2。
  **注意：新客户端 + 旧服务端 + `min_enc=gcm` 会进入可见的重连失败循环**
  （客户端拒绝 CTR 协商结果）——这是刻意的，两端同时升级即恢复。
- 参考实现：Go `crypto.go`（`encAlgoGCMv2`/`gcmKeyLabel`/`newGCMInnerCipherAlgo`），
  Rust `crypto.rs`（`ENC_ALGO_GCM_V2`/`derive_key_labeled`/`InnerCipher::gcm_algo`）。
  两侧回归测试：`TestGCMV2RoundTripAndKeySeparation`（Go）/
  `gcm_v2_roundtrip_and_key_separation`（Rust）锁定 v1/v2 密文互不相通。

## 追加 F：Go 侧服务端加固（2026-09-19，Rust 侧建议跟进、非线协议）

以下为 Go 服务端内部行为，不影响互通，Rust 侧可视情况对齐：

1. **常量时间比较**：握手 PSK 哈希与 MAC 的比较用 `hmac.Equal`
   （`subtle.ConstantTimeCompare` 等价），非恒定时间比较构成远程时序预言机，
   可逐字节重建 pskHash（它本身就是握手凭据）。
2. **源 MAC 归属校验**：交换机学习表只接受"端口声明本会话注册 MAC"，
   冒充帧整帧丢弃并计数（`tlsvpn_spoofed_src_dropped_frames_total`），
   防跨客户端劫持下行流量。MAC 为空的会话放行保持兼容。
3. **会话上限**：`server.max_sessions`（默认 1024）+ IPv4 池耗尽直接拒连；
   v6 /64 池实际不会枯竭，无上限等于把 OOM 做成持密者可远程触发的功能。
4. **广播令牌桶**：每源端口洪泛预算默认 burst 8192 / 回充 16384/秒
   （覆盖 ~180Mbps 纯洪泛，线速广播攻击被削 90%+），网关端口豁免；
   超预算丢弃计数（`tlsvpn_broadcast_dropped_frames_total`）。
5. **预认证帧长上限**：认证前的首帧（握手 JSON，<2KB）负载上限 16KB，
   防 10 字节帧头声明 131070 长度把扫描缓冲扩到 131KB/连接；认证后恢复全量。
6. **clientID/MAC 格式校验**：clientID 必须是 UUID 形态、MAC 必须
   `aa:bb:cc:dd:ee:ff`（可为空），防换行注入伪造日志行。
7. **Go CLI 收敛为配置文件唯一入口（2026-09-19）**：Go 二进制只保留
   `-c <config.json>` 与 `-print-config`，其余命令行 flag 全部移除。
   任何驱动 Go 二进制的脚本/CI 必须改用 `-c`；Rust 侧自带 flag 不受影响，
   但其 e2e/net-perf 脚本里的 Go 分支已同步改为生成 JSON 配置。

## 追加 G：跨路径 RTT 探针 `0x03`/`0x04`（2026-11，线协议）

Go 侧已实现"跨路径 RTT 探针"，用于把多路径选路从 `rtt/2` 的对称假设改成
去程按 `min fwd`、回程按 `min ret` 独立选路。这是**新增的 typed control kind**，
Rust 侧要实现互通（或至少要做到"不认识也不断连"）。

### 1. 新增 control kind（`seq=0` 控制帧，载荷首字节）

```text
0x01  FEC_PARITY   （既有）
0x02  FEC_MODE     （既有）
0x03  RTT_PROBE    （新增）
0x04  RTT_REPLY    （新增）
```

未知 kind 仍是协议错误并断连，故 Rust 侧**必须**把 `0x03`/`0x04` 加入
allow-list；即便暂时不实现测量逻辑，也要接受这两类帧而不视为违规。

### 2. 载荷线格式（固定 18 字节，大小端）

```text
偏移  长度  字段        说明
0     1     kind        0x03 探针 / 0x04 回包
1     1     flags       必须为 0，非零即畸形
2     4     nonce u32   发起端关联 id，非零，每笔唯一
6     4     reply_on u32 探针=目标回包连接 index；回包=0
10    8     send_ts u64 发起端发送时刻（UnixNano）
```

`send_ts` 由**发送 goroutine 在 `Write` 之前**写入固定偏移，回包**回显**探针
的值。只有发起端比较时间戳，两侧时钟无需同步。

### 3. 测量语义（跨路径分解）

发起端在连接 `i` 发探针、要求对端在连接 `j` 回包，测得
`RTT(i,j) = fwd_i + ret_j`。以参考连接 `ref`（最小存活 index）为锚，取生成集
`{RTT(i,ref)} ∪ {RTT(ref,j)}`：

```text
fwd(i) = decayed_min(RTT(i,ref)) - anchor(ref)
ret(j) = decayed_min(RTT(ref,j)) - anchor(ref)
anchor(ref) = tcpi_min_rtt(ref)/2，否则 decayed_min(RTT(ref,ref))/2
```

`decayed_min` 慢升快降（与内核 `tcpi_min_rtt` 语义平行）；锚定常数在 argmin 中
抵消，参考连接是否对称只影响显示值、不影响选路。

### 4. 抗指纹约定（实现者必须遵守）

探针/回包是 `seq=0` 控制帧，**必须**走与普通记录相同的带桶填充写出路径
（随机桶尺寸 + 随机覆盖字节），并在**数据批量间隙**发送；不得用独立定时器
裸发小帧，否则会留下固定周期的流量指纹。节奏为基准 500ms 均匀抖动 ±250ms，
生成集每周期轮转一对，非严格周期。

### 5. 调度器口径变化（不在线协议，但影响行为对齐）

- 资格包络、候选排序、路径质量改用 `tcpi_min_rtt`（无拥塞地板）；`min_rtt`
  未观测到时退回 SRTT，**不使用** 50000µs 哨兵当参考值。
- ETA 预测保留 SRTT（含当前拥塞，预测更准）。
- 单向估计未收敛前回退 `min_rtt/2` → `SRTT/2`，与改造前一致。
- 快照新增 `fwd_oneway_us` / `ret_oneway_us`（µs，`omitempty`，0=未收敛）。

### 6. 协商与向后兼容

握手请求新增 `rtt_probe: bool`，响应同名字段为**交集**结果。任一侧不声明支持
则两侧都不发 `0x03`/`0x04`，新旧混跑互不干扰——Rust 侧未实现前把该字段留空
即为安全的兼容状态。

## 追加阶段的验收

- 跑 Go 侧 `go test -run 'TestPadMode|TestSessionToken|TestHandshake|TestFEC|TestGCMV2|TestRttProbe'`；
- e2e 组 C/D 在 `pad_mode=bucket`、`server.session_token=true`、
  `min_enc=gcm` 下仍然互通；把三者全部关回默认再跑一遍确认回退路径；
- GCM-v2 专项：两侧同为最新版本时协商出 `enc_algo=3`（查日志/面板
  enc_algo），组 C/D 吞吐正常；任一侧回退旧版本时回退 legacy CTR 且互通；
- 跨路径探针专项：Rust 侧**尚未实现**测量逻辑时，只要把 `0x03`/`0x04` 加入
  control allow-list 并忽略其载荷，Go 侧就不会因未知 kind 断连（握手不带
  `rtt_probe` 时 Go 根本不发探针）；Rust 侧实现后按追加 G 的帧偏移与分解公式
  对齐，面板应能看到两侧一致的 `fwd_oneway_us`/`ret_oneway_us`。

