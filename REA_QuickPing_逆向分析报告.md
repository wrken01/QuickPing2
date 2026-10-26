# QuickPing_v0.80.exe 逆向分析报告（REA 五层还原法）

- 分析日期：2026-10-16
- 分析方式：纯静态（零执行、零联网、零额外依赖）；peek.py 体检 + 手写 PE/DFM 解析器逐字节还原
- 证据分级：E0 直接观测（字节级） / E1 强推断（有证据链） / E2 弱推断 / E3 推测
- 引擎闸门结论：binary-reverser ✅ 通过；protocol-decoder ✅ 通过；behavior-analyst ⚠️ 触发 `needs_dynamic_probe` 闸门——运行期行为仅作假设，不进结论章节

---

## 1. 目标与边界

| 项 | 内容 | 证据 |
|---|---|---|
| 文件 | QuickPing_v0.80.exe，433,152 字节 | E0 |
| 本质 | 32 位 Windows GUI 程序，Delphi 编译 | E0（区段名 + DVCLAL + PACKAGEINFO） |
| 原名 | QckPing.exe（版本资源 OriginalFilename） | E0 |
| 版本 | 0.8.0.0 / ProductVersion 0.80 | E0 |
| 作者 | 署名 CBB（标题与 ICMP payload 中两处出现） | E0 |
| 自述定位 | 窗口标题 `#QuickPing(V0.80/Windows98) --By CBB` → 面向 Windows 98 时代 | E0 |
| 语言 | 简体中文（资源语言 0804/GB2312，字体宋体） | E0 |
| 授权状态 | LegalCopyright 为空，无许可协议文本，无数字签名 | E0 |
| 安全初筛 | 无壳无混淆；导入表全部为正常系统 API；无 autorun/持久化/可疑字符串 | E0 |
| 本次止层 | L1–L4 静态完成 + L5 复刻规格；**动态行为未验证（未经授权未运行目标）** | — |

---

## 2. 结构（L1/L2：它是什么、由什么组成）

### 2.1 PE 容器 [E0]

```
PE32 / i386 / GUI子系统 / ImageBase 0x400000 / EntryPoint RVA 0x5CA5C
区段(8)：CODE(0x5BC00) DATA BSS .idata .tls .rdata .reloc .rsrc(0x4800)   ← Borland 标准布局
Linker 2.25（Borland）；TimeDateStamp=1992-06-19 为 Borland 假时间戳
DllCharacteristics=0（无 ASLR/DEP，时代产物）
整体熵 6.57（编译代码正常范围，.rsrc 仅 4.6 → 无加壳迹象）
```

### 2.2 编译器判定 [E1]

Delphi 5/6 时代 VCL。依据（证据链）：PACKAGEINFO 单元表含 `ActnList`、`FlatSB`、`StdActns`、`Contnrs`、`MultiMon`（Delphi 5 VCL50 单元组合）；STRING 资源含 docking 错误消息（D4+ 文案）；中文 GB2312_CHARSET 资源。

### 2.3 模块结构（PACKAGEINFO 单元表，E0）

```
QckPing        ← 工程主文件
 ├ test01      ← 主窗体单元（TForm1 及全部事件处理器）
 ├ pingthrd    ← Ping 线程单元（多线程扫描核心）
 ├ IcmpApi      ← ICMP API 封装（Icmp.dll 动态绑定）
 ├ ah_tool     ← 作者自制工具单元
 ├ Aligrid/XGrids  ← 第三方网格控件 TStringAlignGrid（16×16 矩阵视图）
 ├ MyEdit      ← 第三方 TTelNoEdit（电话号码式数字输入框，用于 IP 字段）
 └ VCL 标准单元约 40 个（Forms/Classes/Registry/IniFiles/WinSock/...）
```

### 2.4 导入表（401 个函数，全部正常系统 API）[E0]

| DLL | 关键函数 | 用途 |
|---|---|---|
| **Icmp.dll** | IcmpCreateFile / IcmpSendEcho / IcmpCloseHandle | 核心：发 ICMP Echo |
| **Iphlpapi.dll** | GetIpNetTable | 读 ARP 表 → 由 IP 反查 MAC |
| **wsock32.dll** | WSAStartup / gethostname / gethostbyname / gethostbyaddr / inet_addr / WSACleanup | 地址解析（含反向 DNS） |
| kernel32/user32/gdi32/comctl32/comdlg32/advapi32/ole* | 常规 GUI/文件/注册表操作 | — |

### 2.5 UI 结构（二进制 DFM 完整还原，E0）

窗口 422×342，不可调大小，宋体，屏幕居中，标题 `#QuickPing(V0.80/Windows98) --By CBB`。

```
┌─ Panel1（顶栏，参数区）───────────────────────────────┐
│ IP地址:[132].[105].[112].[0] 从[0] 到[255]  超时:[200] 线程:[20] │
│   └ TTelNoEdit ×7：IP01~IP05 + timeout01 + thread_No（数字输入）│
├─ Panel2（主视图区）────────────────────────────────┤
│ StringAlignGrid2：16列×16行=256格状态矩阵（黑底）          │
│   ← /24 网段每个 IP 一格，颜色/内容表示在线状态              │
│ StringAlignGrid1：4列结果列表（IP/MAC/状态等，运行时增行）    │
├─ Panel3（底栏）───────────────────────────────────┤
│ 起始：■  终止：■  用时：■  响应数：■   （红标签+紫红动态值） │
│ [开始][停止✕][表格模式][精简结果✕][保存][关闭]              │
│  ✕=默认禁用；Timer1(默认禁用)；SaveDialog1(CSV/pinglog)     │
└──────────────────────────────────────────────┘
```

事件处理器（E0，来自 DFM）：`FormCreate` / `startbuttonClick` / `stopbuttonClick` / `modebuttonClick`（切换列表↔矩阵视图）/ `savetologbuttonClick`（导出 CSV）/ `dealresultbuttonClick`（精简结果）/ `Timer1Timer`。

---

## 3. 机制（L3：怎么运作）

### 3.1 数据流（静态还原，E1）

```
输入：IP前3段(132.105.112) + 起始主机号(0) + 结束主机号(255) + 超时(200ms) + 线程数(20)
  ↓ 开始按钮
pingthrd 线程池（默认20线程）遍历 132.105.112.0 → 132.105.112.255
  ↓ 每线程
IcmpCreateFile → IcmpSendEcho(payload="PING, written by CBB!", timeout)
  ├ 有回应 → 解析 IP头/ICMP（内置 TTL、Source quench、Option too big 等 RFC792 错误消息表）
  │           → GetIpNetTable 查 ARP → "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x" 格式化 MAC
  └ 超时/错误 → 标记离线
  ↓ 更新 UI
16×16 矩阵着色 / 4 列列表刷新 / 统计标签（起始·终止·用时·响应数）
  ↓ 保存按钮
SaveDialog1（默认名 pinglog，CSV 过滤器）→ 写出 CSV 文件
```

### 3.2 关键字段/常量映射表

| 观测物 | 值/位置 | 语义 | 证据 |
|---|---|---|---|
| ICMP payload | `PING, written by CBB!` @0x59A44 | 22 字节自定义 echo 数据（签名即作者署名） | E0 |
| MAC 格式串 | `%2.2x:×6` @0x59A64 | ARP 查得的 6 字节 MAC 显示格式 | E0 |
| 子网常量 | `255.255.255` / `0.0.0` @0x5B134 | 掩码/通配计算 | E1 |
| RFC792 错误表 | TTL/Source quench/Option too big @0x59168 | ICMP 差错报文分类显示 | E0 |
| 默认参数 | 132.105.112.0–255 / 200ms / 20 线程 | DFM Text 属性 | E0 |
| `quickping` | 代码区 @0x5BEC1（仅 1 处） | 用途未定（见 §6） | E2 |
| CSV 默认名 | `pinglog` + `CSV File(*.csv)` | 日志导出 | E0 |

### 3.3 ⚠️ 动态闸门声明

behavior-analyst 闸门判定 `needs_dynamic_probe=true`：以上运行期流程为静态强推断（E1），**未实际运行验证**。以下事项未经动态确认：矩阵颜色语义、CSV 列结构、Timer 用途、quickping 字符串用途、注册表/ini 是否实际写入。

---

## 4. 意图（L4：为什么这样设计）

### 4.1 有据意图（证据支撑）

| 意图 | 证据 |
|---|---|
| 一屏尽览整个 /24 网段在线状态 | 16×16=256 格矩阵精确对应 /24 主机数（DFM，E0） |
| 关注「是哪台物理设备」而非仅 IP | 导入 GetIpNetTable + MAC 格式化串（E0） |
| 追求扫描吞吐 | 线程数可配置、默认 20 并发（E0） |
| 结果留档/交接 | CSV 导出、默认文件名 pinglog（E0） |
| 面向非专业使用者 | 全中文界面、参数极简（一个网段+超时+线程）（E0） |
| 时代约束下的兼容 | 标题自述 Windows98；单线程程 IP Helper API；Win9x 无内置 ping 图形化工具 | E1 |

### 4.2 可证伪假设（与上严格分栏，未验证）

| 假设 | 证伪方式 |
|---|---|
| `quickping` 字符串是配置持久化键（ini 文件名或注册表节名） | 运行后用 Procmon 监视文件/注册表访问 |
| `TTelNoEdit` 复用电话号码输入控件只为限制数字输入 | 动态输入字母验证 |
| 典型场景是 1999–2003 年网吧/校园机房网管 | 无法从二进制直接证明（E3，仅场景推演） |
| 「精简结果」= 过滤只显示响应设备 | 运行扫描后点击按钮对比列表 |

---

## 5. 复刻规格（L5：怎么照着做一个）

### 5.1 接口契约

```
输入参数：
  ip_prefix   : str    "a.b.c"        （网段前三段）
  host_start  : int    0..255          （起始主机号）
  host_end    : int    0..255          （结束主机号）
  timeout_ms  : int    默认 200
  workers     : int    默认 20
输出：
  结果集 List[HostResult]：
    HostResult { ip: str, alive: bool, rtt_ms: float|None,
                 mac: str|None,          # "AA:BB:CC:DD:EE:FF"
                 error: str|None }       # RFC792 错误类别
  汇总：{ start, end, elapsed, reply_count }
  导出：CSV（默认文件名 pinglog.csv）
```

### 5.2 核心伪代码（现代等价实现）

```python
# Windows 现代等价：IP Helper API（与原程序同一底层机制）
def scan(prefix, start, end, timeout_ms, workers):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:      # 对应 pingthrd 线程池
        futures = {pool.submit(ping_one, f"{prefix}.{h}", timeout_ms): h
                   for h in range(start, end + 1)}
        for f in as_completed(futures):
            ip, alive, rtt, err = f.result()                    # IcmpSendEcho 等价
            mac = arp_lookup(ip) if alive else None             # GetIpNetTable 等价
            results.append(HostResult(ip, alive, rtt, mac, err))
    return results

def ping_one(ip, timeout_ms):
    # Python: sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)，payload=b"PING, written by CBB!"
    # C#:     System.Net.NetworkInformation.Ping().Send(ip, timeout_ms)
    ...

def arp_lookup(ip):
    # Windows: GetIpNetTable (P/Invoke) 或 `arp -a` 解析；Linux: /proc/net/arp
    ...
```

### 5.3 UI 复刻要点（来自 DFM 还原）

- 参数区一行式布局：IP 三段 + 从/到主机号 + 超时 + 线程数
- 双视图：**列表视图**（每主机一行：IP/MAC/状态）与**矩阵视图**（16×16 格，每格一 IP，颜色编码在线状态）——矩阵是本工具最具辨识度的设计
- 底栏四统计：起始 / 终止 / 用时 / 响应数
- 按钮：开始 / 停止（运行时才启用）/ 视图切换 / 精简（只看在线）/ 保存 CSV / 关闭

### 5.4 验收测试

1. 扫 255.255.255.0–255（全部无响应）：响应数=0，矩阵全灰，用时合理
2. 扫本机所在 /24：至少网关与本机在线，矩阵对应格着色，MAC 非空
3. 20 线程扫 254 主机总时长 < 单线程线性时长（并发生效）
4. 超时 1ms vs 1000ms 对慢设备的检出差异
5. CSV 打开可读，行数 = 响应数（若精简）或 扫描数（全量）

---

## 6. 未知与下一步

| 未确认项 | 等级 | 获取方式 |
|---|---|---|
| `quickping` 字符串确切用途 | E2 | 动态运行 + Procmon 监视文件/注册表 |
| CSV 具体列头与行格式 | E2 | 运行扫描→保存→查看文件；或反编译 savetologbuttonClick |
| 矩阵格子的颜色语义（在线/离线/扫描中） | E2 | 动态运行观察 |
| StringAlignGrid1 四列的准确列名 | E2 | 动态运行或反编译 test01 单元 |
| Timer1 具体职责（进度刷新/超时清理） | E2 | 反编译 Timer1Timer |
| 「精简结果」过滤规则 | E2 | 动态对比 |
| Delphi 精确版本（5 还是 6） | E1 | Ghidra/IDA 加载后看 VCL RTTI 细节 |
| 作者 CBB 真实身份 | E3 | 网络检索（本次未联网） |

**阻断性未知：无。** 静态证据已支撑 L1–L4 结论与 L5 规格的主体。

**建议的动态验证流程（需你授权执行）：** 在隔离 VM 中运行 → Procmon 记录文件/注册表/网络 → Wireshark 抓包确认 ICMP payload 与并发模式 → 保存 CSV 查看格式。原程序为 32 位 Win9x 时代工具，现代 Windows 上 IP Helper 与 ARP 机制不变，预计可正常运行。

**深入反编译路径：** Ghidra/IDA + Delphi 签名库（FLIRT）可定位 test01/pingthrd/IcmpApi 单元的函数边界，结合已还原的事件处理器名可恢复近源码级逻辑。

---

*本报告由 REA 逆向工程专家团流程产出；结论均可回溯至文中标注的文件偏移与字节证据。*
