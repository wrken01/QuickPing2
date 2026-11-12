# QuickPing2 — 设备在线率监控软件

复刻自 QuickPing v0.80（Windows 98，原作 by CBB）并优化在线检测准确性，作者 Örken。
当前界面版本 **V1.00**，文档对应 **2026-11-12** 的程序状态。

一个本地运行的单页 Web 工具，把「网段在线率扫描」「单 IP 端口扫描」「局域网设备发现」三件事放在同一界面里，所有结果都能导出 CSV。

---

## 快速开始

| 方式 | 操作 | 说明 |
|---|---|---|
| 桌面版（推荐） | 双击 `quickping2/dist/QuickPing2GUI.exe` | WebView2 原生窗口，关闭窗口即退出并停止服务 |
| 源码 / 浏览器版 | 运行 `quickping2/start.bat`，或 `python quickping2/server.py` | 自动打开 `http://127.0.0.1:8730/` |

- **环境**：Windows。底层用 IP Helper API 的 `IcmpSendEcho` / `SendARP`，**免管理员权限**；桌面版需 WebView2 运行时（Win10/11 通常已自带）。
- 服务只监听 `127.0.0.1`；8730 被占用时自动顺延到 8739，并在控制台提示。
- **注意**：工作区根目录的 `QuickPing2GUI.exe` 是手动放置的旧副本（14:26 版本），不是最新构建产物。以 `quickping2/dist/QuickPing2GUI.exe` 为准。

---

## 功能总览

### 1. 网段在线率扫描

输入 /24 前缀与起止主机号（默认 `192.168.253.0–255`），可调超时、线程数，支持「ARP 兜底」「协议识别」开关；矩阵与表格双视图，实时显示响应数、在线率、系统分布、进度。

主机判定采用四阶段递进，尽量避免把禁 ping 的设备误判为离线：

1. ICMP echo（原版同款）
2. **首包立即重试** —— 挽回 ARP 尚未解析导致首包被丢的误判
3. **ARP 兜底** —— 防火墙禁 ICMP echo 的设备仍可判在线，顺带取 MAC
4. **TCP 445/80/443 connect** —— 跨网段或 ARP 不可达时，`open` 或收到 `RST` 都证明主机存活

在线设备附带 RTT / TTL / OS 推测、反向 DNS 主机名、`SendARP` MAC，以及协议标签（SSH/HTTP/HTTPS/SMB/RDP）；DNS 解析失败时用 NetBIOS 节点状态查询兜底取 Windows 计算机名与 MAC。

导出 `pinglog.csv`：`ip,state,method,rtt_ms,ttl,hostname,mac,os,protocols,error`，支持只导出在线主机。

### 2. 单 IP 端口扫描

- 协议：TCP / UDP / TCP+UDP；范围：`全部`(1–65535) / `常用` / `80,443` / `1-1024` / `8000-8100` 等自定义写法。
- TCP 三态 `open / closed / filtered`；UDP 三态 `open / closed / unknown`（无响应只代表「未知」，可能是静默服务或被过滤）。
- **假开放识别（2026-11-12 新增）**：企业网关/中间设备会对任意端口伪造 SYN-ACK，造成「全端口开放」假象。处理方式：
  - 对服务端主动发欢迎语的明文协议（21 FTP / 22 SSH / 25 SMTP / 110 POP3 / 119 NNTP / 143 IMAP / 587 Submission），connect 成功后额外用 0.35s 短超时收一次 greeting，校验 `220` / `SSH-` / `+OK` / `* OK` 等前缀，得出 `confirmed / unconfirmed / silent`。HTTP、HTTPS、SMB、RDP、MySQL 等客户端先说话的协议判 `silent`，不参与判定、不误伤。
  - 全局启发式：TCP 开放数 ≥100 且占比 ≥30%，或 ≥2 个问候端口全部无欢迎语且 0 个已验证 → 判定疑似 SYN 代理，界面出警告条。
  - 概览扫描的 `tcp_probe` 三态语义保持不变，二次校验由独立连接完成，零回归。
- 端口标签覆盖常见服务，并补齐 `1 TCPMUX`、`444 SNPP`、`119 NNTP`、`162 SNMP Trap`、`1900 SSDP`、`5353 mDNS`、`5355 LLMNR`、`3702 WS-Discovery`、`6514 Syslog-TLS` 等发现/告警类端口。
- 界面：存疑端口黄色标记（悬停看 banner）、统计行「已验证 / 存疑」、开放端口 chip 最多渲染 300 个（防全端口假开放时 DOM 卡死）。
- 导出 `portscan.csv`：`ip,proto,port,state,service,verdict,banner`。

### 3. 局域网设备发现（组播 / 广播）

与端口扫描语义不同：向组播或广播地址发标准查询，收集全网段设备主动回的应答，按 IP 归并协议标签、名称、详情与首次发现时间。

| 类别 | 协议 | 目标 |
|---|---|---|
| 通用 | SSDP | `239.255.255.250:1900` |
| 通用 | mDNS | `224.0.0.251:5353` |
| 通用 / ONVIF | WS-Discovery | `239.255.255.250:3702` |
| 通用 | NetBIOS | `255.255.255.255:137` |
| 安防 | 大华 DHIP | `239.255.255.251:37810` + 受限广播 |
| 安防 | 海康 SADP | `239.255.255.250:37020` |
| 安防 | 大华 DVRIP（老设备） | `255.255.255.255:5050` |

- **宇视没有公开的私有组播发现协议**：官方 EZTools 的按 IP 段搜索遵循 ONVIF，实测摄像机应答标准 WS-Discovery。因此不编造私有报文，改为解析 ONVIF `Scopes` 中的 `name / hardware / version / serial / macaddr / manufacturer / type`，可带出型号、序列号、固件、设备类型；厂商按明确品牌串/型号前缀推断，一律标注「疑似」。大华、海康则由私有协议直接给出型号、序列号、固件、MAC、通道数等，取不到的字段不显示。
- 私有协议应答常回到**固定的本地端口**，随机端口 socket 收不到。`Discoverer` 为每个协议建专用 socket 绑定 `37810 / 37020 / 5050 / 3702` 并加入组播组；端口被占用（如 SADP 工具、Windows WSD 服务）时退化随机端口并在界面提示。
- 查询逐条捕获发送异常，避免受限广播在禁播网络里失败后挡住后续协议；过半程补发一次查询防组播丢包；`meta` 含 `packets / multicast_ok / warn`，组播不可用或零应答时给中性提示。
- **LLMNR(5355) 不做主动探测**：需要查询一个具体名字，且只有认为自己是该名字的主机才应答，主动探测命中率极低，被动监听才有意义。
- **不需要指定目标网段**：按 Kane 2026-11-12 实测，现有组播发现已能覆盖所需网段、效果良好，界面保持无网段输入。
- 导出 `discovery.csv`：`ip,protocols,name,details,first_seen`。

---

## HTTP API

服务仅监听 `127.0.0.1`。

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/` | Web UI（`index.html`） |
| GET | `/api/status` | 扫描状态与结果 |
| GET | `/api/localnet` | 本机 IP（页面自动填网段） |
| POST | `/api/start` | 开始扫描，参数 `prefix,start,end,timeout,workers,arp,deep` |
| POST | `/api/stop` | 停止扫描 |
| GET | `/api/export?only=online` | 导出 `pinglog.csv` |
| GET | `/api/portstatus` | 端口扫描状态（含 `suspect_syn_proxy` 等判据） |
| POST | `/api/portscan` | 开始端口扫描，参数 `ip,ports,proto,workers,timeout` |
| POST | `/api/portstop` | 停止端口扫描 |
| GET | `/api/portexport` | 导出 `portscan.csv` |
| GET | `/api/discoverstatus` | 设备发现状态与设备表 |
| POST | `/api/discover` | 开始发现，参数 `protos,timeout` |
| POST | `/api/discoverstop` | 停止发现 |
| GET | `/api/discoverexport` | 导出 `discovery.csv` |

---

## 目录结构

```
设备在线率监控软件/
├─ README.md                              本文件
├─ QuickPing_v0.80.exe                    原版程序（逆向参考）
├─ QuickPing_v0.80_逆向分析报告.html        原版逆向资料
├─ REA_QuickPing_逆向分析报告.md           原版逆向资料
├─ QuickPing_安全审计报告.md               原版安全审计资料
└─ quickping2/
   ├─ server.py                          核心引擎 + 全部 HTTP API
   ├─ index.html                         Web UI（作为资源内嵌进 exe）
   ├─ gui.py                             WebView2 桌面窗口入口
   ├─ start.bat                          源码模式启动
   ├─ test_smoke.py                      不依赖 HTTP 的引擎冒烟测试
   ├─ app.ico
   ├─ build_gui/QuickPing2GUI.spec       PyInstaller 配置
   └─ dist/QuickPing2GUI.exe             唯一交付构建产物
```

根目录三份报告与 html 都是针对**原版 QuickPing v0.80** 的逆向/安全审计背景资料，与 QuickPing2 的实现没有对应关系，不要当作当前程序的功能说明。

---

## 构建

- 工具：PyInstaller 6.x（本机为 6.22.3，托管 venv：`C:/Users/kane/.workbuddy/binaries/python/envs/default`）。
- 配置：`quickping2/build_gui/QuickPing2GUI.spec`，入口 `gui.py`，`datas` 内嵌 `index.html`，`console=False`，图标 `app.ico`。spec 内的路径按本机绝对路径写死，迁移目录后需同步修改；该 spec 目录被 `.gitignore` 排除，未纳入版本库。
- 重建命令（工作目录 `quickping2/`）：

```powershell
& "C:/Users/kane/.workbuddy/binaries/python/envs/default/Scripts/python.exe" -m PyInstaller `
  --noconfirm --distpath "dist" --workpath "build_gui" "build_gui/QuickPing2GUI.spec"
```

- **`index.html` 是内嵌资源，任何前端改动都必须重新打包才会在 exe 里生效**。
- 项目约定：**只生成 `quickping2/dist/QuickPing2GUI.exe`**，不生成 `QuickPing2.exe` 或 `QuickPing2Portable.exe`，除非另行明确要求。

---

## 已知限制

- 仅支持 Windows（依赖 `iphlpapi`、`IcmpSendEcho`、`SendARP`）。
- 组播与受限广播通常不跨 VLAN / 三层边界；Kane 的实际环境实测覆盖良好，以现场结果为准。NetBIOS 受限广播在部分交换机会被丢弃。
- 安防私有协议依据公开源码、抓包与官方文档实现，不同厂商固件字段存在差异；解析不到的字段留空，不猜测。
- banner 校验只覆盖明文欢迎语协议；TLS 与客户端先说话的协议判 `silent`，不参与假开放判定。
- 存在伪造 TCP 握手的网关时，端口扫描结果要结合 `verdict` 与警告条判读。
- `162 / 1900 / 5353 / 5355 / 3702` 等发现类端口以 UDP 为主，端口扫描里只补了标签，TCP 扫描本身覆盖不到；发现这些设备应走「组播发现」功能。
- 服务只监听本机回环地址，不对外提供访问。

---

## 版本记录

**2026-11-12**（本次文档对应版本）

1. 端口扫描新增 greeting 二次校验与全局假开放识别，CSV 增加 `verdict / banner` 两列，前端加警告条与转义/渲染上限。
2. 补齐 `PORT_LABELS` 的历史服务与发现/告警类端口标签。
3. 新增独立「组播发现」模块（SSDP / mDNS / WS-Discovery / NetBIOS）与对应 API、CSV。
4. 新增安防设备发现（大华 DHIP、海康 SADP、大华 DVRIP）与 ONVIF Scopes 深度解析（覆盖宇视），固定端口专用 socket 接收应答。
5. 「指定 /24 目标网段」需求提出后即撤销，已完整回滚；组播发现保持无网段输入的实现。
6. 按约定只重建 `dist/QuickPing2GUI.exe`（17:40，16964150 B），移除 dist 下另两个旧 exe。

**2026-10-26 / 更早**：初始提交，含源码、构建成品与原版逆向分析报告。
