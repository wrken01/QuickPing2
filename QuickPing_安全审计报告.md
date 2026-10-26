# QuickPing_v0.80.exe 木马/病毒深度检测报告

- 审计日期：2026-10-16
- 方式：纯静态深度审计（不执行目标）+ 公开情报核对
- 结论先行：**未发现任何木马、病毒、后门或恶意行为指标。静态证据链完整且自洽，判定为干净的 2000 年代 Delphi 免费网工工具（E0/E1 级证据）。**

## 文件指纹（可自行到 VirusTotal 复核）

```
MD5    : 869ba7ecb8aab466063a8d795114e0c6
SHA1   : 6009f759c16be6738325e009af3f961342da1e3e
SHA256 : 76414d0e9cf9c73b116bb03aa045a41d91d43be7d925d9dd36925532a4294a45
大小   : 433,152 字节 (423 KB)
```

## 一、打包与隐藏检测 —— 全部阴性

| 检查项 | 结果 | 证据 |
|---|---|---|
| 加壳/压缩 | 无（8 个标准 Delphi 区段，CODE 熵 6.5、.rsrc 熵 4.6，无 >7.2 高熵区段） | E0 |
| W+X 可写可执行区段 | 无（CODE 只执行不可写） | E0 |
| Overlay 附加数据 | 0 字节（文件末尾 = 最后区段末尾 0x69C00，严丝合缝） | E0 |
| 嵌套 PE / ZIP / gzip 载荷 | 无 | E0 |
| base64 / 长 hex 加密块 | 无 | E0 |
| TLS 回调（入口点前执行的隐藏代码） | **空回调表**，无 | E0 |
| 入口点花指令 | 无（`55 8B EC` 标准 Delphi 单元初始化桩） | E0 |
| 反调试（IsDebuggerPresent 等） | 无 | E0 |

## 二、完整攻击面检测（全量 ~369 个导入函数逐一核对）

### 木马必需能力 → 本程序实际情况

| 恶意能力 | 所需 API | 本程序 | 判定 |
|---|---|---|---|
| 进程注入 | WriteProcessMemory / CreateRemoteThread / VirtualAllocEx / OpenProcess / SetThreadContext | **全部缺失** | 不可能 |
| 下载二次载荷 | WinExec / CreateProcess / URLDownloadToFile / wininet 全家 | **全部缺失**（wininet.dll 零导入） | 不可能 |
| C2 网络外传 | socket / connect / send / recv / WSAConnect | **全部缺失**（wsock32 仅 6 个域名解析函数） | 不可能 |
| 注册表持久化 | RegSetValueExA（写 Run 键必需） | **缺失**（advapi32 仅 5 个函数，唯一写类 RegCreateKeyExA 只能建键不能写值） | 不可能 |
| 键盘记录 | SetWindowsHookEx(WH_KEYBOARD) + 外传通道 | 有 SetWindowsHookExA 但为 **Delphi VCL 消息机制标配**；且无外传通道（见上） | 阴性 |
| 隐藏窗口/服务 | CreateMutex / 服务 API | 缺失 | 阴性 |
| 自毁/时间锁 | SetFileTime / MoveFile / CopyFile | 缺失 | 阴性 |

### 实际导入的全部"敏感"API 逐条归因（均为 Delphi 运行时标配）

- `SetWindowsHookExA`/`CallNextHookEx`/`UnhookWindowsHookEx` → VCL TApplication 内部消息钩子
- `GetKeyState` → VCL 菜单快捷键处理
- `VirtualAlloc`/`VirtualFree` → Delphi 内存管理器
- `CreateThread`/`WaitForSingleObject`/`SetEvent` → pingthrd 多线程 ping（正是软件本体功能）
- `CreateFileA`/`WriteFile` → CSV 结果导出
- `GetTickCount` → ping RTT 延迟测量
- `LoadLibraryA`/`GetProcAddress` → Delphi 动态加载 Icmp.dll（IP Helper 标准 ping 通道）
- `RegQueryValueExA`/`RegOpenKeyExA` → 只读注册表（见下条用途）

### 网络能力边界（E0）

程序唯一能出的网络流量 = `IcmpSendEcho`（固定 22 字节签名 payload `PING, written by CBB!`，同步请求-应答模式）。不含任意数据外传通道。`GetIpNetTable` 为本机 ARP 表只读查询。无 socket、无 HTTP、无 DNS 隧道构造能力。

### 唯一的注册表路径（E0，良性归因）

代码区发现唯一非系统注册表引用：
`System\CurrentControlSet\Services\Class\NetTrans\...\IPAddress`（@0x5B8D4）+ 掩码常量 `255.0.0.0` —— 这是 **Windows 9x 读取本机网卡 IP 配置的标准路径**，用途是启动时自动探测本机所在网段填入界面（1999–2003 年的合法做法）。与下载站"不写注册表、绿色免安装"的口碑一致。

### 字符串面（E0）

全二进制无 URL、无邮箱、无 cmd/powershell/rundll32/mshta 等脚本解释器调用、无 Run 键路径、无可疑配置。

## 三、公开情报（OSINT）核对

QuickPing 为国内多个下载站长期收录的经典免费网工工具（ZOL、天天软件园、下载之家等），ZOL 收录版本大小 423KB 与本文件一致；功能描述（20 线程默认/绿色=占用/亮绿=取得主机名/MAC 解析/CSV 导出）与静态逆向结果逐项吻合；多家站点口碑为"绿色免安装、不写注册表"。

## 四、残余风险声明（诚实边界）

1. **静态分析 ≠ 100% 免疫**：理论上存在运行时 GetProcAddress 动态解析隐藏行为的可能，但本程序代码为无混淆的 Delphi 原生代码，动态解析点仅 Icmp.dll 一处（字符串可证实），未发现其他隐藏解析目标（E1）。
2. 无数字签名属时代常态（1999–2003 年个人免费软件几乎都无签名），不构成恶意指标。
3. 建议自助闭环：将上方 SHA256 提交 VirusTotal 查多引擎交叉结论；如需终极验证可在隔离 VM 中运行并用 Procmon/Wireshark 复核（预期仅见 ICMP Echo 流量 + 只读注册表查询 + CSV 写入）。

## 总判定

**干净。无木马、无病毒、无后门、无持久化、无隐藏执行点、无外传通道。**
所有检测维度证据等级均为 E0（字节直接观测）或 E1（强推断），无任何 E2 以下证据支撑的可疑项。

---
*审计脚本与中间数据留存于 `.workbuddy/rea_work/`（sec_audit.py / sec_audit2.py / ioc_scan.py），全部只读，可复核。*
