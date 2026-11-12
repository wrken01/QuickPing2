# -*- coding: utf-8 -*-
"""
QuickPing2 — 复刻 QuickPing v0.80 (原作 by CBB) 并优化 IP 在线检测准确性，作者 Örken
后端：与原程序相同的 IP Helper API (IcmpSendEcho)，免管理员权限
优化：
  1. 二次确认重试 —— 首包常因 ARP 未命中被丢，重试可挽回
  2. ARP 兜底探测 —— 防火墙禁 ICMP echo 的设备仍能判在线
  3. 在线设备顺带 SendARP 解析 MAC（替代原程序 GetIpNetTable 被动查表）
  4. TCP 探测兜底 —— 禁 ICMP 且 ARP 不可达时，对 445/80/443 做 connect 探测
     （收到 RST 也证明主机在线，nmap 同款语义）
  5. 协议标签 —— 每个在线 IP 输出 protos 数组（ICMP/ARP/DNS/NBNS/SSH/HTTP/
     HTTPS/SMB/RDP），NBNS 查询顺带取 Windows 计算机名
运行：python server.py  → 自动打开 http://127.0.0.1:8730/
"""
import ctypes
import ctypes.wintypes as wt
import csv
import io
import json
import os
import random
import re
import select
import socket
import struct
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT = 8730
PAYLOAD = "PING, written by Örken!".encode("latin-1")  # echo payload（作者 Örken）

# ---------- 阶段4 TCP 探测 & 协议标签 ----------
# 存活判定端口（阶段4 按序尝试：open（可建立连接）或 refused（收到 RST）都证明主机在线）
TCP_LIVENESS_PORTS = (445, 80, 443)
# 协议标签探测端口（对在线设备做服务识别）
TCP_PROBE_PORTS = (22, 80, 443, 445, 3389)
# 端口扫描常用预设（单个 IP 的端口扫描默认范围）
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 137, 139, 143, 389, 443, 445,
                993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
PORT_LABELS = {
    1: "TCPMUX(历史)",
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP Trap", 389: "LDAP", 443: "HTTPS", 444: "SNPP(寻呼)",
    445: "SMB", 465: "SMTPS", 500: "IPsec", 514: "Syslog", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 1883: "MQTT", 1900: "SSDP 发现", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 3702: "WS-Discovery", 5353: "mDNS 发现", 5355: "LLMNR",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6514: "Syslog-TLS",
    8080: "HTTP", 8443: "HTTPS", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}
# 注：162/1900/5353/5355/3702 以 UDP 为主，仅作标签提示；TCP 扫到这些端口时需结合 banner 判断。
# PyInstaller onefile 打包后资源解压在 _MEIPASS；源码模式取脚本目录
BASE = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))

iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)


# ---------- 原程序同款 ICMP 通道 (IcmpCreateFile / IcmpSendEcho / IcmpCloseHandle) ----------
class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_uint8),
        ("Tos", ctypes.c_uint8),
        ("Flags", ctypes.c_uint8),
        ("OptionsSize", ctypes.c_uint8),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


REPLY_BUF_SIZE = ctypes.sizeof(ICMP_ECHO_REPLY) + len(PAYLOAD) + 64

# 原程序内置的 ICMP 状态码 -> 错误消息映射（E0：二进制内含 11003/11004/11006/
# 11012/11018 等立即数 + TTL/Source quench/Option too big 消息表，本表为现代重述）
ICMP_STATUS_MSG = {
    11001: "缓冲区太小", 11002: "网络不可达", 11003: "主机不可达",
    11004: "协议不可达", 11005: "端口不可达", 11006: "无资源",
    11008: "错误选项", 11009: "硬件错误", 11010: "请求超时",
    11011: "错误请求", 11012: "错误路由", 11013: "TTL 传输过期",
    11014: "TTL 重组过期", 11015: "参数问题", 11016: "源抑制",
    11017: "选项过大", 11018: "目标无效", 11050: "一般错误",
}

# 函数原型（必须显式声明：64 位进程下 HANDLE 截断会导致 access violation）
iphlpapi.IcmpCreateFile.restype = wt.HANDLE
iphlpapi.IcmpCreateFile.argtypes = []
iphlpapi.IcmpCloseHandle.restype = wt.BOOL
iphlpapi.IcmpCloseHandle.argtypes = [wt.HANDLE]
iphlpapi.IcmpSendEcho.restype = wt.DWORD
iphlpapi.IcmpSendEcho.argtypes = [
    wt.HANDLE,        # IcmpHandle
    wt.DWORD,         # DestinationAddress (network order)
    wt.LPVOID,        # RequestData
    wt.WORD,          # RequestSize
    wt.LPVOID,        # RequestOptions
    wt.LPVOID,        # ReplyBuffer
    wt.DWORD,         # ReplySize
    wt.DWORD,         # Timeout
]
iphlpapi.SendARP.restype = wt.DWORD
iphlpapi.SendARP.argtypes = [
    wt.DWORD,                          # DestIP
    wt.DWORD,                          # SrcIP (0)
    ctypes.POINTER(ctypes.c_ulong),    # pMacAddr
    ctypes.POINTER(ctypes.c_ulong),    # PhyAddrLen
]

_tls = threading.local()


def _icmp_handle():
    if not hasattr(_tls, "h") or not _tls.h:
        _tls.h = iphlpapi.IcmpCreateFile()
    return _tls.h


def ip_to_u32(ip: str) -> int:
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def icmp_ping(ip: str, timeout_ms: int):
    """单次 ICMP Echo。成功返回 (rtt_ms, ttl)；失败返回 (None, None, 状态码)。"""
    h = _icmp_handle()
    if not h:
        return None, None, None
    buf = ctypes.create_string_buffer(REPLY_BUF_SIZE)
    n = iphlpapi.IcmpSendEcho(
        h,
        ip_to_u32(ip),
        PAYLOAD,
        len(PAYLOAD),
        None,
        buf,
        REPLY_BUF_SIZE,
        int(timeout_ms),
    )
    if n == 0:
        # 无回应：状态码取 GetLastError（如 11010 IP_REQ_TIMED_OUT）
        return None, None, ctypes.get_last_error()
    reply = ctypes.cast(buf, ctypes.POINTER(ICMP_ECHO_REPLY)).contents
    if reply.Status != 0:  # 0 = IP_SUCCESS
        return None, None, int(reply.Status)
    return int(reply.RoundTripTime), int(reply.Options.Ttl), None


def send_arp(ip: str):
    """主动 ARP 探测/取 MAC。返回 'aa:bb:cc:dd:ee:ff'（小写，对齐原版 %2.2x 格式）或 None。
    注意：跨网段存在代理 ARP 时可能返回网关 MAC，结果以 method=arp 标注。"""
    mac = (ctypes.c_ulong * 2)()  # 6 字节 MAC + 对齐
    mac_len = ctypes.c_ulong(6)
    rc = iphlpapi.SendARP(ip_to_u32(ip), 0, mac, ctypes.byref(mac_len))
    if rc == 0 and mac_len.value == 6:
        raw = ctypes.string_at(mac, 6)
        return ":".join(f"{b:02x}" for b in raw)
    return None


def tcp_probe(ip: str, port: int, timeout_s: float):
    """TCP connect 探测（纯标准库，免管理员权限）。
    返回 'open'（端口开放）/ 'refused'（收到 RST：端口关闭但主机网络栈活着）/
    'filtered'（无响应，被防火墙丢弃或主机离线）。"""
    try:
        s = socket.create_connection((ip, port), timeout=timeout_s)
        s.close()
        return "open"
    except (ConnectionRefusedError, BrokenPipeError):
        return "refused"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except OSError as e:
        # WSAECONNREFUSED=10061（Windows）；其他错误（不可达等）按 filtered 处理
        if getattr(e, "winerror", None) == 10061 or e.errno in (10061, 111):
            return "refused"
        return "filtered"


# ---------- 服务端主动欢迎语校验（识别 SYN 代理造成的"全端口假开放"） ----------
# 只有「连上后服务端先说话」的明文协议才能据此判定；HTTP/HTTPS/SMB/RDP/MySQL 等
# 都是客户端先发请求，connect 成功后收不到数据是正常的，不做判断（verdict=silent）。
GREETING_PREFIXES = {
    21: (b"220",),              # FTP
    22: (b"SSH-",),             # SSH
    25: (b"220",),              # SMTP
    110: (b"+OK",),             # POP3
    119: (b"200", b"201"),      # NNTP
    143: (b"* OK",),            # IMAP
    587: (b"220",),             # SMTP Submission
}
BANNER_TIMEOUT = 0.35
# 全局假开放判据：开放数量与占比同时超阈值
SYN_PROXY_MIN_OPEN = 100
SYN_PROXY_MIN_RATIO = 0.30


def tcp_greeting(ip: str, port: int, timeout_s: float = BANNER_TIMEOUT):
    """对已知会主动发欢迎语的端口做二次校验，返回 (banner, verdict)。

    verdict: confirmed=收到预期问候语 / unconfirmed=连上但无问候语（可疑） /
             silent=该端口无已知问候语，不判定。
    独立建连，不改变 tcp_probe 的三态语义（概览扫描仍复用原函数）。"""
    prefixes = GREETING_PREFIXES.get(port)
    if not prefixes:
        return "", "silent"
    s = None
    try:
        s = socket.create_connection((ip, port), timeout_s)
        s.settimeout(timeout_s)
        try:
            data = s.recv(256)
        except (socket.timeout, TimeoutError, OSError):
            data = b""
    except OSError:
        return "", "unconfirmed"
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
    banner = data.decode("utf-8", "replace").strip().replace("\r", " ").replace("\n", " ")[:120]
    ok = any(data.startswith(p) for p in prefixes)
    return banner, ("confirmed" if ok else "unconfirmed")


# 常见 UDP 服务的探针报文（其余端口发通用 2 字节占位包）
DNS_QUERY = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            + b"\x07version\x04bind\x00" + b"\x00\x10\x00\x03"
NTP_QUERY = b"\x1b" + b"\x00" * 47
UDP_PROBE_PAYLOADS = {53: DNS_QUERY, 123: NTP_QUERY}


def udp_probe(ip: str, port: int, timeout_s: float):
    """UDP 探测（UDP 无连接，只能三态判定）：
    - 收到应用层应答 → 'open'
    - 收到 ICMP 端口不可达（Windows 已 connect 的 UDP socket 表现为
      WSAECONNRESET/10054，Linux 为 ECONNREFUSED/111）→ 'closed'
    - 无任何响应 → 'unknown'（可能是开放但静默的服务，也可能被防火墙过滤）"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_s)
        try:
            s.connect((ip, port))
        except OSError as e:
            # 网络不可达等 → 该主机不可达，视同关闭
            if getattr(e, "winerror", None) in (10051, 10065) or e.errno in (101, 113):
                return "closed"
            return "unknown"
        payload = UDP_PROBE_PAYLOADS.get(port, b"\x00\x00")
        try:
            s.send(payload)
        except (ConnectionResetError, ConnectionRefusedError):
            s.close()
            s = None
            return "closed"  # 首包即报错 = 该端口 ICMP 不可达证据
        except OSError as e:
            if getattr(e, "winerror", None) in (10054, 10061) or e.errno in (111, 104):
                return "closed"
            return "unknown"
        try:
            data = s.recv(4096)
            return "open" if data else "unknown"
        except (ConnectionResetError, ConnectionRefusedError):
            return "closed"  # ICMP 端口不可达 → 端口关闭
        except (socket.timeout, TimeoutError):
            return "unknown"
        except OSError as e:
            if getattr(e, "winerror", None) in (10054, 10061) or e.errno in (111, 104):
                return "closed"
            return "unknown"
    except Exception:
        return "unknown"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def nbns_build_query():
    """构造 NetBIOS 节点状态查询（UDP 137，nbtstat -A 同款报文）。"""
    # 通配名 "*" 的 level-1 编码：每个字节拆两个 4bit 各加 'A'（0x2A→'CK'，0x00→'AA'）
    return struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0010, 1, 0, 0, 0) \
        + b"CK" + b"AA" * 15 + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)


def nbns_parse_reply(data):
    """解析 NBSTAT 应答，返回 (计算机名, MAC) 或 (None, None)。"""
    if len(data) < 60 or not (data[2] & 0x80):  # 太短或非应答
        return None, None
    # 应答布局：header(12) + 应答名(33) + RR_TYPE(2@45) + RR_CLASS(2) + TTL(4) + RDLEN(2@53) + RDATA(@55)
    if data[45:47] != b"\x00\x21":
        return None, None
    rdata = data[55:55 + int.from_bytes(data[53:55], "big")]
    if len(rdata) < 3:
        return None, None
    # NBSTAT RDATA：NUM_NAMES(1) + N×(名字15 + 后缀1 + 标志2) + 统计区（前 6 字节 = MAC）
    n = rdata[0]
    names, off = [], 1
    for _ in range(n):
        if off + 18 > len(rdata):
            break
        nm = rdata[off:off + 15].split(b"\x00")[0].decode("ascii", "ignore").strip()
        suffix = rdata[off + 15]
        unique = bool(int.from_bytes(rdata[off + 16:off + 18], "big") & 0x8000)
        names.append((nm, suffix, unique))
        off += 18
    mac = (":".join(f"{b:02x}" for b in rdata[off:off + 6])
           if off + 6 <= len(rdata) else None)
    # 优先取后缀 <00> 的独立名（工作站计算机名）
    for nm, suffix, unique in names:
        if nm and suffix == 0x00 and unique:
            return nm, mac
    for nm, suffix, unique in names:
        if nm:
            return nm, mac
    return None, None


def nbns_query(ip: str, timeout_s: float = 1.0):
    """向单个 IP 发 NetBIOS 节点状态查询（UDP 137，nbtstat -A 同款）。
    Windows 主机会应答并携带计算机名与 MAC。返回 (计算机名, MAC) 或 (None, None)。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_s)
        s.sendto(nbns_build_query(), (ip, 137))
        data, _ = s.recvfrom(2048)
        s.close()
    except Exception:
        return None, None
    return nbns_parse_reply(data)


# ---------- 局域网组播发现（发现类 UDP 协议） ----------
# 与「单 IP 端口扫描」不同：向组播/广播地址发查询，收集全网段设备主动回的应答。
# 覆盖 SSDP(1900) / mDNS(5353) / WS-Discovery(3702) / NetBIOS(137)。
# LLMNR(5355) 不做主动探测：需要查询一个具体名字且只有认为自己是该名字的主机才应答，
# 主动探测命中率极低，被动监听才有意义。
MCAST_SSDP = ("239.255.255.250", 1900)
MCAST_MDNS = ("224.0.0.251", 5353)
MCAST_WSD = ("239.255.255.250", 3702)
BCAST_NBNS = ("255.255.255.255", 137)
# dahua/hikvision/dvrip 为安防设备私有发现；宇视无公开私有组播，走 wsd(ONVIF)
DISCOVERY_PROTOS = ("ssdp", "mdns", "wsd", "nbns", "dahua", "hikvision", "dvrip")

SSDP_QUERY = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")


def mdns_build_query():
    """DNS-SD 服务类型枚举查询：PTR _services._dns-sd._udp.local"""
    qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    return struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)


def wsd_build_query():
    """WS-Discovery Probe（SOAP 1.2 over UDP 组播）"""
    uid = "uuid:" + "".join(f"{random.randint(0, 15):x}" for _ in range(32))
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        '<s:Header>'
        '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
        f'<a:MessageID>{uid}</a:MessageID>'
        '<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
        '</s:Header><s:Body><d:Probe/></s:Body></s:Envelope>'
    ).encode("utf-8")


def dns_read_name(data, off):
    """读取 DNS 名称（支持压缩指针），返回 (名称, 该字段结束偏移)。"""
    labels, end, hops = [], None, 0
    while hops < 32 and off < len(data):
        n = data[off]
        if n == 0:
            off += 1
            if end is None:
                end = off
            break
        if (n & 0xC0) == 0xC0:  # 压缩指针（括号必需：== 优先级高于 &）
            if off + 1 >= len(data):
                break
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            hops += 1
            continue
        if (n & 0xC0) != 0:  # 未知标签类型
            break
        off += 1
        labels.append(data[off:off + n].decode("utf-8", "replace"))
        off += n
        hops += 1
    return ".".join(labels), (end if end is not None else off)


def parse_mdns(data):
    """解析 mDNS / DNS-SD 应答，返回 {"name", "services"} 或 None。"""
    if len(data) < 12 or not (data[2] & 0x80):  # QR 位：必须是应答
        return None
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        _, off = dns_read_name(data, off)
        off += 4
    services, names = [], []
    for _ in range(an):
        owner, off = dns_read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd_start = off
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 12:  # PTR：服务类型或实例名
            target, _ = dns_read_name(data, rd_start)
            if target:
                services.append(target)
        elif rtype == 33 and rdlen >= 6:  # SRV：target 是设备主机名
            target, _ = dns_read_name(data, rd_start + 6)
            if target:
                names.append(target.split(".")[0])
        elif rtype == 1 and len(rdata) == 4:  # A
            head = owner.split(".")[0]
            if head and not head.startswith("_"):
                names.append(head)
        head = owner.split(".")[0] if owner else ""
        if head and not head.startswith("_") and "." in owner:
            names.append(head)
    name = next((x for x in names if x), "")
    return {"name": name, "services": services[:8]}


def parse_ssdp(data):
    """解析 SSDP M-SEARCH 应答 / NOTIFY，返回 {"name", "details"} 或 None。"""
    text = data.decode("utf-8", "ignore")
    first = text.split("\r\n", 1)[0]
    if not (first.startswith("HTTP/1.1 200") or first.startswith("NOTIFY ")):
        return None
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().upper()] = v.strip()
    details = [f"{k}: {headers[k]}" for k in ("SERVER", "LOCATION", "ST", "USN", "NT")
               if headers.get(k)]
    return {"name": (headers.get("SERVER") or headers.get("USN") or "")[:120],
            "details": details}


def parse_wsd(data):
    """解析 WS-Discovery ProbeMatches，返回 {"name", "details"} 或 None。"""
    text = data.decode("utf-8", "ignore")
    if "ProbeMatch" not in text:
        return None

    def grab(tag):
        m = re.search(r"<(?:\w+:)?%s[^>]*>(.*?)</(?:\w+:)?%s>" % (tag, tag),
                      text, re.S | re.I)
        return re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else ""

    xaddrs, types, addr = grab("XAddrs"), grab("Types"), grab("Address")
    details = []
    if xaddrs:
        details.append("XAddrs: " + xaddrs[:160])
    if types:
        details.append("Types: " + types[:120])
    if addr:
        details.append("Endpoint: " + addr[:80])
    return {"name": types[:80], "details": details}


# ---------- 安防监控设备发现 ----------
# 协议依据（公开源码 / 抓包 / 官方文档，未猜测字段）：
#   大华 DHIP  : DahuaConsole net.py dh_discover()，UDP 37810 / 组播 239.255.255.251，
#                method=DHDiscover.search；应答 = 32 字节 DHIP 头 + client.notifyDevInfo JSON
#   大华 DVRIP : 同上，老设备用 UDP 5050 受限广播，32 字节二进制查询/应答
#   海康 SADP  : 专利 CN111031286A + hiktools/sadp，UDP 37020 / 组播 239.255.255.250，
#                XML 查询 <Probe><Uuid/><MAC/><Types>inquiry</Types></Probe>
#   宇视       : 官方 EZTools 文档「按 IP 段搜索遵循 ONVIF」，没有公开的私有组播协议；
#                因此不做假报文，改为深挖标准 WS-Discovery 应答里的 ONVIF Scopes
#                （实测宇视应答含 /name/ /hardware/ /version/ /serial/ /macaddr/）
MCAST_DAHUA = ("239.255.255.251", 37810)
BCAST_DAHUA = ("255.255.255.255", 37810)
MCAST_SADP = ("239.255.255.250", 37020)
BCAST_DVRIP = ("255.255.255.255", 5050)

# 这些协议的设备应答常回到「查询源端口」或固定端口，必须专用 socket 绑定本地端口才收得到
DISCOVERY_FIXED_PORTS = {
    "dahua": (37810, "239.255.255.251"),
    "hikvision": (37020, "239.255.255.250"),
    "dvrip": (5050, None),
    "wsd": (3702, "239.255.255.250"),
}

# 仅凭明确品牌串/型号前缀推断，命中不了就留空（不硬猜）
VENDOR_HINTS = (
    ("大华", ("dahua", "dh-ipc", "dh-", "dhi-", "ipc-hdw", "ipc-hfw", "dh-sd")),
    ("海康", ("hikvision", "ds-2", "ds-7", "ds-8")),
    ("宇视", ("uniview", "unv-", "gipc-", "sc-3", "ipc2", "hic-")),
)


def guess_camera_vendor(*texts):
    s = " ".join(str(t) for t in texts if t).lower()
    for label, keys in VENDOR_HINTS:
        if any(k in s for k in keys):
            return label
    return ""


def _kv(label, value):
    v = "" if value is None else str(value).strip()
    return f"{label}: {v[:120]}" if v and v != "0" else ""


def dahua_dhip_build_query():
    """32 字节 DHIP 头 + DHDiscover.search JSON，与 DahuaConsole 字节一致。"""
    body = json.dumps({"method": "DHDiscover.search",
                       "params": {"mac": "", "uni": 1}}).encode("latin-1")
    n = len(body)
    head = (b"\x20\x00\x00\x00DHIP" + b"\x00" * 8
            + struct.pack("<I", n) + b"\x00" * 4
            + struct.pack("<I", n) + b"\x00" * 4)
    return head + body


def sadp_build_query():
    """海康 SADP inquiry（XML over UDP 37020 组播）。"""
    uid = "-".join("".join(f"{random.randint(0, 15):X}" for _ in range(k))
                   for k in (8, 4, 4, 4, 12))
    return ('<?xml version="1.0" encoding="utf-8"?>\r\n'
            '<Probe>\r\n'
            f'<Uuid>{uid}</Uuid>\r\n'
            '<MAC>ff-ff-ff-ff-ff-ff</MAC>\r\n'
            '<Types>inquiry</Types>\r\n'
            '</Probe>\r\n').encode("utf-8")


def dvrip_build_query():
    """大华 DVRIP 老设备查询（32 字节，UDP 5050 广播）。"""
    return (struct.pack(">I", 0xA3010001) + b"\x00" * 12
            + struct.pack(">I", 0x02000000) + b"\x00" * 12)


def parse_dahua_dhip(data):
    """DHIP 应答 → {"name","details"}；自己发出的查询包没有 deviceInfo，自动排除。"""
    if len(data) <= 32 or data[4:8] != b"DHIP":
        return None
    try:
        j = json.loads(data[32:].decode("latin-1", "ignore").strip("\x00\r\n \t"))
    except (ValueError, TypeError):
        return None
    info = (j.get("params") or {}).get("deviceInfo") or {}
    if not info:
        return None
    ipv4 = (info.get("IPv4Address") or {}).get("IPAddress") or ""
    vendor = guess_camera_vendor(info.get("Vendor"), info.get("Manufacturer"),
                                 info.get("DeviceType"), info.get("MachineName"))
    model = str(info.get("DeviceType") or info.get("MachineName") or "")
    details = ["厂商: 大华(DHIP)" if not vendor else f"疑似厂商: {vendor}"]
    details += [x for x in (
        _kv("型号", model),
        _kv("设备类型", info.get("DeviceClass")),
        _kv("序列号", info.get("SerialNo")),
        _kv("固件", info.get("Version")),
        _kv("MAC", j.get("mac")),
        _kv("设备自报IP", ipv4),
        _kv("HTTP端口", info.get("HttpPort")),
        _kv("服务端口", info.get("Port")),
        _kv("视频通道数", info.get("VideoInputChannels")),
    ) if x]
    return {"name": model or str(info.get("DeviceClass") or ""), "details": details}


SADP_FIELDS = (
    ("DeviceDescription", "型号"), ("DeviceType", "设备类型"),
    ("DeviceSN", "序列号"), ("SoftwareVersion", "软件版本"),
    ("DSPVersion", "编码版本"), ("MAC", "MAC"),
    ("IPv4Address", "设备自报IP"), ("IPv4SubnetMask", "子网掩码"),
    ("IPv4Gateway", "网关"), ("CommandPort", "服务端口"),
    ("HttpPort", "HTTP端口"), ("BootTime", "启动时间"),
)


def parse_sadp(data):
    """海康 SADP inquiry 应答（XML）；查询包不带设备字段，会被条件自动排除。"""
    if not (b"inquiry" in data and
            (b"DeviceDescription" in data or b"DeviceSN" in data)):
        return None
    text = data.decode("utf-8", "ignore")
    tags = {}
    # 值限定为不含 "<"：否则外层 <Probe> 会把整段内容吞成一个标签，内层字段全丢
    for m in re.finditer(
            r"<(?:[A-Za-z0-9_]+:)?([A-Za-z0-9_]+)[^>]*>([^<]*)</(?:[A-Za-z0-9_]+:)?\1>",
            text, re.I):
        k = m.group(1)
        v = m.group(2).strip()
        if v and k not in tags:
            tags[k] = v[:160]
    model = tags.get("DeviceDescription") or tags.get("DeviceType") or ""
    details = ["厂商: 海康威视(SADP)"]
    details += [x for x in (_kv(label, tags.get(key))
                            for key, label in SADP_FIELDS) if x]
    return {"name": model, "details": details}


def parse_dvrip(data, from_port_5050=False):
    """大华 DVRIP 广播应答：32 字节头 + 二进制信息区（字段偏移据 DahuaConsole）。"""
    if len(data) < 88:
        return None
    if not from_port_5050 and data[:2] != b"\xb3\x00":
        return None
    b = data[32:]

    def u16(off):
        return int.from_bytes(b[off:off + 2], "little") if len(b) >= off + 2 else 0

    ver = ".".join(str(u16(o)) for o in (0, 2, 4, 6))
    if ver == "0.0.0.0":  # 全零说明该型号不填版本，别输出噪声
        ver = ""
    host = b[8:24].split(b"\x00")[0].decode("latin-1", "ignore").strip()
    tail = b[88:].split(b"\x00")[0].decode("latin-1", "ignore").strip()
    details = ["厂商: 大华(DVRIP 老设备)"]
    details += [x for x in (
        _kv("主机名", host), _kv("版本", ver),
        _kv("Web端口", u16(62)), _kv("HTTPS端口", u16(64)),
        _kv("服务端口", u16(66)), _kv("描述", tail),
    ) if x]
    return {"name": host or tail, "details": details}


ONVIF_SCOPE_LABELS = {
    "name": "设备名", "hardware": "硬件型号", "version": "固件版本",
    "serial": "序列号", "macaddr": "MAC", "manufacturer": "厂商字段",
    "location": "位置", "max_resolution": "最大分辨率",
}


def parse_onvif_scopes(data):
    """从 ProbeMatches 抽 ONVIF Scopes 元数据 —— 宇视等设备的型号/序列号在这里。"""
    text = data.decode("utf-8", "ignore")
    if "ProbeMatch" not in text:
        return None
    scopes = re.findall(r"onvif://www\.onvif\.org/([A-Za-z0-9_.-]+)/([^\s<>]*)",
                        text, re.I)
    details, seen = [], set()
    for key, val in scopes:
        key, val = key.lower(), val.strip()
        label = ONVIF_SCOPE_LABELS.get(key)
        if not label or not val or val.upper() == "NONE" or (label, val) in seen:
            continue
        seen.add((label, val))
        details.append(_kv(label, val))
    tm = re.search(r"<(?:\w+:)?Types[^>]*>(.*?)</(?:\w+:)?Types>", text, re.S | re.I)
    types = re.sub(r"<[^>]+>", "", tm.group(1)).strip() if tm else ""
    kind = ""
    if "NetworkVideoTransmitter" in types:
        kind = "网络摄像机(IPC)"
    elif "NetworkVideoDisplay" in types:
        kind = "网络显示/解码设备"
    elif "NetworkVideoRecorder" in types:
        kind = "网络录像机(NVR)"
    name = next((v for k, v in scopes if k.lower() == "name" and v), "")
    vendor = guess_camera_vendor(
        name,
        *(v for k, v in scopes if k.lower() in ("hardware", "manufacturer", "version")))
    if kind:
        details.insert(0, "设备类别: " + kind)
    if vendor:
        details.insert(0, "疑似厂商: " + vendor)
    return {"name": name, "details": details[:10]}


def reverse_dns(ip: str):
    """反向 DNS 解析主机名（原版 gethostbyaddr 同款；解析到 = 亮绿 = Windows 主机）。
    失败返回 None。"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def detect_local_ip():
    """探测本机出口 IP（UDP connect 只查路由表，不实际发包）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return None


# ---------- 四阶段探测（准确性优化核心）+ 协议标签 ----------
def _arp_useful(ip: str) -> bool:
    return not ip.startswith("127.")  # 环回口无 ARP，跳过避免阻塞


def _guess_os(ttl, protos):
    """系统指纹推断。依据：
    - ICMP 回包 TTL：Windows 初值 128、Linux/Unix 系 64、网络设备（路由器/交换机/打印机）多为 200+；
      本地 /24 只 1 跳，衰减可忽略
    - 无 TTL（ARP/TCP 判定在线）时按端口特征：NBNS/RDP=Windows，SSH=Linux，SMB=Windows(Samba)"""
    if ttl is not None:
        if ttl > 180:
            return "网络设备"
        if ttl > 64:
            return "Windows"
        return "Linux/Unix"
    if "NBNS" in protos or "RDP" in protos:
        return "Windows"
    if "SMB" in protos and "SSH" not in protos:
        return "Windows"
    if "SSH" in protos:
        return "Linux/Unix"
    return "未知"


def _finish_online(ip, method, rtt, ttl, arp_fallback, deep=True, mac=None):
    protos = []
    if method.startswith("icmp"):
        protos.append("ICMP")
    if mac is None and arp_fallback and _arp_useful(ip):
        mac = send_arp(ip)
    if mac:
        protos.append("ARP")
    hostname = reverse_dns(ip)
    if hostname:
        protos.append("DNS")
    else:
        hostname = None
    if deep:
        # 服务识别：常见端口 connect 探测，开放则打标签
        for p in TCP_PROBE_PORTS:
            if tcp_probe(ip, p, 0.6) == "open":
                protos.append(PORT_LABELS[p])
        # NetBIOS：Windows 计算机名（PTR 解析失败时的兜底），顺带可能补 MAC
        nb_name, nb_mac = nbns_query(ip)
        if nb_name:
            protos.append("NBNS")
            if hostname is None:
                hostname = nb_name
            if mac is None and nb_mac:
                mac = nb_mac
    return {"state": "online", "method": method, "rtt": rtt, "ttl": ttl,
            "mac": mac, "hostname": hostname, "os": _guess_os(ttl, protos),
            "protos": protos, "error": None}


def probe_host(ip: str, timeout_ms: int, arp_fallback: bool, deep: bool = True):
    # 阶段1：标准 ICMP echo（与原程序相同）
    rtt, ttl, err = icmp_ping(ip, timeout_ms)
    if rtt is not None:
        return _finish_online(ip, "icmp", rtt, ttl, arp_fallback, deep)
    # 阶段2：立即重发一次 —— 挽回「首包因 ARP 未命中被丢弃」的误判
    # （重试的价值在第二发包时机，ARP 此时已解析完成，无需加长超时）
    rtt, ttl, err2 = icmp_ping(ip, timeout_ms)
    if rtt is not None:
        return _finish_online(ip, "icmp2", rtt, ttl, arp_fallback, deep)
    # 阶段3：ARP 兜底 —— 挽回「防火墙禁 ICMP echo」的误判
    if arp_fallback and _arp_useful(ip):
        mac = send_arp(ip)
        if mac:
            return _finish_online(ip, "arp", None, None, arp_fallback, deep, mac=mac)
    # 阶段4：TCP 探测 —— 跨网段/禁 ICMP 且 ARP 不可达的设备
    # （收到 RST 同样证明网络栈活着：nmap 同款语义）
    tcp_t = min(max(timeout_ms / 1000.0, 0.3), 1.0)
    for port in TCP_LIVENESS_PORTS:
        st = tcp_probe(ip, port, tcp_t)
        if st == "open":
            return _finish_online(ip, "tcp", None, None, arp_fallback, deep)
        if st == "refused":
            return _finish_online(ip, "tcp-rst", None, None, arp_fallback, deep)
    # 离线：携带 ICMP 状态码分类（原版同款语义，区分「超时」与「不可达」等）
    code = err2 if err2 is not None else err
    error = ICMP_STATUS_MSG.get(code, f"错误#{code}") if code else "-"
    return {"state": "offline", "method": "-", "rtt": None, "ttl": None,
            "mac": None, "hostname": None, "os": None, "protos": [], "error": error}


# ---------- 扫描器 ----------
class Scanner:
    def __init__(self):
        self.lock = threading.Lock()
        self._reset()

    def _reset(self):
        self.results = []
        self.meta = {
            "running": False, "prefix": "", "start": 0, "end": 255,
            "timeout": 200, "workers": 20, "arp": True, "deep": True,
            "t0": 0, "elapsed": 0, "t0_str": "", "t1_str": "",
        }
        self.stop_flag = False
        self.pool = None
        self._done_count = 0

    def start(self, prefix, start, end, timeout, workers, arp_fallback, deep=True):
        prefix = (prefix or "").strip().strip(".")
        parts = prefix.split(".") if prefix else []
        if len(parts) == 4:
            # 兼容把起始主机号一并拼进前缀的情况（192.168.253.0），取前 3 段
            parts = parts[:3]
        if (len(parts) != 3
                or any((not p.isdigit()) or int(p) > 255 for p in parts)):
            return False, "IP 前缀不合法（示例：192.168.253）"
        prefix = ".".join(parts)
        try:
            socket.inet_aton(prefix + ".0")
        except OSError:
            return False, "IP 前缀不合法（示例：192.168.253）"
        start, end = int(start), int(end)
        if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
            return False, "主机号范围应为 0-255 且 起<=止"
        timeout = max(10, int(timeout))
        workers = min(max(1, int(workers)), 128)
        with self.lock:
            if self.meta["running"]:
                return False, "扫描进行中，请先停止"
            self._reset()
            hosts = [f"{prefix}.{h}" for h in range(start, end + 1)]
            self.results = [{"ip": ip, "state": "pending", "method": "", "rtt": None,
                             "ttl": None, "mac": None, "hostname": None, "os": None,
                             "protos": [], "error": None}
                            for ip in hosts]
            self.meta.update(running=True, prefix=prefix, start=start, end=end,
                             timeout=timeout, workers=workers, arp=bool(arp_fallback),
                             deep=bool(deep),
                             t0=time.time(), elapsed=0,
                             t0_str=time.strftime("%H:%M:%S"), t1_str="")
            self.stop_flag = False
            self._done_count = 0
            pool = ThreadPoolExecutor(max_workers=workers)
            self.pool = pool
            for i, ip in enumerate(hosts):
                pool.submit(self._work, i, ip, timeout, arp_fallback, deep)
        return True, "ok"

    def _work(self, i, ip, timeout, arp_fallback, deep):
        if self.stop_flag:
            with self.lock:
                if self.results[i]["state"] in ("pending", "probing"):
                    self.results[i].update(state="cancelled", method="-")
                self._bump_done()
            return
        with self.lock:
            self.results[i]["state"] = "probing"
        r = probe_host(ip, timeout, arp_fallback, deep)
        with self.lock:
            self.results[i].update(r)
            self._bump_done()

    def _bump_done(self):
        """完成计数；全部任务结束时翻转 running。
        注意：绝不能在工作线程里调用 pool.shutdown(wait=True) —— 自己 join 自己会死锁。"""
        self._done_count += 1
        if self._done_count >= len(self.results):
            self.meta["running"] = False
            self.meta["elapsed"] = round(time.time() - self.meta["t0"], 2)
            self.meta["t1_str"] = time.strftime("%H:%M:%S")
            try:
                if self.pool:
                    self.pool.shutdown(wait=False)
            except Exception:
                pass
            self.pool = None

    def stop(self):
        self.stop_flag = True

    def status(self):
        with self.lock:
            online = sum(1 for r in self.results if r.get("state") == "online")
            done = sum(1 for r in self.results
                       if r.get("state") in ("online", "offline", "cancelled"))
            total = len(self.results)
            elapsed = (round(time.time() - self.meta["t0"], 1)
                       if self.meta["running"] else self.meta["elapsed"])
            by_method = {}
            by_os = {}
            for r in self.results:
                if r.get("state") == "online":
                    by_method[r.get("method", "")] = by_method.get(r.get("method", ""), 0) + 1
                    os_name = r.get("os") or "未知"
                    by_os[os_name] = by_os.get(os_name, 0) + 1
            return {
                "meta": dict(self.meta, elapsed=elapsed),
                "total": total, "done": done, "online": online,
                "by_method": by_method, "by_os": by_os,
                "results": [dict(r) for r in self.results],
            }

    def export_csv(self, only_online=False):
        s = io.StringIO()
        w = csv.writer(s)
        w.writerow(["ip", "state", "method", "rtt_ms", "ttl", "hostname", "mac",
                    "os", "protocols", "error"])
        for r in self.results:
            if only_online and r.get("state") != "online":
                continue
            if r.get("state") in ("pending", "probing", "cancelled"):
                continue
            w.writerow([
                r.get("ip", ""), r.get("state", ""), r.get("method", ""),
                r.get("rtt") if r.get("rtt") is not None else "",
                r.get("ttl") if r.get("ttl") is not None else "",
                r.get("hostname") or "",
                r.get("mac") or "",
                r.get("os") or "",
                ",".join(r.get("protos") or []),
                r.get("error") or "",
            ])
        return s.getvalue()


# ---------- 单 IP 端口扫描 ----------
def parse_ports(spec):
    """解析端口范围描述：
    '' / '常用' / 'common' → COMMON_PORTS 预设
    'all' / '全部' / '1-65535' → 全端口
    '80,443' / '1-1024' / '80,443,8000-8100' → 自定义
    """
    s = (spec or "").strip().lower()
    if s in ("", "常用", "常用端口", "common"):
        return list(COMMON_PORTS)
    if s in ("all", "全部", "1-65535"):
        return list(range(1, 65536))
    ports = set()
    for tok in s.replace("，", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            if not (a.isdigit() and b.isdigit()):
                raise ValueError("端口范围格式错误（示例：80,443 或 1-1024）")
            lo, hi = int(a), int(b)
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
                raise ValueError("端口应在 1-65535 且 起<=止")
            ports.update(range(lo, hi + 1))
        else:
            if not tok.isdigit():
                raise ValueError("端口格式错误（示例：80,443 或 1-1024）")
            n = int(tok)
            if not 1 <= n <= 65535:
                raise ValueError("端口应在 1-65535")
            ports.add(n)
    return sorted(ports)


class PortScanner:
    """单个 IP 的 TCP/UDP 端口扫描（纯标准库，免管理员权限）。
    TCP: connect 探测（open/refused=关闭/filtered=过滤）
    UDP: 数据报探测（open=有应答/closed=ICMP 不可达/unknown=无响应，开放与过滤不可区分）"""

    def __init__(self):
        self.lock = threading.Lock()
        self.pool = None
        self._reset()

    def _reset(self):
        self.results = []
        self.meta = {
            "running": False, "ip": "", "spec": "", "proto": "tcp",
            "t0": 0, "elapsed": 0, "done": 0,
            "t0_str": "", "t1_str": "",
        }
        self.stop_flag = False
        self.pool = None
        self._done = 0

    def start(self, ip, spec, proto="tcp", workers=64, timeout_s=1.0):
        ip = (ip or "").strip()
        try:
            socket.inet_aton(ip)
        except OSError:
            return False, "IP 地址不合法"
        try:
            ports = parse_ports(spec)
        except ValueError as e:
            return False, str(e)
        if not ports:
            return False, "端口范围为空"
        proto = (proto or "tcp").strip().lower()
        if proto not in ("tcp", "udp", "both"):
            proto = "tcp"
        tasks = []
        if proto in ("tcp", "both"):
            tasks += [(p, "tcp") for p in ports]
        if proto in ("udp", "both"):
            tasks += [(p, "udp") for p in ports]
        if len(tasks) > 150000:
            return False, "任务数过多（TCP+UDP 合计上限 150000）"
        workers = min(max(1, int(workers)), 512)
        with self.lock:
            if self.meta["running"]:
                return False, "端口扫描进行中，请先停止"
            self._reset()
            self.results = [{"port": p, "proto": pr, "state": "pending",
                             "service": PORT_LABELS.get(p, ""),
                             "banner": "", "verdict": ""} for p, pr in tasks]
            self.meta.update(running=True, ip=ip, spec=(spec or "全部"), proto=proto,
                             t0=time.time(), elapsed=0, done=0,
                             t0_str=time.strftime("%H:%M:%S"), t1_str="")
            self.stop_flag = False
            pool = ThreadPoolExecutor(max_workers=workers)
            self.pool = pool
            for i, (p, pr) in enumerate(tasks):
                pool.submit(self._work, i, ip, p, pr, timeout_s)
        return True, "ok"

    def _work(self, i, ip, port, proto, timeout_s):
        if self.stop_flag:
            with self.lock:
                self.results[i]["state"] = "cancelled"
                self._bump_done()
            return
        st = (tcp_probe if proto == "tcp" else udp_probe)(ip, port, timeout_s)
        banner, verdict = "", ""
        # 仅对「服务端应先发欢迎语」的少数明文端口二次校验，不影响扫描速度
        if proto == "tcp" and st == "open" and port in GREETING_PREFIXES:
            banner, verdict = tcp_greeting(ip, port, min(BANNER_TIMEOUT, timeout_s))
        with self.lock:
            self.results[i]["state"] = st
            self.results[i]["banner"] = banner
            self.results[i]["verdict"] = verdict
            self._bump_done()

    def _bump_done(self):
        self._done += 1
        self.meta["done"] = self._done
        if self._done >= len(self.results):
            self.meta["running"] = False
            self.meta["elapsed"] = round(time.time() - self.meta["t0"], 2)
            self.meta["t1_str"] = time.strftime("%H:%M:%S")
            try:
                if self.pool:
                    self.pool.shutdown(wait=False)
            except Exception:
                pass
            self.pool = None

    def stop(self):
        self.stop_flag = True

    def status(self):
        with self.lock:
            running = self.meta["running"]
            elapsed = (round(time.time() - self.meta["t0"], 1)
                       if running else self.meta["elapsed"])
            summary = {}
            for r in self.results:
                st = r["state"]
                if st in ("pending", "cancelled"):
                    continue
                d = summary.setdefault(r["proto"], {"open": 0, "closed": 0, "filtered": 0, "unknown": 0})
                d[st if st in ("open", "closed", "filtered", "unknown") else "unknown"] += 1
            tcp_done = tcp_open = confirmed = unconfirmed = 0
            for r in self.results:
                if r["proto"] != "tcp" or r["state"] in ("pending", "cancelled"):
                    continue
                tcp_done += 1
                if r["state"] == "open":
                    tcp_open += 1
                    v = r.get("verdict", "")
                    if v == "confirmed":
                        confirmed += 1
                    elif v == "unconfirmed":
                        unconfirmed += 1
            ratio = tcp_open / tcp_done if tcp_done else 0.0
            if tcp_open >= SYN_PROXY_MIN_OPEN and ratio >= SYN_PROXY_MIN_RATIO:
                reason = (f"TCP 开放 {tcp_open}/{tcp_done}（{ratio * 100:.0f}%），"
                          "疑似防火墙/代理对任意端口应答 SYN-ACK 造成的假开放")
            elif unconfirmed >= 2 and confirmed == 0:
                reason = (f"{unconfirmed} 个 SMTP/POP3/IMAP/FTP/SSH 端口连上后"
                          "未返回预期欢迎语，疑似假开放或被复用")
            else:
                reason = ""
            open_ports = [{"port": r["port"], "proto": r["proto"], "service": r["service"],
                           "banner": r.get("banner", ""), "verdict": r.get("verdict", "")}
                          for r in self.results if r["state"] == "open"]
            return {
                "meta": dict(self.meta, elapsed=elapsed,
                             suspect_syn_proxy=bool(reason), suspect_reason=reason,
                             verified_open=confirmed, unverified_open=unconfirmed),
                "summary": summary,
                "open_ports": open_ports,
                "results": [dict(r) for r in self.results],
            }


class Discoverer:
    """局域网组播发现：发查询 → 收全网段应答 → 按 IP 归并设备。

    独立于 PortScanner：单 IP 端口扫描是「问一台主机某个端口开不开」，
    组播发现是「向整个网段广播一句谁在」，两者数据源与语义都不同。"""

    def __init__(self):
        self.lock = threading.Lock()
        self._reset()

    def _reset(self):
        self.devices = {}
        self.raw = []
        self.meta = {
            "running": False, "protos": [], "timeout": 5.0,
            "t0": 0, "elapsed": 0, "t0_str": "", "t1_str": "",
            "packets": 0, "multicast_ok": False, "warn": "",
        }
        self.stop_flag = False

    def start(self, protos=None, timeout_s=5.0):
        protos = [p for p in (protos or DISCOVERY_PROTOS) if p in DISCOVERY_PROTOS]
        if not protos:
            return False, "至少选择一种发现协议"
        try:
            timeout_s = min(max(float(timeout_s), 1.0), 30.0)
        except (TypeError, ValueError):
            timeout_s = 5.0
        with self.lock:
            if self.meta["running"]:
                return False, "组播发现进行中，请先停止"
            self._reset()
            self.meta.update(running=True, protos=protos, timeout=timeout_s,
                             t0=time.time(), t0_str=time.strftime("%H:%M:%S"))
        threading.Thread(target=self._run, args=(protos, timeout_s), daemon=True).start()
        return True, "ok"

    def stop(self):
        self.stop_flag = True

    def _add(self, ip, proto, name, details):
        with self.lock:
            d = self.devices.setdefault(ip, {
                "ip": ip, "protos": [], "name": "", "details": [],
                "first_seen": time.strftime("%H:%M:%S"),
            })
            if proto not in d["protos"]:
                d["protos"].append(proto)
            if not d["name"] and name:
                d["name"] = name
            for x in details:
                if x and x not in d["details"] and len(d["details"]) < 12:
                    d["details"].append(x)
            self.raw.append({"ip": ip, "proto": proto, "name": name,
                             "detail": " | ".join(details)[:200],
                             "time": time.strftime("%H:%M:%S")})
            if len(self.raw) > 500:
                self.raw = self.raw[-500:]

    def _handle_packet(self, data, addr):
        if not data:
            return
        ip, sport = addr[0], addr[1]

        # 安防厂商私有协议：按魔数 / 源端口优先判定，避免与通用 XML、DNS 解析交叉误判
        if len(data) > 32 and data[4:8] == b"DHIP":
            r = parse_dahua_dhip(data)
            if r:
                self._add(ip, "大华DHIP", r["name"], r["details"])
                return
        if b"inquiry" in data and (b"DeviceDescription" in data or b"DeviceSN" in data):
            r = parse_sadp(data)
            if r:
                self._add(ip, "海康SADP", r["name"], r["details"])
                return
        if sport == 5050 or data[:2] == b"\xb3\x00":
            r = parse_dvrip(data, sport == 5050)
            if r:
                self._add(ip, "大华DVRIP", r["name"], r["details"])
                return

        found = []
        r = parse_ssdp(data)
        if r:
            found.append(("SSDP", r["name"], r["details"]))
        r = parse_wsd(data)
        if r:
            name, details = r["name"], list(r["details"])
            extra = parse_onvif_scopes(data)
            if extra and extra["details"]:
                name = extra["name"] or name
                for x in extra["details"]:
                    if x not in details:
                        details.append(x)
            found.append(("WS-Discovery", name, details))
        # NBNS 与 DNS 头部同构，必须按源端口区分，否则 NetBIOS 应答会被误解析成 mDNS
        r = parse_mdns(data) if sport == 5353 else None
        if r:
            found.append(("mDNS", r["name"], ["服务: " + s for s in r["services"]][:6]))
        if len(data) >= 60 and sport == 137 and data[45:47] == b"\x00\x21":
            nm, mac = nbns_parse_reply(data)
            if nm:
                found.append(("NBNS", nm, ["MAC: " + mac] if mac else []))
        for proto, name, details in found:
            self._add(ip, proto, name, details)

    def _run(self, protos, timeout_s):
        socks = []
        nb = None
        fixed = {}
        port_warn = []
        multicast_ok = False
        warn = ""
        try:
            main = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            main.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                main.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                                struct.pack("B", 2))
            except OSError:
                pass
            main.bind(("", 0))
            socks.append(main)
            for grp in ("239.255.255.250", "224.0.0.251"):
                try:
                    mreq = socket.inet_aton(grp) + socket.inet_aton("0.0.0.0")
                    main.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                    multicast_ok = True
                except OSError:
                    pass
            # mDNS 应答常组播回 5353，另绑一个接收 socket；占用则跳过，不影响其它协议
            if "mdns" in protos:
                md = None
                try:
                    md = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    md.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    md.bind(("", 5353))
                    mreq = socket.inet_aton("224.0.0.251") + socket.inet_aton("0.0.0.0")
                    md.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                    socks.append(md)
                    multicast_ok = True
                except OSError:
                    if md is not None:
                        try:
                            md.close()
                        except OSError:
                            pass
            if "nbns" in protos:
                nb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                nb.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                nb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                nb.bind(("", 0))
                socks.append(nb)

            # 安防私有协议与 ONVIF 的应答常回到固定的本地端口，必须专用 socket 绑定才收得到。
            # 端口被占用（SADP 工具、Windows WSD 服务常见）时退化为随机端口：
            # 仍可发查询并收单播应答，只是可能漏掉只回固定端口的设备。
            for key, (lport, group) in DISCOVERY_FIXED_PORTS.items():
                if key not in protos:
                    continue
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                try:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                                 struct.pack("B", 2))
                except OSError:
                    pass
                try:
                    s.bind(("", lport))
                except OSError:
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.bind(("", 0))
                    port_warn.append(f"{key}:{lport} 端口被占用，已改用随机端口")
                if group:
                    try:
                        mreq = socket.inet_aton(group) + socket.inet_aton("0.0.0.0")
                        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                        multicast_ok = True
                    except OSError:
                        pass
                socks.append(s)
                fixed[key] = s

            def send_all():
                # 逐条捕获：受限广播在部分网络会失败，不能让它挡住后面协议的查询
                def emit(sock, payload, target):
                    try:
                        sock.sendto(payload, target)
                    except OSError as e:
                        msg = f"发往 {target[0]}:{target[1]} 失败：{e}"
                        if msg not in port_warn:
                            port_warn.append(msg)

                if "ssdp" in protos:
                    emit(main, SSDP_QUERY, MCAST_SSDP)
                if "mdns" in protos:
                    emit(main, mdns_build_query(), MCAST_MDNS)
                if "wsd" in protos:
                    emit(fixed.get("wsd") or main, wsd_build_query(), MCAST_WSD)
                if "nbns" in protos and nb is not None:
                    emit(nb, nbns_build_query(), BCAST_NBNS)
                if "dahua" in protos and "dahua" in fixed:
                    q = dahua_dhip_build_query()
                    emit(fixed["dahua"], q, MCAST_DAHUA)
                    emit(fixed["dahua"], q, BCAST_DAHUA)
                if "hikvision" in protos and "hikvision" in fixed:
                    emit(fixed["hikvision"], sadp_build_query(), MCAST_SADP)
                if "dvrip" in protos and "dvrip" in fixed:
                    emit(fixed["dvrip"], dvrip_build_query(), BCAST_DVRIP)

            try:
                send_all()
            except OSError as e:
                warn = f"查询报文发送失败：{e}（当前网络可能禁用了组播/广播）"
            deadline = time.time() + timeout_s
            resent = False
            while not self.stop_flag:
                left = deadline - time.time()
                if left <= 0:
                    break
                # 组播丢包常见，过半程补发一次
                if not resent and time.time() > deadline - timeout_s * 0.5:
                    try:
                        send_all()
                    except OSError:
                        pass
                    resent = True
                try:
                    readable, _, _ = select.select(socks, [], [], min(0.25, left))
                except (OSError, ValueError):
                    break
                for s in readable:
                    try:
                        data, addr = s.recvfrom(65535)
                    except OSError:
                        continue
                    with self.lock:
                        self.meta["packets"] += 1
                    self._handle_packet(data, addr)
        except Exception as e:
            warn = f"发现过程异常：{e}"
        finally:
            for s in socks:
                try:
                    s.close()
                except Exception:
                    pass
            with self.lock:
                self.meta["running"] = False
                self.meta["elapsed"] = round(time.time() - self.meta["t0"], 2)
                self.meta["t1_str"] = time.strftime("%H:%M:%S")
                self.meta["multicast_ok"] = multicast_ok
                if not multicast_ok and not warn:
                    warn = "未能加入组播组，当前环境可能不支持组播（容器/沙箱/交换机隔离）"
                elif not warn and self.meta["packets"] == 0:
                    warn = ("未收到任何应答：网段内可能没有响应组播查询的设备，"
                            "或交换机/防火墙隔离了组播流量")
                if port_warn:
                    extra = "；".join(port_warn[:3])
                    warn = (warn + "；" + extra) if warn else extra
                self.meta["warn"] = warn

    def status(self):
        with self.lock:
            elapsed = (round(time.time() - self.meta["t0"], 1)
                       if self.meta["running"] else self.meta["elapsed"])
            devices = [{"ip": d["ip"], "protos": sorted(d["protos"]),
                        "name": d["name"], "details": d["details"][:8],
                        "first_seen": d["first_seen"]}
                       for d in self.devices.values()]
            devices.sort(key=lambda x: socket.inet_aton(x["ip"]))
            return {"meta": dict(self.meta, elapsed=elapsed),
                    "devices": devices, "raw": list(self.raw)}


SCANNER = Scanner()
PORT_SCANNER = PortScanner()
DISCOVERER = Discoverer()


# ---------- HTTP API ----------
class QPHTTPServer(ThreadingHTTPServer):
    # Windows 下 SO_REUSEADDR 会允许两个进程静默绑定同一端口（冲突检测失效），
    # 必须显式关闭，端口被占时才能正确抛 OSError 走顺延逻辑
    allow_reuse_address = False
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype, extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                html = open(os.path.join(BASE, "index.html"), "rb").read()
                self._send(200, html, "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, {"error": "index.html not found"}, "application/json")
        elif self.path == "/api/status":
            self._send(200, SCANNER.status(), "application/json; charset=utf-8")
        elif self.path == "/api/localnet":
            self._send(200, {"ip": detect_local_ip()}, "application/json; charset=utf-8")
        elif self.path == "/api/portstatus":
            self._send(200, PORT_SCANNER.status(), "application/json; charset=utf-8")
        elif self.path.startswith("/api/portexport"):
            s = io.StringIO()
            w = csv.writer(s)
            w.writerow(["ip", "proto", "port", "state", "service", "verdict", "banner"])
            st = PORT_SCANNER.status()
            for r in st["results"]:
                if r["state"] == "open":
                    w.writerow([st["meta"]["ip"], r["proto"].upper(), r["port"],
                                r["state"], r["service"],
                                r.get("verdict", ""), r.get("banner", "")])
            self._send(200, ("\ufeff" + s.getvalue()).encode("utf-8"),
                       "text/csv; charset=utf-8",
                       {"Content-Disposition": 'attachment; filename="portscan.csv"'})
        elif self.path == "/api/discoverstatus":
            self._send(200, DISCOVERER.status(), "application/json; charset=utf-8")
        elif self.path.startswith("/api/discoverexport"):
            s = io.StringIO()
            w = csv.writer(s)
            w.writerow(["ip", "protocols", "name", "details", "first_seen"])
            st = DISCOVERER.status()
            for d in st["devices"]:
                w.writerow([d["ip"], " ".join(d["protos"]), d["name"],
                            " | ".join(d["details"]), d["first_seen"]])
            self._send(200, ("\ufeff" + s.getvalue()).encode("utf-8"),
                       "text/csv; charset=utf-8",
                       {"Content-Disposition": 'attachment; filename="discovery.csv"'})
        elif self.path.startswith("/api/export"):
            only = "only=online" in self.path
            text = "\ufeff" + SCANNER.export_csv(only)  # BOM: Excel 兼容
            self._send(200, text.encode("utf-8"), "text/csv; charset=utf-8",
                       {"Content-Disposition": 'attachment; filename="pinglog.csv"'})
        else:
            self._send(404, {"error": "not found"}, "application/json")

    def do_POST(self):
        if self.path == "/api/start":
            try:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                self._send(400, {"ok": False, "msg": "请求体解析失败"}, "application/json")
                return
            ok, msg = SCANNER.start(
                req.get("prefix", ""), req.get("start", 0), req.get("end", 255),
                req.get("timeout", 200), req.get("workers", 20),
                req.get("arp", True), req.get("deep", True))
            self._send(200, {"ok": ok, "msg": msg}, "application/json")
        elif self.path == "/api/stop":
            SCANNER.stop()
            self._send(200, {"ok": True, "msg": "正在停止..."}, "application/json")
        elif self.path == "/api/portscan":
            try:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                self._send(400, {"ok": False, "msg": "请求体解析失败"}, "application/json")
                return
            ok, msg = PORT_SCANNER.start(
                req.get("ip", ""), req.get("ports", "全部"),
                req.get("proto", "tcp"), req.get("workers", 64),
                float(req.get("timeout", 1.0)))
            self._send(200, {"ok": ok, "msg": msg}, "application/json")
        elif self.path == "/api/portstop":
            PORT_SCANNER.stop()
            self._send(200, {"ok": True, "msg": "正在停止..."}, "application/json")
        elif self.path == "/api/discover":
            try:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                self._send(400, {"ok": False, "msg": "请求体解析失败"}, "application/json")
                return
            ok, msg = DISCOVERER.start(req.get("protos"), req.get("timeout", 5.0))
            self._send(200, {"ok": ok, "msg": msg}, "application/json")
        elif self.path == "/api/discoverstop":
            DISCOVERER.stop()
            self._send(200, {"ok": True, "msg": "正在停止..."}, "application/json")
        else:
            self._send(404, {"error": "not found"}, "application/json")


def _fatal_exit(msg: str):
    """启动失败提示：无控制台（--noconsole 便携版）弹 Windows 消息框，否则控制台输出。"""
    try:
        if sys.stdin is None or sys.stdout is None:
            ctypes.windll.user32.MessageBoxW(None, msg, "QuickPing2", 0x10)
            return
    except Exception:
        pass
    print(msg)
    input("按回车键退出...")


def main():
    # 便携版（--noconsole）打包后 stdout/stdin 为 None，print 会抛异常
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    # 端口被占用时自动顺延（例如已有一个 QuickPing2 在跑）
    server = None
    port = PORT
    for p in range(PORT, PORT + 10):
        try:
            server = QPHTTPServer(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if server is None:
        _fatal_exit(f"端口 {PORT}~{PORT+9} 均被占用，QuickPing2 无法启动。\n"
                    "可能已有多个实例在运行，请先在任务管理器结束 QuickPing2 进程。")
        return
    url = f"http://127.0.0.1:{port}/"
    if port != PORT:
        print(f"提示: 端口 {PORT} 已被占用（可能已有一个 QuickPing2 在运行），本次使用 {port}")
    print(f"QuickPing2 已启动: {url}  (Ctrl+C 退出，浏览器将自动打开)")
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
