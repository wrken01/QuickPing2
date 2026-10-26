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
PORT_LABELS = {22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP"}
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


def nbns_query(ip: str, timeout_s: float = 1.0):
    """NetBIOS 节点状态查询（UDP 137，nbtstat -A 同款报文）。
    Windows 主机会应答并携带计算机名与 MAC。返回 (计算机名, MAC) 或 (None, None)。"""
    # 通配名 "*" 的 level-1 编码：每个字节拆两个 4bit 各加 'A'（0x2A→'CK'，0x00→'AA'）
    q = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0010, 1, 0, 0, 0) \
        + b"CK" + b"AA" * 15 + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_s)
        s.sendto(q, (ip, 137))
        data, _ = s.recvfrom(2048)
        s.close()
    except Exception:
        return None, None
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
            "mac": mac, "hostname": hostname, "protos": protos, "error": None}


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
            "mac": None, "hostname": None, "protos": [], "error": error}


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
                             "ttl": None, "mac": None, "hostname": None, "protos": [],
                             "error": None}
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
            for r in self.results:
                if r.get("state") == "online":
                    by_method[r.get("method", "")] = by_method.get(r.get("method", ""), 0) + 1
            return {
                "meta": dict(self.meta, elapsed=elapsed),
                "total": total, "done": done, "online": online,
                "by_method": by_method,
                "results": [dict(r) for r in self.results],
            }

    def export_csv(self, only_online=False):
        s = io.StringIO()
        w = csv.writer(s)
        w.writerow(["ip", "state", "method", "rtt_ms", "ttl", "hostname", "mac",
                    "protocols", "error"])
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
                ",".join(r.get("protos") or []),
                r.get("error") or "",
            ])
        return s.getvalue()


SCANNER = Scanner()


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
