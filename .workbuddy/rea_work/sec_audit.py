# Security audit: full import table + dangerous API matching + TLS callbacks + overlay + hash
import struct, re, hashlib

path = r"C:/Users/kane/Desktop/设备在线率监控软件/QuickPing_v0.80.exe"
data = open(path, 'rb').read()

print("===== File hashes =====")
md5 = hashlib.md5(data).hexdigest()
sha1 = hashlib.sha1(data).hexdigest()
sha256 = hashlib.sha256(data).hexdigest()
print(f"MD5    : {md5}")
print(f"SHA1   : {sha1}")
print(f"SHA256 : {sha256}")
print(f"Size   : {len(data)} bytes")

pe_off = struct.unpack_from('<I', data, 0x3C)[0]
nsec = struct.unpack_from('<H', data, pe_off+6)[0]
optsz = struct.unpack_from('<H', data, pe_off+20)[0]
opt = pe_off+24
secs=[]
sh = opt + optsz
for i in range(nsec):
    off = sh + i*40
    name = data[off:off+8].rstrip(b'\0').decode('latin1')
    vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, off+8)
    ch = struct.unpack_from('<I', data, off+36)[0]
    secs.append((name,vaddr,vsize,raddr,rsize,ch))
def rva2off(rva):
    for name,vaddr,vsize,raddr,rsize,ch in secs:
        if vaddr <= rva < vaddr+max(vsize,rsize):
            o = raddr + (rva-vaddr)
            if o < len(data): return o
    return None

# ---- security-relevant section flags ----
print("\n===== Section flags (W^X check) =====")
for name,vaddr,vsize,raddr,rsize,ch in secs:
    w = bool(ch & 0x80000000); x = bool(ch & 0x20000000)
    print(f"  {name:8s} W={w} X={x} {'!! WRITABLE+EXECUTABLE' if (w and x) else ''}")

# ---- full import parse: try both OFT and IAT, validate name ----
print("\n===== Full imports =====")
imp_rva, imp_sz = struct.unpack_from('<II', data, opt+96+1*8)
all_imports = {}
off = rva2off(imp_rva)
while off:
    oft, ts, fc, nameRva, fthunk = struct.unpack_from('<IIIII', data, off)
    if nameRva == 0: break
    noff = rva2off(nameRva)
    if noff is None: off += 20; continue
    dllname = data[noff:data.index(b'\0',noff)].decode('latin1').lower()
    funcs = []
    for source in (oft, fthunk):
        if source == 0: continue
        t_off = rva2off(source)
        if t_off is None: continue
        i = 0
        while True:
            val = struct.unpack_from('<I', data, t_off+i*4)[0]
            if val == 0: break
            fname = None
            if val & 0x80000000:
                fname = f"#ord{val&0xFFFF}"
            else:
                fno = rva2off(val)
                if fno is not None:
                    hint = struct.unpack_from('<H', data, fno)[0]
                    end = data.find(b'\0', fno+2, fno+2+64)
                    if end is not None and end > fno+2:
                        cand = data[fno+2:end]
                        if all(0x20 <= c < 0x7f for c in cand):
                            fname = cand.decode('latin1')
            if fname and fname not in funcs:
                funcs.append(fname)
            i += 1
            if i > 500: break
        if funcs: break  # OFT preferred if it worked
    all_imports[dllname] = funcs
    off += 20

total = 0
for dll, funcs in all_imports.items():
    total += len(funcs)
    print(f"{dll} ({len(funcs)})")
    print("   " + ", ".join(funcs))
print(f"\nTOTAL resolved imports: {total}")

# ---- dangerous API blacklist ----
print("\n===== Dangerous API scan =====")
DANGER = {
 'process_injection': ['WriteProcessMemory','CreateRemoteThread','VirtualAllocEx','NtUnmapViewOfSection','QueueUserAPC','SetThreadContext','NtWriteVirtualMemory'],
 'memory_exec': ['VirtualProtect','VirtualAlloc','CreateProcessInternalW'],
 'downloader': ['URLDownloadToFileA','URLDownloadToFileW','WinHttpOpen','InternetOpenUrlA','WinExec','ShellExecuteA','ShellExecuteW','DownloadFile'],
 'persistence': ['RegSetValueExA','RegSetValueExW','RegCreateKeyExA','CreateServiceA','ScheduleJob','SetFileTime'],
 'keylogger_ratk': ['SetWindowsHookExA','SetWindowsHookExW','GetAsyncKeyState','GetKeyState'],
 'anti_debug': ['IsDebuggerPresent','CheckRemoteDebuggerPresent','OutputDebugStringA','NtQueryInformationProcess'],
 'credential': ['CryptUnprotectData','CredEnumerateA','LsaEnumerateLogonSessions'],
 'network_c2': ['connect','send','recv','WSAConnect','socket','InternetReadFile','HttpSendRequestA'],
 'packer_self': ['LoadLibraryA','GetProcAddress','FreeLibrary'],
}
flat = {f: cat for cat, fl in DANGER.items() for f in fl}
hits = []
for dll, funcs in all_imports.items():
    for f in funcs:
        if f in flat:
            hits.append((dll, f, flat[f]))
if hits:
    for dll, f, cat in hits:
        print(f"  [{cat}] {dll}!{f}")
else:
    print("  (blacklist direct hits: none)")

# note: LoadLibraryA/GetProcAddress always imported by Delphi runtime (delay loading)
print("\n  说明: Delphi RTL 必然静态导入 LoadLibrary/GetProcAddress 用于动态解析（本程序即用其加载 Icmp.dll），属正常。")

# ---- bound imports directory ----
print("\n===== Bound imports (directory 11) =====")
bnd_rva, bnd_sz = struct.unpack_from('<II', data, opt+96+11*8)
print(f"  BoundImport RVA=0x{bnd_rva:X} Size={bnd_sz}  {'(存在绑定导入 → 解释此前函数名解析为空的原因)' if bnd_rva else '(无)'}")

# ---- TLS callbacks ----
print("\n===== TLS directory (callbacks run before entry point) =====")
tls_rva, tls_sz = struct.unpack_from('<II', data, opt+96+9*8)
print(f"  TLS RVA=0x{tls_rva:X} Size={tls_sz}")
if tls_rva:
    toff = rva2off(tls_rva)
    start,end,idx,cb_rva,null = struct.unpack_from('<IIIII', data, toff)
    print(f"  callbacks RVA=0x{cb_rva:X}")
    cbo = rva2off(cb_rva)
    if cbo:
        i=0
        while True:
            v = struct.unpack_from('<I', data, cbo+i*4)[0]
            if v==0: break
            print(f"    callback[#{i}] -> RVA 0x{v:X}")
            i+=1
        if i==0: print("    (空回调表，无 TLS 回调)")

# ---- overlay check ----
print("\n===== Overlay / appended data =====")
end_raw = max(raddr+rsize for name,v,vsize,raddr,rsize,ch in secs)
print(f"  last section raw end = 0x{end_raw:X}, file size = 0x{len(data):X}")
print(f"  overlay bytes = {len(data)-end_raw}  {'!! 存在附加数据' if len(data)>end_raw else '(无 overlay)'}")

# ---- digital signature ----
print("\n===== Authenticode =====")
sec_rva, sec_sz = struct.unpack_from('<II', data, opt+96+4*8)
print(f"  Certificate directory: RVA=0x{sec_rva:X} Size={sec_sz}  {'(无数字签名)' if sec_sz==0 else '(存在签名块)'}")

# ---- entry point sanity ----
ep = struct.unpack_from('<I', data, opt+16)[0]
epc = rva2off(ep)
code_bytes = data[epc:epc+32]
print(f"\n===== Entry point bytes (RVA 0x{ep:X}) =====")
print(f"  {code_bytes.hex(' ')}")
print("  (Delphi 程序入口通常是 PUSH EBP/MOV EBP,ESP 的单元初始化桩，无花指令)")
