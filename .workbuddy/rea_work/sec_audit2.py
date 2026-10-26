# Patch: resolve kernel32 imports (hint/name table beyond .idata VSz) + TLS callbacks as VA
import struct

path = r"C:/Users/kane/Desktop/设备在线率监控软件/QuickPing_v0.80.exe"
data = open(path, 'rb').read()
pe_off = struct.unpack_from('<I', data, 0x3C)[0]
nsec = struct.unpack_from('<H', data, pe_off+6)[0]
optsz = struct.unpack_from('<H', data, pe_off+20)[0]
opt = pe_off+24
imgbase = struct.unpack_from('<I', data, opt+28)[0]
sizeimg = struct.unpack_from('<I', data, opt+56)[0]
secs=[]
sh = opt + optsz
for i in range(nsec):
    off = sh + i*40
    name = data[off:off+8].rstrip(b'\0').decode('latin1')
    vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, off+8)
    secs.append((name,vaddr,vsize,raddr,rsize))

def rva2off_loose(rva):
    # strict first
    for name,vaddr,vsize,raddr,rsize in secs:
        if vaddr <= rva < vaddr+vsize and rsize>0:
            o = raddr + (rva-vaddr)
            if o < len(data): return o
    # loose: map via nearest section below (Borland places data past VSz)
    best = None
    for name,vaddr,vsize,raddr,rsize in secs:
        if vaddr <= rva:
            if best is None or vaddr > best[1]:
                best = (name,vaddr,vsize,raddr,rsize)
    if best:
        name,vaddr,vsize,raddr,rsize = best
        o = raddr + (rva-vaddr)
        if 0 < o < len(data): return o
    return None

# ---- re-parse kernel32 imports with loose mapping ----
imp_rva, imp_sz = struct.unpack_from('<II', data, opt+96+1*8)
off = rva2off_loose(imp_rva)
print("===== kernel32 imports (loose mapping) =====")
kernel32_funcs = set()
while off:
    oft, ts, fc, nameRva, fthunk = struct.unpack_from('<IIIII', data, off)
    if nameRva == 0: break
    noff = rva2off_loose(nameRva)
    dllname = data[noff:data.index(b'\0',noff)].decode('latin1').lower() if noff else '?'
    if dllname == 'kernel32.dll':
        for source in (fthunk, oft):
            if source == 0: continue
            t_off = rva2off_loose(source)
            if t_off is None: continue
            i = 0
            while True:
                val = struct.unpack_from('<I', data, t_off+i*4)[0]
                if val == 0: break
                if val & 0x80000000:
                    kernel32_funcs.add(f"#ord{val&0xFFFF}")
                else:
                    fno = rva2off_loose(val)
                    if fno is not None:
                        end = data.find(b'\0', fno+2, fno+2+80)
                        if end is not None and end > fno+2:
                            cand = data[fno+2:end]
                            if all(0x20 <= c < 0x7f for c in cand) and len(cand) >= 3:
                                kernel32_funcs.add(cand.decode('latin1'))
                i += 1
                if i > 300: break
    off += 20

funcs = sorted(kernel32_funcs)
print(f"resolved {len(funcs)} kernel32 functions:")
for i in range(0, len(funcs), 6):
    print("   " + ", ".join(funcs[i:i+6]))

DANGER = ['WriteProcessMemory','CreateRemoteThread','VirtualAllocEx','VirtualAlloc','VirtualProtect',
          'WinExec','LoadLibraryA','LoadLibrary','GetProcAddress','FreeLibrary','CreateProcessA',
          'CreateFileA','WriteFile','ReadFile','SetFileTime','OpenProcess','TerminateProcess',
          'GetModuleHandleA','IsDebuggerPresent','OutputDebugStringA','CreateThread','ExitProcess',
          'GetTickCount','Sleep','lstrcpyA','GetCommandLineA','GetModuleFileNameA','MoveFileA','CopyFileA',
          'FindFirstFileA','SetFileAttributesA','GlobalAlloc','CloseHandle','CreateMutexA','GetVersionExA',
          'MultiByteToWideChar','WideCharToMultiByte','GetStartupInfoA','GetSystemDirectoryA',
          'GetWindowsDirectoryA','ExpandEnvironmentStringsA','GetComputerNameA','GetUserNameA']
print("\n--- danger-relevant kernel32 hits ---")
for f in funcs:
    if f in DANGER:
        print(f"  HIT: {f}")
print("--- missing (not imported): ---")
for f in DANGER:
    if f not in kernel32_funcs:
        print(f"  (absent) {f}")

# ---- TLS directory re-parse (addresses are VAs incl. ImageBase) ----
print("\n===== TLS directory (VA-aware) =====")
tls_rva, tls_sz = struct.unpack_from('<II', data, opt+96+9*8)
toff = rva2off_loose(tls_rva)
start,end,idx,cb,nul = struct.unpack_from('<IIIII', data, toff)
def va2rva(v): return v - imgbase if v >= imgbase else v
print(f"Start VA=0x{start:X} (RVA 0x{va2rva(start):X})")
print(f"End   VA=0x{end:X} (RVA 0x{va2rva(end):X})")
print(f"Index VA=0x{idx:X}  Callbacks VA=0x{cb:X} (RVA 0x{va2rva(cb):X})")
cbo = rva2off_loose(va2rva(cb))
if cbo is not None:
    i=0
    print("  callback entries:")
    while True:
        v = struct.unpack_from('<I', data, cbo+i*4)[0]
        if v==0: break
        r = va2rva(v)
        fo = rva2off_loose(r)
        b = data[fo:fo+16].hex(' ') if fo else '?'
        print(f"    [{i}] VA 0x{v:X} RVA 0x{r:X} fileoff {'0x%X'%fo if fo else '?'} bytes: {b}")
        i+=1
    if i==0: print("    (empty - no TLS callbacks)")
