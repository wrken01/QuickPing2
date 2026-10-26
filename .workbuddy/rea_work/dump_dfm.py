# Dump TFORM1 DFM resource + GBK Chinese strings + version values
import struct, re

path = r"C:/Users/kane/Desktop/设备在线率监控软件/QuickPing_v0.80.exe"
data = open(path, 'rb').read()

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
    secs.append((name,vaddr,vsize,raddr,rsize))
def rva2off(rva):
    for name,vaddr,vsize,raddr,rsize in secs:
        if vaddr <= rva < vaddr+max(vsize,rsize):
            return raddr + (rva-vaddr)
    return None

res_rva, res_sz = struct.unpack_from('<II', data, opt+96+2*8)
root = rva2off(res_rva)

def find_named_leaf(want_type, want_name):
    """walk resource tree: level0 type(id), level1 name, level2 lang"""
    n_named, n_id = struct.unpack_from('<HH', data, root+12)
    for i in range(n_named+n_id):
        e = root+16+i*8
        tid, offval = struct.unpack_from('<II', data, e)
        if tid == want_type and offval & 0x80000000:
            sub = root + (offval & 0x7FFFFFFF)
            n2n, n2i = struct.unpack_from('<HH', data, sub+12)
            for j in range(n2n+n2i):
                e2 = sub+16+j*8
                nv, ov = struct.unpack_from('<II', data, e2)
                nm = None
                if nv & 0x80000000:
                    noff = root + (nv & 0x7FFFFFFF)
                    ln = struct.unpack_from('<H', data, noff)[0]
                    nm = data[noff+2:noff+2+ln*2].decode('utf-16-le')
                else:
                    nm = str(nv)
                if nm == want_name and ov & 0x80000000:
                    l3 = root + (ov & 0x7FFFFFFF)
                    n3n, n3i = struct.unpack_from('<HH', data, l3+12)
                    for k in range(n3n+n3i):
                        e3 = l3+16+k*8
                        lang, o3 = struct.unpack_from('<II', data, e3)
                        de = root + o3
                        dva, dsz, cp, rsv = struct.unpack_from('<IIII', data, de)
                        return rva2off(dva), dsz
    return None

# ---- TFORM1 DFM ----
leaf = find_named_leaf(10, 'TFORM1')
if leaf:
    off, sz = leaf
    dfm = data[off:off+sz]
    print(f"TFORM1 RCDATA: offset=0x{off:X} size={sz}")
    # binary DFM starts with 'TPF0'
    print(f"magic: {dfm[:4]}")
    open(r"C:/Users/kane/Desktop/设备在线率监控软件/.workbuddy/rea_work/tform1.dfm.bin", "wb").write(dfm)

    # Minimal binary DFM -> text dump: print all ASCII property strings in order
    # Binary DFM: reader knows types; crude approach: extract length-prefixed strings
    i = 4
    out = []
    while i < len(dfm)-1:
        # try length-prefixed string (Delphi binary dfm uses varint-ish; classic uses byte length)
        ln = dfm[i]
        if 0 < ln < 80 and i+1+ln <= len(dfm):
            s = dfm[i+1:i+1+ln]
            if all(0x20 <= c < 0x7f for c in s):
                out.append(s.decode('latin1'))
                i += 1+ln
                continue
        i += 1
    # dedupe consecutive
    print("\n--- DFM strings (crude, in order) ---")
    prev=None
    for s in out:
        if s != prev:
            print(f"  {s}")
        prev = s

# ---- Version info values (UTF-16) ----
print("\n--- Version values ---")
leaf = find_named_leaf(16, '1')
if leaf:
    off, sz = leaf
    v = data[off:off+sz]
    # parse pairs: key\0 value\0 in utf-16
    # find StringFileInfo block
    idx = v.find('StringFileInfo'.encode('utf-16-le'))
    if idx >= 0:
        blk = v[idx:]
        pairs = re.findall(rb'((?:[\x20-\x7e]\x00){2,})\x00\x00((?:[\x20-\x7e]\x00{0,1})*)\x00\x00', blk)
        for k, vv in pairs:
            key = k.decode('utf-16-le', 'ignore')
            val = vv.decode('utf-16-le', 'ignore')
            print(f"  {key} = {val!r}")

# ---- GBK Chinese strings ----
print("\n--- GBK Chinese strings (>=2 chars) ---")
cnt = 0
for m in re.finditer(rb'(?:[\xb0-\xf7][\xa1-\xfe]){2,}(?:[\x20-\x7e]{0,30})', data):
    try:
        s = m.group().decode('gbk')
        if len(s) >= 2:
            ctx_s = max(0, m.start()-20)
            ctx = data[ctx_s:m.end()+20]
            pre = re.sub(rb'[^\x20-\x7e]', b'.', ctx[:20]).decode('latin1')
            print(f"  @0x{m.start():X}: [{pre}] {s}")
            cnt += 1
    except Exception:
        pass
    if cnt > 80: break

# ---- Delphi unit names from PACKAGEINFO ----
print("\n--- PACKAGEINFO units ---")
leaf = find_named_leaf(10, 'PACKAGEINFO')
if leaf:
    off, sz = leaf
    pi = data[off:off+sz]
    # package info: 2 bytes flags, 2 bytes requires count, ... then unit name list
    req = struct.unpack_from('<H', pi, 2)[0]
    p = 4 + req*8  # each require: 4+4
    # then contains count
    if p+2 <= len(pi):
        contains = struct.unpack_from('<H', pi, p)[0]
        p += 2
        print(f"  requires: {req}, contains: {contains}")
        for i in range(contains):
            ln = pi[p]; p += 1
            name = pi[p:p+ln].decode('latin1', 'ignore'); p += ln
            flags = struct.unpack_from('<I', pi, p)[0] if p+4 <= len(pi) else 0
            p += 4
            print(f"    {name}")
