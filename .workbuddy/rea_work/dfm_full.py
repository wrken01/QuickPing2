# Full binary DFM parser + PACKAGEINFO dump + config traces
import struct, re

path = r"C:/Users/kane/Desktop/设备在线率监控软件/QuickPing_v0.80.exe"
data = open(path, 'rb').read()

pe_off = struct.unpack_from('<I', data, 0x3C)[0]
nsec = struct.unpack_from('<H', data, pe_off+6)[0]
optsz = struct.unpack_from('<H', data, pe_off+20)[0]
opt = pe_off+24
linker_ver = (data[opt+2], data[opt+3])
print(f"Linker version: {linker_ver[0]}.{linker_ver[1]}")
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

# ============ DFM parser ============
def dec(b):
    try:
        s = b.decode('gbk')
        return s
    except Exception:
        return b.decode('latin1', 'replace')

class R:
    def __init__(self, b): self.b=b; self.i=0
    def byte(self):
        v=self.b[self.i]; self.i+=1; return v
    def s(self):
        ln=self.b[self.i]; self.i+=1
        v=self.b[self.i:self.i+ln]; self.i+=ln
        return v

def read_value(r, depth):
    t = r.byte()
    if t == 0: return None
    if t == 1:  # vaList
        vals=[]
        while True:
            v = read_value(r, depth)
            if v is None: break
            vals.append(v)
        return ('list', vals)
    if t == 2: return dec(r.s())
    if t == 3: return dec(r.s())
    if t == 4:  # vaBinary
        ln = struct.unpack_from('<I', r.b, r.i)[0]; r.i+=4
        v = r.b[r.i:r.i+ln]; r.i+=ln
        return ('bin', ln, v[:24].hex())
    if t == 5:  # vaSet
        vals=[]
        while True:
            if r.b[r.i]==0: r.i+=1; break
            vals.append(dec(r.s()))
        return ('set', vals)
    if t == 6:  # vaLString
        ln = struct.unpack_from('<I', r.b, r.i)[0]; r.i+=4
        v = r.b[r.i:r.i+ln]; r.i+=ln
        return dec(v)
    if t == 7: return None
    if t == 8: return ('collection',)  # not fully parsed
    if t == 9: v=struct.unpack_from('<f', r.b, r.i)[0]; r.i+=4; return v
    if t == 10: v=struct.unpack_from('<d', r.b, r.i)[0]; r.i+=8; return v
    if t == 11: r.i+=10; return ('ext',)
    if t == 12:  # vaWString? treat as binary len
        ln = struct.unpack_from('<I', r.b, r.i)[0]; r.i+=4
        v = r.b[r.i:r.i+ln]; r.i+=ln
        try: return v.decode('utf-16-le')
        except Exception: return ('wbin', v[:24].hex())
    if t in (13,):  # vaInt64
        v = struct.unpack_from('<q', r.b, r.i)[0]; r.i+=8; return v
    return ('unknown_type', t)

def read_int(r):
    b = r.b[r.i]
    if b < 0x80:
        r.i += 1; return b
    if b == 0xFF:
        r.i += 1; v = struct.unpack_from('<b', r.b, r.i)[0]; r.i+=1; return v
    if b == 0xFE:
        r.i += 1; v = struct.unpack_from('<h', r.b, r.i)[0]; r.i+=2; return v
    if b == 0xFD:
        r.i += 1; v = struct.unpack_from('<i', r.b, r.i)[0]; r.i+=4; return v
    r.i += 1
    return b

def read_prop_value(r, depth):
    # peek: is it an int (0..0x7F or FD/FE/FF)? ints have no type byte
    # In binary DFM ints ARE written via type bytes vaInt8.. hmm — classic DFM uses
    # marker-less ints only for legacy; Delphi>=2 writes ints with NO type byte:
    # TWriter.WriteInteger writes raw (no WriteValue). So property value position:
    # if next byte in {0xFD,0xFE,0xFF} or <=0x7F -> integer (ambiguous with vaList etc.)
    # Resolution: Delphi writes ints WITHOUT type marker; other types WITH marker.
    # vaString=2, vaIdent=3... a small int value 2 collides with vaString marker.
    # => cannot disambiguate reliably; use property-name heuristic instead.
    name = r.cur_prop
    INT_PROPS = {'Left','Top','Width','Height','ClientHeight','ClientWidth','TabOrder',
                 'ColCount','RowCount','FixedCols','FixedRows','DefaultRowHeight',
                 'DefaultColWidth','PixelsPerInch','TextHeight','Font.Height','Tag',
                 'Cursor','HelpContext','ImageIndex','MaxWidth','MinWidth'}
    if name in INT_PROPS:
        return read_int(r)
    return read_value(r, depth)

def parse_component(r, depth):
    cls = r.s()
    if len(cls)==0:
        return None
    name = r.s()
    ind = '  '*depth
    props=[]
    while True:
        pn = r.s()
        if len(pn)==0: break
        r.cur_prop = pn.decode('latin1')
        val = read_prop_value(r, depth)
        props.append((pn.decode('latin1','replace'), val))
    pstr = []
    for k,v in props:
        if isinstance(v, tuple) and v and v[0]=='set':
            pstr.append(f"{k}=[{','.join(v[1])}]")
        elif isinstance(v, tuple):
            pstr.append(f"{k}={v}")
        else:
            pstr.append(f"{k}={v!r}")
    print(f"{ind}<{dec(cls)} id={dec(name)}>")
    for s in pstr:
        print(f"{ind}  {s}")
    while True:
        c = parse_component(r, depth+1)
        if c is None: break
    return (cls, name, props)

leaf = find_named_leaf(10, 'TFORM1')
off, sz = leaf
dfm = data[off:off+sz]
print(f"DFM size {sz}")
r = R(dfm)
assert dfm[:4]==b'TPF0'
r.i = 4
print("\n===== TFORM1 DFM (parsed) =====")
while True:
    c = parse_component(r, 0)
    if c is None: break
    break_ = None
print(f"[parsed up to offset {r.i}/{len(dfm)}]")

# ============ PACKAGEINFO ============
print("\n===== PACKAGEINFO =====")
leaf = find_named_leaf(10, 'PACKAGEINFO')
if leaf:
    off, sz = leaf
    pi = data[off:off+sz]
    print(f"offset=0x{off:X} size={sz}")
    # hex dump first 300 bytes
    for row in range(0, min(sz,400), 16):
        chunk = pi[row:row+16]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"  {row:04X}: {hexs:48s} {asc}")
    # extract printable strings >=3
    print("  strings:", re.findall(rb'[\x20-\x7e]{3,}', pi)[:60])

# ============ DVCLAL ============
leaf = find_named_leaf(10, 'DVCLAL')
if leaf:
    off, sz = leaf
    print(f"\nDVCLAL: {data[off:off+sz].hex()}")

# ============ registry/config traces ============
print("\n===== config/registry traces =====")
for pat in [rb'quickping', rb'QuickPing', rb'QckPing', rb'Software\\', rb'\.ini', rb'pinglog', rb'PingLog', rb'\.csv', rb'\.txt', rb'\.dat']:
    for m in re.finditer(pat, data):
        ctx = data[max(0,m.start()-40):m.end()+60]
        txt = re.sub(rb'[^\x20-\x7e\xb0-\xf7\xa1-\xfe]', b'.', ctx)
        try:
            s = txt.decode('gbk')
        except Exception:
            s = txt.decode('latin1')
        print(f"  [{pat.decode('latin1','replace')}] @0x{m.start():X}: {s}")
