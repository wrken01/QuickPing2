# REA static PE analysis (read-only) for QuickPing_v0.80.exe
import struct, math, re, datetime

path = r"C:/Users/kane/Desktop/设备在线率监控软件/QuickPing_v0.80.exe"
data = open(path, 'rb').read()
print(f"File size: {len(data)}")

def entropy(b):
    if not b: return 0.0
    freq = [0]*256
    for x in b: freq[x]+=1
    e = 0.0
    n = len(b)
    for f in freq:
        if f:
            p = f/n
            e -= p*math.log2(p)
    return e

pe_off = struct.unpack_from('<I', data, 0x3C)[0]
print(f"e_lfanew: 0x{pe_off:X}")
assert data[pe_off:pe_off+4] == b'PE\0\0'
mach, nsec, tds, symp, nsym, optsz, chars = struct.unpack_from('<HHIIIHH', data, pe_off+4)
print(f"Machine: 0x{mach:X}  Sections: {nsec}  TimeDateStamp: {tds} ({datetime.datetime.utcfromtimestamp(tds)} UTC)")
opt = pe_off+24
magic = struct.unpack_from('<H', data, opt)[0]
print(f"OptMagic: 0x{magic:X} ({'PE32' if magic==0x10b else 'PE32+'})")
ep = struct.unpack_from('<I', data, opt+16)[0]
imgbase = struct.unpack_from('<I', data, opt+28)[0]
subsys = struct.unpack_from('<H', data, opt+68)[0]
print(f"EntryPoint RVA: 0x{ep:X}  ImageBase: 0x{imgbase:X}  Subsystem: {subsys} ({'GUI' if subsys==2 else 'CUI'})")
dllchars = struct.unpack_from('<H', data, opt+70)[0]
print(f"DllCharacteristics: 0x{dllchars:X}")

print("\n--- Sections ---")
secs=[]
sh = opt + optsz
for i in range(nsec):
    off = sh + i*40
    name = data[off:off+8].rstrip(b'\0').decode('latin1')
    vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, off+8)
    ch = struct.unpack_from('<I', data, off+36)[0]
    raw = data[raddr:raddr+rsize] if rsize else b''
    e = entropy(raw)
    secs.append((name,vaddr,vsize,raddr,rsize,ch,e))
    print(f"{name:8s} VA=0x{vaddr:06X} VSz=0x{vsize:06X} Raw=0x{raddr:06X} RSz=0x{rsize:06X} Ent={e:.3f} CH=0x{ch:08X}")

def rva2off(rva):
    for name,vaddr,vsize,raddr,rsize,ch,e in secs:
        if vaddr <= rva < vaddr+max(vsize,rsize):
            return raddr + (rva-vaddr)
    return None

print("\n--- Imports (.idata) ---")
imp_rva, imp_sz = struct.unpack_from('<II', data, opt+96+1*8)
off = rva2off(imp_rva)
total = 0
if off:
    while True:
        oft, ts, fc, nameRva, fthunk = struct.unpack_from('<IIIII', data, off)
        if nameRva==0: break
        noff = rva2off(nameRva)
        dllname = data[noff:data.index(b'\0',noff)].decode('latin1')
        funcs=[]
        t_off = rva2off(oft if oft else fthunk)
        i=0
        while True:
            val = struct.unpack_from('<I', data, t_off+i*4)[0]
            if val==0: break
            if val & 0x80000000:
                funcs.append(f"#ord{val&0xFFFF}")
            else:
                fno = rva2off(val)
                end = data.index(b'\0', fno)
                funcs.append(data[fno+2:end].decode('latin1'))
            i+=1
        total += len(funcs)
        print(f"{dllname}  ({len(funcs)} imports)")
        print("   " + ", ".join(funcs))
        off += 20
print(f"TOTAL imports: {total}")

print("\n--- Resources (top-level types) ---")
res_rva, res_sz = struct.unpack_from('<II', data, opt+96+2*8)
root = rva2off(res_rva)
types = {1:'CURSOR',2:'BITMAP',3:'ICON',4:'MENU',5:'DIALOG',6:'STRING',7:'FONTDIR',9:'ACCEL',10:'RCDATA',14:'GROUP_ICON',16:'VERSION'}
if root:
    n_named, n_id = struct.unpack_from('<HH', data, root+12)
    for i in range(n_named+n_id):
        e_off = root+16+i*8
        nameval, offval = struct.unpack_from('<II', data, e_off)
        if nameval & 0x80000000:
            noff = root + (nameval & 0x7FFFFFFF)
            ln = struct.unpack_from('<H', data, noff)[0]
            nm = data[noff+2:noff+2+ln*2].decode('utf-16-le')
        else:
            nm = str(nameval)
        sub = root + (offval & 0x7FFFFFFF) if offval & 0x80000000 else None
        if sub:
            n2n, n2i = struct.unpack_from('<HH', data, sub+12)
            names = []
            for j in range(n2n+n2i):
                e2 = sub+16+j*8
                nv, ov = struct.unpack_from('<II', data, e2)
                if nv & 0x80000000:
                    noff2 = root + (nv & 0x7FFFFFFF)
                    ln2 = struct.unpack_from('<H', data, noff2)[0]
                    names.append(data[noff2+2:noff2+2+ln2*2].decode('utf-16-le'))
                else:
                    names.append(str(nv))
            tname = types.get(nameval, str(nameval))
            print(f"  {tname}: names={names[:16]}{'...' if len(names)>16 else ''}")

print("\n--- Version Info (from VERSIONINFO resource) ---")
ver_rva, ver_sz = struct.unpack_from('<II', data, opt+96+16*8)
# walk to find type 16 leaf
def find_ver(dir_off):
    n_named, n_id = struct.unpack_from('<HH', data, dir_off+12)
    for i in range(n_named+n_id):
        e_off = dir_off+16+i*8
        nameval, offval = struct.unpack_from('<II', data, e_off)
        nxt = root + (offval & 0x7FFFFFFF) if offval & 0x80000000 else None
        if nxt:
            r = find_ver(nxt)
            if r: return r
        else:
            de = root + offval
            dva, dsz, cp, rsv = struct.unpack_from('<IIII', data, de)
            return (dva, dsz)
    return None
if root:
    # locate type 16 subtree
    n_named, n_id = struct.unpack_from('<HH', data, root+12)
    for i in range(n_named+n_id):
        e_off = root+16+i*8
        nameval, offval = struct.unpack_from('<II', data, e_off)
        if nameval == 16 and offval & 0x80000000:
            leaf = find_ver(root + (offval & 0x7FFFFFFF))
            if leaf:
                dva, dsz = leaf
                voff = rva2off(dva)
                vdata = data[voff:voff+dsz]
                # extract UTF-16 key/value pairs from StringFileInfo
                txt = re.findall(rb'(?:[\x20-\x7e]\x00){3,}', vdata)
                vals = [t.decode('utf-16-le') for t in txt]
                for v in vals:
                    print(f"  {v}")

print("\n--- Delphi package info ---")
for m in re.finditer(rb'PACKAGEINFO', data):
    print(f"  PACKAGEINFO at 0x{m.start():X}")
for m in re.finditer(rb'(?:SOFTWARE\\|Borland|Delphi)[\x20-\x7e]{0,60}', data):
    print(f"  0x{m.start():X}: {m.group().decode('latin1')!r}")

print("\n--- Form / DFVCL strings (Delphi DFM/RCDATA names) ---")
for m in re.finditer(rb'T[A-Z][a-zA-Z0-9_]{2,20}[\x00]', data):
    s = m.group()[:-1].decode('latin1')
    if s in ('TForm','TButton','TEdit','TLabel','TTimer','TListBox','TComboBox','TCheckBox','TMainMenu','TPanel','TGroupBox','TStringGrid','TListView','TStatusBar','TSaveDialog','TOpenDialog','TMenuItem','TToolBar','TCoolBar','TPageControl','TTabSheet','TImage','TShape','TTrayIcon'):
        pass

print("\n--- Keyword strings scan ---")
kw = ['ping','Ping','PING','icmp','ICMP','Icmp','host','Host','HOST','addr','timeout','Timeout','interval','online','Online','监控','alarm','Alarm','log','Log','ini','INI','reg','Reg','http','www','mail','smtp','ftp','dll','exe','socket','Socket','WSA','winsock','startup','autorun','Run\\','temp','appdata']
seen = set()
for k in kw:
    pat = k.encode('latin1')
    for m in re.finditer(re.escape(pat), data):
        ctx_start = max(0, m.start()-30)
        ctx_end = min(len(data), m.end()+50)
        ctx = data[ctx_start:ctx_end]
        # only printable context
        txt = re.sub(rb'[^\x20-\x7e]', b'.', ctx).decode('latin1')
        key = (k, txt)
        if key not in seen:
            seen.add(key)
        if len([1 for kk in seen if kk[0]==k]) <= 6 and key in seen:
            print(f"  [{k}] @0x{m.start():X}: ...{txt}...")
