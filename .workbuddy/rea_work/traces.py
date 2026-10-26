# PACKAGEINFO + STRING tables + remaining traces
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

def find_leaf(want_type, want_name=None):
    results=[]
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
                if want_name and nm != want_name: continue
                if ov & 0x80000000:
                    l3 = root + (ov & 0x7FFFFFFF)
                    n3n, n3i = struct.unpack_from('<HH', data, l3+12)
                    for k in range(n3n+n3i):
                        e3 = l3+16+k*8
                        lang, o3 = struct.unpack_from('<II', data, e3)
                        de = root + o3
                        dva, dsz, cp, rsv = struct.unpack_from('<IIII', data, de)
                        results.append((nm, rva2off(dva), dsz))
    return results

print("===== PACKAGEINFO =====")
for nm, off, sz in find_leaf(10, 'PACKAGEINFO'):
    pi = data[off:off+sz]
    print(f"offset=0x{off:X} size={sz}")
    for row in range(0, min(sz, 512), 16):
        chunk = pi[row:row+16]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"  {row:04X}: {hexs:48s} {asc}")

print("\n===== DVCLAL =====")
for nm, off, sz in find_leaf(10, 'DVCLAL'):
    print(f"  {data[off:off+sz].hex()}  ({data[off:off+sz]!r})")

print("\n===== STRING tables (RT_STRING) =====")
for nm, off, sz in find_leaf(6):
    # 16 strings per table, each: 2-byte len + UTF-16 data
    p = off
    strs=[]
    for k in range(16):
        if p+2 > off+sz: break
        ln = struct.unpack_from('<H', data, p)[0]; p+=2
        s = data[p:p+ln*2].decode('utf-16-le', 'replace'); p += ln*2
        strs.append(s)
    nonempty = [s for s in strs if s]
    if nonempty:
        print(f"  table {nm}: {nonempty}")

print("\n===== ICON resource =====")
for nm, off, sz in find_leaf(3):
    print(f"  ICON {nm}: size={sz}, header={data[off:off+8].hex()}")

print("\n===== quickping / registry strings in code =====")
for pat in [rb'quickping', rb'QuickPing', rb'QckPing', rb'Software', rb'CurrentVersion', rb'pinglog', rb'ping\.log', rb'\.log', rb'ping[0-9]', rb'online', rb'Online']:
    hits = list(re.finditer(pat, data))
    print(f"  pattern {pat!r}: {len(hits)} hits")
    for m in hits[:8]:
        ctx = data[max(0,m.start()-48):m.end()+64]
        txt = re.sub(rb'[^\x20-\x7e]', b'.', ctx).decode('latin1')
        print(f"    @0x{m.start():X}: {txt}")

print("\n===== Delphi version markers =====")
for pat in [rb'Delphi Version', rb'Borland Delphi', rb'\$D+', rb'rtl[0-9]', rb'vcl[0-9]', rb'sysutils', rb'SysUtils', rb'TelNoEdit', rb'StringAlignGrid', rb'XGrids', rb'ah_tool']:
    hits = list(re.finditer(pat, data))
    print(f"  {pat!r}: {len(hits)}")
    for m in hits[:4]:
        ctx = data[max(0,m.start()-40):m.end()+80]
        txt = re.sub(rb'[^\x20-\x7e]', b'.', ctx).decode('latin1')
        print(f"    @0x{m.start():X}: {txt}")

print("\n===== ICMP/packet related strings =====")
for pat in [rb'PING, written', rb'%2\.2x', rb'IcmpSendEcho', rb'echo', rb'ttl', rb'TTL', rb'mac', rb'MAC', rb'Arp', rb'GetIpNetTable', rb'192\.', rb'127\.0', rb'255\.255']:
    hits = list(re.finditer(pat, data))
    print(f"  {pat!r}: {len(hits)}")
    for m in hits[:5]:
        ctx = data[max(0,m.start()-50):m.end()+80]
        txt = re.sub(rb'[^\x20-\x7e]', b'.', ctx).decode('latin1')
        print(f"    @0x{m.start():X}: {txt}")
