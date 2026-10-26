# Extract RT_ICON from QuickPing_v0.80.exe and wrap into a .ico file
import struct

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
            o = raddr + (rva-vaddr)
            if o < len(data): return o
    return None

res_rva, _ = struct.unpack_from('<II', data, opt+96+2*8)
root = rva2off(res_rva)

# walk type 3 (RT_ICON), name '1'
n_named, n_id = struct.unpack_from('<HH', data, root+12)
icon_data = None
for i in range(n_named+n_id):
    e = root+16+i*8
    tid, offval = struct.unpack_from('<II', data, e)
    if tid == 3 and offval & 0x80000000:
        sub = root + (offval & 0x7FFFFFFF)
        n2n, n2i = struct.unpack_from('<HH', data, sub+12)
        for j in range(n2n+n2i):
            e2 = sub+16+j*8
            nv, ov = struct.unpack_from('<II', data, e2)
            if ov & 0x80000000:
                l3 = root + (ov & 0x7FFFFFFF)
                n3n, n3i = struct.unpack_from('<HH', data, l3+12)
                for k in range(n3n+n3i):
                    e3 = l3+16+k*8
                    lang, o3 = struct.unpack_from('<II', data, e3)
                    de = root + o3
                    dva, dsz, cp, rsv = struct.unpack_from('<IIII', data, de)
                    fo = rva2off(dva)
                    icon_data = data[fo:fo+dsz]

assert icon_data, "icon not found"
# parse BITMAPINFOHEADER
biSize, biWidth, biHeight, biPlanes, biBitCount = struct.unpack_from('<IiiHH', icon_data, 0)
print(f"icon bmp: size={biSize} w={biWidth} h={biHeight} planes={biPlanes} bpp={biBitCount} bytes={len(icon_data)}")

# wrap into ico: ICONDIR + ICONDIRENTRY + raw data
w = min(biWidth, 255)
h_vis = biHeight // 2 if biHeight >= 64 else biHeight  # icon height = XOR part
ico = struct.pack('<HHH', 0, 1, 1)
ico += struct.pack('<BBBBHHII', w, h_vis, 0, 0, biPlanes, biBitCount, len(icon_data), 22)
ico += icon_data
out = r"C:/Users/kane/Desktop/设备在线率监控软件/quickping2/app.ico"
open(out, 'wb').write(ico)
print(f"written {out} ({len(ico)} bytes)")
