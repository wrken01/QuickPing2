# Binary DFM parser (old Delphi TPF0 format, empirically verified type codes)
import struct, re

def dec(b):
    try:
        return b.decode('gbk')
    except Exception:
        return b.decode('latin1', 'replace')

dfm = open(r"C:/Users/kane/Desktop/设备在线率监控软件/.workbuddy/rea_work/tform1.dfm.bin",'rb').read()

class R:
    def __init__(self, b): self.b=b; self.i=0
    def byte(self):
        v=self.b[self.i]; self.i+=1; return v
    def s(self):
        ln=self.b[self.i]; self.i+=1
        v=self.b[self.i:self.i+ln]; self.i+=ln
        return v

def rv(r):
    t = r.b[r.i]; r.i += 1
    if t == 0x00: return ('NULL',)
    if t == 0x02:
        v = struct.unpack_from('<b', r.b, r.i)[0]; r.i += 1; return v
    if t == 0x03:
        v = struct.unpack_from('<h', r.b, r.i)[0]; r.i += 2; return v
    if t == 0x04:
        v = struct.unpack_from('<i', r.b, r.i)[0]; r.i += 4; return v
    if t == 0x06: return dec(r.s())
    if t == 0x07: return dec(r.s())
    if t == 0x08: return False
    if t == 0x09: return True
    if t == 0x0B:
        vals=[]
        while r.b[r.i] != 0:
            vals.append(dec(r.s()))
        r.i += 1
        return ('set', vals)
    if t == 0x0C:  # list
        vals=[]
        while r.b[r.i] != 0:
            vals.append(rv(r))
        r.i += 1
        return ('list', vals)
    if t == 0x0A or t == 0x0D:  # binary (4-byte length)
        ln = struct.unpack_from('<I', r.b, r.i)[0]; r.i += 4
        v = r.b[r.i:r.i+ln]; r.i += ln
        return ('bin', ln)
    return ('UNK_TYPE', hex(t))

def parse_component(r, depth):
    cls = r.s()
    if len(cls)==0:
        return None
    name = r.s()
    ind = '  ' * depth
    props = {}
    order = []
    while True:
        pn = r.s()
        if len(pn)==0: break
        key = pn.decode('latin1')
        val = rv(r)
        props[key] = val
        order.append((key, val))
    # print component
    interesting = {k:v for k,v in order if k in (
        'Caption','Text','Left','Top','Width','Height','Align','ColCount','RowCount',
        'FixedCols','FixedRows','DefaultRowHeight','DefaultColWidth','Enabled',
        'Interval','Filter','DefaultExt','FileName','OnTimer','OnClick','OnCreate',
        'BorderStyle','Color','Font.Height','ClientHeight','ClientWidth','TabOrder',
        'ShowCellHints','Editable','ScrollBars')}
    print(f"{ind}<{dec(cls)} id={dec(name)}>")
    for k,v in order:
        if k in ('Left','Top','Width','Height','TabOrder','Interval','ColCount','RowCount',
                 'FixedCols','FixedRows','DefaultRowHeight','DefaultColWidth','ClientHeight','ClientWidth'):
            continue
        if isinstance(v, tuple) and v and v[0]=='set':
            print(f"{ind}  {k} = [{','.join(v[1])}]")
        elif isinstance(v, tuple) and v and v[0]=='NULL':
            pass
        elif isinstance(v, tuple):
            print(f"{ind}  {k} = {v}")
        else:
            print(f"{ind}  {k} = {v!r}")
    geom = []
    for k in ('Left','Top','Width','Height','ClientWidth','ClientHeight','ColCount','RowCount','DefaultRowHeight','Interval'):
        if k in props:
            geom.append(f"{k}={props[k]}")
    print(f"{ind}  @geom: {' '.join(geom)}")
    while True:
        c = parse_component(r, depth+1)
        if c is None: break
    return (cls, name)

r = R(dfm)
assert dfm[:4] == b'TPF0'
r.i = 4
print("===== TFORM1 DFM (old-format parsed) =====")
n=0
while r.i < len(dfm):
    save = r.i
    c = parse_component(r, 0)
    if c is None:
        break
    n+=1
print(f"[components parsed: {n}, consumed {r.i}/{len(dfm)} bytes]")
if r.i < len(dfm):
    print(f"REMAINING {len(dfm)-r.i} bytes hex: {dfm[r.i:r.i+64].hex()}")
