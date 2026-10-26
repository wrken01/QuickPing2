# REA gap-verification: length-prefixed GBK strings in CODE (runtime grid headers),
# ColWidths binary in DFM, hostname/TTL context
import struct, re

path = r"C:/Users/kane/Desktop/设备在线率监控软件/QuickPing_v0.80.exe"
data = open(path, 'rb').read()

# CODE section: Raw 0x400 - 0x5C000
CODE = (0x400, 0x5C000)

def try_gbk(b):
    try:
        return b.decode('gbk')
    except Exception:
        return None

print("===== length-prefixed GBK strings in CODE (Delphi string constants) =====")
found = []
i = CODE[0]
while i < CODE[1]:
    ln = data[i]
    if 4 <= ln <= 60 and i + 1 + ln <= CODE[1]:
        s = data[i+1:i+1+ln]
        # need at least 2 GBK chinese chars OR meaningful ascii mix
        chinese = sum(1 for c in s if c >= 0x80)
        if chinese >= 4:  # at least 2 hanzi
            txt = try_gbk(s)
            if txt and all(ch == '\n' or ch == '\r' or ch == '\t' or 32 <= ord(ch) < 0xFFFF for ch in txt):
                # verify pure: re-encode check
                try:
                    if txt.encode('gbk') == s:
                        found.append((i, txt))
                        i += 1 + ln
                        continue
                except Exception:
                    pass
    i += 1
for off, s in found:
    print(f"  @0x{off:05X}: {s!r}")
print(f"total: {len(found)}")

print("\n===== ColWidths binary in TFORM1 DFM =====")
dfm = open(r"C:/Users/kane/Desktop/设备在线率监控软件/.workbuddy/rea_work/tform1.dfm.bin", 'rb').read()
for m in re.finditer(rb'ColWidths', dfm):
    off = m.start()
    ctx = dfm[off:off+40]
    print(f"  @0x{off:X}: {ctx.hex(' ')}")
    # after 'ColWidths' name comes type byte + 4-byte length + data
    p = off + len(b'ColWidths')
    t = dfm[p]
    if t in (0x0A, 0x0D):  # binary type
        ln = struct.unpack_from('<I', dfm, p+1)[0]
        payload = dfm[p+5:p+5+ln]
        print(f"    binary len={ln} payload={payload.hex(' ')}")
        # interpret as int32 array (col widths)
        n = ln // 4
        widths = struct.unpack_from(f'<{n}i', payload)
        print(f"    as int32 x{n}: {widths}")

print("\n===== hostname / DNS context strings =====")
for pat in [rb'gethostbyaddr', rb'hostname', rb'HostName', rb'host name', rb'\bname\b', rb'TTL', rb'timeout', rb'RTT', rb'round']:
    hits = list(re.finditer(pat, data))
    print(f"  {pat!r}: {len(hits)}")
    for m in hits[:3]:
        ctx = data[max(0,m.start()-60):m.end()+80]
        txt = re.sub(rb'[^\x20-\x7e]', b'.', ctx).decode('latin1')
        print(f"    @0x{m.start():X}: {txt}")

print("\n===== ICMP status code immediates in code (11010/11013/11003...) =====")
# search little-endian dword immediates of common IP_STATUS values
for code, name in [(11000,'IP_SUCCESS'),(11001,'IP_BUF_TOO_SMALL'),(11002,'IP_DEST_NET_UNREACHABLE'),
                   (11003,'IP_DEST_HOST_UNREACHABLE'),(11004,'IP_DEST_PROT_UNREACHABLE'),
                   (11005,'IP_DEST_PORT_UNREACHABLE'),(11006,'IP_NO_RESOURCES'),(11008,'IP_BAD_OPTION'),
                   (11009,'IP_HW_ERROR'),(11010,'IP_REQ_TIMED_OUT'),(11011,'IP_BAD_REQ'),
                   (11012,'IP_BAD_ROUTE'),(11013,'IP_TTL_EXPIRED_TRANSIT'),(11014,'IP_TTL_EXPIRED_REASSEM'),
                   (11015,'IP_PARAM_PROBLEM'),(11016,'IP_SOURCE_QUENCH'),(11017,'IP_OPTION_TOO_BIG'),
                   (11018,'IP_BAD_DESTINATION')]:
    pat = struct.pack('<I', code)
    hits = [m.start() for m in re.finditer(re.escape(pat), data[CODE[0]:CODE[1]])]
    if hits:
        print(f"  {name} ({code}): {len(hits)} hit(s) in CODE @{[CODE[0]+h for h in hits[:4]]}")
