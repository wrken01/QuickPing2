# Nested payload / IOC string scan
import re

data = open(r"C:/Users/kane/Desktop/设备在线率监控软件/QuickPing_v0.80.exe", 'rb').read()

print("===== nested executable / archive blobs =====")
nested_pe = []
for m in re.finditer(rb'MZ', data):
    if m.start() == 0: continue
    if b'PE\0\0' in data[m.start():m.start()+0x200]:
        nested_pe.append(m.start())
print(f"  embedded PE: {len(nested_pe)} {'!! ' + str([hex(x) for x in nested_pe]) if nested_pe else '(none)'}")
print(f"  ZIP magic: {len(list(re.finditer(rb'PK\x03\x04', data)))} (none expected)")

print("\n===== base64-like / long-hex strings =====")
b64 = list(re.finditer(rb'[A-Za-z0-9+/]{40,}={0,2}', data))
print(f"  base64-like runs >=40 chars: {len(b64)}")
hexs = list(re.finditer(rb'(?:[0-9a-fA-F]{2}){20,}', data))
print(f"  long hex runs: {len(hexs)}")

print("\n===== script interpreter / persistence invocations =====")
FOUND = False
for pat in [rb'cmd\.exe', rb'command\.com', rb'powershell', rb'rundll32', rb'regsvr32', rb'mshta', rb'wscript', rb'cscript', rb'\.bat', rb'\.vbs', rb'\.ps1', rb'CurrentVersion.\\?Run', rb'schtasks', rb'netsh ', rb'at\.exe', rb'\\Services\\']:
    for m in re.finditer(pat, data):
        FOUND = True
        ctx = data[max(0,m.start()-40):m.end()+40]
        print(f"  HIT {pat!r} @0x{m.start():X}: {re.sub(rb'[^ -~]', b'.', ctx).decode('latin1')}")
if not FOUND:
    print("  (no hits)")

print("\n===== embedded URLs / emails / IPs =====")
for pat in [rb'https?://[\x21-\x7e]{4,60}', rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}']:
    uniq = {}
    for m in re.finditer(pat, data):
        uniq.setdefault(m.group().decode('latin1','ignore'), m.start())
    print(f"  {pat!r}: {len(uniq)} unique {list(uniq.items())[:8]}")
ips = {}
for m in re.finditer(rb'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', data):
    ips.setdefault(m.group().decode(), m.start())
print(f"  dotted IPv4 literals: {len(ips)} unique")
for s, off in list(ips.items())[:10]:
    print(f"    @0x{off:X}: {s}")

print("\n===== IAT does NOT contain these C2 / downloader APIs =====")
for f in [b'socket', b'connect', b'send', b'recv', b'WSAConnect', b'InternetOpen', b'HttpSendRequest', b'URLDownloadToFile', b'FtpPutFile', b'SetWindowsHookExW']:
    idx = data.find(f, 0x5D000, 0x5F400)
    print(f"  .idata(0x5D000-0x5F400) '{f.decode()}': {'YES @0x%X'%idx if idx>=0 else 'no'}")
