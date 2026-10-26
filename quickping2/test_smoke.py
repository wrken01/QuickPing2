# -*- coding: utf-8 -*-
# Smoke test for QuickPing2 core engine (no HTTP)
import json
import time
from server import probe_host, icmp_ping, send_arp, tcp_probe, nbns_query, Scanner

print("== 单点探测 127.0.0.1 ==")
print("icmp_ping :", icmp_ping("127.0.0.1", 500))
print("send_arp  :", send_arp("127.0.0.1"))
print("tcp_probe :", tcp_probe("127.0.0.1", 9999, 0.5))
print("nbns_query:", nbns_query("127.0.0.1", 1.0))
print("probe     :", json.dumps(probe_host("127.0.0.1", 200, True, True), ensure_ascii=False))

print("\n== 扫描 127.0.0.0 - 127.0.0.9 ==")
sc = Scanner()
ok, msg = sc.start("127.0.0", 0, 9, 200, 8, True, True)
print("start:", ok, msg)
for _ in range(50):
    st = sc.status()
    if not st["meta"]["running"] and st["done"] == st["total"]:
        break
    time.sleep(0.2)
print("status:", {k: st[k] for k in ("total", "done", "online", "by_method")})
print("elapsed:", st["meta"]["elapsed"], "s")
print("\nCSV:")
print(sc.export_csv())
