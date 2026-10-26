# -*- coding: utf-8 -*-
"""
QuickPing2 GUI 版 — 原生桌面窗口（WebView2）承载 Web UI
关闭窗口 = 退出整个程序（HTTP 服务一并停止）
"""
import ctypes
import threading

import webview

import server
from server import QPHTTPServer, Handler

TITLE = "#QuickPing2(V1.00) --By Örken"


def _find_port():
    for p in range(server.PORT, server.PORT + 10):
        try:
            return QPHTTPServer(("127.0.0.1", p), Handler), p
        except OSError:
            continue
    return None, None


def _alert(msg):
    try:
        ctypes.windll.user32.MessageBoxW(None, msg, "QuickPing2", 0x10)
    except Exception:
        pass


def main():
    httpd, port = _find_port()
    if httpd is None:
        _alert(f"端口 {server.PORT}~{server.PORT+9} 均被占用，QuickPing2 GUI 无法启动。\n"
               "可能已有多个实例在运行，请先在任务管理器结束相关进程。")
        return
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{port}/"
    try:
        window = webview.create_window(
            TITLE, url, width=810, height=650, min_size=(660, 540))
        webview.start()  # 阻塞直至窗口关闭
    except Exception as e:
        _alert(f"窗口创建失败：{e}\n（GUI 版依赖 WebView2 运行时，Win10/11 一般自带）\n"
               "可改用 QuickPing2Portable.exe（浏览器版）。")
    finally:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
