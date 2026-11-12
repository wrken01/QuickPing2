# 项目长期约定

- QuickPing2 后续构建或更新时，只生成 `quickping2/dist/QuickPing2GUI.exe`；不要生成 `QuickPing2.exe` 或 `QuickPing2Portable.exe`，除非 Kane 另行明确要求。工作区根目录的 `QuickPing2GUI.exe` 是 Kane 自己放的，不要覆盖。
- 组播发现（含大华/海康/宇视等安防协议）保持 2026-11-12 17:40 版的实现：Kane 实测效果很好、已能覆盖所需网段，**不需要指定 /24 目标网段，也不要加网段输入或逐 IP 单播探测**，除非他另行明确要求。
