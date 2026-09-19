# NetWatch

> Windows 桌面应用：实时监控**每个应用程序**的上传 / 下载流量

![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4) ![Platform](https://img.shields.io/badge/platform-Windows-blue) ![License](https://img.shields.io/badge/license-MIT-green)

![NetWatch 界面](docs/screenshot.png)

## ✨ 功能

- **按应用统计**上传速度、下载速度、累计上传、累计下载，按流量自动排序，最活跃的应用置顶
- 同一应用的多个进程自动合并显示（如 Chrome、微信的多进程）
- **双击应用**查看它当前的所有 TCP/UDP 连接：本地 / 远程地址、连接状态、PID（每 2 秒自动刷新）
- **目标 IP 视图**（v1.2 新增）：一键切换，按远程地址聚合——"数据都发给了谁、各发了多少"，附带通信应用名；右键可直接屏蔽该 IP，双击查看与它的连接
- **🚫 屏蔽 IP**（v1.1 新增）：在连接详情里右键某个远程 IP，即可禁止该应用（或所有程序）向它发送数据；支持 IP 和 CIDR 网段，可随时启停/删除，规则持久保存
- **🔍 数据包查看**（v1.3 新增）：对任意 IP（屏蔽管理或目标 IP 视图右键）实时抓包，直接看到发往它的数据内容——HTTP 请求、JSON、表单等明文一览；支持文本/十六进制视图、上下行过滤。明文协议可见全文，HTTPS/TLS 显示为加密数据
- 右键 → 打开文件位置
- 顶部实时显示整机上传 / 下载速率与累计总量
- 关闭窗口最小化到系统托盘，托盘提示实时显示整机速率
- 深色界面，支持高 DPI 与多显示器

## 🚀 快速开始

### 方式一：直接下载

从 [**Releases**](../../releases) 或 Actions 构建产物中下载 `NetWatch.exe`（单文件约 5.7 MB）。

> 需要安装 [.NET 8 桌面运行时](https://dotnet.microsoft.com/download/dotnet/8.0)。

### 方式二：从源码构建

```bash
git clone <本仓库地址>
cd NetWatch
dotnet run -c Release --project src/NetWatch.App
```

发布单文件 exe：

```bash
# 框架依赖版（约 5.7 MB，需目标机装有 .NET 8）
dotnet publish src/NetWatch.App -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish

# 自包含版（约 150 MB，免装运行时）
dotnet publish src/NetWatch.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish-selfcontained
```

## 🧰 命令行版

仓库同时附带一个无界面版本，便于脚本化验证：

```bash
netwatch-cli 20       # 监控 20 秒，每 2 秒打印一次有流量的进程
netwatch-cli --events # 列出内核网络事件（诊断用）
netwatch-cli --block 1.2.3.4            # 屏蔽所有程序访问 1.2.3.4
netwatch-cli --block 10.0.0.0/24 --app "C:\path\app.exe"  # 仅屏蔽某个程序
netwatch-cli --unblock 1.2.3.4          # 解除屏蔽
netwatch-cli --blocks                  # 查看屏蔽列表
netwatch-cli --remotes 15              # 目标 IP 视图（CLI 版）
netwatch-cli --sniff 1.2.3.4 10        # 抓包：打印发往/来自该 IP 的包内容预览
```

输出示例：

```text
── 10:03:52  整机 ↑9.88 KB/s  ↓4.96 MB/s   事件总数 4,925
   curl      PID 92768    ↑      0 B/s   ↓   4.91 MB/s
   GameViewer PID 69856    ↑   3.95 KB/s   ↓  43.72 KB/s
   chrome    PID 68256    ↑    275 B/s   ↓     948 B/s
```

## ⚙️ 运行要求

- Windows 10 / 11 / Server 2016+
- **以管理员身份运行**（读取内核网络事件需要管理员权限；程序已内置 UAC 提权清单，双击即弹出提权确认）

## 🔧 工作原理

```
内核 ETW 网络事件（每次 TCP/UDP 收发，含 PID + 字节数）
        │  Microsoft-Windows-Kernel-Network · NetworkTCPIP 关键字
        ▼
按 PID 累加字节数 ──► 每秒取增量算速率 ──► WPF 界面展示
        │
        ├─► 按"对端 IP"聚合 ──► 目标 IP 视图
        └─► 连接列表：GetExtendedTcpTable / GetExtendedUdpTable（IP Helper API）

屏蔽：WFP（Windows 筛选平台）自建子层 + BLOCK 过滤器
        └─► 在 ALE_AUTH_CONNECT 层按「程序 + 远程 IP/网段」拦截新建连接，
            无需开启 Windows 防火墙，不装驱动；过滤器不带 PERSISTENT 标志

抓包：IPv4 原始套接字（SIO_RCVALL）+ IP/TCP/UDP 头解析
        └─► 按远程地址过滤后展示负载内容（文本/十六进制，TLS 自动识别标注）
```

**屏蔽规则说明**

- 只拦**新建**的连接；已建立的旧连接会继续到断开为止，屏蔽后重启目标程序即完全阻断
- 规则保存在 `%APPDATA%\NetWatch\blocks.json`，NetWatch 启动时自动重建到 WFP
- NetWatch 退出后已生效的屏蔽会继续生效；**系统重启后**若未启动 NetWatch 则不再恢复
- 想彻底清掉所有屏蔽：在 NetWatch 里删除全部规则（或重启系统）

不安装驱动、不注入 DLL、不修改系统网络栈，全部使用 Windows 原生跟踪机制，关闭程序后不留任何残留。

## 📁 项目结构

```
NetWatch/
├── src/
│   ├── NetWatch.Core/   # 采集核心：ETW 按进程统计流量 + 连接枚举 + WFP 屏蔽（P/Invoke）
│   ├── NetWatch.App/    # WPF 桌面界面
│   └── NetWatch.Cli/    # 命令行验证工具
├── docs/                # 截图等文档资源
└── .github/workflows/   # CI：Windows 构建并上传产物
```

## ⚠️ 已知限制

- 只统计 **NetWatch 启动之后** 的流量（Windows 不提供按进程的历史流量回溯）
- 回环（localhost）流量两侧都会计入
- 走 VPN / 代理的流量会归到代理进程名下（如 cloudflared），而非原始应用
- 与其他占用内核跟踪会话的工具（如 PerfView、Wireshark 内核捕获）互斥，同时只能开一个
- 抓包为明文分析工具：HTTPS/TLS 内容加密不可见（与 Wireshark 无密钥时一致）；抓包仅支持 IPv4，本机回环流量不可见
- 日志位于 `%TEMP%\netwatch.log`

## 📄 许可证

[MIT](LICENSE)
