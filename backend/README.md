# 桌面辅助工具与网页版隔离环境源码

这是作者电脑上维护过的实现的**可构建源码快照**，用于审查、复用和继续开发。包括实际桌面启动器、DevTools 辅助程序、隔离 Edge 控制器、进程绑定监控、专用出口网关、Clash 入口跟随器、DNS 和 WFP 工具源码。不是截图、伪代码或只有说明文档。

公开副本已移除个人出口、凭据和路径；未复制浏览器配置、登录资料、截图、历史报告、运行状态、旧候选二进制、Claude/Edge/Mihomo 程序。**构建成功不等于在另一台电脑已安装并验收。** 本版未提供完整跨机器一键部署器；仍需按下文完成部署审查。原电脑上的运行环境未被替换。

## 包含哪些内容

| 目录或文件 | 用途 |
| --- | --- |
| `source/native-launcher/` | 桌面安全入口、临时官方 Inspector 引导、WebRTC 策略与 DevTools 元数据检测 |
| `source/privacy-qa/` | 隔离浏览器私有调试管道控制器、状态发布与相关离线测试；目录名为历史布局，保留用于兼容源码中的路径 |
| `source/claude_browser_launch.py` | 用单独配置目录启动 Claude 网页环境，不复制普通 Edge 登录 |
| `source/guard.py` | 不解密 TLS 的本地 CONNECT 网关、实际出口探测、许可撤销和失败关闭 |
| `source/environment_lease.py`、`environment_watchdog.py` | 以 PID、创建时间、nonce 和实际状态绑定检测，拒绝旧状态续期 |
| `source/ingress_follow.py` | 从本地 Clash Verge 的真实手动选择中取得入口，保留住宅 SOCKS5 出口；不导入作者订阅 |
| `source/dns/`、`dns_service.py` | 作用域 DNS 转发与监督源码，需另外安装并验证 NRPT 规则 |
| `source/wfp/` | 原生 Windows WFP helper；只有显式 `install` / `remove` 才修改其规则 |
| `build.py` | 在全新目录编译自己的辅助 EXE、生成完整性清单，不执行或安装工具 |
| `configure.py`、`examples/` | 用自己的运行时路径、IP 与私密核心配置准备新目录；保留离线锁，不启动网络 |

**DevTools 本身来自 Electron/Chromium**，不由本项目开发、复制或重新发布。`DevToolsUi.exe` 是本项目用 C# 编译的辅助工具，负责与应用已有工具界面交互；名称相近但不是同一个程序。Electron [DevTools 接口文档](https://www.electronjs.org/docs/latest/api/web-contents#contentsopendevtoolsoptions)。

## 依赖与兼容范围

- Windows x64，Python 3.10+（桌面 GUI 需要 Tkinter 与 `pythonw.exe`）、Node.js 22+、Windows 自带 .NET Framework 4.x C# 编译器和 UIAutomation 组件。
- 自行安装官方 Claude MSIX、Microsoft Edge、Clash Verge Rev 和 Mihomo 核心；不捆绑这些第三方产品，遵守各自许可。源码中的入口跟随器依赖 Clash Verge 配置与命名管道布局，其他代理客户端尚未适配。
- `configure.py` 和入口跟随器使用 PyYAML：`python -m pip install -r backend/requirements.txt`。其他主要 Python 部件使用标准库。
- 本快照采用固定本地拓扑：普通网关 `17893`、受保护网关 `17894`、专用核心 `17895`、核心控制 `17896`、DNS loopback `53`，临时主进程 Inspector `9229`。它们是程序协议约定，不是作者住宅信息。发生端口占用应停止，不能只改一处端口继续使用。
- **此快照的网页版继承 Windows 美东时区**并校验，使用英语启动参数；不是在任意系统时区上都能单独覆盖。桌面方案同样需要按实际组件区分原生时区与页面时区。准备工具不会改变整机时区或语言。Windows 时区不符时保持拒绝，另行决定是否授权更改。
- DevTools/菜单行为随 Claude 更新变化，可能要求用户点【继续配置】并保持相关窗口可见。没有移除窗口输入保护、自粘贴保护或 UAC。不能承诺关闭 DevTools、最小化、锁屏、睡眠唤醒后均可无人值守。

## 第一步：构建，不动当前安装

先在仓库根执行隔离测试：

```powershell
python -B -X utf8 -m unittest discover -s tests
python -B -X utf8 backend/run_tests.py
```

测试只使用内存或临时夹具，不打开 Claude/浏览器、不读账号、不装系统规则。然后在**不存在的新目录**构建：

```powershell
$sourceBuild = Join-Path $env:TEMP ("claude-guard-source-" + [guid]::NewGuid().ToString('N'))
python -B -X utf8 backend/build.py --output $sourceBuild
```

输出中 `built: true` 仅表示源码与编译成功，`installed: false`、`live_acceptance: false` 保持明确。工具不覆盖已有目录，拒绝直接输出到 `.claude-network-guard`。编译失败保留新目录供检查，不启动半成品。`hold.block` 保留部署锁。

源码逐文件 SHA256 和公开改动见 [source-manifest.json](source-manifest.json)。编译后按自己机器的实际产物生成 helper/RTC manifest；不要拿作者旧 EXE 的 hash 当新产物校验值。

## 第二步：填写自己的配置

将 [settings.example.json](examples/settings.example.json) 与 [core.example.yaml](examples/core.example.yaml) **复制到仓库以外的私人目录**，填写真实内容。前者只写路径、住宅服务端地址和允许的实际公网 IPv4；后者含入口与住宅出口凭据，不提交 GitHub、不贴到 Issue。

`allowed_exit_ips` 是服务看到的实际公网出口；`residential_server` 是 SOCKS5 服务端地址，两者可能因供应商 NAT 而不同。名单必须非空；不会自动把当前普通网络 IP 加进去。模板故意不能直接联网。

入口代理必须是一个真实、具体的可用节点，名称保留 `PINNED-ENTRY`。住宅节点为 `PINNED-RESIDENTIAL`、SOCKS5、UDP 关闭、经前者拨号；不加 DIRECT、自动选择组或订阅回退。跟随器之后从用户本机手动选择的主 Clash 线路同步入口，前提是主线路的住宅节点与专用配置凭据一致。它不创建主 Clash 节点，也不会把订阅上传。

用上一步 `$sourceBuild` 与实际私人文件路径执行：

```powershell
python -B -X utf8 backend/configure.py --output $sourceBuild --settings 'C:/YOUR_PRIVATE/settings.json' --core-config 'C:/YOUR_PRIVATE/core.yaml'
```

路径是占位示例。工具核对拓扑、运行时文件、新构建产物和原部署锁，在新目录生成自己的 `policy.json`、`runtime.json`、`environment-runtime.json`、`deployment_allowlist.py` 和私密 `core/config.yaml`；为控制器生成新的本地随机密码。配置失败不打印可能含密码的 YAML 错误或内容。

输出 `configured: true` 仍然不是部署成功。它不创建 `installed.json`，也不移除离线锁。不要仅为了启动而手写“verified”登记文件。

## 第三步：部署审查与现场验收

这一步需要有 Windows 网络保护经验的维护者或按 Skill 操作的代理。复用源码可以省去从零开发，但不能跳过本机身份、权限和真实流量验证。详见 [复现流程](../references/replication.md) 和 [验收清单](../references/acceptance.md)。

1. 保留部署锁；盘点目标机器当前包、全部实际 EXE、签名、版本、进程与端口。保存工作并正常退出 Claude，处理会占用旧组件的后台服务。不能强杀未保存工作。
2. 确认构建产物来自此源码，第三方核心与浏览器来自各自可信来源。稳定运行目录需单独安装，不能直接覆盖一个活跃安装或复制旧运行状态。
3. 用 WFP helper 的只读 `plan` 检查精确 EXE 和包 SID，然后在用户明确授权及管理员确认下部署。规则仅允许对应身份访问专用 IPv4 TCP 网关。每个身份 4 条 block 是当前实现，不是固定版本的总条数。不要使用测试探针的规则代替应用规则。
4. 验证实际规则条件与签名清单、正负流量探针，之后才由部署程序写入真实 `installed.json`。本仓库故意未复制早期会处理进程的一次性 `install.ps1` 或旧版本维护事务。**当前源码包缺少通用、受审查的完整安装事务**，不要把本步骤描述成已经自动提供。
5. 配置并验证作用域 DNS、网关和入口跟随器，确认当前链路实际出口在用户名单。部署锁的移除只能在完成本轮安装条件后由明确的部署步骤处理；不是遇到“foreign hold”就删文件。用户原有维护锁不得删除。
6. 先以无账号方式检查欢迎页。桌面入口为 `native-launcher/native_desktop_launch.py --gui`，网页入口为 `claude_browser_launch.py`；根据目标机器创建快捷方式。它们可能启动自身服务，但都不代替系统规则安装。独立 Edge 仍共享浏览器 EXE，不宣称有按配置文件的 WFP 硬隔离。
7. 冷启动、刷新、新标签、入口切换、控制器停止、锁定与恢复逐项验收；WebRTC 检查候选，UDP/IPv6 用目标身份及正对照验证。用户自行登录前不发起实际账号任务；未测的 Cowork、外部 MCP、云端出口单列。

管理员授权只能用户确认。源代码接口开放不代表调用者可以绕过 Windows 权限或第三方应用限制。完整部署之前，所有构建/离线测试结果都应标为“构建验证”，不能称已获得可用安全环境。

## 与原电脑实现的差异

- `guard.py` 和网页启动器的个人 IP 上限改为独立 `deployment_allowlist.py`；源码默认空名单，配置阶段只在新输出目录写入用户名单。
- 入口跟随器的根目录改为从自身源码位置解析，住宅地址来自独立配置。
- DevTools 的候选检测移除了作者个人公网地址例外；所有原始公网 WebRTC 候选都标为不符合该检测策略。没有为了移植而放宽拦截。
- 网络探针的第二个参数是明确的允许 IP 逗号列表，不内置作者地址；缺少名单不会报告出口允许。
- 一些早期测试夹具已更新到当前源码的 RTC 证明、英语参数和系统元数据协议。原始/公开 SHA 与差异说明保存在 manifest；不宣称重新编译的 EXE 与原电脑二进制完全相同。

## 隐私与范围

不要上传构建目录、生成配置、Cookie、OAuth 缓存、控制器密码、浏览器 profiles、logs、状态文件或截图。公开仓库只保留白名单源码、示例和离线测试。DevTools 辅助界面是调试依赖而不是隐身技术；本地清理和美国出口不能重置硬件身份、删除服务器记录或保证账号不受限。
