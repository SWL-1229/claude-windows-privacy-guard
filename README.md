# Claude Windows Privacy Guard

面向 Codex 的 Windows Skill：定向清理 Claude 本地登录状态，检查专用代理启动条件，并指导实施指定出口与失败关闭保护。

A Codex skill for scoped Claude sign-in cleanup, read-only Windows startup checks, and fail-closed networking workflows.

## 解决什么问题

- **应用更新后突然无法连接。** 比对实际安装包与保护登记，发现旧规则仍指向旧版本的情况。
- **使用安全入口仍报 `ERR_PROXY_CONNECTION_FAILED`。** 检查是否已有 Claude 主进程占用单实例，并继续使用错误的代理参数。
- **需要退出本地登录，又要保留工作配置。** 清理独立桌面应用的认证存储和缓存，保留 MCP、普通配置与用户工作文件。
- **只清 Claude/Anthropic 浏览器数据。** 提供按域名、配置文件和存储类型处理的工作流，避免清空其他站点。

## 能力边界

| 内容 | 本仓库提供 |
| --- | --- |
| 桌面登录清理 | `desktop_cleanup.py`，默认只读，显式 `--apply` 才删除 |
| 启动前检查 | `launch_preflight.py`，只读检查包身份、主进程代理参数与端口监听 |
| 软件更新与旧进程防复发 | 分步骤排查、维护及验证流程 |
| 指定出口 / WFP / 浏览器代理保护 | 实施与验收方法；不包含网络保护安装器或代理服务 |
| 浏览器定向清理 | 操作方法与兼容性要点；不包含通用数据库修改器 |

**安装 Skill 本身不会创建防火墙规则、启动代理或开启断网保护。** 预检通过也不代表实际出口、WFP、浏览器策略已经有效。此工具不用于伪造设备指纹，也不承诺规避封号。

## 安装

需要 Windows 10/11、PowerShell、Git，以及 Python 3.10 或更高版本。脚本只使用 Python 标准库；网络保护的实施还取决于已有组件和系统权限。启动预检目前面向 MSIX / Microsoft Store 安装；传统安装需要按工作流人工核对，不能把“未发现软件包”当作应用没有安装。

在 PowerShell 中克隆到 Codex 的技能目录：

```powershell
$skillsRoot = if ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME 'skills' } else { Join-Path $env:USERPROFILE '.codex\skills' }
New-Item -ItemType Directory -Force -Path $skillsRoot | Out-Null
git clone https://github.com/SWL-1229/claude-windows-privacy-guard.git (Join-Path $skillsRoot 'claude-windows-privacy-guard')
```

已有同名目录时先检查现有改动，不要覆盖私人配置。安装后在新对话中使用：

```text
使用 $claude-windows-privacy-guard 检查 Claude 为什么无法连接。
先只读检查当前安装版本、专用代理监听和旧主进程，不要清理登录数据。
```

也可以明确请求：

```text
使用 $claude-windows-privacy-guard 清理 Claude 桌面软件的本地登录状态，保留 MCP 和工作文件。
```

## 本次增加的预防措施

1. **每次更新后重新发现安装包。** 不硬编码版本、EXE 数量或旧安装目录；维护保护时核对可执行文件的签名、路径和摘要。
2. **启动前检查现有主进程。** Electron 会复用已有实例；安全快捷方式的新代理参数可能无法替换旧实例。发现错误参数应先保存工作、完整退出，再从安全入口打开。
3. **代理参数逐项核对。** 专用代理、禁用本地绕过、禁用 QUIC 必须一致；重复或冲突参数不能视为通过。
4. **故障时保留限制。** 不通过删除 WFP 规则、切换共享自动节点或开放直连来“修好联网”。
5. **维护后验证成功与拒绝两面。** 除允许出口成功，还应验证错误出口、网关故障、共享端口和直连都会被拒绝，并确认普通网络可用。

详细步骤见 [启动与更新防复发](references/startup-prevention.md) 和 [出口保护验收](references/exit-protection.md)。

## 直接运行只读检查

在仓库目录运行。以下 `17894` 是**示例专用端口**，请换成本机已经配置的受保护网关端口：

```powershell
python -X utf8 scripts/launch_preflight.py --gateway-port 17894
```

可选的 `--installed-marker` 接收本工具约定的本地登记文件。登记用于检查一致性，不会安装保护或验证 WFP；不要把其他程序的任意 JSON 报告直接当登记使用。格式与命令见脚本的 `--help` 和防复发文档。

| 预检结果 | 含义 |
| --- | --- |
| `preflight_checks_passed` | 本轮启动条件检查通过，退出码 0；仍未验证出口与网络强制限制 |
| `needs_review` | 例如未提供登记、应用未运行；信息不足，退出码 2 |
| `blocked` | 例如版本不符、参数错误、监听缺失或查询失败；退出码 2，先排查原因 |

脚本在所有结果中都保留 `protection_verified: false`。不要为了获得退出码 0 而临时改登记或启动未受保护的应用。

桌面资料盘点：

```powershell
python -X utf8 scripts/desktop_cleanup.py
```

先保存工作并正常退出 Claude，再盘点。清理命令的 `--root` 必须来自本次发现结果，`--report` 必须是应用目录之外的一个新文件：

```powershell
python -X utf8 scripts/desktop_cleanup.py --root '<本次发现的绝对数据目录>' --apply --report '<新的报告绝对路径.json>'
```

尖括号内容是占位说明，不能直接执行。清理会删除桌面应用的网站缓存、离线状态和未同步草稿；不删除云端聊天，不自动撤销服务端会话，不清独立 Claude Code CLI。

## 验证与开发

```powershell
python -X utf8 -m unittest discover -s tests -v
python -X utf8 scripts/launch_preflight.py --help
python -X utf8 scripts/desktop_cleanup.py --help
```

测试使用临时目录和模拟进程信息，不清理真实应用资料，不修改真实网络规则。Windows CI 会运行同一套测试。测试证明辅助脚本的行为，不代替每台电脑的实际联网验收。

## 隐私与贡献

本仓库不包含真实出口地址、代理密码、账户、登录 Cookie、运行配置、私人机器报告或用户截图。提交问题时只提供脱敏后的错误类型、系统/应用版本和检查结论；不要上传 Cookie、令牌、完整进程命令行或代理订阅。

欢迎通过 Issue 描述复现步骤，通过 Pull Request 改进版本兼容与测试。新清理逻辑应同时证明目标记录被删除、无关数据被保留；未知存储格式应保留并报告。

[MIT License](LICENSE)
