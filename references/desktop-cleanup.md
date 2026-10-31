# Claude Desktop：本地登录状态清理

## 发现与授权范围

仅在用户要求清理桌面软件时执行。浏览器、Claude Code CLI 的 `~/.claude`、项目代码、Cowork/虚拟机工作目录不是同一份数据。不要因为桌面软件登录而顺带清这些位置。

在实际技能根目录运行 `scripts/desktop_cleanup.py`，默认仅检查目录名称、Cookie 数量和包版本，不读取/输出 Cookie 值。使用自定义 `CODEX_HOME` 时以实际安装位置为准：

```powershell
python -X utf8 scripts/desktop_cleanup.py
```

辅助程序通过 `Get-AppxPackage -Name Claude` 定位当前 MSIX 包。常见实际资料根：

- `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude`
- 新版可使用 `%LOCALAPPDATA%\Claude-Data\claude_pzs8sxrjxfjjc`。以当前运行进程的 `--user-data-dir` 或 Electron `app.getPath("userData")` 核对；仅检查旧目录的零 Cookie 不代表新版已退出登录。
- 传统安装可能使用 `%APPDATA%\Claude`。
- `%LOCALAPPDATA%\Claude` 可留有旧版本独立日志；包内 `LocalCache\Local\Claude` 也需检查。辅助程序会盘点这些根，只处理清单内的登录/缓存子项。

Codex 自己的 MSIX AppData 重定向不能当成 Claude 的目录。以实际发现并解析后的路径为准；没有找到时继续只读定位，不能猜路径后递归删除。

## 清理

让 Claude 正常退出，先保存用户未提交工作。不在应用仍运行或文件锁定时修改资料。辅助程序的 `--apply` 会拒绝仍运行的 Claude 进程；没有自动杀进程，也不操作登录窗口。

用户已要求“清理登录痕迹”时，可在该独立应用根内清理登录 Cookie、`ant-did`、Local Storage、Session Storage、IndexedDB、WebStorage、网络状态、网站及图形缓存、日志、崩溃与 Sentry 状态。网站离线状态/未同步草稿也会清空，应在执行前简短告知。这不等于从 Anthropic 删除云端聊天或撤销服务器会话。

```powershell
python -X utf8 scripts/desktop_cleanup.py --root "<上一步实际发现的 Claude 目录>" --apply --report "<本次独立的报告路径.json>"
```

不得把尖括号示例当成实际路径执行。每次重新检查，不凭旧报告跳过工作。

若本次盘点显示新旧资料目录同时存在，且用户授权清理全部已发现的桌面登录根，可使用 `--all-discovered --apply`。该模式仅处理当次已发现根，不遍历整个磁盘：

```powershell
$cleanupReport = Join-Path $env:TEMP ("claude-cleanup-" + [guid]::NewGuid().ToString('N') + '.json')
python -X utf8 scripts/desktop_cleanup.py --all-discovered --apply --report $cleanupReport
python -X utf8 scripts/desktop_cleanup.py
```

先保存并完整退出应用、确认本次盘点范围，再执行清理命令。全部所选根先预检，再逐根清理；磁盘故障或程序重启时仍可能部分完成，按报告补查。

辅助程序验证整个待删目录树无重定向/符号链接、目标为已发现根的直接子项，才按有限清单操作。保留：

- `claude_desktop_config.json`、MCP 配置、`git-worktrees.json`、工作区及普通本地文件。
- `Local State` 中的 OS 加密材料和应用 `Preferences`。
- `config.json` 的正常配置，只清除已验证字段 `windowSizeWasSignedIn`、`planUsageLastTrayOpenAt`、`lastKnownAccountUuid`、`oauth:tokenCache`、`oauth:tokenCacheV2`。后两项为已核查的桌面 OAuth 缓存，不解密、不输出、不备份其值。另清理桌面 `ant-device-registry.json`（本地会话绑定设备登记）及 `plan-usage-history.json`（用量历史）。新版本出现未知身份字段时，先审查结构及程序用途；不要按 `token` 关键字全盘删配置。保留 `claude-code*`、Cowork 会话和工作目录，单独说明不属于登录清理范围。
- 既有网络网关、WFP、PAC、启动项和代理凭据。

该有限清单适合已审查的 Electron/MSIX 数据布局。不同版本或其他分区要重新检查；未知目录不因名称相似而整删。尤其不要删除整个 MSIX 包资料根，也不要调用 Windows“重置应用”代替定向清理。

## 凭据与验证

Windows 凭据管理器只列出并本地过滤 Claude/Anthropic 的目标名称，不打印全部其他账户，也不解密凭据。仅当确有属于桌面 Claude 的凭据、且在用户授权范围内，才按精确目标删除。通用 Google/Apple/Microsoft/GitHub SSO 凭据不属于此次清理。

验证清理报告：`cookies_after == 0`、`remaining_selected_entries` 和 `login_ui_keys_remaining` 为空、`preserved_files_verified == true`、`normal_config_verified == true`。随后重新运行默认检查，确认所选存储未被后台重建。报告只保留路径、键名、数量和校验结果，无身份令牌备份。报告路径必须位于所有 Claude 数据根之外，且为本次新文件；辅助程序拒绝覆盖已有文件，避免报告意外覆盖 MCP/正常配置。

不要为了验证而自动登录；用户下次打开应进入登录流程。若需要查看欢迎页，先验证当前安全启动保护覆盖已安装版本，且用户已授权启动。

已验证 helper 的行为：只读模式不删除；不匹配根或 junction 拒绝；清理保留 MCP/普通文件/正常 locale；SQLite 计数连接显式关闭后再删文件；重复执行归零。未知 Cookies schema 在清理前拒绝，不能当成零记录。SQLite 即使 `mode=ro` 也可能创建 WAL 的 shm 文件，因此在即用即删的完整 DB/WAL/SHM 副本上计数；不能用 `immutable=1` 忽略 WAL。Python 的 SQLite 连接上下文管理器不负责关闭连接，不能只用 `with connection` 后就假定 Windows 文件锁已释放。

本地设备标识可删除，硬件/字体/GPU等重新计算的设备特征不会因删缓存消失。系统备份、同步云端和 Anthropic 服务器记录不在这个脚本的删除范围内。
