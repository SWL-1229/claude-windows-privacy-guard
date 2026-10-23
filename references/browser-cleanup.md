# 浏览器定向登录清理

目标是删除本地 Claude/Anthropic 登录与使用痕迹，同时保留其他站点会话、密码和书签。云端同步与服务端删除不属于这一步。

## 盘点与目标匹配

动态发现实际安装浏览器及全部配置目录，不假定只用 Default。当前常见路径在 `%LOCALAPPDATA%` 下：

- Chrome：`Google\Chrome\User Data`
- Edge：`Microsoft\Edge\User Data`
- 联想：`Lenovo\SLBrowser\User Data`

以本机清单核对，不能把历史五个配置写死。确认所有对应进程已退出并释放锁；不能离线写入仍运行的浏览器文件。

当前域名根：`claude.ai`、`claude.com`、`anthropic.com`、`claude.app`、`claudeusercontent.com`、`claudemcpcontent.com`。先解析 URL 主机，再做精确或点分隔子域匹配，处理大小写和尾点。不要子串匹配；不因 Claude 使用 Google/Apple/Microsoft 登录而清除那些网站的通用会话。

盘点只读取 URL/源/主机元数据并输出计数；不读取认证值。需要处理的类别：Cookie、已保存登录、站点存储、访问/下载元数据、恢复页面记录、相关权限与网络持久状态。下载文件、书签和无关会话保留。

## 执行方式

优先浏览器支持的、按源或注册域名清理的原生接口；接口不支持的类别才使用已审查的离线处理。不要假定单一 `browsingData` 调用同时覆盖历史、密码、分区存储与恢复页面。

### SQLite

关闭后，在单库事务中按当前 schema 制定删除计划，先统计再提交；不解密 Cookie 或密码。建议启用 `secure_delete`，根据 WAL 状态检查点并进行必要整理，随后 `quick_check`/完整性验证。未知 schema 保留并报告。

| 存储 | 定向处理要点 |
|---|---|
| `Network/Cookies` 或 `Cookies` | 匹配 `host_key` 和分区的 `top_frame_site_key` |
| `Login Data`、`Login Data For Account` | 按 origin/realm/action 匹配；处理关联 `password_notes`、`insecure_credentials`、`stats` |
| `History` | 处理 URL 对应 visits、annotations、clusters、segments、keyword 及 visited_links 引用；不留下指向已删记录的关联 |
| downloads 元数据 | 仅删除与目标 URL 链关联的本地记录，不删除已下载文件 |
| Favicons、网络及权限存储 | 只删除可归属目标的记录；保留共享项和其他站点 |

不要批量清空不理解的同步元数据。离线修改不生成可靠的云端删除标记，同步可能重新引入记录。

### 共享结构化存储

Local Storage、Session Storage、Service Worker、CacheStorage 和现代 Storage Buckets 常共享一个数据库。不能删整个共享目录，也不能在 SST/LOG 二进制中搜索替换域名。

原生清理可在仅含所需存储、没有账号/历史/密码配置的隔离工作副本中执行。禁用同步和不必要的后台联网，不打开目标站点；清理目标源/分区后验证。提交前重新确认原浏览器已退出、原文件摘要未变化，采用可回滚的目录替换，完成后立即删除含敏感数据的临时副本。不要把临时副本当永久备份。

原生报告可能没有穷尽旧厂商版本的 Local/Session Storage 等存储；有证据时使用与版本对应的结构化解析器补充检查。未知格式必须停止该项，不能用“整个目录删除”替代。

### 已验证的兼容性与提交陷阱

- **Session Storage 不跟随通用工作副本整目录换回。** 新浏览器实例缺少原恢复会话时，可能把旧 namespace 当孤立数据回收。先独立结构化检查/删除目标引用，保留其他 namespace 的 map；不能用 WebUI 站点使用量证明 Session Storage 完整保留。
- Chromium 141 的 Session Storage schema v1：`namespace-<36字符GUID>-<StorageKey>` 指向十进制 map ID，`map-<id>-...` 存数据；只删除目标引用，仍被非目标引用使用的 map 保留。StorageKey 同时检查首部 origin 和 `^0` 顶级分区站点。保留版本与 next-map-id。Local Storage 的 `META:`、`METAACCESS:` 与 `_<StorageKey>\0...` 分别处理；前后核对所有非目标逻辑键值摘要。
- LevelDB 库“打开检查”也可能写入恢复日志；只读审计使用即用即删的私有副本。不要在真实共享库上假定 readonly 选项存在。
- Chrome 新版 WebUI 的站点使用量异步通过 `onStorageListFetched` 返回；`getAllSites` 的立即返回可能不完整。新版分组删除命令为 `clearSiteGroupDataAndCookies`，不把旧命令名硬套到所有版本。
- 已测试的 Edge 155 设置 target 类型可为 `browser_ui`，React 设置页不保证实现 Chrome 的 WebUI 消息。退回明确源清单的原生清理时，报告枚举范围，补查实际 Local Storage、IndexedDB、QuotaManager 与分区数据，不能称已全量枚举。
- 联想 Chromium 141 实测 TCP DevTools WebSocket 不可用，调试管道可用。临时扩展在持久 HTML 页调用 `browsingData.remove` 并等待完成，比把长调用放进可能休眠的后台 worker 更可靠。所有操作只用于自有、无账号配置的隔离存储副本。
- 只把已验证的原存储变更提交回去；新清理扩展/临时网页生成的注册和无关数据不应带回用户配置。清理报告的源用量为 0 仍可能留有空的 QuotaManager bucket 元数据；仅在确认其数据目录不存在/为空且表结构支持时，才按精确 bucket ID 清理此元数据并检查完整性。

### 页面恢复与附加记录

SNSS/Session Storage 需要结构化、版本受限的处理。保持非目标记录和导航索引完整；解析失败不提交。Preferences、HSTS、Network Persistent State 等只移除已确认属于目标域的项，不能清整个 JSON 或全体网络状态。

未加密 SNSS v1/v3 中，Session/Apps 的导航命令与 Tabs 的导航命令 ID 不同（本机已验证分别为 6 和 1）。目标导航可替换为保留 tab ID/索引的有效 `about:blank` 项，并清除其标题、referrer、page state；不靠删原始字节片段破坏恢复结构。其他完整导航指令应逐字节不变，未知/加密版本不应用这个解析器。

## 现有代码的使用边界

此公开版提供浏览器定向清理方法，不附带共享 LevelDB、SNSS 或各浏览器原生接口的通用修改脚本。环境没有已审查的兼容工具时，优先使用浏览器自己的站点数据清理界面，并如实报告它没有覆盖的历史、密码、恢复记录等类别；不能临时拼接未验证的二进制修改器。

复用用户已有辅助程序前，审查函数入口、闭锁检查、schema 和依赖。不要直接重放固定配置清单、读取旧成功报告跳过处理的一次性脚本。每次建立新的运行清单、报告和隔离目录，不能把旧成功结果当作本次清理结果。

## 验证与报告

- 每个实际配置重新统计目标记录为零；各已处理数据库完整性通过。
- 结构化存储逐项复查，至少核对原生数据源报告和已证明存在的旧式/分区存储。
- 选取有意义的无关条目或摘要确认其他数据保留；不输出其内容。
- 不残留敏感工作副本，现有 PAC、WFP、启动项、固定家宽配置未变。
- 报告“已检查存储”的范围；未支持格式、占用、同步或删除阻止均明确列出，不宣称全部痕迹消失。

## 权威资料

- [Chrome browsingData API 与按源限制](https://developer.chrome.com/docs/extensions/reference/api/browsingData)
- [Chromium 站点设置原生清理接口源码](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/resources/settings/site_settings/site_settings_prefs_browser_proxy.ts)
- [Chromium Session 命令格式](https://chromium.googlesource.com/chromium/src/+/main/components/sessions/core/session_command.cc)

解析器应匹配实际浏览器版本，不把 main 分支格式自动套到旧版本。
