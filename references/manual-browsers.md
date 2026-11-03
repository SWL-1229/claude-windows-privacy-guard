# 独立 Edge／Brave：日常手动入口

## 先识别模式

| 环境 | 本版入口 | 监控范围 |
| --- | --- | --- |
| Edge 手动网页 | `claude_browser_launch.py` → `manual_browser_launch.py` | `manual_native_browser_v2`，当前 Windows 时区、进程身份、真实启动参数和专用配置 |
| Brave 隐私网页 | `claude_brave_launch.py` → `brave_browser_launch.py` | `brave_manual_browser_v1`，另核对官方浏览器的本机文件绑定 |
| Claude 桌面 | `native-launcher/native_desktop_launch.py --gui` | 原生策略和已有页面监控；仍有独立 DevTools 依赖 |

日常网页入口不附着 CDP／WebDriver，不注入 Canvas／WebGL、`navigator.webdriver` 或人机验证脚本。旧调试控制器保留用于兼容和诊断，不能误当当前手动入口。Brave 的官方抗指纹机制可减少关联，不等于匿名或新设备身份。

## 维护顺序

1. 只读核对实际根目录、入口目标、进程创建时间及所用 profile。Edge 与 Brave 使用各自独立目录；不要复制普通浏览器登录或把用户带到无保护窗口。
2. 保留用户手动链式选择。`ingress-follow-policy.json` 的 `manual-group` 只观察指定组，不替用户连接、选节点或切换到 DIRECT。入口可变，最终 SOCKS5 出口仍需匹配自有配置并通过实际出口复验。
3. 当前快照要求 Windows 为 `Mountain Standard Time`，对应 `America/Denver`，英语偏好为 `en-US,en`；冬季偏移 420 分钟、夏季 360 分钟。改变系统时区须在用户授权范围内，不同时改系统显示语言或硬改系统时钟。
4. 修改浏览器 Preferences 前，确认**该独立 profile 已完整退出**。真实设置为 `webrtc.ip_handling_policy = disable_non_proxied_udp`，必须写入并重新读取对应 `Default/Preferences`。启动参数或仅 Claude 域名的 URL 策略不能代替实际 profile 设置；在检测站页面同样复测。
5. Preferences 可能大于许可记录的 32 KiB 限制。使用本版专用、有大小边界的原子 JSON 写入，保留所有其他字段；异常 JSON／重解析路径应停止，不能清空重建来强行修复。
6. Brave 从官方安装源获得。本版绑定用户级 `%LOCALAPPDATA%/BraveSoftware/Brave-Browser/Application/brave.exe`；重新安装／更新后重新核验签名与哈希，不复制作者的 `brave-runtime.json`。构建目录绑定准备见 [后端说明](../backend/README.md)。

## 验收与故障

- 当前窗口的 HTTP 出口、DNS 和 ICE 候选分别检查。没有公网候选与完全不能枚举私网地址是不同结果；不把浏览器结果套到桌面应用。
- 手动模式的实时证明明确标记 `page_javascript_measured: false`、`ice_candidates_measured: false`。它证明当前进程／配置策略，不伪造实时页面或 STUN 测量。
- 保留原四秒出口许可和失败关闭。分别测允许出口成功、维护锁／监控停止时拒绝、恢复重新核验、普通网络不受影响；不能以截图或历史绿字代替。
- 人机验证失败时先排查官方浏览器版本、Cookie／JavaScript、网络和扩展冲突；用户自行完成验证。不做自动验证码、stealth 插件或反检测补丁。[Cloudflare 官方排查](https://developers.cloudflare.com/cloudflare-challenges/troubleshooting/challenge-solve-issues/)。
- 面板 `IPv6 / UDP` 的策略行、内核条件核验与真实包级拦截测试分别报告。管理员拒绝、读取器缺失或证据过期保持待验证，不写假通过。

实际图片见 [前后对比](../docs/before-after.md)，仅供理解界面；执行仍按 [验收清单](acceptance.md) 核对本机当前状态。不得将第三方“风险分／中国用户分”称为 Anthropic 官方结论。
