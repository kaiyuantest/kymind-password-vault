# KyMind 账号密码管理器

在支持插件独立数据库及本插件发行版的 KyMind 桌面版，打开「插件 → 从 GitHub 安装」，粘贴 `https://github.com/kaiyuantest/kymind-password-vault`。核对安装信息后点卡片上的「打开密码管理器」，将打开可移动、缩放的独立桌面窗口。重复点击会回到同一窗口。

也可以从 [GitHub Releases](https://github.com/kaiyuantest/kymind-password-vault/releases) 下载 ZIP，解压后选「插件 → 从本地目录安装」，选择直接含 `plugin.json` 的目录。两种安装方式均需要支持 `database.read` 和 `database.commit` 的桌面宿主。首次打开设置至少 12 个字符的主密码。请记住它，主密码遗失后无法找回库中内容。

你可以新增网站或应用、账号、密码和备注，按网站、账号或备注搜索，查看、复制、修改或删除单条记录。复制密码会把明文放入系统剪贴板，剪贴板历史由系统管理。点「锁定」、关闭密码管理器窗口、切到后台使页面隐藏或闲置五分钟后，需要重新解锁。

「加密备份」提供一段可保存到文件的文本，可以在另一台 KyMind 上恢复。恢复备份需要备份创建时的主密码。已有密码库要先解锁，界面会提示恢复将替换库中所有账号。修改主密码后请重新备份。插件只接受自己的加密备份格式。

## 在卡片上更新

点击卡片上的 GitHub 地址可查看源码。点「检查更新」查询最新正式 Release，有更高版本时点「更新到 …」并确认。KyMind 校验 GitHub 附件摘要和包内清单后切换程序文件。已有窗口可以继续使用，关闭后再打开即加载新版本。原有 0.1.0 密码库沿用同一数据库、主密码和加密格式。

发布者请使用三段数字版本号，同时更新清单的 `version`。在仓库根目录创建带 `v` 前缀的版本标签，以 `git archive --format=zip --prefix=kymind-password-vault/ -o kymind-password-vault-0.2.0.zip v0.2.0 -- plugin.json main.js README.md LICENSE` 为例，在正式 Release 附上对应版本的 ZIP 并设为 Latest。发行包沿用上述四个文件和两项数据库权限。校验失败会保留原安装。

## 文件和信任边界

程序由 MIT 许可证授权。所有账号字段组成的 JSON 在插件沙箱内使用 Web Crypto 加密，宿主只收到密文封装和用于防止覆盖的版本号。格式 v1 使用 PBKDF2-HMAC-SHA-256（600,000 次、随机 16 字节盐）从主密码派生不可导出的 AES-256-GCM 密钥，每次保存生成随机 12 字节 IV。锁定时移除界面输入和解密数据引用。解锁期间设备和正在运行的插件代码必须可信。请只从信任的来源安装和更新此插件。

Windows 下的独立 SQLite 文件位于 `%APPDATA%/com.mindmap.app.v2/plugin-databases/`，文件名是插件 key 的 UTF-8 SHA-256 十六进制摘要。密码库属于该 KyMind 应用配置，同一配置切换知识工作区仍可使用。卸载插件保留此库，重新导入同一 key 后用原主密码打开。

## 给插件作者

清单声明 `database:read` 和 `database:commit` 后，使用注入的 SDK：

```js
const database = window.__KM_PLUGIN_API__.database;
const { revision, value } = await database.read();
// 初次读取返回 { revision: 0, value: null }。value 是插件自己编码的字符串。
const newRevision = await database.commit(revision, encodedValue);
```

宿主从调用方 iframe 识别插件身份，原生侧核对调用窗口、插件身份、启用状态和权限，按插件 key 选择独立文件。当前接口每库保存一份最大 4 MiB 的文档，提交时通过一条 SQLite 写语句检查版本；并发冲突会拒绝覆盖。遇到冲突先锁定并重新打开，读取最新数据再编辑。这个接口适合小型插件数据。需要保密的插件须在跨越 SDK 边界前加密。普通插件仍可使用原有 `storage:plugin` 保存设置。
