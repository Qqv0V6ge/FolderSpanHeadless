<p align="center">
  <img src="https://raw.githubusercontent.com/Qqv0V6ge/FolderSpan/7638cdab5df8693c4c60ca6f8cffa589d2038814/docs/readme/logo.png" alt="FolderSpan 图标" width="96">
</p>

<h1 align="center">FolderSpanHeadless</h1>

<p align="center">在服务器或常开电脑上运行 FolderSpan，通过浏览器管理文件</p>

<p align="center">
  <a href="#下载与平台支持">下载</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#源码构建">源码构建</a> ·
  <a href="#english">English</a>
</p>

FolderSpanHeadless 是 FolderSpan 的原生 Rust 无界面宿主。本仓库提供普通版源码。宿主负责访问运行它的设备上的文件、网络存储和局域网设备，浏览器提供操作界面。配套的 JavaScript 和 WebAssembly 前端由 [FolderSpan 客户端仓库](https://github.com/Qqv0V6ge/FolderSpan) 构建。

## 功能亮点

| 功能 | 可以做什么 |
| --- | --- |
| 文件管理 | 在浏览器中浏览、上传、下载和管理宿主上已授权的文件。 |
| 网络存储 | 添加 FTP、SFTP、SMB、WebDAV、S3 等文件来源。 |
| 局域网设备 | 发现并连接局域网设备，按授权访问共享文件和传输。 |
| 访问密钥 | 为不同使用者创建密钥，按目录授予只读或读写权限，并分别配置网络存储、设备和分享等功能的访问权限。 |
| 终端管理 | 启停服务、编辑部署配置、管理访问密钥、检查诊断信息。 |

运行传输、同步或分享任务时，请保持宿主、浏览器页面和会话连接运行。

## 下载与平台支持

打开客户端的 [Package FolderSpanHeadless](https://github.com/Qqv0V6ge/FolderSpan/actions/workflows/package-native-headless.yml) 工作流，在成功的普通版运行详情中从 **Artifacts** 下载 `headless-<平台>-<js|wasm>-standard`。产物保留 14 天。初次使用可选 JS，Wasm 需要浏览器支持 Kotlin/Wasm 所需特性。

| 宿主系统 | 架构 | 便携包 |
| --- | --- | --- |
| Windows | x64、ARM64 | ZIP |
| macOS | Intel x64、Apple Silicon ARM64 | TAR.GZ |
| Linux | x64、ARM64 | TAR.GZ |

普通版便携包内置配套 Web 界面，解压后即可运行原生程序，无需安装 Java。Pro 的宿主和配套外置 Web 制品由私有工作流构建，应从同一次运行获取。

## 快速开始

1. 完整解压对应平台的便携包。在交互终端运行 `./folderspan-headless`，Windows 使用 `.\folderspan-headless.exe`。
2. 首次部署时，在终端主菜单按 `6` 进入密钥管理，选择「新增密钥」并保存只显示一次的密钥。已有的 Rust 宿主单密钥升级后仍可用于登录。
3. 返回主菜单，按 `1` 进入服务启停，选择「启动服务」。
4. 在浏览器打开终端显示的地址，用刚保存的密钥登录。从其他设备访问时，使用该设备能访问的宿主地址。

终端主菜单的 `2` 用于设置数据目录、监听地址、端口、Web 资源目录和允许的前端来源。使用 systemd 等无交互方式部署时，先用相同的系统用户和数据目录完成密钥初始化，再启动服务。可用 `--data-dir` 指定目录，用 `--help` 查看全部启动参数。

从旧 JVM 宿主切换时，先停止旧进程并备份原数据。Rust 宿主使用独立的状态目录、访问密钥和 TLS 证书，并与 Desktop 共用实例锁。

### 配套 Web 界面

宿主默认从可执行文件旁的 `web-ui/` 加载页面。源码构建的宿主或 Pro 便携包可用 `--web-root` 指向配套制品解压后的 `web-ui/` 目录。

```bash
./folderspan-headless --web-root /path/to/web-ui
```

将前端单独部署到其他来源时，可在宿主上设置 `FOLDERSPAN_WEB_UI_ALLOWED_ORIGINS`，填入页面的完整来源，例如 `https://files.example.com`。多个来源用逗号分隔。

打包流程生成 `upstream.lock.json` 并随 Actions 制品交付，记录本次构建的宿主提交、配套客户端提交、协议版本和 Web 目录摘要。在源码仓库中可用制品附带的锁定文件校验：

```bash
python3 tools/web_artifact.py --verify /path/to/web-ui --lock /path/to/upstream.lock.json
```

## 源码构建

安装 Rust 1.88.0 后执行以下命令构建普通版宿主。可执行文件位于 `target/release/`，网页由上述工作流单独构建。

```bash
git clone https://github.com/Qqv0V6ge/FolderSpanHeadless.git
cd FolderSpanHeadless
cargo build --release --locked
```

获准访问私有 Rust 实现的开发者可将其检出到本仓库忽略的 `pro/`，再用 `--features pro` 编译。

| 目录 | 职责 |
| --- | --- |
| `src/tui/`、`src/runtime/` | 终端管理台、运行配置和实例锁。 |
| `src/management/` | Web 管理协议、身份验证、会话与静态资源服务。 |
| `src/storage/`、`src/peer/` | 宿主文件、网络存储及设备连接和传输。 |
| `tools/`、`tests/` | Web 制品校验、第三方许可收集、便携包打包与测试。 |

## 开源许可

普通版宿主源码采用 [Apache-2.0](LICENSE)，许可范围见 [NOTICE](NOTICE)。第三方组件沿用各自许可，便携包内的 `third-party-licenses/index.json` 列出相应许可和归属声明。Pro 源码的许可由其独立仓库维护。

## 问题反馈

遇到问题时，请附上宿主版本或提交、Web 类型、操作系统和架构、复现步骤，以及已去除密钥的诊断信息。[GitHub Issues](https://github.com/Qqv0V6ge/FolderSpanHeadless/issues)

## English

FolderSpanHeadless is the native Rust host for the [FolderSpan Web UI](https://github.com/Qqv0V6ge/FolderSpan). It lets you manage files on a server or always-on computer, connect to network storage and LAN peers, and assign read-only or read/write permissions per directory through access keys.

Download a standard JS or Wasm portable archive from a successful run of [Package FolderSpanHeadless](https://github.com/Qqv0V6ge/FolderSpan/actions/workflows/package-native-headless.yml). Windows uses ZIP, while Linux and macOS use TAR.GZ. All three support x64 and ARM64. Standard archives bundle the UI and run without Java. Pro uses the separate Web artifact from the same private workflow run.

Extract the archive and run `./folderspan-headless` (`.\folderspan-headless.exe` on Windows) in an interactive terminal. On first setup, open menu `6` to create and save a Web access key, then open menu `1` to start the service. Open the displayed address and sign in with the saved key. Set up the key under the same system user and data directory before running unattended.

Build the standard host with Rust 1.88.0 and `cargo build --release --locked`. Use `--web-root` to select the companion `web-ui/` directory and set `FOLDERSPAN_WEB_UI_ALLOWED_ORIGINS` for a separately hosted frontend. Verify companion files against the lock generated during packaging with `python3 tools/web_artifact.py --verify /path/to/web-ui --lock /path/to/upstream.lock.json`. Developers with access to the private Rust implementation can check it out under `pro/` and build with `--features pro`.

The standard host uses the [Apache-2.0 license](LICENSE). See [NOTICE](NOTICE) and the archive's `third-party-licenses/index.json` for attribution. Report host issues on [GitHub](https://github.com/Qqv0V6ge/FolderSpanHeadless/issues).
