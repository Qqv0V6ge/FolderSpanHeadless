# FolderSpanHeadless

FolderSpan 的独立 Rust 无界面宿主。解压便携包，运行 `./folderspan-headless`（Windows 使用 `folderspan-headless.exe`）。按控制台提示打开管理页面并输入首次启动生成的密钥。普通版便携包可内置 JS 或 Wasm。Pro 使用同一次工作流生成的外置 Web 制品，解压后用 `--web-root` 指向其中的 `web-ui` 目录。

使用 Rust 1.88 执行 `cargo build --release --locked` 即可构建普通版宿主。配套 Web 和便携包通过公开客户端仓库的 **Package FolderSpanHeadless** 工作流构建。获准访问私有 Rust 实现的开发者可将它检出到本仓库忽略的 `pro/`，再以 `--features pro` 编译。

Actions 便携包的 `upstream.lock.json` 记录 Rust 宿主提交、配套 Web 的客户端提交、协议版本和目录摘要。独立下载的 Web 制品可用 `python3 tools/web_artifact.py --verify <web-ui> --lock <upstream.lock.json>` 校验。随包附带的依赖许可见 `third-party-licenses/index.json`。

## English

FolderSpanHeadless is the native Rust host for the FolderSpan Web UI. Extract the portable archive, run `./folderspan-headless` (`folderspan-headless.exe` on Windows), and open the address printed at startup. Enter the key generated on first launch. Standard archives can bundle the JS or Wasm UI. For Pro, extract the Web artifact from the same workflow run and pass its `web-ui` directory to `--web-root`.

Build the standard host with Rust 1.88 and `cargo build --release --locked`. The public client's **Package FolderSpanHeadless** workflow builds the companion Web and portable archives. Developers with access to the private Rust implementation can check it out in the ignored `pro/` directory and enable `--features pro`.

The Actions archive's `upstream.lock.json` records the Rust host revision, companion Web client revision, protocol version, and tree digest. Verify a separately downloaded Web artifact with `python3 tools/web_artifact.py --verify <web-ui> --lock <upstream.lock.json>`. See `third-party-licenses/index.json` for dependency licenses.
