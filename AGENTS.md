# 仓库指南

- 本仓库负责 FolderSpan 的原生 Headless 宿主和便携包。Compose Web 页面和共享业务逻辑由同级 `FolderSpan/` 构建。
- 新增或更新 Headless 能力时，在客户端改动的同一任务维护本仓库。跨仓库修改按已发布客户端契约核对兼容性，并用实际 Rust 宿主和配套 JS/Wasm 制品验证受影响的功能。打包时为配套 Web 制品生成 `upstream.lock.json`，并随制品交付。
- 使用 `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --all-targets` 和 `python3 -m unittest discover -s tests` 验证。涉及 Pro 时再验证 `--features pro` 和获准的 Pro Web 制品。
- Rust 状态目录与 Desktop 分开，实例锁与 Desktop 共享。打包校验原生二进制架构、Web 制品摘要和第三方许可证。凭据、状态目录与 Pro Web 制品保存在各自授权范围内。
- 本仓库提交普通版源码。官方信令、官方云存储和可续传上传的 Pro 实现在独立私有仓库，通过本地忽略的 `pro/` 加载。两版继续兼容已有的存储账号和上传状态文件。

## Rust 源码结构

- `src/main.rs` 负责进程入口。`src/runtime/` 管理配置、私有状态和实例锁。
- `src/management/` 负责 Web 管理协议、认证和会话。`server/` 内分别维护连接、HTTP 路由、WebSocket 和静态资源。
- `src/network/` 负责监听、出站 HTTP 和 TLS。`peer/` 管理设备发现、直连和传输。
- `src/storage/` 负责本机文件、存储账号和内容格式。远程存储的能力分发和协议实现放在 `storage/remote/`。
- 子模块使用 `name.rs` 和同名 `name/` 目录。内部引用指向实现所属模块。`src/lib.rs` 保留对外的模块导入路径。
