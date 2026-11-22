use serde_json::Value;
use std::path::Path;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
};
pub struct Peer {
    pub port: u16,
    pub root: tempfile::TempDir,
    child: Child,
}
impl Peer {
    pub async fn start(encoding: &str, tls: Option<(&Path, &Path)>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let python = std::env::var_os("FOLDERSPAN_TEST_PYTHON").unwrap_or_else(|| {
            if cfg!(windows) {
                "python".into()
            } else {
                "python3".into()
            }
        });
        let mut command = Command::new(python);
        command
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/ftp_peer.py"))
            .args(["--encoding", encoding, "--record"])
            .arg(root.path().join("records.jsonl"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        if let Some((cert, key)) = tls {
            command.arg("--cert").arg(cert).arg("--key").arg(key);
        }
        let mut child = command.spawn().unwrap();
        let mut ready = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready),
        )
        .await
        .unwrap()
        .unwrap();
        let ready: Value = serde_json::from_str(&ready).expect("FTP fixture did not start");
        Self {
            port: ready["port"].as_u64().unwrap() as u16,
            root,
            child,
        }
    }
    pub fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.path().join("records.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    pub async fn close(&mut self) {
        self.child.kill().await.unwrap();
        let _ = self.child.wait().await;
    }
}
