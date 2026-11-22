use super::{Entry, advanced::Path};
use serde::{Deserialize, Serialize};
#[cfg(feature = "pro")]
use serde_json::{Value, json};
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Status {
    Uploading,
    Completed,
    Expired,
    Uncertain,
    Cancelled,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UploadSession {
    pub backend: String,
    pub target: Path,
    pub size: i64,
    pub confirmed_offset: i64,
    pub status: Status,
    pub entry: Option<Entry>,
    pub(crate) secret: String,
    pub(crate) binding: String,
}
impl Drop for UploadSession {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
#[cfg(feature = "pro")]
impl UploadSession {
    pub fn state(&self, handle: &str) -> Value {
        json!({"handle":handle,"target":self.target,"size":self.size,"confirmedOffset":self.confirmed_offset,
            "status":self.status,"entry":self.entry})
    }
}
