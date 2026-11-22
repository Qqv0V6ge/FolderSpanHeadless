use super::*;
use crate::storage::remote::{
    advanced::validate_upload_reference,
    upload_state::{Status, UploadSession},
};

#[cfg(feature = "pro")]
#[rustfmt::skip]
#[path = "../../../pro/src/storage/accounts/uploads.rs"]
mod persistence;

// Keep the persisted record readable in either edition.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Record {
    task_key: i64,
    reference: Value,
    session: UploadSession,
}
impl Storage {
    pub(crate) fn content_has_uncertain_task(&self, task_key: i64) -> Result<bool> {
        let owner = self.upload_owner()?;
        let state = self.state.lock().unwrap();
        for record in state.uploads.values() {
            validate_upload_reference(&record.reference)?;
            if record.task_key == task_key
                && record.reference["ownerRuntimeId"] == owner
                && record.session.status == Status::Uncertain
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(all(test, not(feature = "pro")))]
mod tests {
    use super::*;

    #[test]
    fn standard_edition_preserves_existing_uncertain_uploads() {
        let directory = tempfile::tempdir().unwrap();
        let store = Storage::load(directory.path()).unwrap();
        let owner = store.upload_owner().unwrap();
        let id = "12345678-1234-1234-1234-123456789abc";
        let record = serde_json::from_value(json!({
            "taskKey": 17,
            "reference": {
                "sessionId": id, "ownerRuntimeId": owner, "connectionId": "connection",
                "source": {}, "target": {"path": "/target"}, "sourceVersion": "version"
            },
            "session": {
                "backend": "Dropbox", "target": {"path": "/target"}, "size": 4,
                "confirmedOffset": 4, "status": "UNCERTAIN", "entry": null,
                "secret": "test-session", "binding": "test-account"
            }
        }))
        .unwrap();
        let mut state = store.state.lock().unwrap().clone();
        state.uploads.insert(id.into(), record);
        store.save(&state).unwrap();

        let restored = Storage::load(directory.path()).unwrap();
        assert!(restored.content_has_uncertain_task(17).unwrap());
        assert!(!restored.content_has_uncertain_task(18).unwrap());
    }
}
