use super::*;
use crate::storage::accounts::now;
use crate::storage::http::read_file;
use crate::storage::remote::advanced::{
    Availability as A, Capabilities, Path, Share, ShareCompensation, ShareKind, ShareRequest,
    Version, probe,
};
use chrono::{DateTime, SecondsFormat, Utc};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

fn hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn optional(v: &Value, key: &str) -> Option<String> {
    string(v, key).ok()
}
fn timestamp(value: Option<&str>) -> i64 {
    value
        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|v| v.timestamp_millis())
        .unwrap_or(0)
}
fn share_token(value: &str) -> bool {
    !value.trim().is_empty()
        && value.encode_utf16().count() <= 1024
        && !value.chars().any(char::is_control)
        && safe_segment(value)
}
impl Seafile {
    fn binding(&self) -> Result<String> {
        Ok(serde_json::to_string(&[
            "Seafile",
            &self.options.account_id,
            &self.options.connection_id,
            if self.root.is_empty() {
                "/"
            } else {
                &self.root
            },
            &self.options.library_id,
        ])?)
    }
    fn require_binding(&self, value: &str) -> Result<()> {
        ensure!(
            !value.trim().is_empty() && value == self.binding()?,
            "Seafile operation belongs to another connection"
        );
        Ok(())
    }
    fn require_user_token(&self) -> Result<()> {
        ensure!(!self.options.seafile_repo_token, PlatformFailure);
        Ok(())
    }
    fn advanced_url(&self, parts: &[&str], query: &[(&str, String)]) -> Result<Url> {
        let mut target = Url::parse(&self.server)?;
        {
            let mut segments = target
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("invalid storage server"))?;
            segments.pop_if_empty();
            for part in parts {
                ensure!(safe_segment(part), "invalid Seafile URL segment");
                segments.push(part);
            }
            segments.push("");
        }
        if !query.is_empty() {
            target
                .query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        Ok(target)
    }
    async fn library_permission(&self) -> Result<bool> {
        self.require_user_token()?;
        let value = self
            .request(
                Method::GET,
                self.advanced_url(&["api2", "repos", &self.options.library_id], &[])?,
                None,
            )
            .await?;
        ensure!(
            value.is_object(),
            ResourceUnavailable("invalid Seafile library response")
        );
        Ok(self.writable() && optional(&value, "permission").as_deref() == Some("rw"))
    }
    fn history_location(
        &self,
        file: &Path,
        cursor: Option<&str>,
    ) -> Result<(String, Option<String>)> {
        let Some(cursor) = cursor else {
            return Ok((self.remote(&file.path)?, None));
        };
        ensure!(
            cursor.encode_utf16().count() <= 32 * 1024,
            "invalid Seafile history cursor"
        );
        let value: Value = serde_json::from_str(cursor)?;
        ensure!(
            value.is_object(),
            ResourceUnavailable("invalid Seafile history cursor")
        );
        ensure!(
            string(&value, "file")? == file.path,
            "Seafile history cursor belongs to another file"
        );
        let historical = path(&string(&value, "path")?)?;
        self.historical_root(&historical)?;
        let commit = string(&value, "commit")?;
        ensure!(hex40(&commit), "invalid Seafile history cursor");
        Ok((historical, Some(commit)))
    }
    fn historical_root(&self, historical: &str) -> Result<()> {
        ensure!(
            self.root.is_empty() || historical.starts_with(&format!("{}/", self.root)),
            "Seafile history leaves the configured root"
        );
        Ok(())
    }
    fn history_url(&self, file: &Path, cursor: Option<&str>) -> Result<Url> {
        let (historical, commit) = self.history_location(file, cursor)?;
        let mut query = vec![("path", historical), ("limit", "50".into())];
        if let Some(commit) = commit {
            query.push(("commit_id", commit));
        }
        self.advanced_url(
            &[
                "api",
                "v2.1",
                "repos",
                &self.options.library_id,
                "file",
                "history",
            ],
            &query,
        )
    }
    fn invitation_url(&self, file: &Path, recipient: Option<&str>) -> Result<Url> {
        let mut query = vec![
            ("p", self.remote(&file.path)?),
            ("share_type", "user".into()),
        ];
        if let Some(recipient) = recipient {
            query.push(("username", recipient.into()));
        }
        self.advanced_url(
            &[
                "api2",
                "repos",
                &self.options.library_id,
                "dir",
                "shared_items",
            ],
            &query,
        )
    }
    fn links_url(&self, file: &Path, page: i32) -> Result<Url> {
        self.advanced_url(
            &["api", "v2.1", "share-links"],
            &[
                ("repo_id", self.options.library_id.clone()),
                ("path", self.remote(&file.path)?),
                ("page", page.to_string()),
                ("per_page", "100".into()),
            ],
        )
    }
    pub(crate) async fn advanced_capabilities(&self, file: &Path) -> Result<Capabilities> {
        if self.options.seafile_repo_token {
            return Ok(Capabilities::default());
        }
        let entry = match self.stat(&file.path, file.reference.as_ref()).await {
            Ok(entry) => entry,
            Err(e) if e.is::<Missing>() => return Ok(Capabilities::default()),
            Err(e) => return Err(e),
        };
        let write = self.library_permission().await?;
        let versions = if entry.is_directory {
            A::Unsupported
        } else {
            probe(
                self.request(Method::GET, self.history_url(file, None)?, None)
                    .await,
            )?
        };
        let links = probe(
            self.request(Method::GET, self.links_url(file, 1)?, None)
                .await,
        )?;
        let invitations = if entry.is_directory {
            probe(
                self.request(Method::GET, self.invitation_url(file, None)?, None)
                    .await,
            )?
        } else {
            A::Unsupported
        };
        Ok(Capabilities {
            features: BTreeMap::from([
                ("RESUMABLE_UPLOAD".into(), A::Unsupported),
                ("LIST_VERSIONS".into(), versions),
                ("READ_VERSION".into(), versions),
                (
                    "RESTORE_VERSION".into(),
                    if write { versions } else { A::PermissionDenied },
                ),
                ("LIST_SHARES".into(), links),
                (
                    "CREATE_LINK".into(),
                    if write { links } else { A::PermissionDenied },
                ),
                (
                    "INVITE_USER".into(),
                    if write {
                        invitations
                    } else {
                        A::PermissionDenied
                    },
                ),
                (
                    "REVOKE_SHARE".into(),
                    if write { links } else { A::PermissionDenied },
                ),
            ]),
            share_roles: vec!["reader".into(), "writer".into()],
            share_expiry: true,
            ..Default::default()
        })
    }
    pub(crate) async fn versions(&self, file: &Path, cursor: Option<&str>) -> Result<Value> {
        self.require_user_token()?;
        ensure!(
            !self
                .stat(&file.path, file.reference.as_ref())
                .await?
                .is_directory,
            ResourceUnavailable("Seafile directory versions are unsupported")
        );
        let response = self
            .request(Method::GET, self.history_url(file, cursor)?, None)
            .await?;
        let values = response
            .get("data")
            .and_then(Value::as_array)
            .context(ResourceUnavailable("invalid Seafile history response"))?;
        let next = optional(&response, "next_start_commit")
            .filter(|s| s != "false" && !s.trim().is_empty());
        let (query_path, query_commit) = self.history_location(file, cursor)?;
        ensure!(
            next.as_ref()
                .is_none_or(|s| hex40(s) && Some(s) != query_commit.as_ref()),
            "invalid Seafile history cursor"
        );
        let mut entries = Vec::new();
        let mut ids = HashSet::new();
        for revision in values {
            let id = string(revision, "commit_id")?;
            ensure!(hex40(&id), "invalid Seafile revision");
            let historical = optional(revision, "path").unwrap_or_else(|| query_path.clone());
            let historical = path(&historical)?;
            self.historical_root(&historical)?;
            let file_id = string(revision, "rev_file_id")?;
            ensure!(hex40(&file_id), "invalid Seafile revision file ID");
            ensure!(
                ids.insert(id.clone()) && entries.len() < 50,
                ResourceUnavailable("invalid Seafile history page")
            );
            let updated = timestamp(optional(revision, "ctime").as_deref());
            entries.push(Version {file:Path{path:file.path.clone(),reference:Some(json!({
                "parentId":file_id,"ancestorId":self.options.library_id,"ancestorPath":historical}))},
                id,size:long(revision,"size").filter(|n|*n>=0),updated_date:if updated>0{Some(updated)}else{None},
                connection_binding:self.binding()?});
        }
        let next_cursor = if let Some(commit) = next {
            let historical = values
                .last()
                .and_then(|v| optional(v, "rev_renamed_old_path"))
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(query_path);
            let historical = path(&historical)?;
            self.historical_root(&historical)?;
            Some(serde_json::to_string(
                &json!({"file":file.path,"path":historical,"commit":commit}),
            )?)
        } else {
            None
        };
        Ok(json!({"entries":entries,"nextCursor":next_cursor}))
    }
    fn checked_version(&self, v: &Version) -> Result<String> {
        self.require_binding(&v.connection_binding)?;
        self.require_user_token()?;
        path(&v.file.path)?;
        let reference = v.file.reference.as_ref().context(ResourceUnavailable(
            "Seafile version requires its historical identity",
        ))?;
        ensure!(
            reference["ancestorId"].as_str() == Some(&self.options.library_id)
                && hex40(&v.id)
                && reference["parentId"].as_str().is_some_and(hex40),
            "Seafile version belongs to another library"
        );
        let historical = path(reference["ancestorPath"].as_str().unwrap_or(""))?;
        self.historical_root(&historical)?;
        Ok(historical)
    }
    async fn selected_version_path(&self, v: &Version) -> Result<String> {
        let historical = self.checked_version(v)?;
        let mut cursor: Option<String> = None;
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let page = self.versions(&v.file, cursor.as_deref()).await?;
            let selected = page["entries"]
                .as_array()
                .context(PlatformFailure)?
                .iter()
                .any(|item| {
                    item["id"].as_str() == Some(&v.id)
                        && item["file"]["reference"]["parentId"]
                            == v.file.reference.as_ref().unwrap()["parentId"]
                        && item["file"]["reference"]["ancestorPath"].as_str() == Some(&historical)
                        && v.size
                            .is_none_or(|size| item["size"].as_i64() == Some(size))
                });
            if selected {
                return Ok(historical);
            }
            let next = page["nextCursor"].as_str().context(ResourceUnavailable(
                "Seafile revision is no longer in the selected file history",
            ))?;
            ensure!(
                seen.insert(next.to_owned()),
                ResourceUnavailable("Seafile history cursor cycle")
            );
            cursor = Some(next.into());
        }
        Err(ResourceUnavailable("Seafile history exceeds the page limit").into())
    }
    fn revision_url(&self, historical: &str, commit: &str) -> Result<Url> {
        self.advanced_url(
            &[
                "api2",
                "repos",
                &self.options.library_id,
                "file",
                "revision",
            ],
            &[("p", historical.into()), ("commit_id", commit.into())],
        )
    }
    pub(crate) async fn read_version(
        &self,
        v: &Version,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        let historical = self.selected_version_path(v).await?;
        let link = self
            .request(Method::GET, self.revision_url(&historical, &v.id)?, None)
            .await?;
        let target = self.transfer_url(link.as_str().context("invalid Seafile revision link")?)?;
        read_file(
            &self.client,
            target,
            v.size.unwrap_or(-1),
            reqwest::header::HeaderMap::new(),
            output,
        )
        .await
    }
    pub(crate) async fn restore_version(&self, v: &Version, confirmed: bool) -> Result<Entry> {
        ensure!(confirmed, "confirm the selected version before restoring");
        let historical = self.checked_version(v)?;
        ensure!(
            historical == self.remote(&v.file.path)?,
            "native restore before a Seafile rename is unsupported"
        );
        self.selected_version_path(v).await?;
        ensure!(
            self.library_permission().await?,
            ResourceUnavailable("Seafile account cannot restore versions")
        );
        self.request(Method::GET, self.revision_url(&historical, &v.id)?, None)
            .await?;
        self.request(
            Method::POST,
            self.url("file", Some(&self.remote(&v.file.path)?), true)?,
            Some(&[("operation", "revert".into()), ("commit_id", v.id.clone())]),
        )
        .await?;
        let restored = self
            .request(
                Method::GET,
                self.advanced_url(
                    &["api2", "repos", &self.options.library_id, "file", "detail"],
                    &[("p", self.remote(&v.file.path)?)],
                )?,
                None,
            )
            .await?;
        ensure!(
            restored["id"] == v.file.reference.as_ref().unwrap()["parentId"]
                && v.size
                    .is_none_or(|size| long(&restored, "size") == Some(size)),
            ResourceUnavailable("Seafile restore result is uncertain")
        );
        Ok(Entry {
            name: v.file.path.rsplit('/').next().unwrap_or("").into(),
            path: v.file.path.clone(),
            is_directory: false,
            size: long(&restored, "size").unwrap_or(-1),
            created_date: 0,
            updated_date: 0,
            is_hidden: false,
            is_symbolic_link: false,
            is_symbolic_link_known: false,
            reference: None,
        })
    }
    fn link(&self, file: &Path, value: &Value) -> Result<Share> {
        ensure!(
            string(value, "repo_id")? == self.options.library_id
                && string(value, "path")?.trim_end_matches('/')
                    == self.remote(&file.path)?.trim_end_matches('/'),
            "Seafile share belongs to another library or file"
        );
        let permissions =
            value
                .get("permissions")
                .filter(|v| v.is_object())
                .context(ResourceUnavailable(
                    "Seafile did not confirm sharing permissions",
                ))?;
        let edit = permissions["can_edit"].as_bool().unwrap_or(false);
        let upload = permissions["can_upload"].as_bool().unwrap_or(false);
        let download = permissions["can_download"].as_bool().unwrap_or(false);
        let expires_at =
            if let Some(value) = optional(value, "expire_date").filter(|v| !v.trim().is_empty()) {
                let time = timestamp(Some(&value));
                ensure!(
                    time > 0,
                    ResourceUnavailable("unknown Seafile share expiration")
                );
                Some(time)
            } else {
                None
            };
        Ok(Share {
            file: file.clone(),
            id: string(value, "token")?,
            kind: ShareKind::Link,
            role: if !edit && !upload && download {
                "reader"
            } else if !edit && !upload && !download {
                "preview"
            } else {
                "editor"
            }
            .into(),
            recipient: None,
            expires_at,
            url: Some(string(value, "link")?),
            can_revoke: true,
            connection_binding: self.binding()?,
        })
    }
    fn invitation(&self, file: &Path, value: &Value) -> Result<Share> {
        ensure!(
            string(value, "share_type")? == "user",
            "unsupported Seafile sharing type"
        );
        let recipient = string(&value["user_info"], "name")?;
        let role = if value["is_admin"].as_bool() == Some(true) {
            "admin".into()
        } else {
            match string(value, "permission")?.as_str() {
                "r" => "reader".into(),
                "rw" => "writer".into(),
                other => other.into(),
            }
        };
        Ok(Share {
            file: file.clone(),
            id: format!("user:{recipient}"),
            kind: ShareKind::Invitation,
            role,
            recipient: Some(recipient),
            expires_at: None,
            url: None,
            can_revoke: true,
            connection_binding: self.binding()?,
        })
    }
    pub(crate) async fn shares(&self, file: &Path, cursor: Option<&str>) -> Result<Value> {
        self.require_user_token()?;
        let page = cursor
            .map(|s| {
                s.parse::<i32>()
                    .map_err(|_| ResourceUnavailable("invalid Seafile sharing cursor"))
            })
            .transpose()?
            .unwrap_or(1);
        ensure!(
            (1..=10_000).contains(&page),
            "invalid Seafile sharing cursor"
        );
        let values = self
            .request(Method::GET, self.links_url(file, page)?, None)
            .await?;
        let values = values
            .as_array()
            .context(ResourceUnavailable("invalid Seafile share list"))?;
        ensure!(
            values.len() <= 100,
            ResourceUnavailable("Seafile share page exceeds its limit")
        );
        let mut entries = values
            .iter()
            .map(|v| self.link(file, v))
            .collect::<Result<Vec<_>>>()?;
        if page == 1
            && self
                .stat(&file.path, file.reference.as_ref())
                .await?
                .is_directory
        {
            let invitations = self
                .request(Method::GET, self.invitation_url(file, None)?, None)
                .await?;
            for v in invitations
                .as_array()
                .context(ResourceUnavailable("invalid Seafile invitation list"))?
            {
                entries.push(self.invitation(file, v)?);
            }
        }
        Ok(
            json!({"entries":entries,"nextCursor":if values.len()==100{Some((page+1).to_string())}else{None}}),
        )
    }
    pub(crate) async fn create_share(
        &self,
        file: &Path,
        request: &ShareRequest,
        confirmed: bool,
        cancel: &CancellationToken,
    ) -> Result<Share> {
        ensure!(
            confirmed,
            "confirm file, recipient and permissions before sharing"
        );
        self.require_user_token()?;
        self.advanced_capabilities(file)
            .await?
            .validate_share(request)?;
        ensure!(
            request.expires_at.is_none_or(|n| n > now()),
            "share expiration must be in the future"
        );
        if request.kind == ShareKind::Invitation {
            ensure!(
                request.expires_at.is_none(),
                "Seafile directory invitation expiration is unsupported"
            );
            let recipient = request.recipient.as_deref().context(PlatformFailure)?;
            let existing = self
                .request(Method::GET, self.invitation_url(file, None)?, None)
                .await?;
            ensure!(
                !existing
                    .as_array()
                    .context(ResourceUnavailable("invalid Seafile invitation list"))?
                    .iter()
                    .any(|v| optional(&v["user_info"], "name").as_deref() == Some(recipient)),
                ResourceUnavailable("Seafile selected recipient already has access")
            );
            let value = self
                .request(
                    Method::PUT,
                    self.invitation_url(file, None)?,
                    Some(&[
                        ("share_type", "user".into()),
                        ("username", recipient.into()),
                        (
                            "permission",
                            if request.role == "reader" { "r" } else { "rw" }.into(),
                        ),
                    ]),
                )
                .await?;
            let created = value["success"]
                .as_array()
                .filter(|v| v.len() == 1)
                .and_then(|v| v.first())
                .context(ResourceUnavailable(
                    "Seafile invitation result is uncertain",
                ))?;
            ensure!(
                optional(&created["user_info"], "name").as_deref() == Some(recipient),
                ResourceUnavailable("Seafile did not confirm the selected new grant identity")
            );
            let client = self.clone();
            let target = file.clone();
            let selected = recipient.to_owned();
            let guard = ShareCompensation::new(self.store.clone(), async move {
                client
                    .request(
                        Method::DELETE,
                        client.invitation_url(&target, Some(&selected))?,
                        None,
                    )
                    .await?;
                Ok(())
            });
            let result = (|| {
                ensure!(
                    value["failed"].as_array().is_some_and(Vec::is_empty),
                    ResourceUnavailable("Seafile rejected the selected recipient")
                );
                let result = self.invitation(file, created)?;
                ensure!(
                    result.role == request.role && result.recipient.as_deref() == Some(recipient),
                    ResourceUnavailable("Seafile returned different invitation permissions")
                );
                ensure!(
                    !cancel.is_cancelled(),
                    ResourceUnavailable("network connection closed")
                );
                Ok(result)
            })();
            match result {
                Ok(v) => {
                    guard.commit();
                    Ok(v)
                }
                Err(e) => {
                    guard.rollback().await?;
                    Err(e)
                }
            }
        } else {
            ensure!(
                request.role == "reader",
                "Seafile public links support read-only sharing"
            );
            let mut body = json!({"repo_id":self.options.library_id,"path":self.remote(&file.path)?,
                "permissions":{"can_edit":false,"can_upload":false,"can_download":true}});
            if let Some(expiry) = request.expires_at {
                body["expiration_time"] = json!(
                    DateTime::<Utc>::from_timestamp_millis(expiry)
                        .context("invalid sharing deadline")?
                        .to_rfc3339_opts(SecondsFormat::AutoSi, true)
                );
            }
            let created = self
                .execute(
                    self.authorized(
                        Method::POST,
                        self.advanced_url(&["api", "v2.1", "share-links"], &[])?,
                    )?
                    .json(&body),
                )
                .await?;
            let token = optional(&created, "token")
                .filter(|s| share_token(s))
                .context(ResourceUnavailable("Seafile link result is uncertain"))?;
            let client = self.clone();
            let guard = ShareCompensation::new(self.store.clone(), async move {
                client
                    .request(
                        Method::DELETE,
                        client.advanced_url(&["api", "v2.1", "share-links", &token], &[])?,
                        None,
                    )
                    .await?;
                Ok(())
            });
            let result = (|| {
                let result = self.link(file, &created)?;
                ensure!(
                    result.role == request.role
                        && request
                            .expires_at
                            .is_none_or(|n| result.expires_at.is_some_and(|actual| actual <= n)),
                    ResourceUnavailable("Seafile returned different link restrictions")
                );
                ensure!(
                    !cancel.is_cancelled(),
                    ResourceUnavailable("network connection closed")
                );
                Ok(result)
            })();
            match result {
                Ok(v) => {
                    guard.commit();
                    Ok(v)
                }
                Err(e) => {
                    guard.rollback().await?;
                    Err(e)
                }
            }
        }
    }
    pub(crate) async fn revoke_share(&self, share: &Share) -> Result<()> {
        self.require_binding(&share.connection_binding)?;
        self.require_user_token()?;
        if share.kind == ShareKind::Invitation {
            let current = self
                .request(Method::GET, self.invitation_url(&share.file, None)?, None)
                .await?;
            let mut found = false;
            for v in current
                .as_array()
                .context(ResourceUnavailable("invalid Seafile invitation list"))?
            {
                let v = self.invitation(&share.file, v)?;
                found |= v.id == share.id && v.recipient == share.recipient;
            }
            ensure!(
                found,
                ResourceUnavailable("Seafile invitation does not belong to the selected directory")
            );
            self.request(
                Method::DELETE,
                self.invitation_url(&share.file, share.recipient.as_deref())?,
                None,
            )
            .await?;
        } else {
            ensure!(share_token(&share.id), "invalid Seafile share token");
            let url = self.advanced_url(&["api", "v2.1", "share-links", &share.id], &[])?;
            let value = self.request(Method::GET, url.clone(), None).await?;
            let current = self.link(&share.file, &value)?;
            ensure!(
                current.id == share.id,
                ResourceUnavailable("Seafile share identity changed")
            );
            self.request(Method::DELETE, url, None).await?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_expiry_and_tokens_match_history_and_grant_boundaries() {
        assert!(hex40(&"a".repeat(40)) && !hex40(&"g".repeat(40)));
        for bad in ["", " ", "..", "a/b", "a\\b", "x\n"] {
            assert!(!share_token(bad));
        }
        assert_eq!(timestamp(Some("2020-01-01T08:00:00+08:00")), 1577836800000);
        assert_eq!(timestamp(Some("not-an-instant")), 0);
    }
}
