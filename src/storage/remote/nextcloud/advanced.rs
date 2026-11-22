use super::*;
use crate::storage::accounts::{now, read_json, string};
use crate::storage::http::read_file;
use crate::storage::remote::advanced::{
    Availability as A, Capabilities, Path, Share, ShareKind, ShareRequest, Version,
};
use crate::storage::remote::advanced::{ShareCompensation, probe};
use anyhow::Context;
use chrono::{DateTime, NaiveDateTime, Offset, TimeZone, Utc};
use chrono_tz::Tz;
use std::collections::{BTreeMap, HashSet};
use tokio_util::sync::CancellationToken;

fn number(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}
fn optional(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .filter(|v| !v.is_null())
        .and_then(|_| string(v, key).ok())
}
fn numeric(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
}
impl Nextcloud {
    fn binding(&self) -> Result<String> {
        let root = self.root()?;
        Ok(serde_json::to_string(&[
            "Nextcloud",
            &self.options.account_id,
            &self.options.connection_id,
            if root.is_empty() { "/" } else { root },
            &self.options.library_id,
        ])?)
    }
    fn require_binding(&self, binding: &str) -> Result<()> {
        ensure!(
            !binding.trim().is_empty() && binding == self.binding()?,
            "Nextcloud operation belongs to another connection"
        );
        Ok(())
    }
    fn versions_url(&self, a: &Credential, id: &str, revision: Option<&str>) -> Result<Url> {
        ensure!(
            numeric(id) && revision.is_none_or(numeric),
            "invalid Nextcloud revision"
        );
        let mut parts = vec![
            "remote.php",
            "dav",
            "versions",
            &a.provider_account_id,
            "versions",
            id,
        ];
        if let Some(revision) = revision {
            parts.push(revision);
        }
        Self::url(a, &parts)
    }
    fn shares_url(&self, a: &Credential, id: Option<&str>, path: Option<&str>) -> Result<Url> {
        ensure!(id.is_none_or(numeric), "invalid Nextcloud share");
        let mut parts = vec![
            "ocs",
            "v2.php",
            "apps",
            "files_sharing",
            "api",
            "v1",
            "shares",
        ];
        if let Some(id) = id {
            parts.push(id);
        }
        let mut target = Self::url(a, &parts)?;
        target.query_pairs_mut().append_pair("format", "json");
        if let Some(path) = path {
            target
                .query_pairs_mut()
                .append_pair("path", &self.remote(path)?);
        }
        Ok(target)
    }
    async fn advanced_request(
        &self,
        a: &Credential,
        method: Method,
        url: Url,
        depth: Option<&str>,
        destination: Option<Url>,
        form: Option<&BTreeMap<String, String>>,
    ) -> Result<Response> {
        let mut r = self
            .client
            .request(method, url)
            .basic_auth(&a.username, Some(&a.access_token))
            .header("OCS-APIRequest", "true");
        if let Some(depth) = depth {
            r = r
                .header("Depth", depth)
                .header("Content-Type", "application/xml")
                .body(PROPFIND);
        }
        if let Some(destination) = destination {
            r = r.header("Destination", destination.as_str());
        }
        if let Some(form) = form {
            r = r.form(form);
        }
        success(r.send().await.map_err(|_| PlatformFailure)?)
    }
    async fn ocs(
        &self,
        a: &Credential,
        method: Method,
        url: Url,
        form: Option<&BTreeMap<String, String>>,
    ) -> Result<Value> {
        let value = read_json(
            self.advanced_request(a, method, url, None, None, form)
                .await?,
            8 * 1024 * 1024,
        )
        .await?;
        let body = value
            .get("ocs")
            .context(ResourceUnavailable("Invalid Nextcloud share response"))?;
        ensure!(
            matches!(number(&body["meta"], "statuscode"), Some(100 | 200)),
            ResourceUnavailable("Invalid Nextcloud advanced storage response")
        );
        Ok(body.get("data").cloned().unwrap_or(Value::Null))
    }
    async fn sharing_zone(&self, a: &Credential, cache: &mut Option<Tz>) -> Result<Tz> {
        if let Some(zone) = *cache {
            return Ok(zone);
        }
        let mut target = Self::url(a, &["ocs", "v2.php", "cloud", "capabilities"])?;
        target.query_pairs_mut().append_pair("format", "json");
        let value = self.ocs(a, Method::GET, target, None).await?;
        let zone = value
            .pointer("/capabilities/core/user/timezone")
            .and_then(Value::as_str)
            .context(ResourceUnavailable(
                "Invalid Nextcloud advanced storage response",
            ))?
            .parse::<Tz>()
            .map_err(|_| ResourceUnavailable("Invalid Nextcloud advanced storage response"))?;
        *cache = Some(zone);
        Ok(zone)
    }
    pub(crate) async fn advanced_capabilities(&self, path: &Path) -> Result<Capabilities> {
        let m = match self.metadata(&path.path, path.reference.as_ref()).await {
            Ok(m) => m,
            Err(e) if e.downcast_ref::<HttpStatus>().is_some_and(|s| s.0 == 404) => {
                return Ok(Capabilities::default());
            }
            Err(e) => return Err(e),
        };
        let a = self.account()?;
        let versions = if m.directory {
            A::Unsupported
        } else {
            probe(
                self.advanced_request(
                    &a,
                    Method::from_bytes(b"PROPFIND")?,
                    self.versions_url(&a, &m.id, None)?,
                    Some("0"),
                    None,
                    None,
                )
                .await,
            )?
        };
        let shares = probe(
            self.ocs(
                &a,
                Method::GET,
                self.shares_url(&a, None, Some(&path.path))?,
                None,
            )
            .await,
        )?;
        let share = if self.writable() && m.permissions.contains('R') {
            shares
        } else {
            A::PermissionDenied
        };
        let restore = if self.writable() && m.permissions.contains('W') {
            versions
        } else {
            A::PermissionDenied
        };
        Ok(Capabilities {
            features: BTreeMap::from([
                ("RESUMABLE_UPLOAD".into(), A::Unsupported),
                ("LIST_VERSIONS".into(), versions),
                ("READ_VERSION".into(), versions),
                ("RESTORE_VERSION".into(), restore),
                ("LIST_SHARES".into(), shares),
                ("CREATE_LINK".into(), share),
                ("INVITE_USER".into(), share),
                ("REVOKE_SHARE".into(), share),
            ]),
            share_roles: ["reader", "writer", "reader+reshare", "writer+reshare"]
                .map(str::to_owned)
                .to_vec(),
            share_expiry: true,
            ..Default::default()
        })
    }
    pub(crate) async fn versions(&self, path: &Path, cursor: Option<&str>) -> Result<Value> {
        ensure!(cursor.is_none(), "Nextcloud versions do not use a cursor");
        self.advanced_capabilities(path)
            .await?
            .require("LIST_VERSIONS")?;
        let m = self.metadata(&path.path, path.reference.as_ref()).await?;
        let a = self.account()?;
        let body = text(
            self.advanced_request(
                &a,
                Method::from_bytes(b"PROPFIND")?,
                self.versions_url(&a, &m.id, None)?,
                Some("1"),
                None,
                None,
            )
            .await?,
        )
        .await?;
        let doc = xml(&body)?;
        let mut entries = Vec::new();
        let mut ids = HashSet::new();
        for block in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "response")
        {
            let Some(revision) = tag(block, "href")
                .map(|s| s.trim_end_matches('/').rsplit('/').next().unwrap_or(""))
            else {
                continue;
            };
            if !numeric(revision)
                || (revision == m.id
                    && block
                        .descendants()
                        .any(|n| n.is_element() && n.tag_name().name() == "collection"))
            {
                continue;
            }
            let props = successful(block);
            if props.is_empty() {
                continue;
            }
            ensure!(
                entries.len() < 100_000 && ids.insert(revision.to_owned()),
                ResourceUnavailable("Invalid Nextcloud advanced storage response")
            );
            entries.push(Version {
                file: path.selected(&m.id),
                id: revision.into(),
                size: property(&props, "getcontentlength")
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|n| *n >= 0),
                updated_date: revision
                    .parse::<i64>()
                    .ok()
                    .and_then(|n| n.checked_mul(1000)),
                connection_binding: self.binding()?,
            });
        }
        Ok(json!({"entries":entries,"nextCursor":null}))
    }
    pub(crate) async fn read_version(
        &self,
        v: &Version,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        self.require_binding(&v.connection_binding)?;
        self.advanced_capabilities(&v.file)
            .await?
            .require("READ_VERSION")?;
        let m = self
            .metadata(&v.file.path, v.file.reference.as_ref())
            .await?;
        let a = self.account()?;
        let mut headers = reqwest::header::HeaderMap::new();
        use base64::{Engine, engine::general_purpose::STANDARD};
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", a.username, a.access_token))
            )
            .parse()?,
        );
        read_file(
            &self.client,
            self.versions_url(&a, &m.id, Some(&v.id))?,
            v.size.unwrap_or(-1),
            headers,
            output,
        )
        .await
    }
    pub(crate) async fn restore_version(&self, v: &Version, confirmed: bool) -> Result<Entry> {
        ensure!(confirmed, "confirm the selected version before restoring");
        self.require_binding(&v.connection_binding)?;
        self.advanced_capabilities(&v.file)
            .await?
            .require("RESTORE_VERSION")?;
        let m = self
            .metadata(&v.file.path, v.file.reference.as_ref())
            .await?;
        let a = self.account()?;
        let source = self.versions_url(&a, &m.id, Some(&v.id))?;
        self.advanced_request(
            &a,
            Method::from_bytes(b"PROPFIND")?,
            source.clone(),
            Some("0"),
            None,
            None,
        )
        .await?;
        let dest = Self::url(
            &a,
            &[
                "remote.php",
                "dav",
                "versions",
                &a.provider_account_id,
                "restore",
                &m.id,
            ],
        )?;
        self.advanced_request(
            &a,
            Method::from_bytes(b"MOVE")?,
            source,
            None,
            Some(dest),
            None,
        )
        .await?;
        let restored = self
            .metadata(&v.file.path, v.file.reference.as_ref())
            .await?;
        ensure!(
            restored.id == m.id && v.size.is_none_or(|n| n == restored.size),
            ResourceUnavailable("Invalid Nextcloud advanced storage response")
        );
        Ok(Entry {
            name: v.file.path.rsplit('/').next().unwrap_or("").into(),
            path: v.file.path.clone(),
            is_directory: false,
            size: restored.size,
            created_date: 0,
            updated_date: 0,
            is_hidden: false,
            is_symbolic_link: false,
            is_symbolic_link_known: false,
            reference: Some(json!({"id":m.id})),
        })
    }
    async fn parse_share(
        &self,
        a: &Credential,
        file: &Path,
        value: &Value,
        zone: &mut Option<Tz>,
    ) -> Result<Share> {
        ensure!(
            string(value, "path")?.trim_end_matches('/')
                == self.remote(&file.path)?.trim_end_matches('/'),
            ResourceUnavailable("Invalid Nextcloud advanced storage response")
        );
        let kind = match number(value, "share_type") {
            Some(3) => ShareKind::Link,
            Some(0) => ShareKind::Invitation,
            _ => anyhow::bail!("unsupported Nextcloud share type"),
        };
        let permissions = number(value, "permissions").context(ResourceUnavailable(
            "Invalid Nextcloud advanced storage response",
        ))?;
        let role = match permissions {
            1 => "reader".into(),
            3 => "writer".into(),
            17 => "reader+reshare".into(),
            19 => "writer+reshare".into(),
            _ => format!("permissions:{permissions}"),
        };
        let expires_at =
            if let Some(expiry) = optional(value, "expiration").filter(|s| !s.trim().is_empty()) {
                let stamp = expiry.replace(' ', "T");
                let millis = if let Ok(instant) = DateTime::parse_from_rfc3339(&stamp) {
                    instant.timestamp_millis()
                } else {
                    let local = NaiveDateTime::parse_from_str(&stamp, "%Y-%m-%dT%H:%M:%S%.f")?;
                    local_millis(local, self.sharing_zone(a, zone).await?)?
                };
                ensure!(millis > 0, "invalid Nextcloud share expiration");
                Some(millis)
            } else {
                None
            };
        Ok(Share {
            file: file.clone(),
            id: string(value, "id")?,
            kind,
            role,
            recipient: if kind == ShareKind::Invitation {
                optional(value, "share_with")
            } else {
                None
            },
            expires_at,
            url: if kind == ShareKind::Link {
                optional(value, "url")
            } else {
                None
            },
            can_revoke: optional(value, "uid_owner").as_deref() == Some(&a.provider_account_id)
                || optional(value, "uid_initiator").as_deref() == Some(&a.provider_account_id),
            connection_binding: self.binding()?,
        })
    }
    pub(crate) async fn shares(&self, path: &Path, cursor: Option<&str>) -> Result<Value> {
        ensure!(cursor.is_none(), "Nextcloud shares do not use a cursor");
        let m = self.metadata(&path.path, path.reference.as_ref()).await?;
        let a = self.account()?;
        let values = self
            .ocs(
                &a,
                Method::GET,
                self.shares_url(&a, None, Some(&path.path))?,
                None,
            )
            .await?;
        let mut entries = Vec::new();
        let mut zone = None;
        for v in values.as_array().context(ResourceUnavailable(
            "Invalid Nextcloud advanced storage response",
        ))? {
            if matches!(number(v, "share_type"), Some(0 | 3)) {
                entries.push(
                    self.parse_share(&a, &path.selected(&m.id), v, &mut zone)
                        .await?,
                );
            }
        }
        Ok(json!({"entries":entries,"nextCursor":null}))
    }
    pub(crate) async fn create_share(
        &self,
        path: &Path,
        request: &ShareRequest,
        confirmed: bool,
        cancel: &CancellationToken,
    ) -> Result<Share> {
        ensure!(
            confirmed,
            "confirm file, recipient and permissions before sharing"
        );
        self.advanced_capabilities(path)
            .await?
            .validate_share(request)?;
        ensure!(
            request.kind == ShareKind::Link || request.expires_at.is_none(),
            "Nextcloud invitation expiration is unsupported"
        );
        ensure!(
            request.expires_at.is_none_or(|n| n > now()),
            "share expiration must be in the future"
        );
        let m = self.metadata(&path.path, path.reference.as_ref()).await?;
        let a = self.account()?;
        let mut zone = None;
        let expiry = if let Some(deadline) = request.expires_at {
            Some(expiry_date(
                deadline,
                self.sharing_zone(&a, &mut zone).await?,
                now(),
            )?)
        } else {
            None
        };
        let mut form = BTreeMap::from([
            ("path".into(), self.remote(&path.path)?),
            (
                "shareType".into(),
                if request.kind == ShareKind::Link {
                    "3"
                } else {
                    "0"
                }
                .into(),
            ),
            (
                "permissions".into(),
                match request.role.as_str() {
                    "reader" => "1",
                    "writer" => "3",
                    "reader+reshare" => "17",
                    "writer+reshare" => "19",
                    _ => anyhow::bail!("unsupported Nextcloud role"),
                }
                .into(),
            ),
            ("sendMail".into(), "false".into()),
        ]);
        if let Some(recipient) = &request.recipient {
            form.insert("shareWith".into(), recipient.clone());
        }
        if let Some(expiry) = expiry {
            form.insert("expireDate".into(), expiry);
        }
        let created = self
            .ocs(
                &a,
                Method::POST,
                self.shares_url(&a, None, None)?,
                Some(&form),
            )
            .await?;
        let id = optional(&created, "id")
            .filter(|s| numeric(s))
            .context(ResourceUnavailable(
                "Invalid Nextcloud advanced storage response",
            ))?;
        let client = self.clone();
        let account = a.clone();
        let guard = ShareCompensation::new(self.store.clone(), async move {
            client
                .ocs(
                    &account,
                    Method::DELETE,
                    client.shares_url(&account, Some(&id), None)?,
                    None,
                )
                .await?;
            Ok(())
        });
        let outcome = async {
            let result = self
                .parse_share(&a, &path.selected(&m.id), &created, &mut zone)
                .await?;
            ensure!(
                result.role == request.role
                    && result.kind == request.kind
                    && result.recipient == request.recipient
                    && request
                        .expires_at
                        .is_none_or(|n| result.expires_at.is_some_and(|actual| actual <= n)),
                ResourceUnavailable("Invalid Nextcloud advanced storage response")
            );
            ensure!(
                !cancel.is_cancelled(),
                ResourceUnavailable("network connection closed")
            );
            Ok(result)
        }
        .await;
        match outcome {
            Ok(result) => {
                guard.commit();
                Ok(result)
            }
            Err(error) => {
                guard.rollback().await?;
                Err(error)
            }
        }
    }
    pub(crate) async fn revoke_share(&self, share: &Share) -> Result<()> {
        self.require_binding(&share.connection_binding)?;
        self.metadata(&share.file.path, share.file.reference.as_ref())
            .await?;
        let a = self.account()?;
        let response = self
            .ocs(
                &a,
                Method::GET,
                self.shares_url(&a, Some(&share.id), None)?,
                None,
            )
            .await?;
        let selected = if let Some(values) = response.as_array() {
            ensure!(
                values.len() == 1,
                ResourceUnavailable("Invalid Nextcloud advanced storage response")
            );
            &values[0]
        } else {
            &response
        };
        let current = self
            .parse_share(&a, &share.file, selected, &mut None)
            .await?;
        ensure!(
            current.id == share.id && current.can_revoke,
            "Nextcloud share belongs to another account"
        );
        self.ocs(
            &a,
            Method::DELETE,
            self.shares_url(&a, Some(&share.id), None)?,
            None,
        )
        .await?;
        Ok(())
    }
}
fn local_millis(local: NaiveDateTime, zone: Tz) -> Result<i64> {
    if let Some(instant) = zone.from_local_datetime(&local).earliest() {
        return Ok(instant.timestamp_millis());
    }
    // Kotlin resolves a daylight-saving gap using the offset before the transition.
    let gap = chrono_tz::GapInfo::new(&local, &zone).context("invalid share local time")?;
    let (_, offset) = gap.begin.context("invalid share local time")?;
    let utc = local
        .checked_sub_signed(chrono::Duration::seconds(i64::from(
            offset.fix().local_minus_utc(),
        )))
        .context("invalid share local time")?;
    Ok(utc.and_utc().timestamp_millis())
}
fn expiry_date(deadline: i64, zone: Tz, now: i64) -> Result<String> {
    let mut date = DateTime::<Utc>::from_timestamp_millis(deadline)
        .context("invalid share deadline")?
        .with_timezone(&zone)
        .date_naive();
    let end = |date: chrono::NaiveDate| -> Result<i64> {
        local_millis(date.and_hms_opt(23, 59, 59).unwrap(), zone)
    };
    if end(date)? > deadline {
        date = date.pred_opt().context("invalid share expiry date")?;
    }
    ensure!(
        end(date)? <= deadline && end(date)? > now,
        "Nextcloud cannot represent this deadline as a future whole-day expiration"
    );
    Ok(date.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_uses_server_zone_and_never_extends_requested_deadline() {
        let now = DateTime::parse_from_rfc3339("2026-03-06T01:00:00Z")
            .unwrap()
            .timestamp_millis();
        let deadline = DateTime::parse_from_rfc3339("2026-03-09T04:00:00Z")
            .unwrap()
            .timestamp_millis();
        assert_eq!(
            expiry_date(deadline, chrono_tz::America::New_York, now).unwrap(),
            "2026-03-08"
        );
        assert_eq!(
            expiry_date(deadline, chrono_tz::Asia::Shanghai, now).unwrap(),
            "2026-03-08"
        );
        assert!(expiry_date(now + 1000, chrono_tz::Asia::Shanghai, now).is_err());
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use axum::{
        Router,
        extract::{Request, State},
        response::IntoResponse,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::sync::Notify;
    #[derive(Clone)]
    struct Peer {
        blocked: Arc<Notify>,
        deleted: Arc<AtomicUsize>,
    }
    async fn route(State(peer): State<Peer>, request: Request) -> axum::response::Response {
        let method = request.method().clone();
        let path = request.uri().path();
        if path.ends_with("/cloud/capabilities") {
            peer.blocked.notify_one();
            std::future::pending::<()>().await;
        }
        let mut data = json!([]);
        if method == Method::from_bytes(b"PROPFIND").unwrap() {
            return (axum::http::StatusCode::MULTI_STATUS,
                r#"<d:multistatus xmlns:d="DAV:" xmlns:o="http://owncloud.org/ns"><d:response><d:propstat><d:prop><o:fileid>123</o:fileid><o:permissions>RW</o:permissions><d:getcontentlength>0</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#).into_response();
        }
        if method == Method::POST {
            data = json!({"id":"77","path":"/selected/file","share_type":3,"permissions":1,
                "expiration":"2026-12-01 23:59:59","uid_owner":"alice","url":"https://example.test/share/77"});
        }
        if method == Method::DELETE {
            assert!(path.ends_with("/shares/77"));
            peer.deleted.fetch_add(1, Ordering::SeqCst);
        }
        axum::Json(json!({"ocs":{"meta":{"statuscode":100},"data":data}})).into_response()
    }
    #[tokio::test]
    async fn abort_after_new_grant_identity_revokes_it_and_waits_on_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        let peer = Peer {
            blocked: Arc::new(Notify::new()),
            deleted: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new().fallback(route).with_state(peer.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let id = "account_for_cancel_test";
        std::fs::write(directory.path().join("storage-accounts.json"),serde_json::to_vec(&json!({
            "version":1,"accounts":{id:{"id":id,"kind":"Nextcloud","providerAccountId":"alice","label":"Alice",
                "username":"alice","server":host,"accessToken":"private-test-token"}},"generations":{}
        })).unwrap()).unwrap();
        let store = Storage::load(directory.path()).unwrap();
        let client = Nextcloud::new(
            &host,
            "/",
            &json!({"cloud":{"accountId":id,"rootId":"/selected","connectionId":"cancel"}}),
            store.clone(),
        )
        .unwrap();
        let operation = tokio::spawn(async move {
            client
                .create_share(
                    &Path {
                        path: "/file".into(),
                        reference: None,
                    },
                    &ShareRequest {
                        kind: ShareKind::Link,
                        role: "reader".into(),
                        recipient: None,
                        expires_at: None,
                    },
                    true,
                    &CancellationToken::new(),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), peer.blocked.notified())
            .await
            .unwrap();
        operation.abort();
        assert!(operation.await.is_err_and(|e| e.is_cancelled()));
        tokio::time::timeout(Duration::from_secs(6), store.finish_cleanup())
            .await
            .unwrap();
        assert_eq!(peer.deleted.load(Ordering::SeqCst), 1);
        server.abort();
        let _ = server.await;
    }
}

#[cfg(test)]
mod timezone_transition_tests {
    use super::*;
    #[test]
    fn local_expiry_matches_kotlin_for_gaps_and_overlaps() {
        for (local, expected) in [
            ("2026-03-08T02:30:00", "2026-03-08T07:30:00Z"),
            ("2026-11-01T01:30:00", "2026-11-01T05:30:00Z"),
        ] {
            let local = NaiveDateTime::parse_from_str(local, "%Y-%m-%dT%H:%M:%S").unwrap();
            let expected = DateTime::parse_from_rfc3339(expected)
                .unwrap()
                .timestamp_millis();
            assert_eq!(
                local_millis(local, chrono_tz::America::New_York).unwrap(),
                expected
            );
        }
    }
}
