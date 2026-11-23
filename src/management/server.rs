mod assets;
mod connection;
mod http;
mod websocket;

pub use assets::has_web_index;
pub use connection::{Connection, serve};
pub use http::router;

use crate::{
    management::{
        reply::Reply,
        security::SecurityPolicy,
        session::{MAX_SESSIONS, REQUEST_LIMIT, Session},
    },
    runtime::{
        access::{Access, Credentials, Feature},
        config::Config,
    },
    storage::files::FilePolicy,
};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::timeout;

pub struct App {
    pub config: Config,
    pub policy: SecurityPolicy,
    pub files: Arc<FilePolicy>,
    pub identity: crate::network::tls::Identity,
    pub storage: Arc<crate::storage::accounts::Storage>,
    socket_slots: Arc<tokio::sync::Semaphore>,
    credentials: Credentials,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}
impl App {
    pub fn new(mut config: Config, credentials: Credentials) -> Result<Arc<Self>> {
        let hosts = if_addrs::get_if_addrs()?
            .into_iter()
            .map(|i| i.ip().to_string())
            .collect::<Vec<_>>();
        let policy = config.settings.policy(hosts)?;
        config.data_dir = crate::runtime::config::canonical_path(&config.data_dir)?;
        let desktop = crate::runtime::instance_lock::desktop_data_dir()?;
        let desktop = crate::runtime::config::canonical_path(&desktop).unwrap_or(desktop);
        let private = vec![config.data_dir.clone(), desktop];
        let identity = crate::network::tls::Identity::load(&config.data_dir)?;
        let storage = crate::storage::accounts::Storage::load(&config.data_dir)?;
        Ok(Arc::new(Self {
            identity,
            storage,
            socket_slots: Arc::new(tokio::sync::Semaphore::new(256)),
            files: Arc::new(FilePolicy { private }),
            config,
            policy,
            credentials,
            sessions: Mutex::new(HashMap::new()),
        }))
    }
    fn create_session(&self, access: Access) -> Result<Arc<Session>> {
        self.reap();
        let mut sessions = self.sessions.lock().unwrap();
        ensure!(sessions.len() < MAX_SESSIONS, "session capacity reached");
        let session = Session::with_access(&self.config.data_dir, access)?;
        session.own(session.cache.clone())?;
        sessions.insert(session.token.clone(), session.clone());
        Ok(session)
    }
    fn session(&self, token: &str, touch: bool) -> Option<Arc<Session>> {
        let mut sessions = self.sessions.lock().unwrap();
        let s = sessions.get(token)?.clone();
        if s.expired() {
            sessions.remove(token);
            s.close();
            return None;
        }
        if touch {
            s.touch();
        }
        Some(s)
    }
    pub fn release(&self, token: &str) {
        if let Some(s) = self.sessions.lock().unwrap().remove(token) {
            s.close();
        }
    }
    fn reap(&self) {
        self.sessions.lock().unwrap().retain(|_, s| {
            if s.expired() {
                s.close();
                false
            } else {
                true
            }
        });
    }
    pub async fn close(&self) {
        let sessions = self
            .sessions
            .lock()
            .unwrap()
            .drain()
            .map(|(_, s)| s)
            .collect::<Vec<_>>();
        for session in sessions {
            session.close_wait().await;
            let _ = timeout(
                Duration::from_secs(5),
                session.operations.acquire_many(REQUEST_LIMIT as u32),
            )
            .await;
        }
        self.storage.finish_cleanup().await;
    }
    pub async fn operation(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        session: Arc<Session>,
        allows_credentials: bool,
    ) -> Reply {
        let group = path
            .strip_prefix("/api/web-ui/platform/")
            .unwrap_or_default()
            .split(['/', '?'])
            .next()
            .unwrap_or_default();
        let required = match group {
            "http" => Some(Feature::OutboundHttp),
            "networks" | "storage" => Some(Feature::Storage),
            "devices" => Some(Feature::Devices),
            "files" | "listeners" | "compression" | "resources" => None,
            _ if session.access.directories().is_some() => {
                return Reply::error(403, "permission_denied", "operation is not authorized");
            }
            _ => None,
        };
        if required.is_some_and(|feature| !session.access.allows(feature)) {
            return Reply::error(403, "permission_denied", "feature is not authorized");
        }
        let Ok(permit) = session.operations.clone().try_acquire_owned() else {
            return Reply::error(429, "capacity", "management request capacity reached");
        };
        if path.split('?').next().is_some_and(|p| {
            p == "/api/web-ui/platform/compression"
                || p == "/api/web-ui/platform/compression/finish"
        }) {
            let _permit = permit;
            return tokio::select! {
                _=session.cancel.cancelled()=>Reply::error(401,"unauthorized","session expired"),
                r=crate::management::compression::handle(method,path,body,&session)=>r.unwrap_or_else(Reply::from_error),
            };
        }
        if path.starts_with("/api/web-ui/platform/http/") {
            let _permit = permit;
            return tokio::select! {
                _=session.cancel.cancelled()=>Reply::error(401,"unauthorized","session expired"),
                result=crate::network::outbound_http::handle(method,path,body,&session)=>result.unwrap_or_else(Reply::from_error),
            };
        }
        if path == "/api/web-ui/platform/networks"
            || path.starts_with("/api/web-ui/platform/networks/")
            || path.starts_with("/api/web-ui/platform/networks?")
        {
            let _permit = permit;
            return tokio::select! {
                _=session.cancel.cancelled()=>Reply::error(401,"unauthorized","session expired"),
                result=crate::storage::remote::handle(Some(&self.storage),method,path,body,&session)=>result.unwrap_or_else(Reply::from_error),
            };
        }
        if path.starts_with("/api/web-ui/platform/storage/content/") {
            let _permit = permit;
            return tokio::select! {
                _=session.cancel.cancelled()=>Reply::error(401,"unauthorized","session expired"),
                result=crate::storage::remote::content::handle(method,path,body,&session,&self.storage,
                    crate::storage::remote::content::Host{cache_root:self.config.data_dir.join("content-transfers"),files:self.files.clone()},allows_credentials)=>result.unwrap_or_else(Reply::from_error),
            };
        }
        if path.starts_with("/api/web-ui/platform/storage/") {
            let _permit = permit;
            return tokio::select! {
                _=session.cancel.cancelled()=>Reply::error(401,"unauthorized","session expired"),
                result=crate::storage::accounts::handle(method,path,body,&session,&self.storage)=>result.unwrap_or_else(Reply::from_error),
            };
        }
        #[cfg(not(feature = "pro"))]
        if path.starts_with("/api/web-ui/platform/devices/official-signaling/") {
            return Reply::error(404, "not_found", "official signaling is unavailable");
        }
        #[cfg(feature = "pro")]
        if let Some(path) = path.strip_prefix("/api/web-ui/platform/devices/official-signaling/") {
            if !allows_credentials {
                return Reply::error(
                    403,
                    "forbidden",
                    "official signaling requires HTTPS or loopback",
                );
            }
            let (operation, query) = path.split_once('?').unwrap_or((path, ""));
            let _permit = permit;
            return tokio::select! {
                _ = session.cancel.cancelled() => Reply::error(401, "unauthorized", "session expired"),
                result = crate::network::peer::official_signaling::handle(method, operation, query, &body, &session) => result.unwrap_or_else(Reply::from_error),
            };
        }
        if path.starts_with("/api/web-ui/platform/devices/") {
            let _permit = permit;
            return tokio::select! {
                _=session.cancel.cancelled()=>Reply::error(401,"unauthorized","session expired"),
                result=crate::network::peer::devices::handle(method,path,body,&session,&self.identity,self.files.clone())=>result.unwrap_or_else(Reply::from_error),
            };
        }
        if method == "DELETE" && path.split('?').next() == Some("/api/web-ui/platform/resources") {
            let id = url::form_urlencoded::parse(
                path.split_once('?')
                    .map(|(_, q)| q)
                    .unwrap_or("")
                    .as_bytes(),
            )
            .find(|(name, _)| name == "handle")
            .map(|(_, value)| value.into_owned());
            if let Some(id) = id {
                session.release_wait(&id).await;
                return Reply::json(true);
            }
            return Reply::error(400, "invalid_argument", "invalid platform request");
        }
        if path == "/api/web-ui/platform/listeners"
            || path.starts_with("/api/web-ui/platform/listeners/")
            || path.starts_with("/api/web-ui/platform/listeners?")
        {
            let _permit = permit;
            return tokio::select! {
                _=session.cancel.cancelled()=>Reply::error(401,"unauthorized","session expired"),
                result=crate::network::listeners::handle(method,path,body,&session,&self.identity,self.files.clone())=>result.unwrap_or_else(Reply::from_error),
            };
        }
        let files = self.files.clone();
        let method = method.to_string();
        let path = path.to_string();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            files.handle(&method, &path, &body, &session)
        })
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("platform worker stopped")))
        .unwrap_or_else(Reply::from_error)
    }
    fn host_info(&self, s: &Session) -> serde_json::Value {
        let scoped = s.access.directories().is_some();
        let roots = self.files.roots_for(s);
        let (home, app) = if scoped {
            let home = roots[0]["path"]
                .as_str()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| s.cache.clone());
            (home.clone(), home)
        } else {
            (
                dirs::home_dir().unwrap_or_default(),
                std::env::current_dir().unwrap_or_default(),
            )
        };
        let mut sensitive_paths: Vec<_> = if scoped {
            Vec::new()
        } else {
            self.files.private.iter().map(|p| {
                json!({"path":p,"sensitivity":"critical","category":"application_private_data","descendants":true})
            }).collect()
        };
        // The browser selects the most specific rule. FilePolicy enforces the same session boundary.
        sensitive_paths
            .push(json!({"path":s.cache,"sensitivity":"none","category":"","descendants":true}));
        #[cfg(feature = "pro")]
        let signaling_gateway = crate::network::peer::official_signaling::GATEWAY;
        #[cfg(not(feature = "pro"))]
        let signaling_gateway = "";
        json!({"separator":std::path::MAIN_SEPARATOR_STR,"home":home,
            "cache":s.cache,"app":app,"roots":roots,
            "interfaces":interfaces(),"fingerprint":self.identity.fingerprint,"publicKey":self.identity.public_key,"compressionCodecs":[0,1],
            "deviceCertificatePem":self.identity.certificate_pem,
            "officialSignalingGateway":signaling_gateway,
            "caseInsensitive":cfg!(any(windows,target_os="macos")),
            "sensitivePaths":sensitive_paths,
            "deviceId":self.identity.device_id,"deviceName":std::env::var("HOSTNAME").unwrap_or_else(|_|crate::runtime::config::DISPLAY_NAME.to_owned())})
    }
}

pub fn interfaces() -> serde_json::Value {
    let mut grouped: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();
    for i in if_addrs::get_if_addrs().unwrap_or_default() {
        grouped.entry(i.name.clone()).or_default().push(
            json!({"address":i.ip().to_string(),"isIPv6":i.ip().is_ipv6(),"prefixLength":null}),
        );
    }
    json!(grouped.into_iter().map(|(name,addresses)|json!({"name":name,"displayName":name,"isUp":true,
        "isLoopback":addresses.iter().all(|a|a["address"].as_str().and_then(|s|s.parse::<std::net::IpAddr>().ok()).is_some_and(|ip|ip.is_loopback())),"addresses":addresses})).collect::<Vec<_>>())
}
