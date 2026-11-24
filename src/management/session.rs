use crate::runtime::{
    access::Access,
    config::{private_directory, random_id},
};
use anyhow::{Result, ensure};
use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

type CallbackReceiver = oneshot::Receiver<Result<Vec<u8>>>;

pub const MAX_SESSIONS: usize = 16;
pub const RESOURCE_LIMIT: usize = 64;
pub const EVENT_LIMIT: usize = 32;
pub const REQUEST_LIMIT: usize = 32;
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);
pub const LEASE: Duration = Duration::from_secs(60);
pub struct Event {
    pub id: i64,
    pub handle: String,
    pub kind: String,
    pub body: Vec<u8>,
    pub reply: bool,
}
struct Resource {
    value: Arc<dyn Any + Send + Sync>,
    close: Option<Box<dyn FnOnce() + Send + Sync>>,
    wait: Option<tokio::task::JoinHandle<()>>,
    abort_task: bool,
}
impl Resource {
    fn shutdown(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        if self.abort_task {
            if let Some(task) = &self.wait {
                task.abort();
            }
        }
        if let Some(close) = self.close.take() {
            close();
        }
        self.wait.take()
    }
}
impl Drop for Resource {
    fn drop(&mut self) {
        self.shutdown();
    }
}
struct ReplyGuard<'a> {
    session: &'a Session,
    id: i64,
}
impl Drop for ReplyGuard<'_> {
    fn drop(&mut self) {
        self.session.inner.lock().unwrap().replies.remove(&self.id);
    }
}
struct Inner {
    resources: HashMap<String, Resource>,
    replies: HashMap<i64, oneshot::Sender<Result<Vec<u8>>>>,
    last_access: Instant,
    last_heartbeat: Instant,
    attached: bool,
    next_event: i64,
    latest: VecDeque<Event>,
}
impl Inner {
    fn expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_access) >= IDLE_TIMEOUT
            || now.saturating_duration_since(self.last_heartbeat) >= LEASE
    }
}
pub struct Session {
    pub token: String,
    pub cache: PathBuf,
    pub(crate) access: Access,
    inner: Mutex<Inner>,
    pub cancel: CancellationToken,
    pub operations: Arc<tokio::sync::Semaphore>,
    events: mpsc::Sender<Event>,
    pub receiver: tokio::sync::Mutex<mpsc::Receiver<Event>>,
    signal: tokio::sync::Notify,
}
impl Session {
    pub fn new(root: &Path) -> Result<Arc<Self>> {
        Self::with_access(root, Access::Full)
    }

    pub(crate) fn with_access(root: &Path, access: Access) -> Result<Arc<Self>> {
        let root = crate::runtime::config::canonical_path(root)?;
        let token = random_id(16);
        let cache = root.join("sessions").join(&token);
        private_directory(&cache)?;
        let (events, receiver) = mpsc::channel(EVENT_LIMIT);
        let now = Instant::now();
        Ok(Arc::new(Self {
            token,
            cache,
            access,
            inner: Mutex::new(Inner {
                resources: HashMap::new(),
                replies: HashMap::new(),
                last_access: now,
                last_heartbeat: now,
                attached: false,
                next_event: 0,
                latest: VecDeque::new(),
            }),
            cancel: CancellationToken::new(),
            operations: Arc::new(tokio::sync::Semaphore::new(REQUEST_LIMIT)),
            events,
            receiver: tokio::sync::Mutex::new(receiver),
            signal: tokio::sync::Notify::new(),
        }))
    }
    pub fn expired(&self) -> bool {
        let i = self.inner.lock().unwrap();
        self.cancel.is_cancelled() || i.expired_at(Instant::now())
    }
    pub fn touch(&self) {
        self.inner.lock().unwrap().last_access = Instant::now();
    }
    pub fn heartbeat(&self) {
        self.inner.lock().unwrap().last_heartbeat = Instant::now();
    }
    pub fn attach(&self) -> Result<()> {
        let mut i = self.inner.lock().unwrap();
        ensure!(
            !self.cancel.is_cancelled() && !i.attached,
            "management connection already attached"
        );
        i.attached = true;
        i.last_heartbeat = Instant::now();
        Ok(())
    }
    pub fn own<T: Any + Send + Sync>(&self, value: T) -> Result<String> {
        self.own_with_close(value, || {})
    }
    pub fn own_with_close<T: Any + Send + Sync>(
        &self,
        value: T,
        close: impl FnOnce() + Send + Sync + 'static,
    ) -> Result<String> {
        self.insert_resource(value, close, None, true)
    }
    pub fn own_with_wait<T: Any + Send + Sync>(
        &self,
        value: T,
        close: impl FnOnce() + Send + Sync + 'static,
        task: tokio::task::JoinHandle<()>,
    ) -> Result<String> {
        self.insert_resource(value, close, Some(task), true)
    }
    /// The close callback must wake the task, which completes its bounded cleanup before returning.
    pub fn own_with_cleanup<T: Any + Send + Sync>(
        &self,
        value: T,
        close: impl FnOnce() + Send + Sync + 'static,
        task: tokio::task::JoinHandle<()>,
    ) -> Result<String> {
        self.insert_resource(value, close, Some(task), false)
    }
    fn insert_resource<T: Any + Send + Sync>(
        &self,
        value: T,
        close: impl FnOnce() + Send + Sync + 'static,
        wait: Option<tokio::task::JoinHandle<()>>,
        abort_task: bool,
    ) -> Result<String> {
        let resource = Resource {
            value: Arc::new(value),
            close: Some(Box::new(close)),
            wait,
            abort_task,
        };
        let mut inner = self.inner.lock().unwrap();
        ensure!(
            !self.cancel.is_cancelled(),
            crate::management::reply::ResourceUnavailable("session closed")
        );
        ensure!(
            inner.resources.len() < RESOURCE_LIMIT,
            crate::management::reply::ResourceUnavailable("platform resource capacity reached")
        );
        let id = random_id(16);
        inner.resources.insert(id.clone(), resource);
        Ok(id)
    }
    pub fn resource<T: Any + Send + Sync>(&self, id: &str) -> Result<Arc<T>> {
        self.resource_value(id)?
            .downcast()
            .map_err(|_| anyhow::anyhow!("unknown session resource"))
    }
    pub(crate) fn resource_value(&self, id: &str) -> Result<Arc<dyn Any + Send + Sync>> {
        let i = self.inner.lock().unwrap();
        ensure!(
            !self.cancel.is_cancelled(),
            crate::management::reply::ResourceUnavailable("session closed")
        );
        i.resources
            .get(id)
            .map(|r| r.value.clone())
            .ok_or_else(|| anyhow::anyhow!("unknown session resource"))
    }
    pub fn release(&self, id: &str) {
        let resource = { self.inner.lock().unwrap().resources.remove(id) };
        drop(resource);
    }
    pub async fn release_wait(&self, id: &str) {
        let resource = { self.inner.lock().unwrap().resources.remove(id) };
        if let Some(mut resource) = resource {
            let task = resource.shutdown();
            drop(resource);
            if let Some(task) = task {
                let _ = task.await;
            }
        }
    }
    fn close_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        self.cancel.cancel();
        let mut inner = self.inner.lock().unwrap();
        inner.replies.clear();
        inner.latest.clear();
        let resources = std::mem::take(&mut inner.resources);
        drop(inner);
        resources
            .into_values()
            .filter_map(|mut resource| resource.shutdown())
            .collect()
    }
    pub fn close(&self) {
        self.close_tasks();
    }
    pub async fn close_wait(&self) {
        for task in self.close_tasks() {
            let _ = task.await;
        }
    }
    pub fn emit(
        &self,
        handle: &str,
        kind: &str,
        body: Vec<u8>,
        reply: bool,
    ) -> Result<Option<CallbackReceiver>> {
        Ok(self.publish(handle, kind, body, reply)?.1)
    }
    fn publish(
        &self,
        handle: &str,
        kind: &str,
        body: Vec<u8>,
        reply: bool,
    ) -> Result<(i64, Option<CallbackReceiver>)> {
        ensure!(
            body.len() <= crate::management::wire::BODY_LIMIT,
            "platform event too large"
        );
        let (tx, rx) = oneshot::channel();
        let mut i = self.inner.lock().unwrap();
        ensure!(
            !self.cancel.is_cancelled(),
            crate::management::reply::ResourceUnavailable("session closed")
        );
        i.next_event += 1;
        let id = i.next_event;
        if i.replies.len() >= EVENT_LIMIT
            || self
                .events
                .try_send(Event {
                    id,
                    handle: handle.into(),
                    kind: kind.into(),
                    body,
                    reply,
                })
                .is_err()
        {
            drop(i);
            self.close();
            anyhow::bail!("platform event queue overflow; resources released");
        }
        self.signal.notify_one();
        if reply {
            i.replies.insert(id, tx);
            Ok((id, Some(rx)))
        } else {
            Ok((id, None))
        }
    }
    pub async fn next_event(&self) -> Result<Event> {
        let mut receiver = self.receiver.lock().await;
        loop {
            ensure!(
                !self.cancel.is_cancelled(),
                crate::management::reply::ResourceUnavailable("session closed")
            );
            if let Ok(event) = receiver.try_recv() {
                return Ok(event);
            }
            if let Some(event) = self.inner.lock().unwrap().latest.pop_front() {
                return Ok(event);
            }
            tokio::select! {
                _=self.cancel.cancelled()=>return Err(crate::management::reply::ResourceUnavailable("session closed").into()),
                _=self.signal.notified()=>{},
            }
        }
    }
    pub fn emit_latest(
        &self,
        handle: &str,
        kind: &str,
        body: Vec<u8>,
        complete: bool,
    ) -> Result<()> {
        ensure!(
            body.len() <= crate::management::wire::BODY_LIMIT,
            "platform event too large"
        );
        let mut inner = self.inner.lock().unwrap();
        ensure!(
            !self.cancel.is_cancelled(),
            crate::management::reply::ResourceUnavailable("session closed")
        );
        let position = inner.latest.iter().position(|event| event.handle == handle);
        if complete {
            if let Some(position) = position {
                inner.latest.remove(position);
            }
            drop(inner);
            self.emit(handle, kind, body, false)?;
            return Ok(());
        }
        ensure!(
            position.is_some() || inner.latest.len() < RESOURCE_LIMIT,
            "latest event capacity reached"
        );
        inner.next_event += 1;
        let event = Event {
            id: inner.next_event,
            handle: handle.into(),
            kind: kind.into(),
            body,
            reply: false,
        };
        if let Some(position) = position {
            inner.latest[position] = event;
        } else {
            inner.latest.push_back(event);
        }
        self.signal.notify_one();
        Ok(())
    }
    pub async fn callback(&self, handle: &str, kind: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let (id, receiver) = self.publish(handle, kind, body, true)?;
        let _guard = ReplyGuard { session: self, id };
        tokio::select! {
            _=self.cancel.cancelled()=>anyhow::bail!("session closed"),
            value=receiver.unwrap()=>value?,
        }
    }
    pub fn reply(&self, id: i64, body: Vec<u8>, failed: bool) -> Result<()> {
        ensure!(
            body.len() <= crate::management::wire::BODY_LIMIT,
            "reply too large"
        );
        let sender = self
            .inner
            .lock()
            .unwrap()
            .replies
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("callback expired or already answered"))?;
        let _ = sender.send(if failed {
            Err(anyhow::anyhow!("browser callback failed"))
        } else {
            Ok(body)
        });
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.close();
        let _ = std::fs::remove_dir_all(&self.cache);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resource_ownership_capacity_and_release() {
        let root = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let a = Session::new(root.path()).unwrap();
        let b = Session::new(root.path()).unwrap();
        let id = a.own(42u32).unwrap();
        assert_eq!(*a.resource::<u32>(&id).unwrap(), 42);
        assert!(b.resource::<u32>(&id).is_err());
        for _ in 1..RESOURCE_LIMIT {
            a.own(0u32).unwrap();
        }
        assert_eq!(
            crate::management::reply::Reply::from_error(a.own(0u32).unwrap_err()).status,
            409
        );
        a.release(&id);
        assert!(a.resource::<u32>(&id).is_err());
        a.close();
        assert!(a.own(0u32).is_err());
    }
    #[test]
    fn event_overflow_closes_session() {
        let root = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let a = Session::new(root.path()).unwrap();
        for _ in 0..EVENT_LIMIT {
            a.emit("h", "e", vec![], false).unwrap();
        }
        assert!(a.emit("h", "e", vec![], false).is_err());
        assert!(a.cancel.is_cancelled());
    }
    #[test]
    fn lease_idle_expiry_and_callback_identity() {
        let root = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let s = Session::new(root.path()).unwrap();
        {
            let mut inner = s.inner.lock().unwrap();
            // Advance the observation time to stay within Windows' clock range.
            let start = inner.last_access;
            let tick = Duration::from_nanos(1);
            assert!(!inner.expired_at(start + (LEASE - tick)));
            assert!(inner.expired_at(start + LEASE));

            inner.last_heartbeat = start + (IDLE_TIMEOUT - LEASE / 2);
            assert!(!inner.expired_at(start + (IDLE_TIMEOUT - tick)));
            assert!(inner.expired_at(start + IDLE_TIMEOUT));
        }
        s.heartbeat();
        s.touch();
        assert!(!s.expired());
        assert!(s.reply(999, vec![], false).is_err());
        let reply = s
            .emit("callback", "approval", vec![], true)
            .unwrap()
            .unwrap();
        s.reply(1, b"true".to_vec(), false).unwrap();
        assert!(s.reply(1, vec![], false).is_err());
        assert_eq!(reply.blocking_recv().unwrap().unwrap(), b"true");
    }
    #[test]
    fn close_runs_once_even_while_a_resource_is_borrowed() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let root = tempfile::tempdir().unwrap();
        let s = Session::new(root.path()).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let closed = count.clone();
        let id = s
            .own_with_close(7u32, move || {
                closed.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
        let borrowed = s.resource::<u32>(&id).unwrap();
        s.release(&id);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(*borrowed, 7);
        s.close();
        drop(borrowed);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod latest_tests {
    use super::*;
    #[tokio::test]
    async fn progress_is_conflated_and_completion_has_priority() {
        let root = tempfile::tempdir().unwrap();
        let s = Session::new(root.path()).unwrap();
        for i in 0..1000 {
            s.emit_latest(
                "progress",
                "device-progress",
                i.to_string().into_bytes(),
                false,
            )
            .unwrap();
        }
        s.emit("approval", "http-request", b"normal".to_vec(), false)
            .unwrap();
        assert_eq!(s.next_event().await.unwrap().body, b"normal");
        assert_eq!(s.next_event().await.unwrap().body, b"999");
        s.emit_latest("progress", "device-progress", b"old".to_vec(), false)
            .unwrap();
        s.emit_latest("progress", "device-progress", b"complete".to_vec(), true)
            .unwrap();
        assert_eq!(s.next_event().await.unwrap().body, b"complete");
        assert!(s.inner.lock().unwrap().latest.is_empty());
        assert!(!s.cancel.is_cancelled());
    }
}
