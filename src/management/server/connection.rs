use super::{App, router};
use anyhow::Result;
use axum::extract::Extension;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    task::JoinSet,
    time::{interval, timeout},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Connection {
    pub remote: std::net::IpAddr,
    pub scheme: &'static str,
}

pub async fn serve(listener: TcpListener, app: Arc<App>, cancel: CancellationToken) -> Result<()> {
    let tls = tokio_rustls::TlsAcceptor::from(app.identity.server.clone());
    let router = router(app.clone());
    let slots = Arc::new(tokio::sync::Semaphore::new(256));
    let mut jobs = JoinSet::new();
    let mut reaper = interval(Duration::from_secs(5));
    let result = loop {
        tokio::select! {
            _=cancel.cancelled()=>break Ok(()),
            _=reaper.tick()=>app.reap(),
            _=jobs.join_next(),if !jobs.is_empty()=>{},
            accepted=listener.accept()=>{
                let (stream,peer)=match accepted {
                    Ok(peer) => peer,
                    Err(error) => break Err(error.into()),
                };
                let Ok(permit)=slots.clone().try_acquire_owned()else{drop(stream);continue;};
                let tls=tls.clone();let router=router.clone();
                jobs.spawn(async move {
                    let _permit=permit;
                    let mut byte=[0;1];if !matches!(timeout(Duration::from_secs(5),stream.peek(&mut byte)).await,Ok(Ok(1))){return;}
                    let https=byte[0]==22;
                    if https {
                        if let Ok(Ok(stream))=timeout(Duration::from_secs(5),tls.accept(stream)).await {
                            let service=TowerToHyperService::new(router.layer(Extension(Connection{scheme:"https",remote:peer.ip()})));
                            let _=hyper::server::conn::http1::Builder::new().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_headers(64).serve_connection(TokioIo::new(stream),service).with_upgrades().await;
                        }
                    }else{
                        let service=TowerToHyperService::new(router.layer(Extension(Connection{scheme:"http",remote:peer.ip()})));
                        let _=hyper::server::conn::http1::Builder::new().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_headers(64).serve_connection(TokioIo::new(stream),service).with_upgrades().await;
                    }
                });
            }
        }
    };
    app.close().await;
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}
