use super::App;
use crate::management::{
    reply::Reply,
    session::{LEASE, REQUEST_LIMIT, Session},
    wire::{self, Packet},
};
use anyhow::{Result, ensure};
use axum::extract::ws::{Message, WebSocket};
use serde_json::json;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    task::JoinSet,
    time::{interval, timeout},
};

async fn receive(ws: &mut WebSocket) -> Result<Packet> {
    loop {
        match ws.recv().await {
            Some(Ok(Message::Binary(b))) => return Packet::decode(&b),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => anyhow::bail!("binary management message required"),
        }
    }
}
async fn send(ws: &mut WebSocket, p: Packet) -> Result<()> {
    timeout(LEASE, ws.send(Message::Binary(p.encode()?.into()))).await??;
    Ok(())
}
pub(super) async fn socket(app: Arc<App>, mut ws: WebSocket, allows_credentials: bool) {
    let auth = timeout(Duration::from_secs(5), receive(&mut ws)).await;
    let Ok(Ok(auth)) = auth else { return };
    if auth.header.kind != "auth"
        || !auth.body.is_empty()
        || auth.header.version != wire::VERSION
        || !(1..=256).contains(&auth.header.token.len())
    {
        return;
    }
    let Some(session) = app.session(&auth.header.token, false) else {
        return;
    };
    if session.attach().is_err() {
        return;
    }
    let _ = serve_socket(&app, &session, &mut ws, allows_credentials).await;
    app.release(&session.token);
}
async fn serve_socket(
    app: &Arc<App>,
    s: &Arc<Session>,
    ws: &mut WebSocket,
    allows_credentials: bool,
) -> Result<()> {
    let mut ready = Packet::new("authenticated");
    ready.header.status = 200;
    send(ws, ready).await?;
    let mut jobs: JoinSet<(i64, Reply)> = JoinSet::new();
    let mut tasks: HashMap<i64, tokio::task::AbortHandle> = HashMap::new();
    let mut last_id = 0i64;
    let mut timer = interval(Duration::from_secs(20));
    timer.tick().await;
    let result=async {
        loop {
            tokio::select! {
                _=s.cancel.cancelled()=>break,
                _=timer.tick()=>{
                    ensure!(app.session(&s.token,false).is_some(),"session expired");
                    send(ws,Packet::new("heartbeat")).await?;
                    ws.send(Message::Ping(vec![].into())).await?;
                },
                event=s.next_event()=>{
                    let e=event?;
                    let mut p=Packet::new("event");p.header.id=e.id;p.header.handle=e.handle;p.header.event_type=e.kind;p.header.requires_reply=e.reply;p.body=e.body;send(ws,p).await?;
                },
                done=jobs.join_next(),if !jobs.is_empty()=>{
                    if let Some(Err(ref e))=done {
                        tasks.retain(|_,handle|handle.id()!=e.id());
                    }
                    if let Some(Ok((id,response)))=done {
                        let mut p=Packet::new("response");p.header.id=id;p.header.status=response.status;p.header.headers=response.headers;p.body=response.body;
                        send(ws,p).await?;tasks.remove(&id);
                    }
                },
                packet=receive(ws)=>{
                    let packet=packet?;ensure!(app.session(&s.token,false).is_some(),"session expired");
                    let h=packet.header;
                    match h.kind.as_str() {
                        "heartbeat"=>s.heartbeat(),
                        "reply"|"reply-failed"=>s.reply(h.id,packet.body,h.kind=="reply-failed")?,
                        "cancel"=>{if let Some(task)=tasks.get(&h.id){task.abort();}},
                        "request"=>{
                            ensure!(h.id>last_id,"management request id invalid");last_id=h.id;
                            if tasks.len()>=REQUEST_LIMIT {
                                let mut p=Packet::new("response");p.header.id=h.id;p.header.status=429;
                                p.body=serde_json::to_vec(&json!({"code":"capacity","error":"management request capacity reached"}))?;send(ws,p).await?;continue;
                            }
                            ensure!(matches!(h.method.as_str(),"GET"|"POST"|"PUT"|"DELETE")&&wire::is_command_route(&h.method,&h.path),"invalid command route");
                            let app=app.clone();let s=s.clone();let id=h.id;s.touch();
                            let task=jobs.spawn(async move{let response=app.operation(&h.method,&h.path,packet.body,s,allows_credentials).await;(id,response)});
                            tasks.insert(id,task);
                        },
                        _=>anyhow::bail!("unexpected management message"),
                    }
                }
            }
        }
        Ok(())
    }.await;
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    result
}
