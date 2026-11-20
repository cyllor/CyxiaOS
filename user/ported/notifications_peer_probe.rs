//! Includes the genuine notifications applet module; no replacement protocol.
use std::{
    io::Write,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};
use zbus::{Connection, connection::Builder};

mod subscriptions {
    pub mod notifications {
        #[derive(Debug)]
        pub enum Input {
            AppletConn(zbus::Connection),
            AppletActivated {
                id: u32,
                action: cosmic_notifications_util::ActionId,
            },
        }
    }
    pub mod applet {
        include!(env!("CYXIA_APPLET_SOURCE"));
    }
}
use subscriptions::{applet, notifications::Input};

fn active_seconds() -> u64 {
    option_env!("CYXIA_PEER_ACTIVE_SECONDS")
        .unwrap_or("1")
        .parse()
        .unwrap()
}

async fn client(socket: std::os::unix::net::UnixStream) -> anyhow::Result<Connection> {
    socket.set_nonblocking(true)?;
    Ok(tokio::time::timeout(
        Duration::from_secs(5),
        Builder::socket(tokio::net::UnixStream::from_std(socket)?)
            .p2p()
            .build(),
    )
    .await??)
}

async fn delayed_peer(full: bool) -> anyhow::Result<()> {
    let (server, peer) = std::os::unix::net::UnixStream::pair()?;
    // Each case is sequential on a single-thread runtime, before spawning tasks.
    unsafe {
        std::env::set_var("DAEMON_NOTIFICATIONS_FD", server.as_raw_fd().to_string());
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    let serving = tokio::spawn(applet::setup_panel_conn(tx));
    let connecting = tokio::spawn(async move {
        // Always exceed the selected active deadline, so changing that deadline
        // alone cannot hide a premature timeout while waiting for startup.
        tokio::time::sleep(Duration::from_secs(active_seconds() + 3)).await;
        client(peer).await
    });
    let server_conn = serving.await??;
    let peer_conn = connecting.await??;
    println!("NOTIFICATIONS_PEER_PROBE DELAYED_HANDSHAKE PASS");
    if !full {
        return Ok(());
    }
    let reply = peer_conn
        .call_method(
            None::<&str>,
            "/com/system76/NotificationsSocket",
            Some("com.system76.NotificationsSocket"),
            "GetFd",
            &(),
        )
        .await?;
    let fd: zbus::zvariant::OwnedFd = reply.body().deserialize()?;
    let socket = std::os::unix::net::UnixStream::from(std::os::fd::OwnedFd::from(fd));
    let applet_conn = client(socket).await?;
    let Input::AppletConn(notification_conn) =
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("no real applet connection"))?
    else {
        anyhow::bail!("wrong notification input");
    };
    println!("NOTIFICATIONS_PEER_PROBE SCM_RIGHTS PASS");
    applet_conn
        .call_method(
            None::<&str>,
            "/com/system76/NotificationsApplet",
            Some("com.system76.NotificationsApplet"),
            "InvokeAction",
            &(41u32, "default"),
        )
        .await?;
    match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await? {
        Some(Input::AppletActivated {
            id: 41,
            action: cosmic_notifications_util::ActionId::Default,
        }) => {}
        other => anyhow::bail!("wrong real action {other:?}"),
    }
    println!("NOTIFICATIONS_PEER_PROBE ACTION PASS");
    drop((
        notification_conn,
        applet_conn,
        peer_conn,
        server_conn,
        server,
    ));
    Ok(())
}

fn fd_count() -> usize {
    (0..64)
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
        .count()
}

#[cfg(not(peer_original))]
async fn idle_cancel() -> anyhow::Result<()> {
    let (server, peer) = std::os::unix::net::UnixStream::pair()?;
    unsafe {
        std::env::set_var("DAEMON_NOTIFICATIONS_FD", server.as_raw_fd().to_string());
    }
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let before = fd_count();
    let task = applet::PanelTask::spawn(tx);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    anyhow::ensure!(
        fd_count() == before + 1,
        "idle peer did not retain exactly one owned FD"
    );
    drop(task);
    tokio::time::timeout(Duration::from_secs(1), async {
        while fd_count() != before {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    drop((server, peer));
    println!("NOTIFICATIONS_PEER_PROBE IDLE_CANCEL PASS");
    Ok(())
}

async fn active_timeout() -> anyhow::Result<()> {
    let (server, mut peer) = std::os::unix::net::UnixStream::pair()?;
    unsafe {
        std::env::set_var("DAEMON_NOTIFICATIONS_FD", server.as_raw_fd().to_string());
    }
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let serving = tokio::spawn(applet::setup_panel_conn(tx));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let started = Instant::now();
    peer.write_all(b"\0AUTH")?; // Real, deliberately incomplete authentication.
    let result = tokio::time::timeout(Duration::from_secs(active_seconds() + 1), serving).await??;
    let error = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("stalled authentication succeeded"))?;
    anyhow::ensure!(
        error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some(),
        "wrong timeout {error}"
    );
    anyhow::ensure!(
        started.elapsed() >= Duration::from_millis(active_seconds() * 1000 - 100),
        "active deadline shortened"
    );
    println!("NOTIFICATIONS_PEER_PROBE ACTIVE_TIMEOUT PASS");
    drop((server, peer));
    Ok(())
}

async fn peer_closed() -> anyhow::Result<()> {
    let (server, peer) = std::os::unix::net::UnixStream::pair()?;
    unsafe {
        std::env::set_var("DAEMON_NOTIFICATIONS_FD", server.as_raw_fd().to_string());
    }
    drop(peer);
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let result = tokio::time::timeout(Duration::from_secs(1), applet::setup_panel_conn(tx)).await?;
    anyhow::ensure!(result.is_err(), "closed peer was accepted");
    println!("NOTIFICATIONS_PEER_PROBE PEER_CLOSED PASS");
    Ok(())
}

fn main() {
    println!("NOTIFICATIONS_PEER_PROBE START");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let full = std::env::args().nth(1).as_deref() != Some("handshake");
    if let Err(error) = runtime.block_on(async {
        #[cfg(not(peer_original))]
        idle_cancel().await?;
        active_timeout().await?;
        peer_closed().await?;
        delayed_peer(full).await
    }) {
        println!("NOTIFICATIONS_PEER_PROBE FAIL {error:?}");
        std::process::exit(1);
    }
    println!("NOTIFICATIONS_PEER_PROBE PASS");
}
