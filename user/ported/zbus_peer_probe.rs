//! Real zbus socket-pair server/client handshake, using COSMIC's original limits.
use std::time::Duration;
use zbus::{connection::Builder, Guid};
use std::os::fd::{AsRawFd, FromRawFd};

struct Peer;

#[zbus::interface(name = "com.system76.NotificationsSocket")]
impl Peer {
    fn probe(&self, value: u32) -> u32 { value + 1 }
}

async fn exercise() -> Result<(), Box<dyn std::error::Error>> {
    let (server, client) = std::os::unix::net::UnixStream::pair()?;
    server.set_nonblocking(true)?;
    client.set_nonblocking(true)?;
    let server = tokio::net::UnixStream::from_std(server)?;
    let client = tokio::net::UnixStream::from_std(client)?;
    let server = Builder::socket(server).p2p().server(Guid::generate())?
        .serve_at("/com/system76/NotificationsSocket", Peer)?.build();
    let client = Builder::socket(client).p2p().build();
    let (server, client) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(1), server),
        tokio::time::timeout(Duration::from_secs(5), client),
    );
    let server = server??;
    let client = client??;
    println!("ZBUS_PEER_PROBE HANDSHAKE PASS");
    let reply = tokio::time::timeout(Duration::from_secs(1), client.call_method(
        None::<&str>, "/com/system76/NotificationsSocket",
        Some("com.system76.NotificationsSocket"), "Probe", &(41u32,),
    )).await??;
    let value: u32 = reply.body().deserialize()?;
    if value != 42 { return Err("wrong actual peer reply".into()); }
    println!("ZBUS_PEER_PROBE ROUNDTRIP PASS");
    drop(client);
    drop(server);
    Ok(())
}

async fn cross_process() -> Result<(), Box<dyn std::error::Error>> {
    let (server, client) = std::os::unix::net::UnixStream::pair()?;
    let argv: Vec<std::ffi::CString> = ["/bin/zbus-peer-probe", "--client"]
        .into_iter().map(|s| std::ffi::CString::new(s).unwrap()).collect();
    let pointers = [argv[0].as_ptr(), argv[1].as_ptr(), std::ptr::null()];
    let environment = [std::ptr::null::<libc::c_char>()];
    #[repr(C)]
    struct Request { size: u32, flags: u32, path: *const libc::c_char,
        argv: *const *const libc::c_char, envp: *const *const libc::c_char,
        cwd: *const libc::c_char, maps: *const [i32; 2], count: u32, reserved: u32, reserved2: u64 }
    let maps = [[0, 0], [1, 1], [2, 2], [client.as_raw_fd(), 3]];
    let request = Request { size: 64, flags: 0, path: argv[0].as_ptr(), argv: pointers.as_ptr(),
        envp: environment.as_ptr(), cwd: std::ptr::null(), maps: maps.as_ptr(), count: 4,
        reserved: 0, reserved2: 0 };
    let pid = unsafe { libc::syscall(0x43595810, &request) };
    if pid < 0 { return Err(std::io::Error::last_os_error().into()); }
    drop(client);
    server.set_nonblocking(true)?;
    let server = tokio::net::UnixStream::from_std(server)?;
    let connection = tokio::time::timeout(Duration::from_secs(1),
        Builder::socket(server).p2p().server(Guid::generate())?
            .serve_at("/com/system76/NotificationsSocket", Peer)?.build()).await??;
    // Keep the real zbus executor running while the child awaits its reply.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
            if waited < 0 { return Err(std::io::Error::last_os_error()); }
            if waited == pid as i32 {
                return if status == 0 { Ok(()) } else { Err(std::io::Error::other(format!("child status {status}"))) };
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await??;
    drop(connection);
    println!("ZBUS_PEER_PROBE INHERITED_FD PASS");
    Ok(())
}

async fn child() -> Result<(), Box<dyn std::error::Error>> {
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    socket.set_nonblocking(true)?;
    let connection = tokio::time::timeout(Duration::from_secs(5),
        Builder::socket(tokio::net::UnixStream::from_std(socket)?).p2p().build()).await??;
    let reply = connection.call_method(None::<&str>, "/com/system76/NotificationsSocket",
        Some("com.system76.NotificationsSocket"), "Probe", &(41u32,)).await?;
    if reply.body().deserialize::<u32>()? != 42 { return Err("cross-process reply".into()); }
    Ok(())
}

fn main() {
    println!("ZBUS_PEER_PROBE START");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let client = std::env::args().nth(1).as_deref() == Some("--client");
    let result = runtime.block_on(async {
        if client { child().await } else { exercise().await?; cross_process().await }
    });
    if let Err(error) = result {
        println!("ZBUS_PEER_PROBE FAIL {error:?}");
        std::process::exit(1);
    }
    if !client { println!("ZBUS_PEER_PROBE PASS"); }
}
