//! Host-only SEC-J01..J12 cross-domain contract probes.
//! These do NOT establish native interleavings or security acceptance.
use super::{device, file, memory, network, process, syscall, Error};

fn request() -> process::Request {
    process::Request { id: 1, caller: 7, group: 2, package: [5;32], cpu: 1 }
}
fn permit(draining: u64) -> process::VerifiedSpawn {
    process::VerifiedSpawn::from_registry(7,2,[5;32],0b1110,0b1110,draining,0)
}
fn tls() -> network::ReadOnlyEcho {
    network::VerifiedTls::from_native_tls(
        [3;32], network::TLS13, network::TLS_AES_128_GCM_SHA256, false, false,
    ).read_only_echo(&[3;32]).unwrap()
}
fn read_op(tag:u64)->syscall::ReadOperation {
    syscall::ReadOperation {op:syscall::FILE_STAT_BY_CAP,flags:0,capability:7,generation:2,tag}
}
#[test] fn j01_spawn_drain_and_tlb_ack_is_not_free() {
    let mut tasks=process::SpawnLedger::<1>::new();
    assert_eq!(tasks.admit(request(),permit(1<<1)),Err(Error::Unauthorized));
    let mut shot=memory::Shootdown::begin(1,1,1<<1,0,0,0).unwrap();
    shot.revoke_pte();
    assert!(!shot.may_reuse());
}
#[test] fn j02_exit_copyin_and_unmap_keep_original_receipt() {
    let mut tasks=process::SpawnLedger::<1>::new();
    let t=tasks.admit(request(),permit(0)).unwrap();
    tasks.publish_runnable(t,permit(0)).unwrap();
    tasks.hold_ref(t).unwrap();
    tasks.begin_exit(t,1<<1,0).unwrap();
    assert_eq!(syscall::user_copy_span(u64::MAX,2,1,u64::MAX,128),Err(Error::Invalid));
    assert_eq!(tasks.mark_reapable(t),Err(Error::Busy));
}
#[test] fn j03_exit_does_not_cancel_unknown_fsync() {
    let mut fs=file::DurableReceipts::<1>::new();
    fs.submit(1,[3;32]).unwrap();
    fs.uncertain(1).unwrap();
    let mut tasks=process::SpawnLedger::<1>::new();
    let t=tasks.admit(request(),permit(0)).unwrap();
    tasks.begin_exit(t,0,0).unwrap();
    tasks.mark_reapable(t).unwrap();
    assert_eq!(fs.state(1),Ok(file::Stage::Unknown));
}
#[test] fn j04_memory_pressure_never_releases_unknown_device_dma() {
    let mut queue=device::Queue::<1>::new(1,1);
    let token=queue.prepare(9,1,1,true).unwrap();
    queue.publish(token).unwrap(); queue.timeout(token).unwrap();
    let mut retire=memory::Shootdown::begin(1,1,0,0,1,1).unwrap();
    retire.revoke_pte();
    assert!(!retire.may_reuse());
    assert!(queue.has_inflight());
}
#[test] fn j05_fsync_unknown_and_device_reset_need_independent_proofs() {
    let mut fs=file::DurableReceipts::<1>::new();
    fs.submit(1,[1;32]).unwrap();fs.uncertain(1).unwrap();
    assert_eq!(fs.acknowledge_fsync(1),Err(Error::Unknown));
    let mut q=device::Queue::<1>::new(1,1);
    q.prepare(1,1,1,true).unwrap();
    assert_eq!(
        q.reset(device::ReliableReset::from_driver(1,1,false,false,false)),
        Err(Error::Unknown)
    );
}
#[test] fn j06_handshake_flood_cannot_change_memory_owner() {
    let mut net=network::RateLimiter::new();
    for ip in 1..=4 {net.request_handshake(ip,0,16).unwrap();}
    assert_eq!(net.request_handshake(5,0,16),Err(Error::Capacity));
    let f=memory::Frame {
        owner:7,generation:1,kind:memory::FrameKind::User,
        zeroed:true,writable_alias:false,executable_alias:false
    };
    let data=memory::Permissions {read:true,write:true,execute:false};
    assert_eq!(memory::authorize_mapping(f,8,data,None),Err(Error::Unauthorized));
}
#[test] fn j07_irq_change_cannot_route_to_draining_core() {
    assert_eq!(
        device::validate_irq_route(device::IrqKind::VirtioSpi,1,1,0b1110,1<<1,0,true),
        Err(Error::Unauthorized)
    );
    let mut tasks=process::SpawnLedger::<1>::new();
    assert_eq!(tasks.admit(request(),permit(1<<1)),Err(Error::Unauthorized));
}
#[test] fn j08_network_batch_does_not_hold_lonely_virtqueue_request() {
    assert_eq!(device::must_notify(1,8,50_000,false),Ok(true));
    let mut packet=[0u8;16];
    packet[0]=1;packet[2]=1;
    assert_eq!(network::parse_read_only_echo(tls(),&packet).unwrap().payload.len(),0);
}
#[test] fn j09_invalid_readonly_vector_is_rejected_before_file_access() {
    let items=[read_op(1),syscall::ReadOperation {op:99,..read_op(2)}];
    assert_eq!(syscall::validate_vector(&items),Err(Error::Invalid));
    let cap=file::FileCapability::from_registry(7,2,1,file::READ);
    assert_eq!(cap.permits(7,2,1,file::WRITE),Err(Error::Unauthorized));
}
#[test] fn j10_ai_advice_cannot_become_publish_right() {
    let ai=syscall::ProtectedRole::from_kernel(1,1);
    let publisher=syscall::ProtectedRole::from_kernel(2,1);
    assert_eq!(syscall::can_publish(ai,publisher),Err(Error::Unauthorized));
    let denied=memory::Frame {
        owner:7,generation:1,kind:memory::FrameKind::Control,
        zeroed:true,writable_alias:false,executable_alias:false
    };
    let data=memory::Permissions {read:true,write:false,execute:false};
    assert_eq!(memory::authorize_mapping(denied,7,data,None),Err(Error::Unauthorized));
}
#[test] fn j11_readonly_service_restart_leaves_old_dma_inflight() {
    let mut packet=[0u8;16];packet[0]=1;packet[2]=1;
    network::parse_read_only_echo(tls(),&packet).unwrap();
    let mut q=device::Queue::<1>::new(1,1);
    let t=q.prepare(1,1,1,true).unwrap();
    q.publish(t).unwrap();q.timeout(t).unwrap();
    assert!(q.has_inflight());
}
#[test] fn j12_failed_boot_epoch_does_not_grant_new_publish_right() {
    let ordinary=file::FileCapability::from_registry(7,0,1,file::READ);
    assert_eq!(ordinary.protected_store(7),Err(Error::Unauthorized));
    let ai=syscall::ProtectedRole::from_kernel(1,1);
    let publisher=syscall::ProtectedRole::from_kernel(2,1);
    assert_eq!(syscall::can_publish(ai,publisher),Err(Error::Unauthorized));
}

#[test]
fn v019_j11_network_logical_close_does_not_erase_unknown_device_custody() {
    // Host cross-domain bookkeeper probe, not an EL1 DMA-stop witness.
    let mut network=network::RateLimiter::new();
    network.request_handshake(7,0,4).unwrap();
    network.finish_handshake(7,true).unwrap();
    let mut dma=device::Queue::<1>::new(1,1);
    let token=dma.prepare(17,1,1,true).unwrap();
    dma.publish(token).unwrap();
    dma.timeout(token).unwrap();
    network.close_active_from(7).unwrap();
    assert_eq!(network.active(),0);
    assert!(dma.has_inflight());
    assert_eq!(dma.state(token),Ok(device::State::Unknown));
    // A logical connection close never constitutes driver quiesce+reconcile.
    assert_eq!(
        dma.reset(device::ReliableReset::from_driver(1,1,true,false,false)),
        Err(Error::Unknown),
    );
}
