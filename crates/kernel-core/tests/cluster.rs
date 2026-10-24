//! Host protocol tests. TestCrypto is intentionally NOT production cryptography.
//! A separate OpenSSL-backed test exercises actual SHA-256 and Ed25519. Neither
//! host process is a formal CyxiaOS cluster member or a native-guest witness.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]
use cyxia_kernel_core::{
    cluster::{
        self,
        auth::*,
        contracts::{self, Ledger, Stage},
        endpoint::*,
        health,
        membership::*,
        replication,
        storage::*,
        tasks, wire, *,
    },
    control_plane::{self as cp, cores, policy},
};
use std::collections::BTreeMap;
fn node(n: u8) -> NodeId {
    NodeId([n; 32])
}
fn id(n: u8) -> ObjectId {
    ObjectId([n; 16])
}
fn inc(n: u8) -> Incarnation {
    Incarnation {
        node: node(n),
        boot: 1,
    }
}
fn test_hash(data: &[u8]) -> Digest {
    let mut a = [0u8; 32];
    for (i, b) in data.iter().enumerate() {
        let j = i % 32;
        a[j] = a[j]
            .wrapping_mul(31)
            .wrapping_add(*b)
            .wrapping_add((i as u8).rotate_left(3));
    }
    a[0] ^= 0x91;
    a
}
#[derive(Clone, Copy)]
struct TestCrypto;
impl TestCrypto {
    fn sign(&self, key: NodeId, msg: &[u8]) -> Signature {
        let mut v = key.0.to_vec();
        v.extend_from_slice(msg);
        let h = test_hash(&v);
        let mut out = [0; 64];
        out[..32].copy_from_slice(&h);
        v.push(0x43);
        out[32..].copy_from_slice(&test_hash(&v));
        out
    }
}
impl Crypto for TestCrypto {
    fn sha256(&self, data: &[u8]) -> Digest {
        test_hash(data)
    }
    fn verify(&self, key: NodeId, msg: &[u8], sig: &Signature) -> bool {
        self.sign(key, msg) == *sig
    }
    fn authorize_native(&self, c: &NativeClaims) -> bool {
        c.measurement == [42; 32]
    }
}
#[derive(Clone, Copy, Debug)]
enum Fail {
    Before,
    After,
}
#[derive(Clone, Default)]
struct Disk {
    records: BTreeMap<Key, (u64, Vec<u8>)>,
    fail: Option<Fail>,
    writes: usize,
}
impl Store for Disk {
    fn load(&mut self, k: Key, out: &mut [u8]) -> std::result::Result<Option<Stored>, StoreError> {
        let Some((revision, data)) = self.records.get(&k) else {
            return Ok(None);
        };
        if data.len() > out.len() {
            return Err(StoreError::Corrupt);
        }
        out[..data.len()].copy_from_slice(data);
        Ok(Some(Stored {
            revision: *revision,
            len: data.len(),
        }))
    }
    fn replace(
        &mut self,
        k: Key,
        expected: u64,
        next: u64,
        data: &[u8],
    ) -> std::result::Result<(), StoreError> {
        let fail = self.fail.take();
        if matches!(fail, Some(Fail::Before)) {
            return Err(StoreError::Io);
        }
        let old = self.records.get(&k).map_or(0, |r| r.0);
        if old != expected || expected.checked_add(1) != Some(next) {
            return Err(StoreError::Conflict);
        }
        self.records.insert(k, (next, data.to_vec()));
        self.writes += 1;
        if matches!(fail, Some(Fail::After)) {
            Err(StoreError::Io)
        } else {
            Ok(())
        }
    }
}
fn claims(n: u8) -> NativeClaims {
    NativeClaims {
        identity: inc(n),
        os: CYXIA_OS,
        protocol: PROTOCOL,
        abi: 1,
        isa: 1,
        measurement: [42; 32],
        failure_domain: id(n),
        control_physical: 2,
        business_physical: 1,
        features: REQUIRED_FEATURES,
    }
}
fn peer(c: NativeClaims) -> Peer {
    let crypto = TestCrypto;
    let mut ch = Challenge::new(node(9), [c.identity.node.0[0]; 32], 0, 10).unwrap();
    let sig = crypto.sign(c.identity.node, ch.signing_bytes(c).unwrap().as_slice());
    ch.authenticate(&crypto, c, &sig, 1).unwrap()
}
fn peers() -> [Peer; 2] {
    [peer(claims(1)), peer(claims(2))]
}
fn config(ps: [Peer; 2], epoch: u64) -> Config {
    Config::new(
        &TestCrypto,
        id(9),
        epoch,
        ps,
        [[11; 32], [22; 32]],
        [33; 32],
    )
    .unwrap()
}
fn signs(cfg: Config, b: &Bytes) -> [Signature; 2] {
    cfg.members()
        .map(|m| TestCrypto.sign(m.identity.node, b.as_slice()))
}
struct Formation {
    a: Membership,
    b: Membership,
    da: Disk,
    db: Disk,
    cfg: Config,
    ps: [Peer; 2],
}
impl Formation {
    fn prepared() -> Self {
        let ps = peers();
        let cfg = config(ps, 1);
        let mut da = Disk::default();
        let mut db = Disk::default();
        let mut a = Membership::open(&mut da, &TestCrypto, inc(1)).unwrap();
        let mut b = Membership::open(&mut db, &TestCrypto, inc(2)).unwrap();
        a.prepare(&mut da, cfg, ps).unwrap();
        b.prepare(&mut db, cfg, ps).unwrap();
        Self {
            a,
            b,
            da,
            db,
            cfg,
            ps,
        }
    }
    fn prove(&mut self) {
        let sig = signs(self.cfg, &confirm_bytes(self.cfg).unwrap());
        self.a.prove(&mut self.da, &TestCrypto, sig).unwrap();
        self.b.prove(&mut self.db, &TestCrypto, sig).unwrap();
    }
    fn activate(&mut self, epoch: u64) {
        let a = self
            .a
            .begin_activation(&mut self.da, &TestCrypto, epoch)
            .unwrap();
        let b = self
            .b
            .begin_activation(&mut self.db, &TestCrypto, epoch)
            .unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        let votes = signs(self.cfg, &a);
        let a = self
            .a
            .commit_activation(&mut self.da, &TestCrypto, votes)
            .unwrap();
        let b = self
            .b
            .commit_activation(&mut self.db, &TestCrypto, votes)
            .unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        let acks = signs(self.cfg, &a);
        self.a.enable(&mut self.da, &TestCrypto, acks).unwrap();
        self.b.enable(&mut self.db, &TestCrypto, acks).unwrap();
    }
    fn active() -> Self {
        let mut f = Self::prepared();
        f.prove();
        f.activate(1);
        f
    }
}
fn policy_env(now: u64) -> policy::Environment {
    policy::Environment {
        epochs: cp::Epochs {
            boot: 1,
            controller: 1,
            model: 1,
            resources: 1,
            cores: 1,
        },
        cores: cores::Snapshot {
            generation: 1,
            control: 2,
            business: 1,
            transition: 0,
            quarantined: 0,
            online: 3,
            phase: cores::Phase::Stable,
        },
        now,
        limits: policy::Limits {
            max_units: 1000,
            max_budget_ticks: 1000,
            max_lifetime: 200,
            allowed_cpus: 3,
        },
    }
}
fn subject() -> cp::Identity {
    cp::Identity {
        id: 8,
        generation: 1,
    }
}
fn bank() -> policy::Bank<3> {
    let env = policy_env(1);
    let publisher = cp::Identity {
        id: 99,
        generation: 1,
    };
    let mut b = policy::Bank::new(publisher, env.epochs).unwrap();
    for domain in 0..3 {
        b.accept(
            publisher,
            1,
            policy::Proposal {
                epochs: env.epochs,
                subject: subject(),
                domain,
                sequence: 1,
                valid_from: 1,
                expires_at: 100,
                plane: cp::Plane::Business,
                cpus: 1,
                units: 100,
                budget_ticks: 100,
            },
            env,
        )
        .unwrap();
    }
    b
}
fn capacity() -> Quota {
    Quota {
        cpu_ticks: 100,
        memory_pages: 100,
        io_units: 100,
    }
}
fn request() -> contracts::Request {
    contracts::Request {
        id: id(10),
        resource: id(20),
        consumer: inc(2),
        subject: subject(),
        quota: Quota {
            cpu_ticks: 10,
            memory_pages: 20,
            io_units: 5,
        },
        isa: 1,
        abi: 1,
        reservation_until: 50,
        lease_until: 120,
    }
}
struct World {
    f: Formation,
    bank: policy::Bank<3>,
    ledger: Ledger<4>,
    endpoint: Endpoint<4>,
    q: contracts::Request,
}
impl World {
    fn reserved() -> Self {
        let mut f = Formation::active();
        let bank = bank();
        let mut ledger = Ledger::open(&mut f.da, inc(1), capacity(), 200).unwrap();
        let endpoint = Endpoint::open(&mut f.da, inc(1), id(20)).unwrap();
        let q = request();
        let ad = admission::Admission::new(&bank, subject(), [0, 1, 2], 0);
        ledger
            .prepare(&mut f.da, &f.a.active().unwrap(), q, &ad, policy_env(2))
            .unwrap();
        Self {
            f,
            bank,
            ledger,
            endpoint,
            q,
        }
    }
    fn granted() -> Self {
        let mut w = Self::reserved();
        let a = w.f.a.active().unwrap();
        let intent = w.ledger.begin_grant(&mut w.f.da, &a, w.q.id, 3).unwrap();
        w.endpoint.install(&mut w.f.da, &intent, &a, 3).unwrap();
        w.ledger
            .commit_grant(&mut w.f.da, &a, w.q.id, &w.endpoint, 3)
            .unwrap();
        w
    }
    fn token(&self) -> contracts::LeaseToken {
        self.ledger
            .execution(self.q.id, &self.endpoint, &self.f.a.active().unwrap(), 4)
            .unwrap()
            .0
    }
}
struct Drain(bool);
impl DrainBackend for Drain {
    fn drained(&mut self, _: contracts::LeaseToken) -> bool {
        self.0
    }
}
#[derive(Default)]
struct Exec {
    launches: usize,
    answer: Option<tasks::LaunchError>,
    observed: Option<tasks::Observation>,
}
impl tasks::Executor for Exec {
    fn launch(
        &mut self,
        _: tasks::Request,
        _: contracts::LeaseToken,
    ) -> std::result::Result<(), tasks::LaunchError> {
        self.launches += 1;
        self.answer.map_or(Ok(()), Err)
    }
    fn reconcile(&mut self, _: tasks::Request, _: contracts::LeaseToken) -> tasks::Observation {
        self.observed.unwrap_or(tasks::Observation::Unknown)
    }
}
fn task() -> tasks::Request {
    tasks::Request {
        task: id(60),
        activation: 1,
        operation: id(61),
        contract: id(10),
        payload_digest: [62; 32],
        isa: 1,
        abi: 1,
    }
}
fn outcome() -> tasks::Outcome {
    tasks::Outcome {
        code: 0,
        digest: [63; 32],
    }
}
fn prepared_task(w: &mut World) -> tasks::Book<4> {
    let mut b = tasks::Book::open(&mut w.f.da, node(1)).unwrap();
    b.prepare(
        &mut w.f.da,
        task(),
        &w.ledger,
        &w.endpoint,
        &w.f.a.active().unwrap(),
        4,
    )
    .unwrap();
    b
}
fn start_task(
    b: &mut tasks::Book<4>,
    w: &mut World,
    e: &mut Exec,
    now: u64,
) -> Result<tasks::Status> {
    b.start(
        &mut w.f.da,
        task().task,
        1,
        &w.ledger,
        &mut w.endpoint,
        &w.f.a.active().unwrap(),
        now,
        e,
    )
}

#[test]
fn native_proxy_and_single_physical_core_are_rejected() {
    for mutation in 0..6 {
        let mut c = claims(1);
        match mutation {
            0 => c.os = 0,
            1 => c.control_physical = 0,
            2 => c.business_physical = 0,
            3 => c.business_physical = 2,
            4 => c.features = 0,
            _ => c.features |= 16,
        };
        let mut ch = Challenge::new(node(2), [7; 32], 0, 10).unwrap();
        assert_eq!(
            ch.authenticate(&TestCrypto, c, &[0; 64], 1).unwrap_err(),
            Error::NativeRequired
        );
    }
}
#[test]
fn native_measurement_requires_trust_even_with_valid_signature() {
    let mut c = claims(1);
    c.measurement = [99; 32];
    let mut ch = Challenge::new(node(2), [7; 32], 0, 10).unwrap();
    let sig = TestCrypto.sign(node(1), ch.signing_bytes(c).unwrap().as_slice());
    assert_eq!(
        ch.authenticate(&TestCrypto, c, &sig, 1).unwrap_err(),
        Error::Authentication
    );
}
#[test]
fn identity_challenge_replay_and_deadline_do_not_grant_membership() {
    let c = claims(1);
    let mut ch = Challenge::new(node(2), [7; 32], 1, 10).unwrap();
    let sig = TestCrypto.sign(node(1), ch.signing_bytes(c).unwrap().as_slice());
    assert_eq!(
        ch.authenticate(&TestCrypto, c, &sig, 0).unwrap_err(),
        Error::Clock
    );
    ch.authenticate(&TestCrypto, c, &sig, 2).unwrap();
    assert_eq!(
        ch.authenticate(&TestCrypto, c, &sig, 3).unwrap_err(),
        Error::Replay
    );
    let mut other = Challenge::new(node(3), [7; 32], 0, 10).unwrap();
    assert_eq!(
        other.authenticate(&TestCrypto, c, &sig, 2).unwrap_err(),
        Error::Authentication
    );
    assert_eq!(
        other.authenticate(&TestCrypto, c, &sig, 10).unwrap_err(),
        Error::Expired
    );
}
#[test]
fn canonical_formation_is_peer_order_independent() {
    let p = peers();
    let a = config(p, 1);
    let b = Config::new(
        &TestCrypto,
        id(9),
        1,
        [p[1], p[0]],
        [[22; 32], [11; 32]],
        [33; 32],
    )
    .unwrap();
    assert_eq!(a, b);
    assert_ne!(a.digest(), config(p, 2).digest());
}
#[test]
fn prepared_and_commit_proof_do_not_activate_shared_authority() {
    let mut f = Formation::prepared();
    assert!(f.a.active().is_err());
    f.prove();
    assert_eq!(f.a.phase(), Some(Phase::Proved));
    assert!(f.a.active().is_err());
}
#[test]
fn both_durable_active_acknowledgements_are_required() {
    let mut f = Formation::prepared();
    f.prove();
    let bytes = f.a.begin_activation(&mut f.da, &TestCrypto, 1).unwrap();
    f.b.begin_activation(&mut f.db, &TestCrypto, 1).unwrap();
    let votes = signs(f.cfg, &bytes);
    let ack =
        f.a.commit_activation(&mut f.da, &TestCrypto, votes)
            .unwrap();
    assert!(f.a.active().is_err());
    let mut incomplete = signs(f.cfg, &ack);
    incomplete[1] = [0; 64];
    assert_eq!(
        f.a.enable(&mut f.da, &TestCrypto, incomplete),
        Err(Error::Authentication)
    );
    f.b.commit_activation(&mut f.db, &TestCrypto, votes)
        .unwrap();
    f.a.enable(&mut f.da, &TestCrypto, signs(f.cfg, &ack))
        .unwrap();
    assert!(f.a.active().is_ok());
}
#[test]
fn duplicated_prepare_and_proof_do_not_write_or_change_cluster() {
    let mut f = Formation::prepared();
    let count = f.da.writes;
    f.a.prepare(&mut f.da, f.cfg, f.ps).unwrap();
    assert_eq!(f.da.writes, count);
    f.prove();
    let count = f.da.writes;
    f.a.prove(
        &mut f.da,
        &TestCrypto,
        signs(f.cfg, &confirm_bytes(f.cfg).unwrap()),
    )
    .unwrap();
    assert_eq!(f.da.writes, count);
}
#[test]
fn conflicting_cluster_and_old_boot_cannot_reconfigure() {
    let mut f = Formation::active();
    f.a.isolate(&mut f.da).unwrap();
    let bad = Config::new(&TestCrypto, id(8), 2, f.ps, [[11; 32], [22; 32]], [33; 32]).unwrap();
    assert!(f.a.prepare(&mut f.da, bad, f.ps).is_err());
    assert_eq!(f.a.config(), Some(f.cfg));
}
#[test]
fn membership_store_failure_is_fail_closed_even_if_write_landed() {
    for fail in [Fail::Before, Fail::After] {
        let mut f = Formation::prepared();
        f.da.fail = Some(fail);
        let sig = signs(f.cfg, &confirm_bytes(f.cfg).unwrap());
        assert_eq!(f.a.prove(&mut f.da, &TestCrypto, sig), Err(Error::Storage));
        assert!(f.a.active().is_err());
        assert_eq!(
            f.a.prove(&mut f.da, &TestCrypto, sig),
            Err(Error::Reconcile)
        );
        let a = Membership::open(&mut f.da, &TestCrypto, inc(1)).unwrap();
        assert!(a.active().is_err());
    }
}
#[test]
fn restart_cannot_replay_active_acknowledgements() {
    let mut f = Formation::active();
    let mut restored = Membership::open(&mut f.da, &TestCrypto, inc(1)).unwrap();
    restored.prepare(&mut f.da, f.cfg, f.ps).unwrap();
    assert_eq!(
        restored.begin_activation(&mut f.da, &TestCrypto, 1).err(),
        Some(Error::Stale)
    );
    assert!(restored.active().is_err());
    restored
        .begin_activation(&mut f.da, &TestCrypto, 2)
        .unwrap();
}
#[test]
fn partition_preserves_cluster_identity_and_requires_new_activation() {
    let mut f = Formation::active();
    f.a.isolate(&mut f.da).unwrap();
    assert!(f.a.active().is_err());
    assert_eq!(f.a.config(), Some(f.cfg));
    f.a.prepare(&mut f.da, f.cfg, f.ps).unwrap();
    assert_eq!(
        f.a.begin_activation(&mut f.da, &TestCrypto, 1).err(),
        Some(Error::Stale)
    );
    f.b.isolate(&mut f.db).unwrap();
    f.b.prepare(&mut f.db, f.cfg, f.ps).unwrap();
    f.activate(2);
    assert_eq!(f.a.active().unwrap().scope().activation_epoch, 2);
}
#[test]
fn reboot_rejoin_requires_both_new_config_signatures() {
    let mut f = Formation::active();
    let mut a = Membership::open(
        &mut f.da,
        &TestCrypto,
        Incarnation {
            node: node(1),
            boot: 2,
        },
    )
    .unwrap();
    assert!(a.prepare(&mut f.da, f.cfg, f.ps).is_err());
    let mut c = claims(1);
    c.identity.boot = 2;
    let ps = [peer(c), peer(claims(2))];
    let new = config(ps, 2);
    let b = a.prepare(&mut f.da, new, ps).unwrap();
    let mut bad = signs(new, &b);
    bad[1] = signs(f.cfg, &confirm_bytes(f.cfg).unwrap())[1];
    assert_eq!(
        a.prove(&mut f.da, &TestCrypto, bad),
        Err(Error::Authentication)
    );
    assert_eq!(a.config().unwrap().cluster(), f.cfg.cluster());
}
#[test]
fn durable_boot_epoch_advances_after_lost_ack() {
    let mut d = Disk::default();
    assert_eq!(cluster::boot::next(&mut d, node(1)).unwrap().boot, 1);
    d.fail = Some(Fail::After);
    assert_eq!(cluster::boot::next(&mut d, node(1)), Err(Error::Storage));
    assert_eq!(cluster::boot::next(&mut d, node(1)).unwrap().boot, 3);
}
#[test]
fn boot_epoch_never_wraps() {
    let mut d = Disk::default();
    cluster::boot::next(&mut d, node(1)).unwrap();
    let key = Key {
        kind: 7,
        id: node(1).0,
    };
    let b = &mut d.records.get_mut(&key).unwrap().1;
    let n = b.len();
    b[n - 8..].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(cluster::boot::next(&mut d, node(1)), Err(Error::Exhausted));
}

#[test]
fn quote_reservation_and_intent_do_not_grant_execution() {
    let mut w = World::reserved();
    let a = w.f.a.active().unwrap();
    assert!(w.ledger.execution(w.q.id, &w.endpoint, &a, 3).is_err());
    let intent = w.ledger.begin_grant(&mut w.f.da, &a, w.q.id, 3).unwrap();
    assert_eq!(w.ledger.status(w.q.id).unwrap(), Stage::GrantIntent);
    assert!(
        w.ledger
            .commit_grant(&mut w.f.da, &a, w.q.id, &w.endpoint, 3)
            .is_err()
    );
    w.endpoint.install(&mut w.f.da, &intent, &a, 3).unwrap();
    w.ledger
        .commit_grant(&mut w.f.da, &a, w.q.id, &w.endpoint, 3)
        .unwrap();
}
#[test]
fn local_policy_and_actual_capacity_are_both_required() {
    let mut w = World::reserved();
    w.bank.revoke(1).unwrap();
    let ad = admission::Admission::new(&w.bank, subject(), [0, 1, 2], 0);
    let mut q = w.q;
    q.id = id(11);
    q.resource = id(21);
    assert_eq!(
        w.ledger
            .prepare(&mut w.f.da, &w.f.a.active().unwrap(), q, &ad, policy_env(3)),
        Err(Error::Policy)
    );
    let b = bank();
    let ad = admission::Admission::new(&b, subject(), [0, 1, 2], 0);
    q.quota.memory_pages = 90;
    assert_eq!(
        w.ledger
            .prepare(&mut w.f.da, &w.f.a.active().unwrap(), q, &ad, policy_env(4)),
        Err(Error::Capacity)
    );
}
#[test]
fn policy_domains_cannot_be_counted_twice() {
    let b = bank();
    let a = admission::Admission::new(&b, subject(), [0, 0, 0], 0);
    assert_eq!(a.check(capacity(), policy_env(2)), Err(Error::Invalid));
}
#[test]
fn duplicate_contract_id_neither_reserves_twice_nor_changes_payload() {
    let mut w = World::reserved();
    let used = w.ledger.used().unwrap();
    let count = w.f.da.writes;
    let ad = admission::Admission::new(&w.bank, subject(), [0, 1, 2], 0);
    assert_eq!(
        w.ledger.prepare(
            &mut w.f.da,
            &w.f.a.active().unwrap(),
            w.q,
            &ad,
            policy_env(3)
        ),
        Ok(Stage::Reserved)
    );
    assert_eq!(w.ledger.used().unwrap(), used);
    assert_eq!(w.f.da.writes, count);
    let mut changed = w.q;
    changed.quota.io_units += 1;
    assert_eq!(
        w.ledger.prepare(
            &mut w.f.da,
            &w.f.a.active().unwrap(),
            changed,
            &ad,
            policy_env(4)
        ),
        Err(Error::Conflict)
    );
}
#[test]
fn wrong_isa_and_abi_are_not_transparent_migration() {
    let mut w = World::reserved();
    let ad = admission::Admission::new(&w.bank, subject(), [0, 1, 2], 0);
    for n in [1, 2] {
        let mut q = w.q;
        q.id = id(11);
        q.resource = id(21);
        if n == 1 {
            q.isa = 2;
        } else {
            q.abi = 2;
        }
        assert_eq!(
            w.ledger
                .prepare(&mut w.f.da, &w.f.a.active().unwrap(), q, &ad, policy_env(3)),
            Err(Error::Unsupported)
        );
    }
}
#[test]
fn expired_reservation_cannot_commit() {
    let mut w = World::reserved();
    assert_eq!(
        w.ledger
            .begin_grant(&mut w.f.da, &w.f.a.active().unwrap(), w.q.id, 50)
            .err(),
        Some(Error::Expired)
    );
    assert_eq!(w.ledger.expire_reservations(&mut w.f.da, 50), Ok(1));
    assert_eq!(w.ledger.used().unwrap(), Quota::default());
}
#[test]
fn committed_capacity_is_not_freed_by_lease_or_policy_expiry() {
    let mut w = World::granted();
    w.bank.revoke(0).unwrap();
    assert!(
        w.ledger
            .execution(w.q.id, &w.endpoint, &w.f.a.active().unwrap(), 110)
            .is_ok()
    );
    assert_eq!(w.ledger.expire_reservations(&mut w.f.da, 130), Ok(0));
    assert_eq!(w.ledger.used().unwrap(), w.q.quota);
    assert_eq!(
        w.ledger
            .execution(w.q.id, &w.endpoint, &w.f.a.active().unwrap(), 130)
            .err(),
        Some(Error::Expired)
    );
}
#[test]
fn fence_exact_match_rejects_larger_uninstalled_tokens_and_wrong_actor() {
    let w = World::granted();
    let t = w.token();
    let mut forged = t;
    forged.serial += 1;
    assert_eq!(
        w.endpoint
            .check(forged, &w.f.a.active().unwrap(), inc(2), 4),
        Err(Error::Stale)
    );
    assert_eq!(
        w.endpoint.check(t, &w.f.a.active().unwrap(), inc(1), 4),
        Err(Error::WrongOwner)
    );
}
#[test]
fn in_flight_operation_blocks_reclamation_and_unfenceable_target_is_refused() {
    let mut w = World::granted();
    let t = w.token();
    let p = w
        .endpoint
        .begin(t, &w.f.a.active().unwrap(), inc(2), 4)
        .unwrap();
    w.endpoint.revoke(&mut w.f.da, t).unwrap();
    assert_eq!(
        w.endpoint.drain(&mut w.f.da, &mut Drain(true)).err(),
        Some(Error::Busy)
    );
    w.endpoint.finish(p).unwrap();
    assert_eq!(
        w.endpoint.drain(&mut w.f.da, &mut Drain(false)).err(),
        Some(Error::Unsupported)
    );
    let proof = w.endpoint.drain(&mut w.f.da, &mut Drain(true)).unwrap();
    w.ledger.release(&mut w.f.da, proof, 5).unwrap();
    assert_eq!(w.ledger.used().unwrap(), Quota::default());
}
#[test]
fn resource_release_survives_partition_and_model_loss() {
    let mut w = World::granted();
    let t = w.token();
    w.f.a.isolate(&mut w.f.da).unwrap();
    w.bank.revoke(0).unwrap();
    w.ledger.mark_revoking(&mut w.f.da, w.q.id, 4).unwrap();
    w.endpoint.revoke(&mut w.f.da, t).unwrap();
    let proof = w.endpoint.drain(&mut w.f.da, &mut Drain(true)).unwrap();
    w.ledger.release(&mut w.f.da, proof, 5).unwrap();
    assert_eq!(w.ledger.status(w.q.id), Ok(Stage::Released));
}
#[test]
fn restored_endpoint_never_resurrects_old_lease() {
    let mut w = World::granted();
    let t = w.token();
    let mut restored = Endpoint::<4>::open(&mut w.f.da, inc(1), w.q.resource).unwrap();
    assert_eq!(
        restored.check(t, &w.f.a.active().unwrap(), inc(2), 4),
        Err(Error::Reconcile)
    );
    let proof = restored.drain(&mut w.f.da, &mut Drain(true)).unwrap();
    w.ledger.release(&mut w.f.da, proof, 5).unwrap();
    assert_eq!(restored.floor(), t.serial);
}
#[test]
fn restored_ledger_keeps_capacity_but_requires_reconciliation() {
    let mut w = World::granted();
    let restored = Ledger::<4>::open(&mut w.f.da, inc(1), capacity(), 200).unwrap();
    assert_eq!(restored.used().unwrap(), w.q.quota);
    assert_eq!(
        restored
            .execution(w.q.id, &w.endpoint, &w.f.a.active().unwrap(), 4)
            .err(),
        Some(Error::Reconcile)
    );
}
#[test]
fn ambiguous_intent_write_cannot_install_from_old_ram_state() {
    let mut w = World::reserved();
    w.f.da.fail = Some(Fail::After);
    assert_eq!(
        w.ledger
            .begin_grant(&mut w.f.da, &w.f.a.active().unwrap(), w.q.id, 3)
            .err(),
        Some(Error::Storage)
    );
    assert_eq!(
        w.ledger
            .begin_grant(&mut w.f.da, &w.f.a.active().unwrap(), w.q.id, 4)
            .err(),
        Some(Error::Reconcile)
    );
    let r = Ledger::<4>::open(&mut w.f.da, inc(1), capacity(), 200).unwrap();
    assert_eq!(r.status(w.q.id), Ok(Stage::GrantIntent));
    assert_eq!(r.used().unwrap(), w.q.quota);
}
#[test]
fn clock_regression_latches_endpoint_closed_to_new_operations() {
    let mut w = World::granted();
    let t = w.token();
    let p = w
        .endpoint
        .begin(t, &w.f.a.active().unwrap(), inc(2), 10)
        .unwrap();
    w.endpoint.finish(p).unwrap();
    assert_eq!(
        w.endpoint
            .begin(t, &w.f.a.active().unwrap(), inc(2), 9)
            .err(),
        Some(Error::Clock)
    );
    assert_eq!(
        w.endpoint
            .begin(t, &w.f.a.active().unwrap(), inc(2), 11)
            .err(),
        Some(Error::Clock)
    );
}

#[test]
fn duplicate_task_activation_launches_once_and_returns_same_result() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec::default();
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 5),
        Ok(tasks::Status::Running)
    );
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 6),
        Ok(tasks::Status::Running)
    );
    assert_eq!(e.launches, 1);
    assert_eq!(w.endpoint.in_flight(), 1);
    let out = outcome();
    book.complete(&mut w.f.da, task().task, 1, out, &mut w.endpoint)
        .unwrap();
    book.complete(&mut w.f.da, task().task, 1, out, &mut w.endpoint)
        .unwrap();
    assert_eq!(w.endpoint.in_flight(), 0);
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 7),
        Ok(tasks::Status::Completed)
    );
    assert_eq!(e.launches, 1);
}
#[test]
fn task_final_start_rechecks_fence_after_prepare() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let t = w.token();
    w.endpoint.revoke(&mut w.f.da, t).unwrap();
    let mut e = Exec::default();
    assert!(start_task(&mut book, &mut w, &mut e, 5).is_err());
    assert_eq!(e.launches, 0);
}
#[test]
fn task_final_start_rechecks_absolute_lease_deadline() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec::default();
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 120),
        Err(Error::Expired)
    );
    assert_eq!(e.launches, 0);
}
#[test]
fn write_failure_before_launch_never_invokes_executor() {
    for fail in [Fail::Before, Fail::After] {
        let mut w = World::granted();
        let mut book = prepared_task(&mut w);
        w.f.da.fail = Some(fail);
        let mut e = Exec::default();
        assert_eq!(
            start_task(&mut book, &mut w, &mut e, 5),
            Err(Error::Storage)
        );
        assert_eq!(e.launches, 0);
        let r = tasks::Book::<4>::open(&mut w.f.da, node(1)).unwrap();
        assert_ne!(r.query(task().task, 1).unwrap().0, tasks::Status::Completed);
    }
}
#[test]
fn restart_running_task_is_uncertain_and_is_never_relaunched() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec::default();
    start_task(&mut book, &mut w, &mut e, 5).unwrap();
    let mut restored = tasks::Book::<4>::open(&mut w.f.da, node(1)).unwrap();
    assert_eq!(
        restored.query(task().task, 1).unwrap().0,
        tasks::Status::Uncertain
    );
    assert_eq!(
        start_task(&mut restored, &mut w, &mut e, 6),
        Ok(tasks::Status::Uncertain)
    );
    assert_eq!(e.launches, 1);
}
#[test]
fn ambiguous_launch_requires_external_reconciliation() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec {
        answer: Some(tasks::LaunchError::Unknown),
        ..Exec::default()
    };
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 5),
        Ok(tasks::Status::Uncertain)
    );
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 6),
        Ok(tasks::Status::Uncertain)
    );
    assert_eq!(e.launches, 1);
    assert_eq!(
        book.reconcile(&mut w.f.da, task().task, 1, &mut w.endpoint, &mut e),
        Ok(tasks::Status::Uncertain)
    );
    e.observed = Some(tasks::Observation::Completed(outcome()));
    assert_eq!(
        book.reconcile(&mut w.f.da, task().task, 1, &mut w.endpoint, &mut e),
        Ok(tasks::Status::Completed)
    );
    assert_eq!(w.endpoint.in_flight(), 0);
}
#[test]
fn definite_launch_failure_is_terminal_not_an_automatic_retry() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec {
        answer: Some(tasks::LaunchError::NotStarted),
        ..Exec::default()
    };
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 5),
        Ok(tasks::Status::NotStarted)
    );
    assert_eq!(
        start_task(&mut book, &mut w, &mut e, 6),
        Ok(tasks::Status::NotStarted)
    );
    assert_eq!(e.launches, 1);
    assert_eq!(w.endpoint.in_flight(), 0);
}
#[test]
fn result_completion_does_not_wait_for_membership_or_ai() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec::default();
    start_task(&mut book, &mut w, &mut e, 5).unwrap();
    w.f.a.isolate(&mut w.f.da).unwrap();
    w.bank.revoke(0).unwrap();
    assert_eq!(
        book.complete(&mut w.f.da, task().task, 1, outcome(), &mut w.endpoint),
        Ok(outcome())
    );
}
#[test]
fn operation_id_cannot_be_reused_with_new_activation() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec::default();
    start_task(&mut book, &mut w, &mut e, 5).unwrap();
    book.complete(&mut w.f.da, task().task, 1, outcome(), &mut w.endpoint)
        .unwrap();
    let mut new = task();
    new.activation = 2;
    assert_eq!(
        book.prepare(
            &mut w.f.da,
            new,
            &w.ledger,
            &w.endpoint,
            &w.f.a.active().unwrap(),
            6
        ),
        Err(Error::Conflict)
    );
}
#[test]
fn task_payload_mismatch_is_a_conflict_not_a_new_attempt() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut changed = task();
    changed.payload_digest = [98; 32];
    assert_eq!(
        book.prepare(
            &mut w.f.da,
            changed,
            &w.ledger,
            &w.endpoint,
            &w.f.a.active().unwrap(),
            5
        ),
        Err(Error::Conflict)
    );
}
#[test]
fn completed_result_survives_ack_loss_and_restore() {
    let mut w = World::granted();
    let mut book = prepared_task(&mut w);
    let mut e = Exec::default();
    start_task(&mut book, &mut w, &mut e, 5).unwrap();
    w.f.da.fail = Some(Fail::After);
    assert_eq!(
        book.complete(&mut w.f.da, task().task, 1, outcome(), &mut w.endpoint),
        Err(Error::Storage)
    );
    let r = tasks::Book::<4>::open(&mut w.f.da, node(1)).unwrap();
    assert_eq!(
        r.query(task().task, 1),
        Ok((tasks::Status::Completed, Some(outcome())))
    );
    assert_eq!(w.endpoint.in_flight(), 1);
}

fn envelope<'a>(f: &Formation, sequence: u64, payload: &'a [u8]) -> wire::Envelope<'a> {
    wire::Envelope {
        kind: wire::Kind::Task,
        scope: f.a.active().unwrap().scope(),
        sender: inc(2),
        receiver: node(1),
        session: [77; 32],
        sequence,
        payload,
    }
}
fn packet(e: wire::Envelope<'_>) -> Bytes {
    let sig = TestCrypto.sign(e.sender.node, e.signing_bytes().unwrap().as_slice());
    e.packet(&sig).unwrap()
}
#[test]
fn wire_roundtrip_authentication_and_replay_gate() {
    let f = Formation::active();
    let active = f.a.active().unwrap();
    let mut rx = wire::Receiver::new(&active, inc(2), [77; 32], 0, 50).unwrap();
    let p = packet(envelope(&f, 1, b"task"));
    assert_eq!(
        rx.accept(&TestCrypto, &active, p.as_slice(), 1)
            .unwrap()
            .payload,
        b"task"
    );
    assert_eq!(
        rx.accept(&TestCrypto, &active, p.as_slice(), 2).err(),
        Some(Error::Replay)
    );
}
#[test]
fn invalid_signature_does_not_advance_replay_watermark() {
    let f = Formation::active();
    let active = f.a.active().unwrap();
    let mut rx = wire::Receiver::new(&active, inc(2), [77; 32], 0, 50).unwrap();
    let e = envelope(&f, 99, b"task");
    let p = e.packet(&[0; 64]).unwrap();
    assert_eq!(
        rx.accept(&TestCrypto, &active, p.as_slice(), 1).err(),
        Some(Error::Authentication)
    );
    assert_eq!(rx.highwater(), 0);
    let p = packet(envelope(&f, 1, b"task"));
    rx.accept(&TestCrypto, &active, p.as_slice(), 2).unwrap();
}
#[test]
fn wire_rejects_every_truncated_length_and_trailing_bytes() {
    let f = Formation::active();
    let p = packet(envelope(&f, 1, b"test"));
    for len in 0..p.as_slice().len() {
        assert!(wire::decode(&p.as_slice()[..len]).is_err(), "len={len}");
    }
    let mut v = p.as_slice().to_vec();
    v.push(0);
    assert!(wire::decode(&v).is_err());
}
#[test]
fn wire_header_unknown_kind_reserved_flags_and_oversize_fail_closed() {
    let f = Formation::active();
    let p = packet(envelope(&f, 1, b"test"));
    for (index, value) in [(0, b'?'), (8, 2), (10, 255), (11, 1)] {
        let mut v = p.as_slice().to_vec();
        v[index] = value;
        assert!(wire::decode(&v).is_err());
    }
    let too_big = [0; wire::MAX_PAYLOAD + 1];
    assert_eq!(
        envelope(&f, 1, &too_big).signing_bytes().err(),
        Some(Error::Invalid)
    );
}
#[test]
fn old_boot_wrong_session_and_wrong_cluster_cannot_cross_receive_gate() {
    let f = Formation::active();
    let a = f.a.active().unwrap();
    let mut rx = wire::Receiver::new(&a, inc(2), [77; 32], 0, 50).unwrap();
    for mode in 0..4 {
        let mut e = envelope(&f, 1, b"test");
        match mode {
            0 => e.sender.boot = 2,
            1 => e.session = [78; 32],
            2 => e.scope.cluster = id(8),
            _ => e.receiver = node(3),
        };
        let p = packet(e);
        assert_eq!(
            rx.accept(&TestCrypto, &a, p.as_slice(), 1 + mode).err(),
            Some(Error::Stale)
        );
    }
    assert_eq!(rx.highwater(), 0);
}
#[test]
fn previous_session_cannot_survive_membership_reactivation() {
    let mut f = Formation::active();
    let mut rx = wire::Receiver::new(&f.a.active().unwrap(), inc(2), [77; 32], 0, 50).unwrap();
    let p = packet(envelope(&f, 1, b"old"));
    f.a.isolate(&mut f.da).unwrap();
    f.b.isolate(&mut f.db).unwrap();
    f.a.prepare(&mut f.da, f.cfg, f.ps).unwrap();
    f.b.prepare(&mut f.db, f.cfg, f.ps).unwrap();
    f.activate(2);
    assert_eq!(
        rx.accept(&TestCrypto, &f.a.active().unwrap(), p.as_slice(), 1)
            .err(),
        Some(Error::Stale)
    );
}
#[test]
fn liveness_delayed_response_does_not_reset_lease_from_arrival() {
    let f = Formation::active();
    let a = f.a.active().unwrap();
    let mut h = health::Health::new(&a, inc(2)).unwrap();
    let b = h.probe([1; 32], 1, 10).unwrap();
    let sig = TestCrypto.sign(node(2), b.as_slice());
    h.response(&TestCrypto, &a, &sig, 9).unwrap();
    assert_eq!(h.healthy(9), Ok(true));
    assert_eq!(h.healthy(10), Ok(false));
    assert_eq!(h.response(&TestCrypto, &a, &sig, 10), Err(Error::Replay));
}
#[test]
fn liveness_old_challenge_and_timed_out_ack_cannot_reconnect() {
    let f = Formation::active();
    let a = f.a.active().unwrap();
    let mut h = health::Health::new(&a, inc(2)).unwrap();
    let old = h.probe([1; 32], 1, 10).unwrap();
    let new = h.probe([2; 32], 2, 11).unwrap();
    assert_eq!(
        h.response(
            &TestCrypto,
            &a,
            &TestCrypto.sign(node(2), old.as_slice()),
            3
        ),
        Err(Error::Authentication)
    );
    assert_eq!(
        h.response(
            &TestCrypto,
            &a,
            &TestCrypto.sign(node(2), new.as_slice()),
            11
        ),
        Err(Error::Expired)
    );
}
#[test]
fn liveness_failure_isolates_without_resetting_cluster_or_vote_count() {
    let mut f = Formation::active();
    let mut h = health::Health::new(&f.a.active().unwrap(), inc(2)).unwrap();
    let bytes = h.probe([1; 32], 1, 10).unwrap();
    h.response(
        &TestCrypto,
        &f.a.active().unwrap(),
        &TestCrypto.sign(node(2), bytes.as_slice()),
        2,
    )
    .unwrap();
    assert_eq!(h.enforce(&mut f.a, &mut f.da, 10), Ok(false));
    assert_eq!(f.a.phase(), Some(Phase::Isolated));
    assert_eq!(f.a.config(), Some(f.cfg));
}

fn write_spec(f: &Formation, data: &[u8]) -> replication::Write {
    replication::Write {
        scope: f.a.active().unwrap().scope(),
        resource: id(20),
        operation: id(81),
        version: 1,
        data_digest: TestCrypto.sha256(data),
    }
}
fn durable_ack(w: replication::Write, n: u8) -> replication::DurableAck {
    replication::DurableAck {
        replica: inc(n),
        signature: TestCrypto.sign(
            node(n),
            replication::ack_bytes(w, inc(n)).unwrap().as_slice(),
        ),
    }
}
#[test]
fn two_node_quorum_requires_two_distinct_durable_voters() {
    let mut f = Formation::active();
    let w = write_spec(&f, b"content");
    let a = f.a.active().unwrap();
    let mut t = replication::Tracker::new(&a, w, 2).unwrap();
    assert_eq!(t.add(&TestCrypto, &a, durable_ack(w, 1)), Ok(true));
    assert_eq!(t.add(&TestCrypto, &a, durable_ack(w, 1)), Ok(false));
    assert_eq!(t.finalize(&mut f.da, &a).err(), Some(Error::NotReady));
    assert_eq!(t.add(&TestCrypto, &a, durable_ack(w, 2)), Ok(true));
    assert_eq!(t.finalize(&mut f.da, &a).unwrap().write(), w);
}
#[test]
fn replica_write_persists_actual_bytes_before_exposing_signable_ack() {
    let mut w = World::granted();
    let spec = write_spec(&w.f, b"real payload");
    let token = w.token();
    let a = w.f.a.active().unwrap();
    let p = w.endpoint.begin(token, &a, inc(2), 5).unwrap();
    let before = w.f.da.writes;
    replication::persist_replica(
        &mut w.f.da,
        &TestCrypto,
        &a,
        &w.endpoint,
        &p,
        spec,
        b"real payload",
        5,
    )
    .unwrap();
    assert_eq!(w.f.da.writes, before + 1);
    assert!(
        w.f.da
            .records
            .iter()
            .any(|(k, (_, b))| k.kind == 5 && b.ends_with(b"real payload"))
    );
    w.endpoint.finish(p).unwrap();
}
#[test]
fn replica_store_failure_never_returns_an_ack_and_retry_reloads_durable_state() {
    let mut w = World::granted();
    let spec = write_spec(&w.f, b"data");
    let t = w.token();
    let a = w.f.a.active().unwrap();
    let p = w.endpoint.begin(t, &a, inc(2), 5).unwrap();
    w.f.da.fail = Some(Fail::After);
    assert_eq!(
        replication::persist_replica(
            &mut w.f.da,
            &TestCrypto,
            &a,
            &w.endpoint,
            &p,
            spec,
            b"data",
            5
        )
        .err(),
        Some(Error::Storage)
    );
    let count = w.f.da.writes;
    replication::persist_replica(
        &mut w.f.da,
        &TestCrypto,
        &a,
        &w.endpoint,
        &p,
        spec,
        b"data",
        6,
    )
    .unwrap();
    assert_eq!(w.f.da.writes, count);
}
#[test]
fn newer_uncommitted_replica_does_not_erase_older_acked_data() {
    let mut w = World::granted();
    let old = write_spec(&w.f, b"old");
    let t = w.token();
    let a = w.f.a.active().unwrap();
    let p = w.endpoint.begin(t, &a, inc(2), 5).unwrap();
    replication::persist_replica(
        &mut w.f.da,
        &TestCrypto,
        &a,
        &w.endpoint,
        &p,
        old,
        b"old",
        5,
    )
    .unwrap();
    let new = replication::Write {
        version: 2,
        operation: id(82),
        data_digest: TestCrypto.sha256(b"new"),
        ..old
    };
    replication::persist_replica(
        &mut w.f.da,
        &TestCrypto,
        &a,
        &w.endpoint,
        &p,
        new,
        b"new",
        6,
    )
    .unwrap();
    let records: Vec<_> = w.f.da.records.iter().filter(|(k, _)| k.kind == 5).collect();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|(_, (_, b))| b.ends_with(b"old")));
    assert!(records.iter().any(|(_, (_, b))| b.ends_with(b"new")));
}
#[test]
fn conflicting_replica_version_and_data_digest_are_rejected() {
    let mut w = World::granted();
    let old = write_spec(&w.f, b"old");
    let t = w.token();
    let a = w.f.a.active().unwrap();
    let p = w.endpoint.begin(t, &a, inc(2), 5).unwrap();
    replication::persist_replica(
        &mut w.f.da,
        &TestCrypto,
        &a,
        &w.endpoint,
        &p,
        old,
        b"old",
        5,
    )
    .unwrap();
    let bad = replication::Write {
        operation: id(82),
        data_digest: TestCrypto.sha256(b"new"),
        ..old
    };
    assert_eq!(
        replication::persist_replica(
            &mut w.f.da,
            &TestCrypto,
            &a,
            &w.endpoint,
            &p,
            bad,
            b"new",
            6
        )
        .err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        replication::persist_replica(
            &mut w.f.da,
            &TestCrypto,
            &a,
            &w.endpoint,
            &p,
            old,
            b"wrong",
            6
        )
        .err(),
        Some(Error::Invalid)
    );
}
#[test]
fn stale_boot_unauthorized_voter_or_other_payload_cannot_count() {
    let f = Formation::active();
    let w = write_spec(&f, b"data");
    let a = f.a.active().unwrap();
    let mut t = replication::Tracker::new(&a, w, 2).unwrap();
    let outsider = durable_ack(w, 3);
    assert_eq!(t.add(&TestCrypto, &a, outsider), Err(Error::WrongOwner));
    let mut rebooted = durable_ack(w, 2);
    rebooted.replica.boot = 2;
    assert_eq!(t.add(&TestCrypto, &a, rebooted), Err(Error::WrongOwner));
    let other = replication::Write {
        data_digest: [1; 32],
        ..w
    };
    assert_eq!(
        t.add(&TestCrypto, &a, durable_ack(other, 2)),
        Err(Error::Authentication)
    );
    assert_eq!(t.acknowledgements(), 0);
}
#[test]
fn same_failure_domain_cannot_satisfy_two_domain_protection() {
    let mut c = claims(2);
    c.failure_domain = id(1);
    let ps = [peer(claims(1)), peer(c)];
    let cfg = config(ps, 1);
    let mut f = Formation::prepared();
    f.da = Disk::default();
    f.db = Disk::default();
    f.a = Membership::open(&mut f.da, &TestCrypto, inc(1)).unwrap();
    f.b = Membership::open(&mut f.db, &TestCrypto, inc(2)).unwrap();
    f.cfg = cfg;
    f.ps = ps;
    f.a.prepare(&mut f.da, cfg, ps).unwrap();
    f.b.prepare(&mut f.db, cfg, ps).unwrap();
    f.prove();
    f.activate(1);
    let w = write_spec(&f, b"data");
    let a = f.a.active().unwrap();
    let mut t = replication::Tracker::new(&a, w, 2).unwrap();
    t.add(&TestCrypto, &a, durable_ack(w, 1)).unwrap();
    t.add(&TestCrypto, &a, durable_ack(w, 2)).unwrap();
    assert_eq!(t.finalize(&mut f.da, &a).err(), Some(Error::Capacity));
}
#[test]
fn commit_result_is_durable_and_recovers_from_lost_ack() {
    let mut f = Formation::active();
    let w = write_spec(&f, b"data");
    let a = f.a.active().unwrap();
    let mut t = replication::Tracker::new(&a, w, 2).unwrap();
    for n in [1, 2] {
        t.add(&TestCrypto, &a, durable_ack(w, n)).unwrap();
    }
    f.da.fail = Some(Fail::After);
    assert_eq!(t.finalize(&mut f.da, &a).err(), Some(Error::Storage));
    let count = f.da.writes;
    let receipt = t.finalize(&mut f.da, &a).unwrap();
    assert_eq!(receipt.write(), w);
    assert_eq!(count, f.da.writes);
}
#[test]
fn obsolete_membership_cannot_finalize_collected_acks() {
    let mut f = Formation::active();
    let w = write_spec(&f, b"data");
    let mut t = replication::Tracker::new(&f.a.active().unwrap(), w, 2).unwrap();
    for n in [1, 2] {
        t.add(&TestCrypto, &f.a.active().unwrap(), durable_ack(w, n))
            .unwrap();
    }
    f.a.isolate(&mut f.da).unwrap();
    f.b.isolate(&mut f.db).unwrap();
    f.a.prepare(&mut f.da, f.cfg, f.ps).unwrap();
    f.b.prepare(&mut f.db, f.cfg, f.ps).unwrap();
    f.activate(2);
    assert_eq!(
        t.finalize(&mut f.da, &f.a.active().unwrap()).err(),
        Some(Error::Stale)
    );
}

#[test]
fn untrusted_packet_noise_never_panics_or_becomes_authority() {
    let mut seed = 0x8746aa13u64;
    for n in 0..20_000 {
        let len = n % 384;
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = seed as u8;
        }
        assert!(wire::decode(&bytes).is_err());
    }
}
#[test]
fn every_single_bit_signed_packet_mutation_is_rejected() {
    let f = Formation::active();
    let p = packet(envelope(&f, 1, b"some authenticated payload"));
    for index in 0..p.as_slice().len() {
        for bit in 0..8 {
            let mut damaged = p.as_slice().to_vec();
            damaged[index] ^= 1 << bit;
            let a = f.a.active().unwrap();
            let mut rx = wire::Receiver::new(&a, inc(2), [77; 32], 0, 50).unwrap();
            assert!(
                rx.accept(&TestCrypto, &a, &damaged, 1).is_err(),
                "{index}:{bit}"
            );
            assert_eq!(rx.highwater(), 0);
        }
    }
}
#[test]
fn malformed_recovered_records_fail_without_new_authority() {
    let f = Formation::active();
    let key = Key {
        kind: 1,
        id: node(1).0,
    };
    let original = f.da.records.get(&key).unwrap().1.clone();
    for len in 0..original.len() {
        let mut disk = f.da.clone();
        disk.records.get_mut(&key).unwrap().1.truncate(len);
        assert!(
            Membership::open(&mut disk, &TestCrypto, inc(1)).is_err(),
            "{len}"
        );
    }
}
#[test]
fn concurrent_stale_store_writer_loses_compare_and_swap() {
    let mut f = Formation::prepared();
    let mut second = Membership::open(&mut f.da, &TestCrypto, inc(1)).unwrap();
    second.prepare(&mut f.da, f.cfg, f.ps).unwrap();
    let sig = signs(f.cfg, &confirm_bytes(f.cfg).unwrap());
    f.a.prove(&mut f.da, &TestCrypto, sig).unwrap();
    assert_eq!(
        second.prove(&mut f.da, &TestCrypto, sig),
        Err(Error::Storage)
    );
    assert!(second.active().is_err());
}
#[test]
fn endpoint_operation_capacity_and_double_finish_are_checked() {
    let mut w = World::granted();
    let t = w.token();
    let a = w.f.a.active().unwrap();
    let mut ps = Vec::new();
    for _ in 0..4 {
        ps.push(w.endpoint.begin(t, &a, inc(2), 5).unwrap());
    }
    assert_eq!(
        w.endpoint.begin(t, &a, inc(2), 5).err(),
        Some(Error::Capacity)
    );
    w.endpoint.finish_ref(&ps[0]).unwrap();
    assert_eq!(w.endpoint.finish_ref(&ps[0]), Err(Error::Stale));
    assert_eq!(w.endpoint.in_flight(), 3);
}
#[test]
fn resource_tombstones_are_not_evicted_to_accept_reused_ids() {
    let mut w = World::reserved();
    w.ledger.expire_reservations(&mut w.f.da, 50).unwrap();
    let b = bank();
    let ad = admission::Admission::new(&b, subject(), [0, 1, 2], 0);
    for n in 11..14 {
        let mut q = w.q;
        q.id = id(n);
        q.resource = id(n + 20);
        q.reservation_until = 60;
        w.ledger
            .prepare(
                &mut w.f.da,
                &w.f.a.active().unwrap(),
                q,
                &ad,
                policy_env(51),
            )
            .unwrap();
    }
    w.ledger.expire_reservations(&mut w.f.da, 60).unwrap();
    let mut q = w.q;
    q.id = id(15);
    q.resource = id(35);
    q.reservation_until = 70;
    assert_eq!(
        w.ledger.prepare(
            &mut w.f.da,
            &w.f.a.active().unwrap(),
            q,
            &ad,
            policy_env(61)
        ),
        Err(Error::Capacity)
    );
}
#[test]
fn quota_overflow_is_rejected_without_wrapping() {
    let a = Quota {
        cpu_ticks: u64::MAX,
        memory_pages: 0,
        io_units: 0,
    };
    assert_eq!(
        a.checked_add(Quota {
            cpu_ticks: 1,
            ..Quota::default()
        }),
        Err(Error::Exhausted)
    );
}

mod real_adapters {
    use super::*;
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write as _},
        path::PathBuf,
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
    };
    static UNIQUE: AtomicU64 = AtomicU64::new(0);
    fn next() -> u64 {
        UNIQUE.fetch_add(1, Ordering::Relaxed)
    }
    struct Openssl {
        root: PathBuf,
        keys: Vec<(NodeId, PathBuf, PathBuf)>,
    }
    impl Openssl {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "cyxia-cluster-crypto-{}-{}",
                std::process::id(),
                next()
            ));
            fs::create_dir(&root).unwrap();
            let mut keys = Vec::new();
            for n in 0..2 {
                let private = root.join(format!("key-{n}.pem"));
                let public = root.join(format!("public-{n}.pem"));
                assert!(
                    Command::new("openssl")
                        .args(["genpkey", "-algorithm", "Ed25519", "-out"])
                        .arg(&private)
                        .output()
                        .unwrap()
                        .status
                        .success()
                );
                assert!(
                    Command::new("openssl")
                        .args(["pkey", "-in"])
                        .arg(&private)
                        .args(["-pubout", "-out"])
                        .arg(&public)
                        .output()
                        .unwrap()
                        .status
                        .success()
                );
                let der = Command::new("openssl")
                    .args(["pkey", "-in"])
                    .arg(&private)
                    .args(["-pubout", "-outform", "DER"])
                    .output()
                    .unwrap();
                assert!(der.status.success());
                assert_eq!(der.stdout.len(), 44);
                let mut id = [0; 32];
                id.copy_from_slice(&der.stdout[12..]);
                keys.push((NodeId(id), private, public));
            }
            Self { root, keys }
        }
        fn paths(&self) -> (PathBuf, PathBuf) {
            let n = next();
            (
                self.root.join(format!("message-{n}")),
                self.root.join(format!("signature-{n}")),
            )
        }
        fn sign(&self, node: NodeId, data: &[u8]) -> Signature {
            let (_, private, _) = self.keys.iter().find(|(id, _, _)| *id == node).unwrap();
            let (message, sig) = self.paths();
            fs::write(&message, data).unwrap();
            let output = Command::new("openssl")
                .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
                .arg(private)
                .arg("-in")
                .arg(&message)
                .arg("-out")
                .arg(&sig)
                .output()
                .unwrap();
            assert!(output.status.success(), "{:?}", output.stderr);
            let bytes = fs::read(&sig).unwrap();
            assert_eq!(bytes.len(), 64);
            let mut result = [0; 64];
            result.copy_from_slice(&bytes);
            fs::remove_file(message).unwrap();
            fs::remove_file(sig).unwrap();
            result
        }
    }
    impl Drop for Openssl {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    impl Crypto for Openssl {
        fn sha256(&self, data: &[u8]) -> Digest {
            let mut child = Command::new("openssl")
                .args(["dgst", "-sha256", "-binary"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(data).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout.len(), 32);
            let mut digest = [0; 32];
            digest.copy_from_slice(&output.stdout);
            digest
        }
        fn verify(&self, key: NodeId, data: &[u8], signature: &Signature) -> bool {
            let Some((_, _, public)) = self.keys.iter().find(|(id, _, _)| *id == key) else {
                return false;
            };
            let (message, sig) = self.paths();
            fs::write(&message, data).unwrap();
            fs::write(&sig, signature).unwrap();
            let output = Command::new("openssl")
                .args(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey"])
                .arg(public)
                .arg("-in")
                .arg(&message)
                .arg("-sigfile")
                .arg(&sig)
                .output()
                .unwrap();
            fs::remove_file(message).unwrap();
            fs::remove_file(sig).unwrap();
            output.status.success()
        }
        // TEST ONLY measured-boot allowlist. Real signatures do not prove that
        // this host is a native CyxiaOS machine or has physical CPU isolation.
        fn authorize_native(&self, c: &NativeClaims) -> bool {
            c.measurement == [42; 32] && self.keys.iter().any(|(id, _, _)| *id == c.identity.node)
        }
    }
    struct FileDisk<'a> {
        root: PathBuf,
        crypto: &'a Openssl,
    }
    impl<'a> FileDisk<'a> {
        fn new(root: PathBuf, crypto: &'a Openssl) -> Self {
            fs::create_dir_all(&root).unwrap();
            Self { root, crypto }
        }
        fn path(&self, key: Key) -> PathBuf {
            let hex: String = key.id.iter().map(|v| format!("{v:02x}")).collect();
            self.root.join(format!("{}-{hex}.record", key.kind))
        }
        fn read(&self, key: Key) -> std::result::Result<Option<(u64, Vec<u8>)>, StoreError> {
            let path = self.path(key);
            if !path.exists() {
                return Ok(None);
            }
            let bytes = fs::read(path).map_err(|_| StoreError::Io)?;
            if bytes.len() < 44 {
                return Err(StoreError::Corrupt);
            }
            let revision = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
            if bytes.len() != 44 + len || revision == 0 {
                return Err(StoreError::Corrupt);
            }
            let mut hashed = bytes[..12].to_vec();
            hashed.extend_from_slice(&bytes[44..]);
            if self.crypto.sha256(&hashed) != bytes[12..44] {
                return Err(StoreError::Corrupt);
            }
            Ok(Some((revision, bytes[44..].to_vec())))
        }
    }
    struct Lock(PathBuf);
    impl Drop for Lock {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    impl Store for FileDisk<'_> {
        fn load(
            &mut self,
            key: Key,
            out: &mut [u8],
        ) -> std::result::Result<Option<Stored>, StoreError> {
            let Some((revision, data)) = self.read(key)? else {
                return Ok(None);
            };
            if data.len() > out.len() {
                return Err(StoreError::Corrupt);
            }
            out[..data.len()].copy_from_slice(&data);
            Ok(Some(Stored {
                revision,
                len: data.len(),
            }))
        }
        fn replace(
            &mut self,
            key: Key,
            expected: u64,
            next: u64,
            bytes: &[u8],
        ) -> std::result::Result<(), StoreError> {
            let lock_path = self.root.join("writer.lock");
            let _file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
                .map_err(|_| StoreError::Conflict)?;
            let _lock = Lock(lock_path);
            if self.read(key)?.map_or(0, |r| r.0) != expected
                || expected.checked_add(1) != Some(next)
            {
                return Err(StoreError::Conflict);
            }
            let mut prefix = next.to_le_bytes().to_vec();
            prefix.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            let mut hashed = prefix.clone();
            hashed.extend_from_slice(bytes);
            let checksum = self.crypto.sha256(&hashed);
            let tmp = self.root.join(format!(
                "next-{}.tmp",
                UNIQUE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|_| StoreError::Io)?;
            file.write_all(&prefix)
                .and_then(|_| file.write_all(&checksum))
                .and_then(|_| file.write_all(bytes))
                .and_then(|_| file.sync_all())
                .map_err(|_| StoreError::Io)?;
            fs::rename(&tmp, self.path(key)).map_err(|_| StoreError::Io)?;
            File::open(&self.root)
                .and_then(|f| f.sync_all())
                .map_err(|_| StoreError::Io)
        }
    }
    fn real_peers(c: &Openssl) -> [Peer; 2] {
        core::array::from_fn(|i| {
            let mut facts = claims((i + 1) as u8);
            facts.identity.node = c.keys[i].0;
            let mut ch = Challenge::new(node(9), [(i + 1) as u8; 32], 0, 10).unwrap();
            let sig = c.sign(
                facts.identity.node,
                ch.signing_bytes(facts).unwrap().as_slice(),
            );
            ch.authenticate(c, facts, &sig, 1).unwrap()
        })
    }
    fn pair_signs(c: &Openssl, cfg: Config, msg: &Bytes) -> [Signature; 2] {
        cfg.members()
            .map(|m| c.sign(m.identity.node, msg.as_slice()))
    }
    #[test]
    fn actual_sha256_ed25519_and_tamper_rejection() {
        let c = Openssl::new();
        assert_eq!(
            c.sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        let mut facts = claims(1);
        facts.identity.node = c.keys[0].0;
        let mut ch = Challenge::new(node(9), [8; 32], 0, 10).unwrap();
        let sig = c.sign(
            facts.identity.node,
            ch.signing_bytes(facts).unwrap().as_slice(),
        );
        let mut altered = facts;
        altered.abi = 2;
        assert_eq!(
            ch.authenticate(&c, altered, &sig, 1).unwrap_err(),
            Error::Authentication
        );
        ch.authenticate(&c, facts, &sig, 1).unwrap();
    }
    #[test]
    fn actual_file_fsync_reload_and_corruption_detection() {
        let c = Openssl::new();
        let path = c.root.join("store");
        let mut disk = FileDisk::new(path.clone(), &c);
        assert_eq!(cluster::boot::next(&mut disk, node(1)).unwrap().boot, 1);
        drop(disk);
        let mut reopened = FileDisk::new(path, &c);
        assert_eq!(cluster::boot::next(&mut reopened, node(1)).unwrap().boot, 2);
        let file = reopened.path(Key {
            kind: 7,
            id: node(1).0,
        });
        let mut content = Vec::new();
        File::open(&file)
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        let last = content.len() - 1;
        content[last] ^= 1;
        fs::write(file, content).unwrap();
        assert_eq!(
            cluster::boot::next(&mut reopened, node(1)),
            Err(Error::Storage)
        );
    }
    #[test]
    fn actual_signed_two_node_formation_with_durable_host_snapshots() {
        let c = Openssl::new();
        let ps = real_peers(&c);
        let cfg = Config::new(&c, id(9), 1, ps, [[1; 32], [2; 32]], [3; 32]).unwrap();
        let mut da = FileDisk::new(c.root.join("a"), &c);
        let mut db = FileDisk::new(c.root.join("b"), &c);
        let mut a = Membership::open(&mut da, &c, ps[0].claims().identity).unwrap();
        let mut b = Membership::open(&mut db, &c, ps[1].claims().identity).unwrap();
        let msg = a.prepare(&mut da, cfg, ps).unwrap();
        b.prepare(&mut db, cfg, ps).unwrap();
        let proof = pair_signs(&c, cfg, &msg);
        a.prove(&mut da, &c, proof).unwrap();
        b.prove(&mut db, &c, proof).unwrap();
        assert!(a.active().is_err());
        let ready = a.begin_activation(&mut da, &c, 1).unwrap();
        b.begin_activation(&mut db, &c, 1).unwrap();
        let votes = pair_signs(&c, cfg, &ready);
        let ack = a.commit_activation(&mut da, &c, votes).unwrap();
        b.commit_activation(&mut db, &c, votes).unwrap();
        let acks = pair_signs(&c, cfg, &ack);
        a.enable(&mut da, &c, acks).unwrap();
        b.enable(&mut db, &c, acks).unwrap();
        assert_eq!(a.active().unwrap().scope(), b.active().unwrap().scope());
        let a = Membership::open(&mut da, &c, ps[0].claims().identity).unwrap();
        assert!(a.active().is_err());
        assert_eq!(a.config(), Some(cfg));
    }
}

#[test]
fn full_owner_flow_replica_quorum_task_ack_loss_partition_and_drain() {
    let mut w = World::granted();
    // The second simulated native member must independently admit its local
    // replica storage; membership alone is not an admission receipt.
    let mut ledger_b = Ledger::<4>::open(&mut w.f.db, inc(2), capacity(), 200).unwrap();
    let mut endpoint_b = Endpoint::<4>::open(&mut w.f.db, inc(2), id(20)).unwrap();
    let bank_b = bank();
    let ad_b = admission::Admission::new(&bank_b, subject(), [0, 1, 2], 0);
    let mut qb = request();
    qb.consumer = inc(1);
    ledger_b
        .prepare(
            &mut w.f.db,
            &w.f.b.active().unwrap(),
            qb,
            &ad_b,
            policy_env(2),
        )
        .unwrap();
    let ib = ledger_b
        .begin_grant(&mut w.f.db, &w.f.b.active().unwrap(), qb.id, 3)
        .unwrap();
    endpoint_b
        .install(&mut w.f.db, &ib, &w.f.b.active().unwrap(), 3)
        .unwrap();
    let tb = ledger_b
        .commit_grant(&mut w.f.db, &w.f.b.active().unwrap(), qb.id, &endpoint_b, 3)
        .unwrap();
    let ta = w.token();
    let pa = w
        .endpoint
        .begin(ta, &w.f.a.active().unwrap(), inc(2), 5)
        .unwrap();
    let pb = endpoint_b
        .begin(tb, &w.f.b.active().unwrap(), inc(1), 5)
        .unwrap();
    let data = b"checkpoint payload shared by two native identities";
    let spec = write_spec(&w.f, data);
    let aa = replication::persist_replica(
        &mut w.f.da,
        &TestCrypto,
        &w.f.a.active().unwrap(),
        &w.endpoint,
        &pa,
        spec,
        data,
        5,
    )
    .unwrap();
    let ab = replication::persist_replica(
        &mut w.f.db,
        &TestCrypto,
        &w.f.b.active().unwrap(),
        &endpoint_b,
        &pb,
        spec,
        data,
        5,
    )
    .unwrap();
    let mut tracker = replication::Tracker::new(&w.f.a.active().unwrap(), spec, 2).unwrap();
    tracker
        .add(
            &TestCrypto,
            &w.f.a.active().unwrap(),
            replication::DurableAck {
                replica: inc(1),
                signature: TestCrypto.sign(node(1), aa.as_slice()),
            },
        )
        .unwrap();
    assert_eq!(
        tracker
            .finalize(&mut w.f.da, &w.f.a.active().unwrap())
            .err(),
        Some(Error::NotReady)
    );
    tracker
        .add(
            &TestCrypto,
            &w.f.a.active().unwrap(),
            replication::DurableAck {
                replica: inc(2),
                signature: TestCrypto.sign(node(2), ab.as_slice()),
            },
        )
        .unwrap();
    tracker
        .finalize(&mut w.f.da, &w.f.a.active().unwrap())
        .unwrap();
    w.endpoint.finish(pa).unwrap();
    endpoint_b.finish(pb).unwrap();
    let mut book = tasks::Book::<4>::open(&mut w.f.da, node(1)).unwrap();
    book.prepare(
        &mut w.f.da,
        task(),
        &w.ledger,
        &w.endpoint,
        &w.f.a.active().unwrap(),
        6,
    )
    .unwrap();
    let mut executor = Exec::default();
    assert_eq!(
        start_task(&mut book, &mut w, &mut executor, 7),
        Ok(tasks::Status::Running)
    );
    assert_eq!(
        start_task(&mut book, &mut w, &mut executor, 8),
        Ok(tasks::Status::Running)
    );
    assert_eq!(executor.launches, 1);
    w.f.a.isolate(&mut w.f.da).unwrap();
    w.f.b.isolate(&mut w.f.db).unwrap();
    assert!(w.f.a.active().is_err());
    assert!(w.f.b.active().is_err());
    assert_eq!(w.ledger.expire_reservations(&mut w.f.da, 121), Ok(0));
    assert_eq!(w.ledger.used().unwrap(), request().quota);
    book.complete(&mut w.f.da, task().task, 1, outcome(), &mut w.endpoint)
        .unwrap();
    let drained = w.endpoint.drain(&mut w.f.da, &mut Drain(true)).unwrap();
    w.ledger.release(&mut w.f.da, drained, 122).unwrap();
    assert_eq!(w.ledger.used().unwrap(), Quota::default());
    let restored = tasks::Book::<4>::open(&mut w.f.da, node(1)).unwrap();
    assert_eq!(
        restored.query(task().task, 1),
        Ok((tasks::Status::Completed, Some(outcome())))
    );
    assert_eq!(w.f.a.config().unwrap().cluster(), id(9));
    eprintln!(
        "CLUSTER_SCENARIO PASS native_identities=2 separate_stores=2 durable_replicas=2 launch_attempts=1 partition=isolated unreclaimed_on_expiry=1 drained=1"
    );
}

#[test]
fn activation_at_maximum_never_wraps_after_isolation() {
    let mut f = Formation::prepared();
    f.prove();
    f.activate(u64::MAX);
    f.a.isolate(&mut f.da).unwrap();
    f.a.prepare(&mut f.da, f.cfg, f.ps).unwrap();
    assert_eq!(
        f.a.begin_activation(&mut f.da, &TestCrypto, 1).err(),
        Some(Error::Stale)
    );
    assert!(f.a.active().is_err());
}

#[test]
fn grant_counter_exhaustion_never_reuses_a_fence() {
    let mut w = World::reserved();
    let key = Key {
        kind: 2,
        id: node(1).0,
    };
    let bytes = &mut w.f.da.records.get_mut(&key).unwrap().1;
    // magic/version/kind (12), owner (32), capacity (2), serial highwater (8).
    bytes[46..54].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut ledger = Ledger::<4>::open(&mut w.f.da, inc(1), capacity(), 200).unwrap();
    // Existing reservations on reload require reconciliation. Create a fresh
    // ID to reach counter exhaustion without granting old recovered state.
    let mut q = request();
    q.id = id(11);
    q.resource = id(21);
    let ad = admission::Admission::new(&w.bank, subject(), [0, 1, 2], 0);
    ledger
        .prepare(&mut w.f.da, &w.f.a.active().unwrap(), q, &ad, policy_env(3))
        .unwrap();
    assert_eq!(
        ledger
            .begin_grant(&mut w.f.da, &w.f.a.active().unwrap(), q.id, 4)
            .err(),
        Some(Error::Exhausted)
    );
    assert_eq!(ledger.status(q.id), Ok(Stage::Reserved));
}

#[test]
fn failed_isolation_write_still_disables_live_authority() {
    for fail in [Fail::Before, Fail::After] {
        let mut f = Formation::active();
        f.da.fail = Some(fail);
        assert_eq!(f.a.isolate(&mut f.da), Err(Error::Storage));
        assert!(f.a.active().is_err());
    }
}

#[test]
fn failed_fence_revocation_blocks_new_effects_and_does_not_release_capacity() {
    let mut w = World::granted();
    let t = w.token();
    w.f.da.fail = Some(Fail::Before);
    assert_eq!(w.endpoint.revoke(&mut w.f.da, t), Err(Error::Storage));
    assert_eq!(
        w.endpoint
            .begin(t, &w.f.a.active().unwrap(), inc(2), 5)
            .err(),
        Some(Error::Reconcile)
    );
    assert_eq!(w.ledger.used().unwrap(), w.q.quota);
}
