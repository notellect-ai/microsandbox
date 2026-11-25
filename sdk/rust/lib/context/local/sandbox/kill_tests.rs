//! W-31m: on Windows, kill, replacement and removal end only the runtime the SDK recorded.
//!
//! The 11-24 repro: a crash after the runtime started but before `sdk-process.json` was written
//! leaves a run whose PID Windows may give to any process (there, a `ping`). Every case below
//! points the run at a live bystander and checks that it is still running afterwards.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sea_orm::{ActiveModelTrait, EntityTrait, Set};

use super::{LocalContext, run_entity, sandbox_entity};
use crate::MicrosandboxError;
use crate::runtime::ownership::RuntimeProcess;
use crate::sandbox::reap_leaked_runtime_process;
use crate::sandbox::{SandboxConfig, SandboxStatus};

/// A process that is not a runtime; ends when dropped.
struct Bystander(Child);

impl Bystander {
    fn start() -> Self {
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::ownership::tests::ownership_child",
                    "--ignored",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn pid(&self) -> i32 {
        self.0.id() as i32
    }

    fn running(&mut self) -> bool {
        self.0.try_wait().unwrap().is_none()
    }
}

impl Drop for Bystander {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How the run's start time relates to the process its PID names.
#[derive(Clone, Copy)]
enum Started {
    /// The process was created long after the run began: a recycled PID.
    BeforeProcess,
    /// Nothing shows the process came later.
    AfterProcess,
}

struct Fixture {
    _home: tempfile::TempDir,
    backend: LocalContext,
    id: i32,
    run: run_entity::Model,
}

const NAME: &str = "w31m";

async fn fixture(pid: i32, started: Started, status: SandboxStatus) -> Fixture {
    let home = tempfile::tempdir().unwrap();
    let backend = crate::test_support::local_backend_builder(home.path())
        .build()
        .unwrap();
    let config = SandboxConfig {
        spec: microsandbox_types::SandboxSpec {
            name: NAME.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let pools = backend.db().await.unwrap();
    let id = LocalContext::insert_sandbox_record(pools.write(), &config)
        .await
        .unwrap();
    LocalContext::update_sandbox_status(pools.write(), id, status)
        .await
        .unwrap();
    let hours = match started {
        Started::BeforeProcess => -1,
        Started::AfterProcess => 1,
    };
    let run = run_entity::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(pid)),
        status: Set(run_entity::RunStatus::Running),
        started_at: Set(Some(
            chrono::Utc::now().naive_utc() + chrono::Duration::hours(hours),
        )),
        ..Default::default()
    }
    .insert(pools.write())
    .await
    .unwrap();
    std::fs::create_dir_all(runtime_dir(&backend)).unwrap();
    Fixture {
        _home: home,
        backend,
        id,
        run,
    }
}

fn runtime_dir(backend: &LocalContext) -> std::path::PathBuf {
    backend.sandboxes_dir().join(NAME).join("runtime")
}

impl Fixture {
    fn record(&self, pid: i32) {
        RuntimeProcess::capture(pid)
            .unwrap()
            .unwrap()
            .publish(&runtime_dir(&self.backend), &self.run, true)
            .unwrap();
    }

    fn cut_record(&self) {
        let path = runtime_dir(&self.backend).join("sdk-process.json");
        let whole = std::fs::read(&path).unwrap();
        std::fs::write(&path, &whole[..whole.len() / 2]).unwrap();
    }

    async fn status(&self) -> SandboxStatus {
        sandbox_entity::Entity::find_by_id(self.id)
            .one(self.backend.db().await.unwrap().read())
            .await
            .unwrap()
            .unwrap()
            .status
    }

    async fn model(&self) -> sandbox_entity::Model {
        sandbox_entity::Entity::find_by_id(self.id)
            .one(self.backend.db().await.unwrap().read())
            .await
            .unwrap()
            .unwrap()
    }

    async fn replace(&self) -> crate::MicrosandboxResult<()> {
        let pools = self.backend.db().await.unwrap();
        LocalContext::stop_sandbox_for_replacement(
            pools,
            &self.model().await,
            Duration::ZERO,
            None,
            &self.backend.sandboxes_dir(),
        )
        .await
    }
}

/// The repro itself: no record, the PID now names a process created after the run began.
/// The runtime is proven gone; the sandbox is settled and the process left alone.
#[tokio::test]
async fn kill_leaves_a_recycled_pid_running() {
    let mut bystander = Bystander::start();
    let fixture = fixture(
        bystander.pid(),
        Started::BeforeProcess,
        SandboxStatus::Running,
    )
    .await;
    fixture
        .backend
        .kill_sandbox(NAME, Some(fixture.id))
        .await
        .unwrap();
    assert!(bystander.running());
    assert_ne!(fixture.status().await, SandboxStatus::Running);
}

/// No record and nothing proving the PID's holder came later: it may be the runtime, so the
/// sandbox stays running, and it may be anything, so kill refuses instead of ending it. A
/// partial record is no record.
#[tokio::test]
async fn kill_refuses_a_pid_nothing_proves_is_the_runtime() {
    let mut bystander = Bystander::start();
    let fixture = fixture(
        bystander.pid(),
        Started::AfterProcess,
        SandboxStatus::Running,
    )
    .await;
    for partial in [false, true] {
        if partial {
            fixture.record(bystander.pid());
            fixture.cut_record();
        }
        let error = fixture
            .backend
            .kill_sandbox(NAME, Some(fixture.id))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, MicrosandboxError::SandboxStillRunning(message)
                if message.contains("no matching SDK process record")),
            "{error}"
        );
        assert!(bystander.running());
        assert_eq!(fixture.status().await, SandboxStatus::Running);
        // Status reads (list, inspect) still work and still report it running.
        let (model, _) = fixture
            .backend
            .sandbox_handle_state(NAME, Some(fixture.id))
            .await
            .unwrap();
        assert_eq!(model.status, SandboxStatus::Running);
    }
}

/// A record whose creation time is not the live process's: the recorded runtime exited and
/// its PID went to another process. Settled, and that process left alone.
#[tokio::test]
async fn kill_leaves_a_process_whose_creation_time_does_not_match_the_record() {
    let mut bystander = Bystander::start();
    let fixture = fixture(
        bystander.pid(),
        Started::AfterProcess,
        SandboxStatus::Running,
    )
    .await;
    fixture.record(bystander.pid());
    let path = runtime_dir(&fixture.backend).join("sdk-process.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["birth"] = (record["birth"].as_u64().unwrap() - 1).into();
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    fixture
        .backend
        .kill_sandbox(NAME, Some(fixture.id))
        .await
        .unwrap();
    assert!(bystander.running());
    assert_ne!(fixture.status().await, SandboxStatus::Running);
}

/// The recorded runtime is ended through its record, with no Job (its SDK is gone), and only it.
#[tokio::test]
async fn kill_ends_the_recorded_runtime_and_nothing_else() {
    let mut runtime = Bystander::start();
    let mut bystander = Bystander::start();
    let fixture = fixture(runtime.pid(), Started::AfterProcess, SandboxStatus::Running).await;
    fixture.record(runtime.pid());
    fixture
        .backend
        .kill_sandbox(NAME, Some(fixture.id))
        .await
        .unwrap();
    assert!(!runtime.running());
    assert!(bystander.running());
    assert_eq!(fixture.status().await, SandboxStatus::Stopped);
}

/// `create --replace` over a sandbox whose runtime nothing proves: refused, process untouched;
/// over a recycled PID: replaced, process untouched; over the recorded runtime: ended.
#[tokio::test]
async fn replacement_ends_only_the_recorded_runtime() {
    let mut bystander = Bystander::start();
    let unproven = fixture(
        bystander.pid(),
        Started::AfterProcess,
        SandboxStatus::Running,
    )
    .await;
    let error = unproven.replace().await.unwrap_err();
    assert!(
        matches!(&error, MicrosandboxError::SandboxStillRunning(_)),
        "{error}"
    );
    assert!(bystander.running());

    let recycled = fixture(
        bystander.pid(),
        Started::BeforeProcess,
        SandboxStatus::Running,
    )
    .await;
    recycled.replace().await.unwrap();
    assert!(bystander.running());
    assert_eq!(recycled.status().await, SandboxStatus::Stopped);

    let mut runtime = Bystander::start();
    let recorded = fixture(runtime.pid(), Started::AfterProcess, SandboxStatus::Running).await;
    recorded.record(runtime.pid());
    recorded.replace().await.unwrap();
    assert!(!runtime.running());
    assert!(bystander.running());
}

/// `remove` of a stopped sandbox whose runtime outlived its row: ended only when recorded.
#[tokio::test]
async fn removal_reaps_only_the_recorded_runtime() {
    use crate::sandbox::reap::LeakedReapVerdict;
    let mut bystander = Bystander::start();
    let unproven = fixture(
        bystander.pid(),
        Started::AfterProcess,
        SandboxStatus::Stopped,
    )
    .await;
    assert_eq!(
        reap_leaked_runtime_process(&unproven.backend, unproven.id, NAME)
            .await
            .unwrap(),
        LeakedReapVerdict::Unverifiable
    );
    assert!(bystander.running());

    let recycled = fixture(
        bystander.pid(),
        Started::BeforeProcess,
        SandboxStatus::Stopped,
    )
    .await;
    assert_eq!(
        reap_leaked_runtime_process(&recycled.backend, recycled.id, NAME)
            .await
            .unwrap(),
        LeakedReapVerdict::NoProcess
    );
    assert!(bystander.running());

    let mut runtime = Bystander::start();
    let recorded = fixture(runtime.pid(), Started::AfterProcess, SandboxStatus::Stopped).await;
    recorded.record(runtime.pid());
    assert_eq!(
        reap_leaked_runtime_process(&recorded.backend, recorded.id, NAME)
            .await
            .unwrap(),
        LeakedReapVerdict::NoProcess
    );
    assert!(!runtime.running());
    assert!(bystander.running());
}
