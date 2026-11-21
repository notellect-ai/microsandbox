//! Windows: a detached sandbox starts from inside a job that forbids breakaway.
//!
//! Task Scheduler, some terminals and CI agents run their children in a job
//! without `JOB_OBJECT_LIMIT_BREAKAWAY_OK`. There, CreateProcess with
//! `CREATE_BREAKAWAY_FROM_JOB` fails with ERROR_ACCESS_DENIED, so the runtime
//! must start inside that job instead.
//!
//! Run this ignored test alone (`--exact`): it moves the whole test process
//! into a new job.

#![cfg(all(windows, feature = "local"))]

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use microsandbox::{MicrosandboxError, Sandbox};
use test_utils::msb_test;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IMAGE: &str = "mirror.gcr.io/library/alpine:3.22";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Put this process in a fresh job with no limits; breakaway is then not allowed.
fn enter_job_without_breakaway() -> Result<()> {
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    ensure!(
        !job.is_null(),
        "CreateJobObjectW: {}",
        std::io::Error::last_os_error()
    );
    let assigned = unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) };
    if assigned == 0 {
        let error = std::io::Error::last_os_error();
        unsafe { CloseHandle(job) };
        anyhow::bail!("AssignProcessToJobObject: {error}");
    }
    // The job stays alive while this process is in it; the handle is not needed.
    unsafe { CloseHandle(job) };
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn windows_detached_create_inside_job_without_breakaway() -> Result<()> {
    enter_job_without_breakaway()?;

    let name = format!("windows-job-{}", std::process::id());
    let sandbox = Sandbox::builder(&name)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .create_detached()
        .await
        .context("create a detached sandbox inside a job without breakaway")?;

    let checked: Result<()> = async {
        let output = sandbox.shell("printf job-ok").await?;
        ensure!(output.status().success, "guest command failed");
        ensure!(
            output.stdout()?.trim() == "job-ok",
            "unexpected guest output"
        );
        Ok(())
    }
    .await;

    let stopped = sandbox.stop_with_timeout(Duration::from_secs(30)).await;
    if stopped.is_err() {
        let _ = sandbox.kill().await;
    }
    drop(sandbox);
    let removed = Sandbox::remove(&name).await;
    checked?;
    stopped.context("stop guest")?;
    removed.context("remove guest")?;
    ensure!(matches!(
        Sandbox::get(&name).await,
        Err(MicrosandboxError::SandboxNotFound(_))
    ));
    Ok(())
}
