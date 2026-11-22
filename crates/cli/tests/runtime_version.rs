use std::process::Command;

use microsandbox::setup::{Version, resolve_runtime_version};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn packaged_version_matches_cargo_and_clap() {
    // Release validation can inspect the final stripped/signed artifact.
    let executable = std::env::var_os("MSB_VERSION_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_msb").into());
    let expected = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    assert_eq!(
        resolve_runtime_version(&executable).unwrap(),
        Some(expected.clone())
    );
    let output = Command::new(executable).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("msb {expected}")
    );
}

#[test]
fn launch_protocol_advertises_directory_mount_cache() {
    // The SDK refuses a `cache=on` mount unless the selected runtime says it
    // honors it; this binary must say so.
    let output = Command::new(env!("CARGO_BIN_EXE_msb"))
        .arg("__launch-protocol")
        .output()
        .unwrap();
    assert!(output.status.success());
    let advertisement: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        advertisement["directory_mount_cache"], true,
        "{advertisement}"
    );
    assert!(
        advertisement["protocols"]
            .as_array()
            .is_some_and(|protocols| protocols.contains(&2.into())),
        "{advertisement}"
    );
}
