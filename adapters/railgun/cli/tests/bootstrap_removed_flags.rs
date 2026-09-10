#![allow(
    clippy::expect_used,
    reason = "test-target process harness; an abort here is the failure report"
)]

use std::process::Command;

#[test]
fn removed_bootstrap_cell_flags_fail_with_actionable_errors() {
    for (flag, value) in [("--entries", "65536"), ("--entry-bytes", "512")] {
        let output = Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
            .args([
                "bootstrap-from-subsquid",
                "--rpc-pool-config",
                "/definitely-missing/raven-rpc-pool.toml",
                "--data-dir-template",
                "/tmp/raven-bootstrap-{N}",
                flag,
                value,
            ])
            .output()
            .expect("spawn raven-railgun");
        assert!(!output.status.success(), "{flag} must fail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(flag), "{flag}: {stderr}");
        assert!(stderr.contains("removed"), "{flag}: {stderr}");
        assert!(stderr.contains("encoder"), "{flag}: {stderr}");
    }
}
