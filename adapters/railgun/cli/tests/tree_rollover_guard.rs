//! The shipped multi-instance example must have tree-rollover protection switched ON.
//!
//! This is the config-shape defect behind the 2026-08-27 tree-4 outage, reproduced as a test.
//! `run_tree_fill_watcher` shipped and worked; the config never enabled it, so Railgun rolled to
//! commitment tree 4, Raven had no instance for it, and every tree-4 event was dropped under
//! `tracing::trace!` while the image ran at `RUST_LOG=info`. Nothing was in a position to notice.
//!
//! The two gates that must BOTH be live are `serve_production_multi.rs:1087`
//! (`if let Some(threshold) = opts.tree_fill_threshold`) and the `[auto_spawn]` wiring that gives
//! the watcher somewhere to spawn into. Either one absent and the protection is silently off.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use raven_railgun_cli::serve_production_multi::{load_options_from_toml, MultiServeOptions};

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples")
        .join("mainnet-6-instance.toml")
}

/// Load the SHIPPED example's contents through the real loader.
///
/// The file cannot be loaded in place: it is tracked at mode 0644 and carries an inline
/// `[global].token`, which the loader refuses on purpose - a group-readable secret is a boot
/// error. That guard is correct and must not be weakened to make this test convenient, so the
/// contents are copied to a 600-mode temp file first, which is exactly what an operator does.
///
/// This matters more than it looks: the first version of this test loaded the path directly, went
/// red, and I nearly recorded that red as proof the threshold was missing. It was failing on the
/// permission guard and would have gone red with a perfectly configured file.
fn load_shipped_example() -> MultiServeOptions {
    let src = example_path();
    assert!(src.is_file(), "example config missing at {}", src.display());
    // The example ships `token = "REPLACE_ME"`, which the loader rejects from every source - also
    // by design, and also correct. Substitute a well-formed token so the load reaches the part
    // this test is about. Neither guard is weakened; both are stepped around the way an operator
    // does, and both remain asserted by their own tests elsewhere.
    let body = std::fs::read_to_string(&src)
        .expect("read example config")
        .replace("REPLACE_ME", &"a1b2c3d4".repeat(8));
    let dir = tempfile::tempdir().expect("tempdir");
    let dst = dir.path().join("mainnet-6-instance.toml");
    std::fs::write(&dst, body).expect("write temp copy");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    load_options_from_toml(&dst).expect("the shipped example must load through the real loader")
}

#[test]
fn the_shipped_example_enables_tree_rollover_protection() {
    let opts = load_shipped_example();

    assert!(
        opts.tree_fill_threshold.is_some(),
        "[global].tree_fill_threshold is unset in the shipped example, so \
         serve_production_multi.rs:1087 never starts run_tree_fill_watcher. This is the exact \
         config shape that caused the tree-4 outage: the mechanism ships, the config leaves it off, \
         and nothing logs that it is off."
    );

    let auto_spawn = opts.auto_spawn.as_ref();
    assert!(
        auto_spawn.is_some_and(|c| c.enabled),
        "[auto_spawn].enabled is not true in the shipped example. The fill watcher can detect the \
         rollover and still have nowhere to spawn the successor instance."
    );
    assert!(
        auto_spawn.is_some_and(|c| c.data_dir_template.contains("{tree_number}")),
        "[auto_spawn].data_dir_template must contain {{tree_number}}; without it every spawned \
         tree would share one data dir."
    );
}

/// The threshold is a fraction of a tree's capacity and must leave real headroom.
///
/// A value at or above 1.0 fires only once the tree is already full, which is the outage; a value
/// at or below 0.0 fires constantly. `serve_production_multi.rs:611-617` refuses the range, but it
/// cannot refuse a value that is in range and still useless.
#[test]
fn the_configured_threshold_leaves_headroom_before_the_tree_fills() {
    let opts = load_shipped_example();
    let threshold = opts
        .tree_fill_threshold
        .expect("threshold must be set; see the sibling test for why");
    assert!(
        (0.5..1.0).contains(&threshold),
        "tree_fill_threshold = {threshold} leaves no useful warning window. Below 0.5 it \
         pre-spawns while the tree is half empty; at 1.0 or above it fires only once the tree is \
         full, which is the outage it exists to prevent."
    );
}
