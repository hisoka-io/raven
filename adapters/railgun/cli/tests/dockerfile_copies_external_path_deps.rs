//! The image's allowlist `COPY` set must cover every path dependency leaving the
//! adapter workspace, else `cargo build` fails in-image after a green host build.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn adapter_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate sits inside the adapter workspace")
        .to_path_buf()
}

fn repo_root() -> PathBuf {
    adapter_root()
        .parent()
        .and_then(Path::parent)
        .expect("adapters/railgun sits two levels under the repo root")
        .to_path_buf()
}

fn quoted_items(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        out.push(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    out
}

fn workspace_members(manifest: &str) -> Vec<String> {
    let start = manifest
        .find("members = [")
        .expect("adapter workspace declares members");
    let body = &manifest[start..];
    let end = body.find(']').expect("members array closes");
    quoted_items(&body[..end])
}

/// Lexically resolve `../`-prefixed dep paths to a repo-root-relative path.
fn resolve_relative(from_dir: &Path, dep: &str) -> Option<PathBuf> {
    let mut parts: Vec<&str> = from_dir
        .strip_prefix(repo_root())
        .ok()?
        .to_str()?
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    for seg in dep.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.iter().collect())
}

fn external_path_deps() -> BTreeSet<PathBuf> {
    let root = adapter_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read adapter Cargo.toml");
    let mut members: Vec<String> = workspace_members(&manifest);
    members.push(String::new());

    let mut deps = BTreeSet::new();
    for member in members {
        let dir = if member.is_empty() {
            root.clone()
        } else {
            root.join(&member)
        };
        let Ok(text) = fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        for line in text.lines() {
            let Some(at) = line.find("path = \"") else {
                continue;
            };
            let tail = &line[at + "path = \"".len()..];
            let Some(close) = tail.find('"') else {
                continue;
            };
            let dep = &tail[..close];
            if !dep.starts_with("..") {
                continue;
            }
            if let Some(resolved) = resolve_relative(&dir, dep) {
                if !resolved.starts_with("adapters") {
                    deps.insert(resolved);
                }
            }
        }
    }
    deps
}

/// `COPY` sources in the build stage, ignoring `COPY --from=` stage-to-stage copies.
fn build_stage_copy_sources(dockerfile: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in dockerfile.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("COPY ") else {
            continue;
        };
        if rest.trim_start().starts_with("--from=") {
            continue;
        }
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        for token in &tokens[..tokens.len() - 1] {
            out.push(PathBuf::from(token));
        }
    }
    out
}

fn covered_by(sources: &[PathBuf], dep: &Path) -> bool {
    sources.iter().any(|src| dep.starts_with(src))
}

#[test]
fn every_external_path_dep_is_copied_into_the_image() {
    let dockerfile =
        fs::read_to_string(adapter_root().join("Dockerfile")).expect("read adapter Dockerfile");
    let sources = build_stage_copy_sources(&dockerfile);
    let deps = external_path_deps();

    assert!(
        !deps.is_empty(),
        "the adapter is expected to path-depend outside its own workspace"
    );
    let missing: Vec<&PathBuf> = deps
        .iter()
        .filter(|dep| !covered_by(&sources, dep))
        .collect();
    assert!(
        missing.is_empty(),
        "Dockerfile COPY set {sources:?} does not cover external path deps {missing:?}; \
         `cargo build` inside the image fails with `failed to read /build/<dep>/Cargo.toml`"
    );
}

#[test]
fn workspace_inheriting_deps_pull_in_the_root_manifest() {
    let dockerfile =
        fs::read_to_string(adapter_root().join("Dockerfile")).expect("read adapter Dockerfile");
    let sources = build_stage_copy_sources(&dockerfile);
    let root = repo_root();

    let inheriting: Vec<PathBuf> = external_path_deps()
        .into_iter()
        .filter(|dep| {
            fs::read_to_string(root.join(dep).join("Cargo.toml"))
                .is_ok_and(|t| t.contains(".workspace = true"))
        })
        .collect();
    if inheriting.is_empty() {
        return;
    }

    assert!(
        covered_by(&sources, Path::new("Cargo.toml")),
        "{inheriting:?} inherit from the root workspace manifest, so the image must COPY \
         the root Cargo.toml; COPY set is {sources:?}"
    );

    let root_manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    for member in workspace_members(&root_manifest) {
        let path = PathBuf::from(&member);
        assert!(
            covered_by(&sources, &path),
            "root workspace member {member} is absent from the image; cargo loads every \
             member to resolve `.workspace = true` inheritance. COPY set is {sources:?}"
        );
    }
}

/// Paths the runtime stage declares `VOLUME`, read from its JSON-array form.
fn volumes(dockerfile: &str) -> Vec<PathBuf> {
    dockerfile
        .lines()
        .filter_map(|line| line.trim().strip_prefix("VOLUME "))
        .flat_map(quoted_items)
        .map(PathBuf::from)
        .collect()
}

/// The `(source, destination)` of the runtime stage's config template `COPY`.
fn shipped_template(dockerfile: &str) -> (String, PathBuf) {
    let joined = dockerfile.replace("\\\n", " ");
    joined
        .lines()
        .filter_map(|line| line.trim().strip_prefix("COPY --from=build "))
        .map(|rest| rest.split_whitespace().collect::<Vec<_>>())
        .find(|tokens| {
            tokens.len() == 2
                && Path::new(tokens[0])
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .map(|tokens| {
            let name = Path::new(tokens[0])
                .file_name()
                .and_then(|name| name.to_str())
                .expect("template file name")
                .to_owned();
            (name, PathBuf::from(tokens[1]))
        })
        .expect("the image ships a config template")
}

/// The template an operator copies with only its token replaced must boot as the image user
/// and keep its state on a declared volume: a data_dir anywhere else is lost with the container
/// or unwritable by uid 1500.
#[test]
fn the_shipped_template_keeps_every_data_dir_on_a_volume_the_image_user_owns() {
    let dockerfile =
        fs::read_to_string(adapter_root().join("Dockerfile")).expect("read adapter Dockerfile");
    let (name, destination) = shipped_template(&dockerfile);
    assert_eq!(
        destination.file_name().and_then(|n| n.to_str()),
        Some(name.as_str()),
        "the image keeps the example's name"
    );
    let template = fs::read_to_string(adapter_root().join("examples").join(&name))
        .expect("the shipped template is an example in the tree");
    let parsed: toml::Value = toml::from_str(&template).expect("the template is TOML");
    let data_dirs: Vec<PathBuf> = parsed
        .get("instance")
        .and_then(toml::Value::as_array)
        .expect("the template declares instances")
        .iter()
        .map(|instance| {
            PathBuf::from(
                instance
                    .get("data_dir")
                    .and_then(toml::Value::as_str)
                    .expect("every instance names its data_dir"),
            )
        })
        .collect();
    assert!(!data_dirs.is_empty());

    let volumes = volumes(&dockerfile);
    let data_volume = volumes
        .iter()
        .find(|volume| data_dirs.iter().all(|dir| dir.starts_with(volume)))
        .unwrap_or_else(|| {
            panic!("every data_dir {data_dirs:?} must lie under one VOLUME of {volumes:?}")
        });

    let volume_line = dockerfile
        .find("\nVOLUME ")
        .expect("the image declares its volumes");
    let before_volume = dockerfile[..volume_line].replace("\\\n", " ");
    let volume_text = data_volume.to_str().expect("utf-8 volume path");
    assert!(
        before_volume.lines().any(|line| {
            line.trim_start().starts_with("RUN ")
                && line.contains(volume_text)
                && line.contains("raven:raven")
        }),
        "{volume_text} must be created owned by raven:raven before VOLUME, or a fresh volume \
         is root-owned and the uid-1500 process cannot create its data_dirs"
    );
    assert!(
        dockerfile.contains("--uid 1500"),
        "the image user is uid 1500"
    );
    assert!(
        dockerfile
            .lines()
            .any(|line| line.trim() == "USER raven:raven"),
        "the node runs as the image user, not root"
    );
}
