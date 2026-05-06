//! Auto-spawn helpers: data-dir templating, spawn log (JSONL) read/write, and instance-id
//! generation. Pure sync — no tokio, no PIR engine interaction.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AutoSpawnConfig {
    /// Must contain `{tree_number}` (e.g. `"/var/lib/raven/commit-tree-{tree_number}"`).
    pub data_dir_template: String,
    pub encoder: String,
    pub scheme_tag: String,
    pub entries: usize,
    pub entry_bytes: usize,
}

/// One line in `spawn_log.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnRecord {
    pub tree_number: u32,
    pub instance_id: String,
    pub data_dir: PathBuf,
    pub spawned_at_secs: u64,
}

pub fn data_dir_for_tree(template: &str, tree_number: u32) -> PathBuf {
    PathBuf::from(template.replace("{tree_number}", &tree_number.to_string()))
}

/// Reject templates missing `{tree_number}` (all trees would collide on the same path).
pub fn validate_data_dir_template(template: &str) -> anyhow::Result<()> {
    if !template.contains("{tree_number}") {
        anyhow::bail!(
            "auto_spawn.data_dir_template must contain the literal substring \
             '{{tree_number}}' (got: {template:?}); without it every spawned \
             instance would collide on the same on-disk path"
        );
    }
    Ok(())
}

pub fn instance_id_for_tree(tree_number: u32) -> String {
    format!("commit-tree-{tree_number}")
}

pub fn spawn_log_path(registry_dir: &Path) -> PathBuf {
    registry_dir.join("spawn_log.jsonl")
}

pub fn append_spawn_record(registry_dir: &Path, record: &SpawnRecord) -> anyhow::Result<()> {
    use std::io::Write;

    let path = spawn_log_path(registry_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create spawn log dir {}: {e}", parent.display()))?;
    }

    let line =
        serde_json::to_string(record).map_err(|e| anyhow::anyhow!("serialize SpawnRecord: {e}"))?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("open spawn log {}: {e}", path.display()))?;

    writeln!(file, "{line}")
        .map_err(|e| anyhow::anyhow!("write spawn log {}: {e}", path.display()))?;

    Ok(())
}

/// One line in `ppoi_list_spawn_log.jsonl`. Kept in a separate file from [`SpawnRecord`]
/// so chain-tree replay (which keys on `tree_number`) stays isolated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpoiListSpawnRecord {
    /// Template id is recorded so restart replay can locate the matching `[[ppoi_list_template]]`
    /// row even if the operator reordered the TOML between runs.
    pub template_id: String,
    pub list_key_hex: String,
    pub encoder: String,
    pub instance_id: String,
    pub data_dir: PathBuf,
    pub spawned_at_secs: u64,
}

#[must_use]
pub fn ppoi_list_spawn_log_path(registry_dir: &Path) -> PathBuf {
    registry_dir.join("ppoi_list_spawn_log.jsonl")
}

#[must_use]
pub fn data_dir_for_list(template: &str, list_key: &[u8; 32]) -> PathBuf {
    PathBuf::from(template.replace("{list_key}", &list_key_hex_lower(list_key)))
}

/// `<template_id>-<first-8-hex-chars-of-list-key>`. Template id is the discriminator so two
/// templates with the same encoder but different `template_id` on the same list_key get distinct
/// engine slots.
#[must_use]
pub fn instance_id_for_list(template_id: &str, list_key: &[u8; 32]) -> String {
    let hex = list_key_hex_lower(list_key);
    let short: String = hex.chars().take(8).collect();
    format!("{template_id}-{short}")
}

fn list_key_hex_lower(list_key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in list_key {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0F)).copied().unwrap_or(b'0');
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

pub fn append_ppoi_list_spawn_record(
    registry_dir: &Path,
    record: &PpoiListSpawnRecord,
) -> anyhow::Result<()> {
    use std::io::Write;

    let path = ppoi_list_spawn_log_path(registry_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create ppoi spawn log dir {}: {e}", parent.display()))?;
    }
    let line = serde_json::to_string(record)
        .map_err(|e| anyhow::anyhow!("serialize PpoiListSpawnRecord: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("open ppoi spawn log {}: {e}", path.display()))?;
    writeln!(file, "{line}")
        .map_err(|e| anyhow::anyhow!("write ppoi spawn log {}: {e}", path.display()))?;
    Ok(())
}

/// Load all valid records from `ppoi_list_spawn_log.jsonl`; skips malformed lines.
pub fn load_ppoi_list_spawn_log(registry_dir: &Path) -> anyhow::Result<Vec<PpoiListSpawnRecord>> {
    use std::io::BufRead;

    let path = ppoi_list_spawn_log_path(registry_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(&path)
        .map_err(|e| anyhow::anyhow!("open ppoi spawn log {}: {e}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut records = Vec::new();
    for (line_idx, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    line = line_idx + 1,
                    path = %path.display(),
                    error = %e,
                    "ppoi spawn log: skipping unreadable line"
                );
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<PpoiListSpawnRecord>(trimmed) {
            Ok(record) => records.push(record),
            Err(e) => {
                tracing::warn!(
                    line = line_idx + 1,
                    path = %path.display(),
                    error = %e,
                    "ppoi spawn log: skipping malformed line"
                );
            }
        }
    }
    Ok(records)
}

/// Load all valid records from `spawn_log.jsonl`; skips malformed lines. Returns oldest first.
pub fn load_spawn_log(registry_dir: &Path) -> anyhow::Result<Vec<SpawnRecord>> {
    use std::io::BufRead;

    let path = spawn_log_path(registry_dir);

    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = std::fs::File::open(&path)
        .map_err(|e| anyhow::anyhow!("open spawn log {}: {e}", path.display()))?;

    let reader = std::io::BufReader::new(file);
    let mut records = Vec::new();

    for (line_idx, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(
                    line = line_idx + 1,
                    path = %path.display(),
                    error = %e,
                    "spawn log: skipping unreadable line"
                );
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<SpawnRecord>(trimmed) {
            Ok(record) => records.push(record),
            Err(e) => {
                tracing::warn!(
                    line = line_idx + 1,
                    path = %path.display(),
                    error = %e,
                    "spawn log: skipping malformed line"
                );
            }
        }
    }

    Ok(records)
}
