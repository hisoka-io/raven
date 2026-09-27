//! Data-dir templating, JSONL spawn log, and instance-id generation. Pure sync.

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

/// Valid records from `spawn_log.jsonl`, oldest first; malformed lines are skipped.
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
