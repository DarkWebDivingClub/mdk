//! TTL sweep of decrypted inbound media temp dirs under `$TMPDIR/marmot-media/`.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::{AgentConnector, MEDIA_TEMP_MAX_AGE, MEDIA_TEMP_SWEEP_INTERVAL};

impl AgentConnector {
    pub(crate) fn spawn_media_temp_sweeper(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(MEDIA_TEMP_SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match sweep_stale_media_downloads(MEDIA_TEMP_MAX_AGE).await {
                    Ok(swept) if swept > 0 => {
                        tracing::warn!(
                            target: "agent_connector",
                            method = "spawn_media_temp_sweeper",
                            swept,
                            "removed stale inbound media download directories"
                        );
                    }
                    Ok(_) => {}
                    Err(_) => {
                        tracing::debug!(
                            target: "agent_connector",
                            method = "spawn_media_temp_sweeper",
                            "media temp sweep failed"
                        );
                    }
                }
            }
        });
    }
}

pub(crate) fn media_download_root() -> PathBuf {
    std::env::temp_dir().join("marmot-media")
}

pub(crate) async fn sweep_stale_media_downloads(max_age: Duration) -> Result<u64, std::io::Error> {
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    sweep_media_dirs_modified_before(&media_download_root(), cutoff).await
}

pub(crate) async fn sweep_media_dirs_modified_before(
    root: &std::path::Path,
    cutoff: SystemTime,
) -> Result<u64, std::io::Error> {
    if !root.is_dir() {
        return Ok(0);
    }
    let mut swept = 0u64;
    let mut entries = match tokio::fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(_) => return Ok(0),
    };
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(_) => continue,
        };
        let is_dir = match entry.file_type().await {
            Ok(file_type) => file_type.is_dir(),
            Err(_) => continue,
        };
        if !is_dir {
            continue;
        }
        let modified = match entry.metadata().await {
            Ok(metadata) => metadata.modified().unwrap_or(SystemTime::now()),
            Err(_) => continue,
        };
        if modified < cutoff && tokio::fs::remove_dir_all(entry.path()).await.is_ok() {
            swept += 1;
        }
    }
    Ok(swept)
}
