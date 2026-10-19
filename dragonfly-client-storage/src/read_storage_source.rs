//! Opened-file and completed-Piece evidence for ordinary Tasks. GC does not
//! wait for native work: the short Storage guard ends when this snapshot is
//! returned, and the opened inode remains owned independently.

use crate::{
    content::{ReadRegionLayout, ReadSourceFile},
    metadata::Piece,
    Storage,
};
use dragonfly_client_core::{Error, Result};
use std::{ops::Range, sync::Arc};

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "cached server policy awaits write-lifecycle audit"
    )
)]
pub(crate) struct ReadStorageSource {
    pub(crate) file: Arc<ReadSourceFile>,
    pub(crate) piece: Piece,
    pub(crate) piece_length: u64,
    pub(crate) completed: Vec<Range<u64>>,
}

impl Storage {
    /// This does not query the URMA cache. Task/Piece availability and the
    /// current opened instance must be established before any cache lookup.
    /// Only ordinary Tasks are covered; persistent hardlink publication uses
    /// another lifecycle and must be integrated separately.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "cached server policy awaits write-lifecycle audit"
        )
    )]
    pub(crate) async fn read_source_snapshot(
        &self,
        task_id: &str,
        piece_number: u32,
        max_region_bytes: u64,
    ) -> Result<ReadStorageSource> {
        let _guard = self.task_file_lifecycle.gate(task_id).read_owned().await;
        let task = self
            .metadata
            .get_task(task_id)?
            .ok_or_else(|| Error::TaskNotFound(task_id.into()))?;
        let piece_length = task.piece_length.ok_or(Error::InvalidParameter)?;
        let content_length = task.content_length.ok_or(Error::InvalidParameter)?;
        let layout = ReadRegionLayout::new(content_length, piece_length, max_region_bytes)?;
        let piece_offset = u64::from(piece_number)
            .checked_mul(piece_length)
            .ok_or(Error::InvalidParameter)?;
        let window = layout.window(piece_offset)?;
        let first = window.start / piece_length;
        let end = window.end.div_ceil(piece_length);
        if end > u64::from(u32::MAX) + 1 {
            return Err(Error::InvalidParameter);
        }
        let file = self.content.open_task_read_source(task_id).await?;
        if file.opened_length() != content_length {
            return Err(Error::InvalidParameter);
        }
        let mut completed = Vec::new();
        let mut requested = None;
        // Bound each RocksDB query; a large Task never requires a full Task
        // scan. The registration policy supplies a bounded region byte cap.
        let mut cursor = first;
        while cursor < end {
            let batch_end = end.min(cursor + 256);
            let ids: Vec<_> = (cursor..batch_end)
                .map(|number| self.piece_id(task_id, number as u32))
                .collect();
            let refs: Vec<_> = ids.iter().map(String::as_str).collect();
            let pieces = self.metadata.get_pieces_by_ids(&refs)?;
            for (index, piece) in pieces.into_iter().enumerate() {
                let Some(piece) = piece.filter(Piece::is_finished) else {
                    continue;
                };
                let number = cursor + index as u64;
                let offset = number
                    .checked_mul(piece_length)
                    .ok_or(Error::InvalidParameter)?;
                let length = piece_length.min(content_length - offset);
                if u64::from(piece.number) != number
                    || piece.offset != offset
                    || piece.length != length
                {
                    return Err(Error::InvalidParameter);
                }
                if self.cache.contains_piece(task_id, &ids[index]).await {
                    // A preallocated file is not evidence that cached bytes
                    // have been persisted in this inode.
                    continue;
                }
                completed.push(offset..offset + length);
                if piece.number == piece_number {
                    requested = Some(piece);
                }
            }
            cursor = batch_end;
        }
        let piece =
            requested.ok_or_else(|| Error::PieceNotFound(self.piece_id(task_id, piece_number)))?;
        Ok(ReadStorageSource {
            file,
            piece,
            piece_length,
            completed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use dragonfly_client_config::dfdaemon::Config;
    use std::time::Duration;

    const TASK: &str = "d3add1f66b0d0b8083f14479d6e181ec9e2b34cf07d4a1a2ee2fcf51d3a3f14a";

    async fn storage() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            Arc::new(Config::default()),
            dir.path(),
            dir.path().to_owned(),
        )
        .await
        .unwrap();
        storage
            .download_task_started(TASK, 8, 40, None)
            .await
            .unwrap();
        (dir, storage)
    }

    async fn finish(storage: &Storage, number: u32, byte: u8) {
        let id = storage.piece_id(TASK, number);
        storage
            .download_piece_started(&id, number, u64::from(number) * 8, 8)
            .await
            .unwrap();
        let mut stream = futures::stream::iter([Ok(Bytes::from(vec![byte; 8]))]);
        storage
            .download_piece_from_source_finished(
                &id,
                TASK,
                u64::from(number) * 8,
                8,
                &mut stream,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn snapshot_uses_only_completed_disk_pieces_in_target_window() {
        let (_dir, storage) = storage().await;
        finish(&storage, 0, 1).await;
        finish(&storage, 2, 2).await;
        let snapshot = storage.read_source_snapshot(TASK, 2, 16).await.unwrap();
        assert_eq!(snapshot.piece.number, 2);
        assert_eq!(snapshot.piece_length, 8);
        assert_eq!(snapshot.file.opened_length(), 40);
        assert_eq!(snapshot.completed, vec![16..24]);
        assert!(matches!(
            storage.read_source_snapshot(TASK, 3, 16).await,
            Err(Error::PieceNotFound(_))
        ));
        let first = storage.read_source_snapshot(TASK, 0, 16).await.unwrap();
        assert_eq!(first.completed, vec![0..8]);
        // Malformed finished metadata must not authorize a different range.
        let invalid = storage.piece_id(TASK, 1);
        storage
            .metadata
            .download_piece_started(&invalid, 1, 7, 8)
            .unwrap();
        storage
            .metadata
            .download_piece_finished(&invalid, 7, 8, "", None)
            .unwrap();
        assert!(matches!(
            storage.read_source_snapshot(TASK, 0, 16).await,
            Err(Error::InvalidParameter)
        ));
    }

    #[tokio::test]
    async fn snapshot_fd_survives_gc_and_same_task_recreation_without_holding_gc_guard() {
        let (_dir, storage) = storage().await;
        finish(&storage, 0, 1).await;
        let old = storage.read_source_snapshot(TASK, 0, 16).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), storage.delete_task(TASK))
            .await
            .unwrap();
        assert!(old.file.is_unlinked().unwrap());
        assert!(matches!(
            storage.read_source_snapshot(TASK, 0, 16).await,
            Err(Error::TaskNotFound(_))
        ));
        storage
            .download_task_started(TASK, 8, 40, None)
            .await
            .unwrap();
        finish(&storage, 0, 2).await;
        let new = storage.read_source_snapshot(TASK, 0, 16).await.unwrap();
        assert_ne!(old.file.identity(), new.file.identity());
        // SAFETY: completed bytes in the unlinked old inode are immutable.
        let mapped = unsafe { old.file.map_range(0, 8) }.unwrap();
        assert_eq!(mapped.as_slice(), &[1; 8]);
    }

    #[tokio::test]
    async fn cancelled_gc_caller_still_invalidates_before_next_snapshot() {
        let (_dir, storage) = storage().await;
        let storage = Arc::new(storage);
        finish(&storage, 0, 1).await;
        let old = storage.read_source_snapshot(TASK, 0, 16).await.unwrap();
        let gate = storage.task_file_lifecycle.gate(TASK);
        let held = gate.clone().read_owned().await;
        let delete_storage = storage.clone();
        let caller = tokio::spawn(async move { delete_storage.delete_task(TASK).await });
        // Tokio's fair RwLock rejects new readers once the writer is queued.
        tokio::time::timeout(Duration::from_secs(2), async {
            while gate.try_read().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let reader_storage = storage.clone();
        let reader =
            tokio::spawn(async move { reader_storage.read_source_snapshot(TASK, 0, 16).await });
        drop(held);
        let result = tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(Error::TaskNotFound(_))));
        assert!(old.file.is_unlinked().unwrap());
        assert!(storage.content.open_task_read_source(TASK).await.is_err());
    }

    #[tokio::test]
    async fn task_recreation_detaches_residual_inode_and_discards_stale_completion() {
        let (_dir, storage) = storage().await;
        finish(&storage, 0, 1).await;
        let old = storage.read_source_snapshot(TASK, 0, 16).await.unwrap();
        // Simulate GC deleting Task metadata but leaving file/Piece metadata.
        storage.metadata.delete_task(TASK).unwrap();
        storage.prepare_download_task(TASK).unwrap();
        storage
            .download_task_started(TASK, 8, 40, None)
            .await
            .unwrap();
        assert!(old.file.is_unlinked().unwrap());
        assert!(matches!(
            storage.read_source_snapshot(TASK, 0, 16).await,
            Err(Error::PieceNotFound(_))
        ));
        finish(&storage, 0, 2).await;
        let new = storage.read_source_snapshot(TASK, 0, 16).await.unwrap();
        assert_ne!(old.file.identity(), new.file.identity());
        // SAFETY: recreation detached the old inode before any new writes.
        assert_eq!(
            unsafe { old.file.map_range(0, 8) }.unwrap().as_slice(),
            &[1; 8]
        );
    }

    #[tokio::test]
    async fn completed_metadata_cannot_recreate_missing_content_or_resize_old_inode() {
        let (_dir, storage) = storage().await;
        finish(&storage, 0, 1).await;
        let old = storage.read_source_snapshot(TASK, 0, 16).await.unwrap();
        assert!(storage
            .download_task_started(TASK, 16, 80, None)
            .await
            .is_err());
        assert_eq!(old.file.file_length().unwrap(), 40);
        storage.content.delete_task(TASK).await.unwrap();
        assert!(storage
            .download_task_started(TASK, 8, 40, None)
            .await
            .is_err());
        assert!(storage.content.open_task_read_source(TASK).await.is_err());
    }

    #[tokio::test]
    async fn failed_residual_unlink_does_not_publish_new_task_metadata() {
        let (_dir, storage) = storage().await;
        storage.delete_task(TASK).await;
        // A directory at the content path deterministically makes unlink fail,
        // including when tests run as root.
        let path = storage
            .content
            .dir
            .join(crate::content::DEFAULT_TASK_DIR)
            .join(&TASK[..3])
            .join(TASK);
        tokio::fs::create_dir(&path).await.unwrap();
        assert!(storage
            .download_task_started(TASK, 8, 40, None)
            .await
            .is_err());
        assert!(storage.get_task(TASK).unwrap().is_none());
    }
}
