//! Thin Storage adapter for completed-file URMA caching. Existing Task creation,
//! writes and GC are unchanged; this follows the same completed-Piece contract
//! as map_upload_piece. No guard spans native operations or remote READ.

use crate::{content::ReadSourceFile, metadata::Piece, Storage};
use dragonfly_client_core::Result;
use std::sync::Arc;

pub(crate) struct ReadStorageSource {
    pub(crate) file: Arc<ReadSourceFile>,
    pub(crate) piece: Piece,
    pub(crate) piece_length: u64,
}

impl Storage {
    /// Establish current Piece availability before looking in the URMA cache.
    /// Missing/unsuitable disk content uses the existing Piece path instead.
    pub(crate) async fn read_cache_source(
        &self,
        task_id: &str,
        piece_id: &str,
    ) -> Result<Option<ReadStorageSource>> {
        let piece = self.wait_for_piece_finished(piece_id).await?;
        if self.cache.contains_piece(task_id, piece_id).await {
            return Ok(None);
        }
        let Some(task) = self.get_task(task_id)? else {
            return Ok(None);
        };
        let (Some(piece_length), Some(content_length)) = (task.piece_length, task.content_length)
        else {
            return Ok(None);
        };
        if piece_length == 0
            || content_length == 0
            || self.piece_id(task_id, piece.number) != piece_id
            || u64::from(piece.number).checked_mul(piece_length) != Some(piece.offset)
            || piece.offset >= content_length
            || piece.length != piece_length.min(content_length - piece.offset)
        {
            return Ok(None);
        }
        // Preserve the existing mmap upload accounting around source opening.
        self.metadata.upload_task_started(task_id);
        let file = match self.content.open_task_read_source(task_id).await {
            Ok(file) if file.opened_length() == content_length => {
                self.metadata.upload_task_finished(task_id);
                file
            }
            _ => {
                self.metadata.upload_task_failed(task_id);
                return Ok(None);
            }
        };
        Ok(Some(ReadStorageSource {
            file,
            piece,
            piece_length,
        }))
    }

    /// Only called on a cache miss. Task.finished_at alone is insufficient:
    /// a successful Range download also sets it. Reuse existing Piece records
    /// and require exactly the canonical, completed, on-disk file coverage.
    pub(crate) async fn file_is_complete_for_cache(
        &self,
        task_id: &str,
        source: &ReadStorageSource,
    ) -> Result<bool> {
        let length = source.file.opened_length();
        let mut pieces = self.get_pieces(task_id)?;
        if pieces.len() as u64 != length.div_ceil(source.piece_length) {
            return Ok(false);
        }
        pieces.sort_unstable_by_key(|piece| piece.number);
        for (number, piece) in pieces.iter().enumerate() {
            let offset = number as u64 * source.piece_length;
            if u64::from(piece.number) != number as u64
                || !piece.is_finished()
                || piece.offset != offset
                || piece.length != source.piece_length.min(length - offset)
                || self
                    .cache
                    .contains_piece(task_id, &self.piece_id(task_id, piece.number))
                    .await
            {
                return Ok(false);
            }
        }
        Ok(true)
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
            .download_task_started(TASK, 8, 19, None)
            .await
            .unwrap();
        (dir, storage)
    }

    async fn finish(storage: &Storage, number: u32, byte: u8) {
        let id = storage.piece_id(TASK, number);
        let offset = u64::from(number) * 8;
        let length = 8.min(19 - offset);
        storage
            .download_piece_started(&id, number, offset, length)
            .await
            .unwrap();
        let mut stream = futures::stream::iter([Ok(Bytes::from(vec![byte; length as usize]))]);
        storage
            .download_piece_from_source_finished(
                &id,
                TASK,
                offset,
                length,
                &mut stream,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
    }

    async fn source(storage: &Storage) -> ReadStorageSource {
        storage
            .read_cache_source(TASK, &storage.piece_id(TASK, 0))
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn range_finished_flag_does_not_authorize_incomplete_file() {
        let (_dir, storage) = storage().await;
        finish(&storage, 0, 1).await;
        storage.download_task_finished(TASK).unwrap();
        assert!(storage.get_task(TASK).unwrap().unwrap().is_finished());
        assert!(!storage
            .file_is_complete_for_cache(TASK, &source(&storage).await)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn complete_file_accepts_short_final_piece_and_rejects_unfinished_or_malformed_records() {
        let (_dir, storage) = storage().await;
        for number in 0..3 {
            finish(&storage, number, number as u8 + 1).await;
        }
        let source = source(&storage).await;
        assert!(storage
            .file_is_complete_for_cache(TASK, &source)
            .await
            .unwrap());
        let id = storage.piece_id(TASK, 2);
        storage.metadata.delete_piece(&id).unwrap();
        storage
            .metadata
            .download_piece_started(&id, 2, 16, 3)
            .unwrap();
        assert!(!storage
            .file_is_complete_for_cache(TASK, &source)
            .await
            .unwrap());
        storage
            .metadata
            .download_piece_finished(&id, 15, 3, "", None)
            .unwrap();
        assert!(!storage
            .file_is_complete_for_cache(TASK, &source)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn gc_remains_independent_and_recreated_file_has_distinct_cache_identity() {
        let (_dir, storage) = storage().await;
        for number in 0..3 {
            finish(&storage, number, 1).await;
        }
        let old = source(&storage).await;
        storage.delete_task(TASK).await;
        assert!(old.file.is_unlinked().unwrap());
        storage
            .download_task_started(TASK, 8, 19, None)
            .await
            .unwrap();
        finish(&storage, 0, 2).await;
        let new = source(&storage).await;
        assert_ne!(old.file.identity(), new.file.identity());
        assert!(!storage
            .file_is_complete_for_cache(TASK, &new)
            .await
            .unwrap());
        // SAFETY: completed old bytes are retained by this open, unlinked inode.
        assert_eq!(
            unsafe { old.file.map_range(0, 8) }.unwrap().as_slice(),
            &[1; 8]
        );
    }

    #[tokio::test]
    async fn memory_cached_piece_does_not_authorize_preallocated_disk_bytes() {
        let (_dir, mut storage) = storage().await;
        for number in 0..3 {
            finish(&storage, number, 1).await;
        }
        let source = source(&storage).await;
        storage.cache.put_task(TASK, 19).await;
        let id = storage.piece_id(TASK, 1);
        storage
            .cache
            .write_piece(TASK, &id, Bytes::from_static(&[2; 8]))
            .await
            .unwrap();
        assert!(storage.cache.contains_piece(TASK, &id).await);
        assert!(!storage
            .file_is_complete_for_cache(TASK, &source)
            .await
            .unwrap());
        assert!(storage
            .read_cache_source(TASK, &id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn missing_or_wrong_sized_content_uses_piece_path() {
        let (_dir, storage) = storage().await;
        finish(&storage, 0, 1).await;
        storage.content.delete_task(TASK).await.unwrap();
        assert!(storage
            .read_cache_source(TASK, &storage.piece_id(TASK, 0))
            .await
            .unwrap()
            .is_none());
        storage.content.create_task(TASK, 8).await.unwrap();
        assert!(storage
            .read_cache_source(TASK, &storage.piece_id(TASK, 0))
            .await
            .unwrap()
            .is_none());
    }
}
