/*
 *     Copyright 2025 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use bytes::Bytes;
use bytesize::ByteSize;
use dragonfly_api::common::v2::Range;
use dragonfly_client_config::dfdaemon::Config;
use dragonfly_client_config::MIN_PIECE_LENGTH;
use dragonfly_client_core::{Error, Result};
use dragonfly_client_util::buffer_pool::BufferPool;
use dragonfly_client_util::fs::fd::{FDCache, DEFAULT_FD_CACHE_CAPACITY};
use dragonfly_client_util::fs::{fadvise_dontneed, fadvise_willneed, fallocate};
use futures::Stream;
use std::cmp::max;
#[cfg(any(feature = "urma", test))]
use std::io::{self, IoSlice};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(feature = "urma")]
use std::time::Instant;
use tokio::fs;
use tokio::io::AsyncRead;
#[cfg(feature = "urma")]
use tracing::debug;
use tracing::{error, info, instrument, warn};
use walkdir::WalkDir;

/// Writes every registered RX span at one positional file offset. Linux may
/// complete a pwritev only partially, including in the middle of an iovec, so
/// keep advancing both the iovec view and the file offset until all bytes have
/// been accepted.
#[cfg(any(feature = "urma", test))]
fn write_all_vectored_at(
    file: &std::fs::File,
    mut buffers: &mut [IoSlice<'_>],
    mut offset: u64,
) -> io::Result<u64> {
    // Match Linux IOV_MAX and the existing stream write path. A configured
    // receive window may grow beyond this, in which case it is split across
    // the minimum number of pwritev calls.
    const MAX_WRITE_IOVECS: usize = 1024;

    let mut calls = 0u64;
    while !buffers.is_empty() {
        calls = calls
            .checked_add(1)
            .ok_or_else(|| io::Error::other("URMA pwritev call count overflow"))?;
        let submitted = &buffers[..buffers.len().min(MAX_WRITE_IOVECS)];
        let written = match rustix::io::pwritev(file, submitted, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write URMA receive window",
                ));
            }
            Ok(written) => written,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        };
        offset = offset
            .checked_add(u64::try_from(written).map_err(|_| {
                io::Error::other("URMA positional vectored write length exceeds u64")
            })?)
            .ok_or_else(|| io::Error::other("URMA positional write offset overflow"))?;
        IoSlice::advance_slices(&mut buffers, written);
    }
    Ok(calls)
}

/// The content of a piece.
pub struct Content {
    /// The configuration of the dfdaemon.
    pub config: Arc<Config>,

    /// The directory to store content.
    pub dir: PathBuf,

    /// The cache of the opened file descriptors for reading pieces.
    fd_cache: FDCache,

    /// The pool of the staging buffers for reading and writing pieces.
    buffer_pool: BufferPool,

    /// Initiates writeback of written piece ranges per storage.writebackMode.
    writeback: super::content::Writeback,
}

/// Implements the content storage.
impl Content {
    /// Returns a new content.
    pub async fn new(config: Arc<Config>, dir: &Path) -> Result<Content> {
        let dir = dir.join(super::content::DEFAULT_CONTENT_DIR);

        // If the storage is not kept, remove the directory.
        if !config.storage.keep {
            fs::remove_dir_all(&dir).await.unwrap_or_else(|err| {
                warn!("remove {:?} failed: {}", dir, err);
            });
        }

        fs::create_dir_all(&dir.join(super::content::DEFAULT_TASK_DIR)).await?;
        fs::create_dir_all(&dir.join(super::content::DEFAULT_PERSISTENT_TASK_DIR)).await?;
        fs::create_dir_all(&dir.join(super::content::DEFAULT_PERSISTENT_CACHE_TASK_DIR)).await?;
        info!("content initialized directory: {:?}", dir);

        Ok(Content {
            buffer_pool: BufferPool::new(
                super::content::MAX_BUFFER_POOL_IDLE_BUFFERS
                    * max(
                        config.storage.write_buffer_size,
                        config.storage.read_buffer_size,
                    ),
            ),
            writeback: super::content::Writeback::new(config.storage.writeback_mode),
            config,
            dir,
            fd_cache: FDCache::new(DEFAULT_FD_CACHE_CAPACITY),
        })
    }

    /// Returns the available space of the disk.
    pub fn available_space(&self) -> Result<u64> {
        let disk_threshold = self.config.gc.policy.disk_threshold;
        if disk_threshold != ByteSize::default() {
            let usage_space = WalkDir::new(&self.dir)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.metadata().ok())
                .filter(|metadata| metadata.is_file())
                .fold(0, |acc, m| acc + m.len());

            if usage_space >= disk_threshold.as_u64() {
                warn!(
                    "usage space {} is greater than disk threshold {}, no need to calculate available space",
                    usage_space, disk_threshold
                );

                return Ok(0);
            }

            return Ok(disk_threshold.as_u64() - usage_space);
        }

        let stat = fs2::statvfs(&self.dir)?;
        Ok(stat.available_space())
    }

    /// Returns the total space of the disk.
    pub fn total_space(&self) -> Result<u64> {
        // If the disk_threshold is set, return it directly.
        let disk_threshold = self.config.gc.policy.disk_threshold;
        if disk_threshold != ByteSize::default() {
            return Ok(disk_threshold.as_u64());
        }

        let stat = fs2::statvfs(&self.dir)?;
        Ok(stat.total_space())
    }

    /// Checks if the storage has enough space to store the content.
    pub fn has_enough_space(&self, content_length: u64) -> Result<bool> {
        let available_space = self.available_space()?;
        if available_space < content_length {
            warn!(
                "not enough space to store the task: available_space={}, content_length={}",
                available_space, content_length
            );

            return Ok(false);
        }

        Ok(true)
    }

    /// Checks if the source and target are the same device and inode.
    async fn is_same_dev_inode<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        source: P,
        target: Q,
    ) -> Result<bool> {
        let source_metadata = fs::metadata(source).await?;
        let target_metadata = fs::metadata(target).await?;

        Ok(source_metadata.dev() == target_metadata.dev()
            && source_metadata.ino() == target_metadata.ino())
    }

    /// Checks if the task and target are the same device and inode.
    pub async fn is_same_dev_inode_as_task(&self, task_id: &str, to: &Path) -> Result<bool> {
        let task_path = self.get_task_path(task_id);
        self.is_same_dev_inode(&task_path, to).await
    }

    /// Creates a new task content.
    ///
    /// Behavior of `create_task`:
    /// 1. If the task already exists, return the task path.
    /// 2. If the task does not exist, create the task directory and file.
    #[instrument(level = "debug", skip_all)]
    pub async fn create_task(&self, task_id: &str, length: u64) -> Result<PathBuf> {
        let task_path = self.get_task_path(task_id);
        if task_path.exists() {
            return Ok(task_path);
        }

        let task_dir = self
            .dir
            .join(super::content::DEFAULT_TASK_DIR)
            .join(&task_id[..3]);
        fs::create_dir_all(&task_dir).await.inspect_err(|err| {
            error!("create {:?} failed: {}", task_dir, err);
        })?;

        let f = fs::File::create(task_dir.join(task_id))
            .await
            .inspect_err(|err| {
                error!("create {:?} failed: {}", task_dir, err);
            })?;

        fallocate(&f, length).await.inspect_err(|err| {
            error!("fallocate {:?} failed: {}", task_dir, err);
        })?;

        Ok(task_dir.join(task_id))
    }

    /// Hard links the task content to the destination.
    ///
    /// Behavior of `hard_link_task`:
    /// 1. If the destination exists:
    ///    1.1. If the source and destination share the same device and inode, return immediately.
    ///    1.2. Otherwise, return an error.
    /// 2. If the destination does not exist:
    ///    2.1. If the hard link succeeds, return immediately.
    ///    2.2. If the hard link fails, copy the task content to the destination once the task is finished, then return immediately.
    #[instrument(level = "debug", skip_all)]
    pub async fn hard_link_task(&self, task_id: &str, to: &Path) -> Result<()> {
        let task_path = self.get_task_path(task_id);
        if let Err(err) = fs::hard_link(task_path.clone(), to).await {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if let Ok(true) = self.is_same_dev_inode(&task_path, to).await {
                    info!("hard already exists, no need to operate");
                    return Ok(());
                }
            }

            warn!("hard link {:?} to {:?} failed: {}", task_path, to, err);
            return Err(Error::IO(err));
        }

        info!("hard link {:?} to {:?} success", task_path, to);
        Ok(())
    }

    /// Copies the task content to the destination.
    #[instrument(level = "debug", skip_all)]
    pub async fn copy_task(&self, task_id: &str, to: &Path) -> Result<()> {
        let length = fs::copy(self.get_task_path(task_id), to).await?;

        // Triggers writeback of the copied content per storage.writebackMode.
        if let Ok(f) = fs::File::open(to).await {
            self.writeback
                .trigger(&Arc::new(f.into_std().await), 0, length)
                .await;
        }

        info!("copy to {:?} success", to);
        Ok(())
    }

    /// Deletes the task content.
    pub async fn delete_task(&self, task_id: &str) -> Result<()> {
        info!("delete task content: {}", task_id);
        let task_path = self.get_task_path(task_id);

        self.fd_cache.remove(&task_path).unwrap_or_else(|err| {
            error!("remove {:?} from fd_cache failed: {}", task_path, err);
        });

        fs::remove_file(task_path.as_path())
            .await
            .inspect_err(|err| {
                error!("remove {:?} failed: {}", task_path, err);
            })?;
        Ok(())
    }

    /// Drops the cached pages of the task content.
    #[instrument(level = "debug", skip_all)]
    pub async fn fadvise_dontneed_task(&self, task_id: &str) -> Result<()> {
        let f = fs::File::open(self.get_task_path(task_id)).await?;
        fadvise_dontneed(&f).await
    }

    /// Reads the piece from the content.
    #[instrument(level = "debug", skip_all)]
    pub async fn read_piece(
        &self,
        task_id: &str,
        offset: u64,
        length: u64,
        range: Option<Range>,
    ) -> Result<super::io::RangeReader> {
        let task_path = self.get_task_path(task_id);

        // Calculate the target offset and length based on the range.
        let (target_offset, target_length) =
            super::content::calculate_piece_range(offset, length, range);

        let fd = self.fd_cache.open(&task_path).await.inspect_err(|err| {
            error!("open {:?} failed: {}", task_path, err);
        })?;

        // Queue readahead of the range explicitly, since interleaved uploads
        // on the shared descriptor break the sequential detection. Skip the
        // small ranges, which the kernel readahead covers quickly.
        if target_length >= MIN_PIECE_LENGTH {
            fadvise_willneed(&fd, target_offset, target_length)
                .await
                .unwrap_or_else(|err| warn!("fadvise_willneed failed: {}", err));
        }

        Ok(super::io::RangeReader::new(
            fd,
            target_offset,
            target_length,
            self.config.storage.read_buffer_size,
            self.buffer_pool.clone(),
        ))
    }

    /// Memory-maps finished piece bytes for registered URMA send windows.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn map_piece(
        &self,
        task_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<super::content::MappedPiece> {
        self.map_path_range(self.get_task_path(task_id), offset, length)
            .await
    }

    /// map_persistent_piece memory-maps finished persistent piece bytes on disk.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn map_persistent_piece(
        &self,
        task_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<super::content::MappedPiece> {
        self.map_path_range(self.get_persistent_task_path(task_id), offset, length)
            .await
    }

    /// map_persistent_cache_piece memory-maps finished persistent cache piece bytes on disk.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn map_persistent_cache_piece(
        &self,
        task_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<super::content::MappedPiece> {
        self.map_path_range(self.get_persistent_cache_task_path(task_id), offset, length)
            .await
    }

    /// map_path_range memory-maps `[offset, offset+length)` of a content file.
    #[cfg(feature = "urma")]
    async fn map_path_range(
        &self,
        path: PathBuf,
        offset: u64,
        length: u64,
    ) -> Result<super::content::MappedPiece> {
        if length == 0 {
            return Err(Error::InvalidParameter);
        }
        let mapped = tokio::task::spawn_blocking(move || -> Result<super::content::MappedPiece> {
            let file = std::fs::File::open(&path).inspect_err(|err| {
                error!("open {:?} failed: {}", path, err);
            })?;
            let metadata = file.metadata().inspect_err(|err| {
                error!("stat {:?} failed: {}", path, err);
            })?;
            let end = offset.checked_add(length).ok_or(Error::InvalidParameter)?;
            if end > metadata.len() {
                return Err(Error::Unknown(format!(
                    "piece range [{}, {}) exceeds content length {}",
                    offset,
                    end,
                    metadata.len()
                )));
            }
            // Safety: the file remains open while the mapping is constructed; MappedPiece owns
            // the resulting pages for the piece lifetime.
            let mmap = unsafe {
                memmap2::MmapOptions::new()
                    .offset(offset)
                    .len(length as usize)
                    .map(&file)
            }
            .inspect_err(|err| {
                error!(
                    "mmap {:?} offset {} length {} failed: {}",
                    path, offset, length, err
                );
            })?;
            // Fault pages in so later window copies do not block the fabric send path on major
            // page faults under memory pressure.
            mmap.advise(memmap2::Advice::Sequential).ok();
            mmap.advise(memmap2::Advice::WillNeed).ok();
            Ok(super::content::MappedPiece::new(mmap))
        })
        .await
        .map_err(|err| Error::Unknown(format!("mmap piece task join failed: {err}")))??;
        Ok(mapped)
    }

    /// Writes the piece from the stream of bytes chunks to the content and
    /// calculates the hash of the piece by crc32.
    #[instrument(level = "debug", skip_all)]
    pub async fn write_piece_from_stream<S>(
        &self,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        stream: &mut S,
    ) -> Result<super::io::WriteRangeResponse>
    where
        S: Stream<Item = std::io::Result<Bytes>> + Unpin + ?Sized,
    {
        let task_path = self.get_task_path(task_id);
        let fd = self
            .fd_cache
            .open_write(&task_path)
            .await
            .inspect_err(|err| {
                error!("open {:?} failed: {}", task_path, err);
            })?;

        let response = super::io::write_range_from_stream(
            fd.clone(),
            offset,
            expected_length,
            self.config.storage.write_buffer_size,
            stream,
        )
        .await
        .inspect_err(|err| {
            error!("write {:?} failed: {}", task_path, err);
        })?;

        self.writeback.trigger(&fd, offset, response.length).await;
        Ok(response)
    }

    /// Writes normal-task content directly from immutable registered URMA
    /// receive spans. No aggregate userspace buffer is constructed.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn write_piece_from_urma_stream(
        &self,
        piece_id: &str,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        reader: &mut crate::client::urma::UrmaStreamReader,
        window_timeout: std::time::Duration,
    ) -> Result<super::io::WriteRangeResponse> {
        self.write_urma_stream_to_path(
            piece_id,
            self.get_task_path(task_id),
            offset,
            expected_length,
            reader,
            window_timeout,
        )
        .await
    }

    /// Writes persistent-task content directly from registered URMA spans.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn write_persistent_piece_from_urma_stream(
        &self,
        piece_id: &str,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        reader: &mut crate::client::urma::UrmaStreamReader,
        window_timeout: std::time::Duration,
    ) -> Result<super::io::WriteRangeResponse> {
        self.write_urma_stream_to_path(
            piece_id,
            self.get_persistent_task_path(task_id),
            offset,
            expected_length,
            reader,
            window_timeout,
        )
        .await
    }

    /// Writes persistent-cache content directly from registered URMA spans.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn write_persistent_cache_piece_from_urma_stream(
        &self,
        piece_id: &str,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        reader: &mut crate::client::urma::UrmaStreamReader,
        window_timeout: std::time::Duration,
    ) -> Result<super::io::WriteRangeResponse> {
        self.write_urma_stream_to_path(
            piece_id,
            self.get_persistent_cache_task_path(task_id),
            offset,
            expected_length,
            reader,
            window_timeout,
        )
        .await
    }

    /// Writes normal-task content from a fully read RM-READ lease. The lease
    /// buffer is contiguous registered memory that was read to completion
    /// before publication; the caller recycles the lease afterwards.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn write_piece_from_read_lease(
        &self,
        piece_id: &str,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        lease: &crate::client::urma_read::UrmaReadPieceLease,
    ) -> Result<super::io::WriteRangeResponse> {
        self.write_read_lease_to_path(
            piece_id,
            self.get_task_path(task_id),
            offset,
            expected_length,
            lease,
        )
        .await
    }

    /// Writes persistent-task content from a fully read RM-READ lease.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn write_persistent_piece_from_read_lease(
        &self,
        piece_id: &str,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        lease: &crate::client::urma_read::UrmaReadPieceLease,
    ) -> Result<super::io::WriteRangeResponse> {
        self.write_read_lease_to_path(
            piece_id,
            self.get_persistent_task_path(task_id),
            offset,
            expected_length,
            lease,
        )
        .await
    }

    /// Writes persistent-cache content from a fully read RM-READ lease.
    #[cfg(feature = "urma")]
    #[instrument(skip_all)]
    pub async fn write_persistent_cache_piece_from_read_lease(
        &self,
        piece_id: &str,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        lease: &crate::client::urma_read::UrmaReadPieceLease,
    ) -> Result<super::io::WriteRangeResponse> {
        self.write_read_lease_to_path(
            piece_id,
            self.get_persistent_cache_task_path(task_id),
            offset,
            expected_length,
            lease,
        )
        .await
    }

    /// Consumes one published RM-READ lease with a single positional vectored
    /// write plus the crc32 digest. The whole span is already final memory, so
    /// the multi-window pipelining of the stream consumer is unnecessary.
    #[cfg(feature = "urma")]
    async fn write_read_lease_to_path(
        &self,
        piece_id: &str,
        task_path: PathBuf,
        offset: u64,
        expected_length: u64,
        lease: &crate::client::urma_read::UrmaReadPieceLease,
    ) -> Result<super::io::WriteRangeResponse> {
        let storage_total_start = Instant::now();
        let data = lease.as_slice();
        let length = u64::try_from(data.len())
            .map_err(|_| Error::Unknown("RM-READ lease length exceeds u64".into()))?;
        if length != expected_length {
            return Err(Error::Unknown(format!(
                "expected length {expected_length} but READ lease holds {length}"
            )));
        }

        let file = self
            .fd_cache
            .open_write(&task_path)
            .await
            .inspect_err(|error| error!("open {:?} failed: {}", task_path, error))?;

        // Digest and positional write share the immutable lease span on one
        // blocking worker; the lease stays exclusively owned until recycle.
        let (write_ns, pwrite_calls) = {
            let file = file.clone();
            tokio::task::spawn_blocking(move || {
                let start = Instant::now();
                let mut buffers = [IoSlice::new(data)];
                write_all_vectored_at(&file, &mut buffers, offset)?;
                Ok::<(u64, u64), std::io::Error>((start.elapsed().as_nanos() as u64, 1))
            })
            .await
            .map_err(|error| Error::Unknown(format!("write READ lease panicked: {error}")))?
            .inspect_err(|error| error!("write {:?} failed: {}", task_path, error))?
        };

        let digest_start = Instant::now();
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(data);
        let digest_ns = digest_start.elapsed().as_nanos() as u64;

        debug!(
            piece_id,
            length,
            write_ns,
            pwrite_calls,
            digest_ns,
            storage_total_ns = storage_total_start.elapsed().as_nanos() as u64,
            "finished writing piece from RM-READ lease"
        );

        Ok(super::io::WriteRangeResponse {
            length,
            hash: hasher.finalize().to_string(),
        })
    }

    /// Runs the B3 direct-RX consumer. Digest and positional write share an
    /// immutable lease on separate blocking workers while the Session receives
    /// into the other pipeline window. The lease is explicitly recycled only
    /// after both workers have joined, including their error paths.
    #[cfg(feature = "urma")]
    async fn write_urma_stream_to_path(
        &self,
        piece_id: &str,
        task_path: PathBuf,
        offset: u64,
        expected_length: u64,
        reader: &mut crate::client::urma::UrmaStreamReader,
        window_timeout: std::time::Duration,
    ) -> Result<super::io::WriteRangeResponse> {
        use tokio::time::timeout;

        let storage_total_start = Instant::now();
        let file_open_start = Instant::now();
        let file = self
            .fd_cache
            .open_write(&task_path)
            .await
            .inspect_err(|error| error!("open {:?} failed: {}", task_path, error))?;
        let file_open_ns = file_open_start.elapsed().as_nanos() as u64;
        let mut hasher = crc32fast::Hasher::new();
        let mut length = 0u64;
        let mut rx_windows = 0u64;
        let mut rx_window_wait_ns = 0u64;
        let mut digest_ns = 0u64;
        let mut pwrite_ns = 0u64;
        let mut pwrite_calls = 0u64;
        let mut recycle_ns = 0u64;

        loop {
            let window_wait_start = Instant::now();
            let window = match timeout(window_timeout, reader.next_window()).await {
                Ok(window) => window?,
                Err(_) => return Err(Error::DownloadPieceFinishedTimeout(piece_id.to_string())),
            };
            rx_window_wait_ns += window_wait_start.elapsed().as_nanos() as u64;
            let Some(window) = window else {
                break;
            };
            rx_windows += 1;
            let window_length = u64::try_from(window.len())
                .map_err(|_| Error::Unknown("URMA window length exceeds u64".into()))?;
            let remaining = expected_length.checked_sub(length).ok_or_else(|| {
                Error::Unknown(format!(
                    "urma stream exceeded expected length {expected_length}"
                ))
            })?;
            if window_length > remaining {
                return Err(Error::Unknown(format!(
                    "urma stream exceeded expected length {expected_length}"
                )));
            }

            let position = offset
                .checked_add(length)
                .ok_or_else(|| Error::Unknown("URMA write offset overflow".into()))?;
            let window = Arc::new(window);
            let digest = {
                let window = window.clone();
                tokio::task::spawn_blocking(move || {
                    let start = Instant::now();
                    for part in window.parts() {
                        hasher.update(part);
                    }
                    (hasher, start.elapsed().as_nanos() as u64)
                })
            };
            let write = {
                let window = window.clone();
                let file = file.clone();
                tokio::task::spawn_blocking(move || {
                    let start = Instant::now();
                    let mut buffers = window.parts().map(IoSlice::new).collect::<Vec<_>>();
                    let calls = write_all_vectored_at(&file, &mut buffers, position)?;
                    Ok::<(u64, u64), std::io::Error>((start.elapsed().as_nanos() as u64, calls))
                })
            };

            let (digest, write) = tokio::join!(digest, write);
            let window = Arc::try_unwrap(window)
                .map_err(|_| Error::Unknown("URMA window worker retained its lease".into()))?;
            let recycle_start = Instant::now();
            let recycle = window.recycle().await;
            recycle_ns += recycle_start.elapsed().as_nanos() as u64;

            let (next_hasher, window_digest_ns) =
                digest.map_err(|error| Error::Unknown(format!("digest panicked: {error}")))?;
            hasher = next_hasher;
            digest_ns += window_digest_ns;
            let (window_pwrite_ns, window_pwrite_calls) = write
                .map_err(|error| Error::Unknown(format!("write piece panicked: {error}")))?
                .inspect_err(|error| error!("write {:?} failed: {}", task_path, error))?;
            pwrite_ns += window_pwrite_ns;
            pwrite_calls += window_pwrite_calls;
            recycle?;
            length += window_length;
        }

        if length != expected_length {
            return Err(Error::Unknown(format!(
                "expected length {expected_length} but got {length}"
            )));
        }

        let storage_total_ns = storage_total_start.elapsed().as_nanos() as u64;
        debug!(
            piece_id,
            expected_length,
            rx_windows,
            file_open_ns,
            rx_window_wait_ns,
            digest_ns,
            pwrite_ns,
            pwrite_calls,
            recycle_ns,
            storage_total_ns,
            "finished writing urma piece from registered receive windows"
        );

        Ok(super::io::WriteRangeResponse {
            length,
            hash: hasher.finalize().to_string(),
        })
    }

    /// Returns the task path by task id.
    fn get_task_path(&self, task_id: &str) -> PathBuf {
        // The task needs split by the first 3 characters of task id(sha256) to
        // avoid too many files in one directory.
        let sub_dir = &task_id[..3];
        self.dir
            .join(super::content::DEFAULT_TASK_DIR)
            .join(sub_dir)
            .join(task_id)
    }

    /// Checks if the persistent task and target
    /// are the same device and inode.
    pub async fn is_same_dev_inode_as_persistent_task(
        &self,
        task_id: &str,
        to: &Path,
    ) -> Result<bool> {
        let task_path = self.get_persistent_task_path(task_id);
        self.is_same_dev_inode(&task_path, to).await
    }

    /// Creates a new persistent task content.
    ///
    /// Behavior of `create_persistent_task`:
    /// 1. If the persistent task already exists, return the persistent task path.
    /// 2. If the persistent task does not exist, create the persistent task directory and file.
    #[instrument(level = "debug", skip_all)]
    pub async fn create_persistent_task(&self, task_id: &str, length: u64) -> Result<PathBuf> {
        let task_path = self.get_persistent_task_path(task_id);
        if task_path.exists() {
            return Ok(task_path);
        }

        let task_dir = self
            .dir
            .join(super::content::DEFAULT_PERSISTENT_TASK_DIR)
            .join(&task_id[..3]);
        fs::create_dir_all(&task_dir).await.inspect_err(|err| {
            error!("create {:?} failed: {}", task_dir, err);
        })?;

        let f = fs::File::create(task_dir.join(task_id))
            .await
            .inspect_err(|err| {
                error!("create {:?} failed: {}", task_dir, err);
            })?;

        fallocate(&f, length).await.inspect_err(|err| {
            error!("fallocate {:?} failed: {}", task_dir, err);
        })?;

        Ok(task_dir.join(task_id))
    }

    /// Creates only the directory for the persistent task.
    #[instrument(level = "debug", skip_all)]
    pub async fn create_persistent_task_dir(&self, task_id: &str) -> Result<PathBuf> {
        let task_path = self.get_persistent_task_path(task_id);
        if task_path.exists() {
            return Ok(task_path);
        }

        let task_dir = self
            .dir
            .join(super::content::DEFAULT_PERSISTENT_TASK_DIR)
            .join(&task_id[..3]);
        fs::create_dir_all(&task_dir).await.inspect_err(|err| {
            error!("create {:?} failed: {}", task_dir, err);
        })?;

        Ok(task_dir)
    }

    /// Hard links the persistent task content to the destination.
    ///
    /// Behavior of `hard_link_persistent_task`:
    /// 1. If the destination exists:
    ///    1.1. If the source and destination share the same device and inode, return immediately.
    ///    1.2. Otherwise, return an error.
    /// 2. If the destination does not exist:
    ///    2.1. If the hard link succeeds, return immediately.
    ///    2.2. If the hard link fails, copy the persistent task content to the destination once the task is finished, then return immediately.
    #[instrument(level = "debug", skip_all)]
    pub async fn hard_link_persistent_task(&self, task_id: &str, to: &Path) -> Result<()> {
        let task_path = self.get_persistent_task_path(task_id);
        if let Err(err) = fs::hard_link(task_path.clone(), to).await {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if let Ok(true) = self.is_same_dev_inode(&task_path, to).await {
                    info!("hard already exists, no need to operate");
                    return Ok(());
                }
            }

            warn!("hard link {:?} to {:?} failed: {}", task_path, to, err);
            return Err(Error::IO(err));
        }

        info!("hard link {:?} to {:?} success", task_path, to);
        Ok(())
    }

    /// Hard links a source file to the persistent task content path.
    ///
    /// Behavior:
    /// 1. If the task path exists:
    ///    1.1. If source and task share the same inode, return success.
    ///    1.2. Otherwise, return an error (task content already exists).
    /// 2. If the task path does not exist:
    ///    2.1. Create hard link from source to task path.
    ///    2.2. If hard link fails, return an error.
    #[instrument(level = "debug", skip_all)]
    pub async fn hard_link_to_persistent_task(&self, from: &Path, task_id: &str) -> Result<()> {
        let task_path = self.get_persistent_task_path(task_id);
        if let Err(err) = fs::hard_link(from, &task_path).await {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if let Ok(true) = self.is_same_dev_inode(from, &task_path).await {
                    info!("hard already exists, no need to operate");
                    return Ok(());
                }
            }

            warn!("hard link {:?} to {:?} failed: {}", task_path, from, err);
            return Err(Error::IO(err));
        }

        info!("hard link {:?} to {:?} success", from, task_path);
        Ok(())
    }

    /// Copies the persistent task content to the destination.
    #[instrument(level = "debug", skip_all)]
    pub async fn copy_persistent_task(&self, task_id: &str, to: &Path) -> Result<()> {
        let length = fs::copy(self.get_persistent_task_path(task_id), to).await?;

        // Triggers writeback of the copied content per storage.writebackMode.
        if let Ok(f) = fs::File::open(to).await {
            self.writeback
                .trigger(&Arc::new(f.into_std().await), 0, length)
                .await;
        }

        info!("copy to {:?} success", to);
        Ok(())
    }

    /// Reads the persistent piece from the content.
    #[instrument(level = "debug", skip_all)]
    pub async fn read_persistent_piece(
        &self,
        task_id: &str,
        offset: u64,
        length: u64,
        range: Option<Range>,
    ) -> Result<super::io::RangeReader> {
        let task_path = self.get_persistent_task_path(task_id);

        // Calculate the target offset and length based on the range.
        let (target_offset, target_length) =
            super::content::calculate_piece_range(offset, length, range);

        let fd = self.fd_cache.open(&task_path).await.inspect_err(|err| {
            error!("open {:?} failed: {}", task_path, err);
        })?;

        // Queue readahead of the range explicitly, since interleaved uploads
        // on the shared descriptor break the sequential detection. Skip the
        // small ranges, which the kernel readahead covers quickly.
        if target_length >= MIN_PIECE_LENGTH {
            fadvise_willneed(&fd, target_offset, target_length)
                .await
                .unwrap_or_else(|err| warn!("fadvise_willneed failed: {}", err));
        }

        Ok(super::io::RangeReader::new(
            fd,
            target_offset,
            target_length,
            self.config.storage.read_buffer_size,
            self.buffer_pool.clone(),
        ))
    }

    /// Writes the persistent piece to the content and
    /// calculates the hash of the piece by crc32.
    #[instrument(level = "debug", skip_all)]
    pub async fn write_persistent_piece<R: AsyncRead + Unpin + ?Sized>(
        &self,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        reader: &mut R,
    ) -> Result<super::io::WriteRangeResponse> {
        let task_path = self.get_persistent_task_path(task_id);
        let fd = self
            .fd_cache
            .open_write(&task_path)
            .await
            .inspect_err(|err| {
                error!("open {:?} failed: {}", task_path, err);
            })?;

        let response = super::io::write_range(
            fd.clone(),
            offset,
            expected_length,
            self.config.storage.write_buffer_size,
            reader,
            &self.buffer_pool,
        )
        .await
        .inspect_err(|err| {
            error!("write {:?} failed: {}", task_path, err);
        })?;

        self.writeback.trigger(&fd, offset, response.length).await;
        Ok(response)
    }

    /// Writes the persistent piece from the stream of bytes chunks to the
    /// content and calculates the hash of the piece by crc32.
    #[instrument(level = "debug", skip_all)]
    pub async fn write_persistent_piece_from_stream<S>(
        &self,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        stream: &mut S,
    ) -> Result<super::io::WriteRangeResponse>
    where
        S: Stream<Item = std::io::Result<Bytes>> + Unpin + ?Sized,
    {
        let task_path = self.get_persistent_task_path(task_id);
        let fd = self
            .fd_cache
            .open_write(&task_path)
            .await
            .inspect_err(|err| {
                error!("open {:?} failed: {}", task_path, err);
            })?;

        let response = super::io::write_range_from_stream(
            fd.clone(),
            offset,
            expected_length,
            self.config.storage.write_buffer_size,
            stream,
        )
        .await
        .inspect_err(|err| {
            error!("write {:?} failed: {}", task_path, err);
        })?;

        self.writeback.trigger(&fd, offset, response.length).await;
        Ok(response)
    }

    /// Deletes the persistent task content.
    pub async fn delete_persistent_task(&self, task_id: &str) -> Result<()> {
        info!("delete persistent task content: {}", task_id);
        let persistent_task_path = self.get_persistent_task_path(task_id);

        self.fd_cache
            .remove(&persistent_task_path)
            .unwrap_or_else(|err| {
                error!(
                    "remove {:?} from fd_cache failed: {}",
                    persistent_task_path, err
                );
            });

        fs::remove_file(persistent_task_path.as_path())
            .await
            .inspect_err(|err| {
                error!("remove {:?} failed: {}", persistent_task_path, err);
            })?;
        Ok(())
    }

    /// Drops the cached pages of the persistent task content.
    #[instrument(level = "debug", skip_all)]
    pub async fn fadvise_dontneed_persistent_task(&self, task_id: &str) -> Result<()> {
        let f = fs::File::open(self.get_persistent_task_path(task_id)).await?;
        fadvise_dontneed(&f).await
    }

    /// Returns the persistent task path by task id.
    fn get_persistent_task_path(&self, task_id: &str) -> PathBuf {
        // The persistent task needs split by the first 3 characters of task id(sha256) to
        // avoid too many files in one directory.
        self.dir
            .join(super::content::DEFAULT_PERSISTENT_TASK_DIR)
            .join(&task_id[..3])
            .join(task_id)
    }

    /// Checks if the persistent cache task and target
    /// are the same device and inode.
    pub async fn is_same_dev_inode_as_persistent_cache_task(
        &self,
        task_id: &str,
        to: &Path,
    ) -> Result<bool> {
        let task_path = self.get_persistent_cache_task_path(task_id);
        self.is_same_dev_inode(&task_path, to).await
    }

    /// Creates a new persistent cache task content.
    ///
    /// Behavior of `create_persistent_cache_task`:
    /// 1. If the persistent cache task already exists, return the persistent cache task path.
    /// 2. If the persistent cache task does not exist, create the persistent cache task directory and file.
    #[instrument(level = "debug", skip_all)]
    pub async fn create_persistent_cache_task(
        &self,
        task_id: &str,
        length: u64,
    ) -> Result<PathBuf> {
        let task_path = self.get_persistent_cache_task_path(task_id);
        if task_path.exists() {
            return Ok(task_path);
        }

        let task_dir = self
            .dir
            .join(super::content::DEFAULT_PERSISTENT_CACHE_TASK_DIR)
            .join(&task_id[..3]);
        fs::create_dir_all(&task_dir).await.inspect_err(|err| {
            error!("create {:?} failed: {}", task_dir, err);
        })?;

        let f = fs::File::create(task_dir.join(task_id))
            .await
            .inspect_err(|err| {
                error!("create {:?} failed: {}", task_dir, err);
            })?;

        fallocate(&f, length).await.inspect_err(|err| {
            error!("fallocate {:?} failed: {}", task_dir, err);
        })?;

        Ok(task_dir.join(task_id))
    }

    /// Creates only the directory for the persistent cache task.
    #[instrument(level = "debug", skip_all)]
    pub async fn create_persistent_cache_task_dir(&self, task_id: &str) -> Result<PathBuf> {
        let task_path = self.get_persistent_cache_task_path(task_id);
        if task_path.exists() {
            return Ok(task_path);
        }

        let task_dir = self
            .dir
            .join(super::content::DEFAULT_PERSISTENT_CACHE_TASK_DIR)
            .join(&task_id[..3]);
        fs::create_dir_all(&task_dir).await.inspect_err(|err| {
            error!("create {:?} failed: {}", task_dir, err);
        })?;

        Ok(task_dir)
    }

    /// Hard links the persistent cache task content to the destination.
    ///
    /// Behavior of `hard_link_persistent_cache_task`:
    /// 1. If the destination exists:
    ///    1.1. If the source and destination share the same device and inode, return immediately.
    ///    1.2. Otherwise, return an error.
    /// 2. If the destination does not exist:
    ///    2.1. If the hard link succeeds, return immediately.
    ///    2.2. If the hard link fails, copy the persistent cache task content to the destination once the task is finished, then return immediately.
    #[instrument(level = "debug", skip_all)]
    pub async fn hard_link_persistent_cache_task(&self, task_id: &str, to: &Path) -> Result<()> {
        let task_path = self.get_persistent_cache_task_path(task_id);
        if let Err(err) = fs::hard_link(task_path.clone(), to).await {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if let Ok(true) = self.is_same_dev_inode(&task_path, to).await {
                    info!("hard already exists, no need to operate");
                    return Ok(());
                }
            }

            warn!("hard link {:?} to {:?} failed: {}", task_path, to, err);
            return Err(Error::IO(err));
        }

        info!("hard link {:?} to {:?} success", task_path, to);
        Ok(())
    }

    /// Hard links a source file to the persistent cache task content path.
    ///
    /// Behavior:
    /// 1. If the task path exists:
    ///    1.1. If source and task share the same inode, return success.
    ///    1.2. Otherwise, return an error (task content already exists).
    /// 2. If the task path does not exist:
    ///    2.1. Create hard link from source to task path.
    ///    2.2. If hard link fails, return an error.
    #[instrument(level = "debug", skip_all)]
    pub async fn hard_link_to_persistent_cache_task(
        &self,
        from: &Path,
        task_id: &str,
    ) -> Result<()> {
        let task_path = self.get_persistent_cache_task_path(task_id);
        if let Err(err) = fs::hard_link(from, &task_path).await {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if let Ok(true) = self.is_same_dev_inode(from, &task_path).await {
                    info!("hard already exists, no need to operate");
                    return Ok(());
                }
            }

            warn!("hard link {:?} to {:?} failed: {}", task_path, from, err);
            return Err(Error::IO(err));
        }

        info!("hard link {:?} to {:?} success", from, task_path);
        Ok(())
    }

    /// Copies the persistent cache task content to the destination.
    #[instrument(level = "debug", skip_all)]
    pub async fn copy_persistent_cache_task(&self, task_id: &str, to: &Path) -> Result<()> {
        let length = fs::copy(self.get_persistent_cache_task_path(task_id), to).await?;

        // Triggers writeback of the copied content per storage.writebackMode.
        if let Ok(f) = fs::File::open(to).await {
            self.writeback
                .trigger(&Arc::new(f.into_std().await), 0, length)
                .await;
        }

        info!("copy to {:?} success", to);
        Ok(())
    }

    /// Reads the persistent cache piece from the content.
    #[instrument(level = "debug", skip_all)]
    pub async fn read_persistent_cache_piece(
        &self,
        task_id: &str,
        offset: u64,
        length: u64,
        range: Option<Range>,
    ) -> Result<super::io::RangeReader> {
        let task_path = self.get_persistent_cache_task_path(task_id);

        // Calculate the target offset and length based on the range.
        let (target_offset, target_length) =
            super::content::calculate_piece_range(offset, length, range);

        let fd = self.fd_cache.open(&task_path).await.inspect_err(|err| {
            error!("open {:?} failed: {}", task_path, err);
        })?;

        // Queue readahead of the range explicitly, since interleaved uploads
        // on the shared descriptor break the sequential detection. Skip the
        // small ranges, which the kernel readahead covers quickly.
        if target_length >= MIN_PIECE_LENGTH {
            fadvise_willneed(&fd, target_offset, target_length)
                .await
                .unwrap_or_else(|err| warn!("fadvise_willneed failed: {}", err));
        }

        Ok(super::io::RangeReader::new(
            fd,
            target_offset,
            target_length,
            self.config.storage.read_buffer_size,
            self.buffer_pool.clone(),
        ))
    }

    /// Writes the persistent cache piece to the content and
    /// calculates the hash of the piece by crc32.
    #[instrument(level = "debug", skip_all)]
    pub async fn write_persistent_cache_piece<R: AsyncRead + Unpin + ?Sized>(
        &self,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        reader: &mut R,
    ) -> Result<super::io::WriteRangeResponse> {
        let task_path = self.get_persistent_cache_task_path(task_id);
        let fd = self
            .fd_cache
            .open_write(&task_path)
            .await
            .inspect_err(|err| {
                error!("open {:?} failed: {}", task_path, err);
            })?;

        let response = super::io::write_range(
            fd.clone(),
            offset,
            expected_length,
            self.config.storage.write_buffer_size,
            reader,
            &self.buffer_pool,
        )
        .await
        .inspect_err(|err| {
            error!("write {:?} failed: {}", task_path, err);
        })?;

        self.writeback.trigger(&fd, offset, response.length).await;
        Ok(response)
    }

    /// Writes the persistent cache piece from the stream of bytes chunks to
    /// the content and calculates the hash of the piece by crc32, without
    /// copying the chunks.
    #[instrument(level = "debug", skip_all)]
    pub async fn write_persistent_cache_piece_from_stream<S>(
        &self,
        task_id: &str,
        offset: u64,
        expected_length: u64,
        stream: &mut S,
    ) -> Result<super::io::WriteRangeResponse>
    where
        S: Stream<Item = std::io::Result<Bytes>> + Unpin + ?Sized,
    {
        let task_path = self.get_persistent_cache_task_path(task_id);
        let fd = self
            .fd_cache
            .open_write(&task_path)
            .await
            .inspect_err(|err| {
                error!("open {:?} failed: {}", task_path, err);
            })?;

        let response = super::io::write_range_from_stream(
            fd.clone(),
            offset,
            expected_length,
            self.config.storage.write_buffer_size,
            stream,
        )
        .await
        .inspect_err(|err| {
            error!("write {:?} failed: {}", task_path, err);
        })?;

        self.writeback.trigger(&fd, offset, response.length).await;
        Ok(response)
    }

    /// Deletes the persistent cache task content.
    pub async fn delete_persistent_cache_task(&self, task_id: &str) -> Result<()> {
        info!("delete persistent cache task content: {}", task_id);
        let persistent_cache_task_path = self.get_persistent_cache_task_path(task_id);

        self.fd_cache
            .remove(&persistent_cache_task_path)
            .unwrap_or_else(|err| {
                error!(
                    "remove {:?} from fd_cache failed: {}",
                    persistent_cache_task_path, err
                );
            });

        fs::remove_file(persistent_cache_task_path.as_path())
            .await
            .inspect_err(|err| {
                error!("remove {:?} failed: {}", persistent_cache_task_path, err);
            })?;
        Ok(())
    }

    /// Drops the cached pages of the persistent cache task content.
    #[instrument(level = "debug", skip_all)]
    pub async fn fadvise_dontneed_persistent_cache_task(&self, task_id: &str) -> Result<()> {
        let f = fs::File::open(self.get_persistent_cache_task_path(task_id)).await?;
        fadvise_dontneed(&f).await
    }

    /// Returns the persistent cache task path by task id.
    fn get_persistent_cache_task_path(&self, task_id: &str) -> PathBuf {
        // The persistent cache task needs split by the first 3 characters of task id(sha256) to
        // avoid too many files in one directory.
        self.dir
            .join(super::content::DEFAULT_PERSISTENT_CACHE_TASK_DIR)
            .join(&task_id[..3])
            .join(task_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content;
    use dragonfly_client_config::dfdaemon::WritebackMode;
    use std::io::Cursor;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_write_all_vectored_at_preserves_offset_and_parts() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("pwritev");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(16).unwrap();
        let mut buffers = [
            IoSlice::new(b"abc"),
            IoSlice::new(b"defg"),
            IoSlice::new(b"h"),
        ];

        let calls = write_all_vectored_at(&file, &mut buffers, 4).unwrap();

        assert!(calls >= 1);
        drop(file);
        let contents = std::fs::read(path).unwrap();
        assert_eq!(&contents[..4], &[0; 4]);
        assert_eq!(&contents[4..12], b"abcdefgh");
        assert_eq!(&contents[12..], &[0; 4]);
    }

    #[tokio::test]
    async fn test_create_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "60409bd0ec44160f44c53c39b3fe1c5fdfb23faded0228c68bee83bc15a200e3";
        let task_path = content.create_task(task_id, 0).await.unwrap();
        assert!(task_path.exists());
        assert_eq!(task_path, temp_dir.path().join("content/tasks/604/60409bd0ec44160f44c53c39b3fe1c5fdfb23faded0228c68bee83bc15a200e3"));

        let task_path_exists = content.create_task(task_id, 0).await.unwrap();
        assert_eq!(task_path, task_path_exists);
    }

    #[tokio::test]
    async fn test_hard_link_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4";
        content.create_task(task_id, 0).await.unwrap();

        let to = temp_dir
            .path()
            .join("c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4");
        content.hard_link_task(task_id, &to).await.unwrap();
        assert!(to.exists());

        content.hard_link_task(task_id, &to).await.unwrap();
    }

    #[tokio::test]
    async fn test_copy_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "bfd3c02fb31a7373e25b405fd5fd3082987ccfbaf210889153af9e65bbf13002";
        content.create_task(task_id, 64).await.unwrap();

        let to = temp_dir
            .path()
            .join("bfd3c02fb31a7373e25b405fd5fd3082987ccfbaf210889153af9e65bbf13002");
        content.copy_task(task_id, &to).await.unwrap();
        assert!(to.exists());
    }

    #[tokio::test]
    async fn test_delete_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "4e19f03b0fceb38f23ff4f657681472a53ef335db3660ae5494912570b7a2bb7";
        let task_path = content.create_task(task_id, 0).await.unwrap();
        assert!(task_path.exists());

        content.delete_task(task_id).await.unwrap();
        assert!(!task_path.exists());
    }

    #[tokio::test]
    async fn test_write_piece_writeback_modes() {
        for mode in [
            WritebackMode::Sync,
            WritebackMode::Async,
            WritebackMode::Off,
        ] {
            let temp_dir = tempdir().unwrap();
            let mut config = Config::default();
            config.storage.writeback_mode = mode;
            let content = Content::new(Arc::new(config), temp_dir.path())
                .await
                .unwrap();

            let task_id = "60409bd0ec44160f44c53c39b3fe1c5fdfb23faded0228c68bee83bc15a200e3";
            content.create_task(task_id, 13).await.unwrap();

            let data = b"hello, world!";
            let mut stream = futures::stream::iter([Ok(Bytes::from_static(data))]);
            let response = content
                .write_piece_from_stream(task_id, 0, 13, &mut stream)
                .await
                .unwrap();
            assert_eq!(response.length, 13);

            if mode == WritebackMode::Async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            let mut reader = content.read_piece(task_id, 0, 13, None).await.unwrap();
            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer).await.unwrap();
            assert_eq!(buffer, data);
        }
    }

    #[tokio::test]
    async fn test_fadvise_dontneed_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        content.create_task(task_id, 13).await.unwrap();

        let data = b"hello, world!";
        let mut stream = futures::stream::iter([Ok(Bytes::from_static(data))]);
        content
            .write_piece_from_stream(task_id, 0, 13, &mut stream)
            .await
            .unwrap();

        content.fadvise_dontneed_task(task_id).await.unwrap();

        let mut reader = content.read_piece(task_id, 0, 13, None).await.unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, data);

        assert!(content
            .fadvise_dontneed_task(
                "aaa6963dccfd5b4f60b48845606946cea72084f14ed5cce61ec96e69f80a30f8"
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_fadvise_dontneed_persistent_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        content.create_persistent_task(task_id, 13).await.unwrap();
        content
            .fadvise_dontneed_persistent_task(task_id)
            .await
            .unwrap();

        assert!(content
            .fadvise_dontneed_persistent_task(
                "aaa6963dccfd5b4f60b48845606946cea72084f14ed5cce61ec96e69f80a30f8"
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_fadvise_dontneed_persistent_cache_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        content
            .create_persistent_cache_task(task_id, 13)
            .await
            .unwrap();
        content
            .fadvise_dontneed_persistent_cache_task(task_id)
            .await
            .unwrap();

        assert!(content
            .fadvise_dontneed_persistent_cache_task(
                "aaa6963dccfd5b4f60b48845606946cea72084f14ed5cce61ec96e69f80a30f8"
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_read_piece() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "c794a3bbae81e06d1c8d362509bdd42a7c105b0fb28d80ffe27f94b8f04fc845";
        content.create_task(task_id, 13).await.unwrap();

        let data = b"hello, world!";
        let mut stream = futures::stream::iter([Ok(Bytes::from_static(data))]);
        content
            .write_piece_from_stream(task_id, 0, 13, &mut stream)
            .await
            .unwrap();

        let mut reader = content.read_piece(task_id, 0, 13, None).await.unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, data);

        let mut reader = content
            .read_piece(
                task_id,
                0,
                13,
                Some(Range {
                    start: 0,
                    length: 5,
                }),
            )
            .await
            .unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn test_write_piece() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "60b48845606946cea72084f14ed5cce61ec96e69f80a30f891a6963dccfd5b4f";
        content.create_task(task_id, 4).await.unwrap();

        let data = b"test";
        let mut stream = futures::stream::iter([Ok(Bytes::from_static(data))]);
        let response = content
            .write_piece_from_stream(task_id, 0, 4, &mut stream)
            .await
            .unwrap();
        assert_eq!(response.length, 4);
        assert!(!response.hash.is_empty());
    }

    #[tokio::test]
    async fn test_create_persistent_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "c4f108ab1d2b8cfdffe89ea9676af35123fa02e3c25167d62538f630d5d44745";
        let task_path = content.create_persistent_task(task_id, 0).await.unwrap();
        assert!(task_path.exists());
        assert_eq!(task_path, temp_dir.path().join("content/persistent-tasks/c4f/c4f108ab1d2b8cfdffe89ea9676af35123fa02e3c25167d62538f630d5d44745"));

        let task_path_exists = content.create_persistent_task(task_id, 0).await.unwrap();
        assert_eq!(task_path, task_path_exists);
    }

    #[tokio::test]
    async fn test_hard_link_persistent_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "5e81970eb2b048910cc84cab026b951f2ceac0a09c72c0717193bb6e466e11cd";
        content.create_persistent_task(task_id, 0).await.unwrap();

        let to = temp_dir
            .path()
            .join("5e81970eb2b048910cc84cab026b951f2ceac0a09c72c0717193bb6e466e11cd");
        content
            .hard_link_persistent_task(task_id, &to)
            .await
            .unwrap();
        assert!(to.exists());

        content
            .hard_link_persistent_task(task_id, &to)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_copy_persistent_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "194b9c2018429689fb4e596a506c7e9db564c187b9709b55b33b96881dfb6dd5";
        content.create_persistent_task(task_id, 64).await.unwrap();

        let to = temp_dir
            .path()
            .join("194b9c2018429689fb4e596a506c7e9db564c187b9709b55b33b96881dfb6dd5");
        content.copy_persistent_task(task_id, &to).await.unwrap();
        assert!(to.exists());
    }

    #[tokio::test]
    async fn test_delete_persistent_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "17430ba545c3ce82790e9c9f77e64dca44bb6d6a0c9e18be175037c16c73713d";
        let task_path = content.create_persistent_task(task_id, 0).await.unwrap();
        assert!(task_path.exists());

        content.delete_persistent_task(task_id).await.unwrap();
        assert!(!task_path.exists());
    }

    #[tokio::test]
    async fn test_read_persistent_piece() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "9cb27a4af09aee4eb9f904170217659683f4a0ea7cd55e1a9fbcb99ddced659a";
        content.create_persistent_task(task_id, 13).await.unwrap();

        let data = b"hello, world!";
        let mut reader = Cursor::new(data);
        content
            .write_persistent_piece(task_id, 0, 13, &mut reader)
            .await
            .unwrap();

        let mut reader = content
            .read_persistent_piece(task_id, 0, 13, None)
            .await
            .unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, data);

        let mut reader = content
            .read_persistent_piece(
                task_id,
                0,
                13,
                Some(Range {
                    start: 0,
                    length: 5,
                }),
            )
            .await
            .unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn test_write_persistent_piece() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "ca1afaf856e8a667fbd48093ca3ca1b8eeb4bf735912fbe551676bc5817a720a";
        content.create_persistent_task(task_id, 4).await.unwrap();

        let data = b"test";
        let mut reader = Cursor::new(data);
        let response = content
            .write_persistent_piece(task_id, 0, 4, &mut reader)
            .await
            .unwrap();
        assert_eq!(response.length, 4);
        assert!(!response.hash.is_empty());
    }

    #[tokio::test]
    async fn test_create_persistent_cache_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "c4f108ab1d2b8cfdffe89ea9676af35123fa02e3c25167d62538f630d5d44745";
        let task_path = content
            .create_persistent_cache_task(task_id, 0)
            .await
            .unwrap();
        assert!(task_path.exists());
        assert_eq!(task_path, temp_dir.path().join("content/persistent-cache-tasks/c4f/c4f108ab1d2b8cfdffe89ea9676af35123fa02e3c25167d62538f630d5d44745"));

        let task_path_exists = content
            .create_persistent_cache_task(task_id, 0)
            .await
            .unwrap();
        assert_eq!(task_path, task_path_exists);
    }

    #[tokio::test]
    async fn test_hard_link_persistent_cache_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "5e81970eb2b048910cc84cab026b951f2ceac0a09c72c0717193bb6e466e11cd";
        content
            .create_persistent_cache_task(task_id, 0)
            .await
            .unwrap();

        let to = temp_dir
            .path()
            .join("5e81970eb2b048910cc84cab026b951f2ceac0a09c72c0717193bb6e466e11cd");
        content
            .hard_link_persistent_cache_task(task_id, &to)
            .await
            .unwrap();
        assert!(to.exists());

        content
            .hard_link_persistent_cache_task(task_id, &to)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_copy_persistent_cache_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "194b9c2018429689fb4e596a506c7e9db564c187b9709b55b33b96881dfb6dd5";
        content
            .create_persistent_cache_task(task_id, 64)
            .await
            .unwrap();

        let to = temp_dir
            .path()
            .join("194b9c2018429689fb4e596a506c7e9db564c187b9709b55b33b96881dfb6dd5");
        content
            .copy_persistent_cache_task(task_id, &to)
            .await
            .unwrap();
        assert!(to.exists());
    }

    #[tokio::test]
    async fn test_delete_persistent_cache_task() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "17430ba545c3ce82790e9c9f77e64dca44bb6d6a0c9e18be175037c16c73713d";
        let task_path = content
            .create_persistent_cache_task(task_id, 0)
            .await
            .unwrap();
        assert!(task_path.exists());

        content.delete_persistent_cache_task(task_id).await.unwrap();
        assert!(!task_path.exists());
    }

    #[tokio::test]
    async fn test_read_persistent_cache_piece() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "9cb27a4af09aee4eb9f904170217659683f4a0ea7cd55e1a9fbcb99ddced659a";
        content
            .create_persistent_cache_task(task_id, 13)
            .await
            .unwrap();

        let data = b"hello, world!";
        let mut reader = Cursor::new(data);
        content
            .write_persistent_cache_piece(task_id, 0, 13, &mut reader)
            .await
            .unwrap();

        let mut reader = content
            .read_persistent_cache_piece(task_id, 0, 13, None)
            .await
            .unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, data);

        let mut reader = content
            .read_persistent_cache_piece(
                task_id,
                0,
                13,
                Some(Range {
                    start: 0,
                    length: 5,
                }),
            )
            .await
            .unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn test_write_persistent_cache_piece() {
        let temp_dir = tempdir().unwrap();
        let config = Arc::new(Config::default());
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let task_id = "ca1afaf856e8a667fbd48093ca3ca1b8eeb4bf735912fbe551676bc5817a720a";
        content
            .create_persistent_cache_task(task_id, 4)
            .await
            .unwrap();

        let data = b"test";
        let mut reader = Cursor::new(data);
        let response = content
            .write_persistent_cache_piece(task_id, 0, 4, &mut reader)
            .await
            .unwrap();
        assert_eq!(response.length, 4);
        assert!(!response.hash.is_empty());
    }

    #[tokio::test]
    async fn test_has_enough_space() {
        let config = Arc::new(Config::default());
        let temp_dir = tempdir().unwrap();
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let has_space = content.has_enough_space(1).unwrap();
        assert!(has_space);

        let has_space = content.has_enough_space(u64::MAX).unwrap();
        assert!(!has_space);

        let mut config = Config::default();
        config.gc.policy.disk_threshold = ByteSize::mib(10);
        let config = Arc::new(config);
        let content = Content::new(config, temp_dir.path()).await.unwrap();

        let file_path = Path::new(temp_dir.path())
            .join(content::DEFAULT_CONTENT_DIR)
            .join(content::DEFAULT_TASK_DIR)
            .join("1mib");
        let mut file = fs::File::create(&file_path).await.unwrap();
        let buffer = vec![0u8; ByteSize::mib(1).as_u64() as usize];
        file.write_all(&buffer).await.unwrap();
        file.flush().await.unwrap();

        let has_space = content
            .has_enough_space(ByteSize::mib(9).as_u64() + 1)
            .unwrap();
        assert!(!has_space);

        let has_space = content.has_enough_space(ByteSize::mib(9).as_u64()).unwrap();
        assert!(has_space);
    }
}

#[cfg(all(test, feature = "urma"))]
mod urma_direct_write_tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tempfile::tempdir;

    const WINDOW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    #[tokio::test(flavor = "multi_thread")]
    async fn writes_registered_windows_without_aggregate_buffer() {
        let temp_dir = tempdir().unwrap();
        let content = Content::new(Arc::new(Config::default()), temp_dir.path())
            .await
            .unwrap();
        let task_id = "3fd7e2a2c1b7a5b19a4b3f7f2a9e6c1d3f5a7b9c1e3d5f7a9b1c3e5d7f9a1b3c";
        let payload = b"urma-tail";
        content.create_task(task_id, 10).await.unwrap();
        let (mut reader, recycled) =
            crate::client::urma::UrmaStreamReader::from_test_windows(vec![
                vec![b"ur".to_vec(), b"ma".to_vec()],
                vec![b"-tail".to_vec()],
            ]);

        let response = content
            .write_piece_from_urma_stream(
                "piece",
                task_id,
                1,
                payload.len() as u64,
                &mut reader,
                WINDOW_TIMEOUT,
            )
            .await
            .unwrap();

        assert_eq!(response.hash, crc32fast::hash(payload).to_string());
        assert_eq!(recycled.load(Ordering::Acquire), 2);
        let written = tokio::fs::read(content.get_task_path(task_id))
            .await
            .unwrap();
        assert_eq!(&written[1..], payload);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_registered_window_length_mismatch() {
        let temp_dir = tempdir().unwrap();
        let content = Content::new(Arc::new(Config::default()), temp_dir.path())
            .await
            .unwrap();
        let task_id = "4ad7e2a2c1b7a5b19a4b3f7f2a9e6c1d3f5a7b9c1e3d5f7a9b1c3e5d7f9a1b3c";
        content.create_task(task_id, 8).await.unwrap();
        let (mut reader, _) =
            crate::client::urma::UrmaStreamReader::from_test_windows(vec![vec![b"0123".to_vec()]]);

        let result = content
            .write_piece_from_urma_stream("piece", task_id, 0, 8, &mut reader, WINDOW_TIMEOUT)
            .await;
        let error = match result {
            Ok(_) => panic!("short URMA stream must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("expected length 8 but got 4"));
    }
}
