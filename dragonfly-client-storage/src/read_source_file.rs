//! Open-file identity and backing retained by Parent READ sources.
//!
//! Storage may unlink a file without waiting for native cleanup. The open file
//! and each mapping keep that inode alive; a replacement at the same path has
//! a different identity. Neither an open file nor a read-only mapping prevents
//! another writer from overwriting or truncating the inode.

use dragonfly_client_core::{Error, Result};
use std::{fs::File, os::unix::fs::MetadataExt, path::Path, sync::Arc};

/// Identifies an inode while an open file or mapping keeps it alive.
/// This is not a persistent identifier or a version of the inode's contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReadFileIdentity {
    device: u64,
    inode: u64,
}

/// A specific opened content file, independent of its current pathname.
/// Sources must retain this object through verified native retirement.
pub struct ReadSourceFile {
    file: File,
    identity: ReadFileIdentity,
    opened_length: u64,
}

impl ReadSourceFile {
    pub(crate) fn open(path: &Path) -> Result<Arc<Self>> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(Error::InvalidParameter);
        }
        Ok(Arc::new(Self {
            identity: ReadFileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            opened_length: metadata.len(),
            file,
        }))
    }

    pub fn identity(&self) -> ReadFileIdentity {
        self.identity
    }

    /// Size captured at open, for owner-side range planning without filesystem
    /// calls. It is neither a completion check nor protection against truncate.
    pub fn opened_length(&self) -> u64 {
        self.opened_length
    }

    /// Tests the opened inode, not a path which may already name a replacement.
    /// A remaining hard link keeps this false even if Storage removed its path.
    pub fn is_unlinked(&self) -> Result<bool> {
        Ok(self.file.metadata()?.nlink() == 0)
    }

    /// Current logical file size, not the number of allocated disk bytes.
    pub fn file_length(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Maps a range using the same file handle that supplied the identity.
    /// File length only validates bounds; it does not prove Piece completion.
    ///
    /// # Safety
    /// Storage must have completed this range and prohibit overwrite/truncate
    /// until the mapping and any native registration using it are released.
    pub(crate) unsafe fn map_range(
        self: &Arc<Self>,
        offset: u64,
        length: u64,
    ) -> Result<MappedPiece> {
        let end = offset.checked_add(length).ok_or(Error::InvalidParameter)?;
        let mapped_length = usize::try_from(length).map_err(|_| Error::InvalidParameter)?;
        if length == 0 || mapped_length > isize::MAX as usize || end > self.file_length()? {
            return Err(Error::InvalidParameter);
        }
        // SAFETY: the caller guarantees immutable completed bytes. Both mmap
        // and fstat use this opened file, even if its pathname was replaced.
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .offset(offset)
                .len(mapped_length)
                .map(&self.file)
        }?;
        mmap.advise(memmap2::Advice::Sequential).ok();
        mmap.advise(memmap2::Advice::WillNeed).ok();
        Ok(MappedPiece {
            mmap,
            source: self.clone(),
            offset,
        })
    }
}

/// A read-only mapping of completed bytes and the exact opened file it uses.
/// Moving it into a native Source retains both resources through retirement.
pub struct MappedPiece {
    mmap: memmap2::Mmap,
    source: Arc<ReadSourceFile>,
    offset: u64,
}

impl MappedPiece {
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap
    }

    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mmap.is_empty()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn source_file(&self) -> &Arc<ReadSourceFile> {
        &self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn unlink_and_recreate_separates_old_mapping_from_new_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("same-task");
        fs::write(&path, b"old piece").unwrap();
        let old = ReadSourceFile::open(&path).unwrap();
        let identity = old.identity();
        // SAFETY: these completed bytes are never overwritten or truncated.
        let mapped = unsafe { old.map_range(0, 9) }.unwrap();
        drop(old);

        fs::remove_file(&path).unwrap();
        assert!(mapped.source_file().is_unlinked().unwrap());
        fs::write(&path, b"new piece").unwrap();
        let new = ReadSourceFile::open(&path).unwrap();
        assert_ne!(identity, new.identity());
        assert!(!new.is_unlinked().unwrap());
        assert_eq!(mapped.as_slice(), b"old piece");
        // SAFETY: the replacement's bytes also remain immutable.
        let replacement = unsafe { new.map_range(0, 9) }.unwrap();
        assert_eq!(replacement.as_slice(), b"new piece");
    }

    #[test]
    fn replacement_between_open_and_map_still_maps_opened_inode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("task");
        fs::write(&path, b"original").unwrap();
        let opened = ReadSourceFile::open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replaced").unwrap();
        // SAFETY: unlink does not modify the opened inode's contents.
        let mapped = unsafe { opened.map_range(1, 5) }.unwrap();
        assert_eq!(mapped.offset(), 1);
        assert_eq!(mapped.as_slice(), b"rigin");
        assert_eq!(mapped.source_file().identity(), opened.identity());
        assert!(mapped.source_file().is_unlinked().unwrap());
    }

    #[test]
    fn hard_link_shares_identity_and_delays_unlinked_detection() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("task");
        let link = dir.path().join("export");
        fs::write(&path, b"piece").unwrap();
        fs::hard_link(&path, &link).unwrap();
        let opened = ReadSourceFile::open(&path).unwrap();
        let alias = ReadSourceFile::open(&link).unwrap();
        assert_eq!(opened.identity(), alias.identity());
        fs::remove_file(path).unwrap();
        assert!(!opened.is_unlinked().unwrap());
        fs::remove_file(link).unwrap();
        assert!(opened.is_unlinked().unwrap());
    }

    #[test]
    fn range_validation_rejects_empty_overflow_and_out_of_bounds() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("task");
        fs::write(&path, b"piece").unwrap();
        let opened = ReadSourceFile::open(&path).unwrap();
        for (offset, length) in [(0, 0), (4, 2), (u64::MAX, 1)] {
            // SAFETY: no file mutation; invalid ranges must fail before mmap.
            assert!(unsafe { opened.map_range(offset, length) }.is_err());
        }
        assert_eq!(opened.file_length().unwrap(), 5);
    }
}
