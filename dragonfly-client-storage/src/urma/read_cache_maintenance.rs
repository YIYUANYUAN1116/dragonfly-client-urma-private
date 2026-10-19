//! Filesystem inspection only. Native ownership and retirement decisions stay
//! on the fabric owner. One bounded batch can be in flight at a time.

use super::{read_registry::ReadOwnerId, Error, Result};
use crate::content::ReadSourceFile;
use std::{
    sync::{mpsc, Weak},
    thread::{self, JoinHandle},
};

type Files = Vec<(ReadOwnerId, Weak<ReadSourceFile>)>;

pub(crate) struct ScanResult {
    pub(crate) unlinked: Vec<ReadOwnerId>,
    pub(crate) errors: Vec<(ReadOwnerId, String)>,
}

pub(crate) struct FileScanner {
    requests: Option<mpsc::SyncSender<Files>>,
    results: mpsc::Receiver<ScanResult>,
    join: Option<JoinHandle<()>>,
    pending: bool,
}

impl FileScanner {
    pub(crate) fn start() -> Result<Self> {
        let (requests, jobs) = mpsc::sync_channel::<Files>(1);
        let (results_tx, results) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("urma-cache-fstat".into())
            .spawn(move || {
                while let Ok(files) = jobs.recv() {
                    let mut result = ScanResult {
                        unlinked: Vec::new(),
                        errors: Vec::new(),
                    };
                    for (id, weak) in files {
                        let Some(file) = weak.upgrade() else { continue };
                        match file.is_unlinked() {
                            Ok(true) => result.unlinked.push(id),
                            Ok(false) => (),
                            Err(error) => result.errors.push((id, error.to_string())),
                        }
                    }
                    if results_tx.send(result).is_err() {
                        break;
                    }
                }
            })
            .map_err(|error| Error::Protocol(format!("cache scanner start: {error}")))?;
        Ok(Self {
            requests: Some(requests),
            results,
            join: Some(join),
            pending: false,
        })
    }

    pub(crate) fn submit(&mut self, files: Files) -> Result<()> {
        if self.pending {
            return Ok(());
        }
        self.requests
            .as_ref()
            .ok_or_else(|| Error::Protocol("cache scanner stopped".into()))?
            .try_send(files)
            .map_err(|error| Error::Protocol(format!("cache scanner submit: {error}")))?;
        self.pending = true;
        Ok(())
    }

    pub(crate) fn poll(&mut self) -> Result<Option<ScanResult>> {
        match self.results.try_recv() {
            Ok(result) => {
                self.pending = false;
                Ok(Some(result))
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                Err(Error::Protocol("cache scanner lost".into()))
            }
        }
    }

    /// Dropping the producer stops the inspector after its current batch. No
    /// caller joins a potentially blocked filesystem syscall synchronously.
    pub(crate) fn stop(&mut self) {
        self.requests.take();
    }

    pub(crate) fn stopped(&self) -> bool {
        self.join.as_ref().is_none_or(|join| join.is_finished())
    }

    pub(crate) fn join(&mut self) -> Result<()> {
        if !self.stopped() {
            return Err(Error::Protocol("cache scanner still running".into()));
        }
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| Error::Protocol("cache scanner panicked".into()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::read_registry::{ReadBudget, ReadCapacity, ReadOwnerRegistry};
    use std::{
        fs,
        sync::Arc,
        time::{Duration, Instant},
    };

    fn scan(scanner: &mut FileScanner, files: Files) -> ScanResult {
        scanner.submit(files).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(result) = scanner.poll().unwrap() {
                return result;
            }
            assert!(Instant::now() < deadline, "scanner stalled");
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn scanner_checks_open_inode_and_hardlinks_without_retaining_queued_files() {
        let cap = ReadCapacity {
            bytes: 128,
            entries: 8,
        };
        let mut registry = ReadOwnerRegistry::<()>::new(ReadBudget {
            total: ReadCapacity {
                bytes: 256,
                entries: 16,
            },
            source: cap,
            destination: cap,
            per_peer_source: cap,
            per_peer_destination: cap,
            quarantine: cap,
        })
        .unwrap();
        let old_id = registry.reserve_source(1).unwrap();
        let new_id = registry.reserve_source(1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("task");
        let alias = dir.path().join("alias");
        fs::write(&path, [1; 8]).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        let old = ReadSourceFile::open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, [2; 8]).unwrap();
        let replacement = ReadSourceFile::open(&path).unwrap();
        let mut scanner = FileScanner::start().unwrap();
        let files = || {
            vec![
                (old_id, Arc::downgrade(&old)),
                (new_id, Arc::downgrade(&replacement)),
            ]
        };
        assert!(scan(&mut scanner, files()).unlinked.is_empty());
        fs::remove_file(&alias).unwrap();
        let result = scan(&mut scanner, files());
        assert_eq!(result.unlinked, vec![old_id]);
        assert!(result.errors.is_empty());
        let weak = Arc::downgrade(&old);
        let queued = vec![(old_id, weak.clone())];
        drop(old);
        assert!(weak.upgrade().is_none());
        assert!(scan(&mut scanner, queued).unlinked.is_empty());
        scanner.stop();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !scanner.stopped() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        scanner.join().unwrap();
    }
}
