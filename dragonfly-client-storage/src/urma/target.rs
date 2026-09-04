use super::{ffi::RemoteJettyId, Error, Result};
use std::collections::{hash_map::Entry, HashMap};

pub(crate) type PeerTargetId = u16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerTargetState {
    Active,
    Draining,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerTargetRoute {
    pub(crate) id: PeerTargetId,
    pub(crate) generation: u8,
    pub(crate) state: PeerTargetState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerTargetEntry {
    remote_id: RemoteJettyId,
    route: PeerTargetRoute,
}

#[derive(Default)]
pub(crate) struct PeerTargetRegistry {
    by_id: HashMap<PeerTargetId, PeerTargetEntry>,
    by_remote: HashMap<RemoteJettyId, PeerTargetId>,
}

impl PeerTargetRegistry {
    pub(crate) fn contains(&self, id: PeerTargetId) -> bool {
        self.by_id.contains_key(&id)
    }

    pub(crate) fn register(
        &mut self,
        id: PeerTargetId,
        generation: u8,
        remote_id: RemoteJettyId,
    ) -> Result<()> {
        if id == 0 || generation == 0 {
            return Err(Error::InvalidConfiguration(
                "PeerTarget id and generation must be non-zero".into(),
            ));
        }
        if self.by_id.contains_key(&id) {
            return Err(Error::Protocol(format!(
                "PeerTarget {id} is already registered"
            )));
        }
        match self.by_remote.entry(remote_id) {
            Entry::Occupied(existing) => {
                return Err(Error::Protocol(format!(
                    "remote Jetty identity is already authorized for PeerTarget {}",
                    existing.get()
                )));
            }
            Entry::Vacant(remote) => {
                remote.insert(id);
            }
        }
        self.by_id.insert(
            id,
            PeerTargetEntry {
                remote_id,
                route: PeerTargetRoute {
                    id,
                    generation,
                    state: PeerTargetState::Active,
                },
            },
        );
        Ok(())
    }

    pub(crate) fn resolve(&self, remote_id: RemoteJettyId) -> Result<PeerTargetRoute> {
        let id = self.by_remote.get(&remote_id).ok_or_else(|| {
            Error::Protocol("receive CQE source is not an authorized PeerTarget".into())
        })?;
        Ok(self
            .by_id
            .get(id)
            .expect("remote and id indexes are updated together")
            .route)
    }

    pub(crate) fn begin_draining(&mut self, id: PeerTargetId) -> Result<()> {
        let entry = self
            .by_id
            .get_mut(&id)
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {id}")))?;
        entry.route.state = PeerTargetState::Draining;
        Ok(())
    }

    pub(crate) fn remove(&mut self, id: PeerTargetId) -> Result<()> {
        let entry = self
            .by_id
            .remove(&id)
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {id}")))?;
        self.by_remote.remove(&entry.remote_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(byte: u8, id: u32) -> RemoteJettyId {
        RemoteJettyId {
            eid: [byte; crate::urma::ffi::EID_SIZE],
            uasid: u32::from(byte),
            id,
        }
    }

    #[test]
    fn registry_resolves_full_remote_identity_and_lifecycle() {
        let mut registry = PeerTargetRegistry::default();
        let identity = remote(7, 11);
        registry.register(3, 5, identity).unwrap();
        assert_eq!(
            registry.resolve(identity).unwrap(),
            PeerTargetRoute {
                id: 3,
                generation: 5,
                state: PeerTargetState::Active,
            }
        );

        registry.begin_draining(3).unwrap();
        assert_eq!(
            registry.resolve(identity).unwrap().state,
            PeerTargetState::Draining
        );
        registry.remove(3).unwrap();
        assert!(registry.resolve(identity).is_err());
    }

    #[test]
    fn registry_rejects_duplicate_id_identity_and_zero_generation() {
        let mut registry = PeerTargetRegistry::default();
        let first = remote(1, 1);
        registry.register(1, 1, first).unwrap();
        assert!(registry.register(1, 2, remote(2, 2)).is_err());
        assert!(registry.register(2, 1, first).is_err());
        assert!(registry.register(2, 0, remote(2, 2)).is_err());

        assert_eq!(registry.resolve(first).unwrap().id, 1);
    }
}
