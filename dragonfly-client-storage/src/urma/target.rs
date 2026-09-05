use super::{ffi::RemoteJettyId, Error, Result};
use std::collections::{HashMap, HashSet};

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
    // A process-shared remote RM endpoint can be referenced by more than one
    // control session. Keep every logical PeerTarget alias; receive routing
    // disambiguates aliases with the routing token registered by the session.
    by_remote: HashMap<RemoteJettyId, HashSet<PeerTargetId>>,
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
        self.by_remote.entry(remote_id).or_default().insert(id);
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

    pub(crate) fn routes(&self, remote_id: RemoteJettyId) -> Result<Vec<PeerTargetRoute>> {
        let ids = self.by_remote.get(&remote_id).ok_or_else(|| {
            Error::Protocol("receive CQE source is not an authorized PeerTarget".into())
        })?;
        Ok(ids
            .iter()
            .map(|id| {
                self.by_id
                    .get(id)
                    .expect("remote and id indexes are updated together")
                    .route
            })
            .collect())
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
        if let Some(ids) = self.by_remote.get_mut(&entry.remote_id) {
            ids.remove(&id);
            if ids.is_empty() {
                self.by_remote.remove(&entry.remote_id);
            }
        }
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
            registry.routes(identity).unwrap()[0],
            PeerTargetRoute {
                id: 3,
                generation: 5,
                state: PeerTargetState::Active,
            }
        );

        registry.begin_draining(3).unwrap();
        assert_eq!(
            registry.routes(identity).unwrap()[0].state,
            PeerTargetState::Draining
        );
        registry.remove(3).unwrap();
        assert!(registry.routes(identity).is_err());
    }

    #[test]
    fn registry_rejects_duplicate_id_and_zero_generation_but_allows_identity_aliases() {
        let mut registry = PeerTargetRegistry::default();
        let first = remote(1, 1);
        registry.register(1, 1, first).unwrap();
        assert!(registry.register(1, 2, remote(2, 2)).is_err());
        registry.register(2, 1, first).unwrap();
        assert!(registry.register(3, 0, remote(2, 2)).is_err());

        let mut aliases = registry
            .routes(first)
            .unwrap()
            .into_iter()
            .map(|route| route.id)
            .collect::<Vec<_>>();
        aliases.sort_unstable();
        assert_eq!(aliases, vec![1, 2]);
    }
}
