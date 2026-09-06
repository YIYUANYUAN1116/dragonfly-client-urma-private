use super::{
    ffi::RemoteJettyId,
    transfer::{RoutingToken, TransferRegistry},
    Error, Result,
};
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

struct PeerTargetEntry<T> {
    remote_id: RemoteJettyId,
    route: PeerTargetRoute,
    transfers: TransferRegistry<T>,
}

pub(crate) struct PeerTargetRegistry<T> {
    by_id: HashMap<PeerTargetId, PeerTargetEntry<T>>,
    // A process-shared remote RM endpoint can be referenced by more than one
    // control session. Keep every logical PeerTarget alias; receive routing
    // disambiguates aliases with the routing token registered by the session.
    by_remote: HashMap<RemoteJettyId, HashSet<PeerTargetId>>,
}

impl<T> Default for PeerTargetRegistry<T> {
    fn default() -> Self {
        Self {
            by_id: HashMap::new(),
            by_remote: HashMap::new(),
        }
    }
}

impl<T> PeerTargetRegistry<T> {
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
                transfers: TransferRegistry::default(),
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

    pub(crate) fn contains_routing_token(&self, id: PeerTargetId, token: RoutingToken) -> bool {
        self.by_id
            .get(&id)
            .is_some_and(|entry| entry.transfers.contains(token))
    }

    pub(crate) fn contains_transfer(&self, id: PeerTargetId, token: RoutingToken) -> bool {
        self.by_id
            .get(&id)
            .is_some_and(|entry| entry.transfers.contains_transfer(token))
    }

    pub(crate) fn register_routing_token(
        &mut self,
        id: PeerTargetId,
        token: RoutingToken,
        value: T,
    ) -> Result<()> {
        self.validate_routing_token(id, token)?;
        let entry = self
            .by_id
            .get_mut(&id)
            .expect("PeerTarget validated before routing token insertion");
        entry.transfers.insert(token, value)
    }

    pub(crate) fn validate_routing_token(
        &self,
        id: PeerTargetId,
        token: RoutingToken,
    ) -> Result<()> {
        let entry = self
            .by_id
            .get(&id)
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {id}")))?;
        if entry.route.state != PeerTargetState::Active {
            return Err(Error::Protocol(format!(
                "cannot register transfer for draining PeerTarget {id}"
            )));
        }
        if entry.transfers.contains(token) {
            return Err(Error::Protocol(format!(
                "registered RX routing token is already active for PeerTarget {id}"
            )));
        }
        Ok(())
    }

    pub(crate) fn take_routing_token(
        &mut self,
        id: PeerTargetId,
        token: RoutingToken,
    ) -> Option<T> {
        self.by_id
            .get_mut(&id)
            .and_then(|entry| entry.transfers.remove(token))
    }

    pub(crate) fn drain_routing_tokens(&mut self, id: PeerTargetId) -> Result<Vec<T>> {
        let entry = self
            .by_id
            .get_mut(&id)
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {id}")))?;
        Ok(entry.transfers.drain())
    }

    pub(crate) fn drain_all_routing_tokens(&mut self) -> Vec<T> {
        self.by_id
            .values_mut()
            .flat_map(|entry| entry.transfers.drain())
            .collect()
    }

    pub(crate) fn has_routing_tokens(&self, id: PeerTargetId) -> bool {
        self.by_id
            .get(&id)
            .is_some_and(|entry| !entry.transfers.is_empty())
    }

    pub(crate) fn routing_token_count(&self) -> usize {
        self.by_id.values().map(|entry| entry.transfers.len()).sum()
    }

    pub(crate) fn remove(&mut self, id: PeerTargetId) -> Result<()> {
        if self.has_routing_tokens(id) {
            return Err(Error::Protocol(format!(
                "cannot remove PeerTarget {id} with registered transfers"
            )));
        }
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
        let mut registry = PeerTargetRegistry::<()>::default();
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
        let mut registry = PeerTargetRegistry::<()>::default();
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

    #[test]
    fn transfer_registries_are_peer_local_and_drained_with_the_peer() {
        let mut registry = PeerTargetRegistry::<&'static str>::default();
        let identity = remote(1, 1);
        registry.register(1, 1, identity).unwrap();
        registry.register(2, 1, identity).unwrap();
        let token = RoutingToken::decode(RoutingToken::encode(7, 3).unwrap()).unwrap();

        registry.register_routing_token(1, token, "peer-1").unwrap();
        registry.register_routing_token(2, token, "peer-2").unwrap();
        assert_eq!(registry.routing_token_count(), 2);
        assert!(registry.contains_routing_token(1, token));
        assert!(registry.contains_routing_token(2, token));

        registry.begin_draining(1).unwrap();
        assert!(registry
            .register_routing_token(
                1,
                RoutingToken::decode(RoutingToken::encode(8, 0).unwrap()).unwrap(),
                "late"
            )
            .is_err());
        assert_eq!(registry.drain_routing_tokens(1).unwrap(), vec!["peer-1"]);
        registry.remove(1).unwrap();
        assert_eq!(registry.take_routing_token(2, token), Some("peer-2"));
    }
}
