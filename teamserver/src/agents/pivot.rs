//! Pivot chain tracking for SMB-linked agent relationships.

use tracing::instrument;

use crate::database::{LinkRecord, TeamserverError};

use super::{AgentRegistry, MAX_PIVOT_CHAIN_DEPTH};

/// Parent and child pivot metadata associated with an agent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PivotInfo {
    /// Upstream parent agent identifier, if one exists.
    pub parent: Option<u32>,
    /// Downstream linked child agent identifiers.
    pub children: Vec<u32>,
}

impl AgentRegistry {
    /// Return the parent agent, if any, for `agent_id`.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn parent_of(&self, agent_id: u32) -> Option<u32> {
        let parent_links = self.parent_links.read().await;
        parent_links.get(&agent_id).copied()
    }

    /// Return all directly linked child agents for `agent_id`.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn children_of(&self, agent_id: u32) -> Vec<u32> {
        let child_links = self.child_links.read().await;
        child_links
            .get(&agent_id)
            .map(|children| children.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Return the current pivot parent and child links for `agent_id`.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn pivots(&self, agent_id: u32) -> PivotInfo {
        PivotInfo {
            parent: self.parent_of(agent_id).await,
            children: self.children_of(agent_id).await,
        }
    }

    /// Persist and register a parent/child SMB pivot relationship.
    ///
    /// Holds the `parent_links` write lock for the entire check-and-insert
    /// sequence to prevent TOCTOU races that could create pivot cycles.
    #[instrument(skip(self), fields(parent_agent_id = format_args!("0x{:08X}", parent_agent_id), link_agent_id = format_args!("0x{:08X}", link_agent_id)))]
    pub async fn add_link(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
    ) -> Result<(), TeamserverError> {
        self.entry(parent_agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: parent_agent_id })?;
        self.entry(link_agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: link_agent_id })?;

        if parent_agent_id == link_agent_id {
            return Err(TeamserverError::InvalidPivotLink {
                message: "agent cannot pivot to itself".to_owned(),
            });
        }

        let mut parent_links = self.parent_links.write().await;

        {
            let mut current = Some(parent_agent_id);
            let mut steps: usize = 0;
            while let Some(agent_id) = current {
                if agent_id == link_agent_id {
                    return Err(TeamserverError::InvalidPivotLink {
                        message: format!(
                            "linking 0x{parent_agent_id:08X} -> 0x{link_agent_id:08X} would create a cycle"
                        ),
                    });
                }
                steps = steps.saturating_add(1);
                if steps > MAX_PIVOT_CHAIN_DEPTH {
                    break;
                }
                current = parent_links.get(&agent_id).copied();
            }
        }

        {
            let mut depth: usize = 0;
            let mut current = parent_agent_id;
            while let Some(parent) = parent_links.get(&current).copied() {
                depth = depth.saturating_add(1);
                if depth > MAX_PIVOT_CHAIN_DEPTH {
                    break;
                }
                current = parent;
            }
            if depth >= MAX_PIVOT_CHAIN_DEPTH {
                return Err(TeamserverError::InvalidPivotLink {
                    message: format!(
                        "pivot chain depth would exceed MAX_PIVOT_CHAIN_DEPTH ({MAX_PIVOT_CHAIN_DEPTH})"
                    ),
                });
            }
        }

        let existing_parent = parent_links.get(&link_agent_id).copied();
        if existing_parent == Some(parent_agent_id) {
            return Ok(());
        }

        if let Some(previous_parent) = existing_parent {
            self.link_repository.delete(previous_parent, link_agent_id).await?;
            parent_links.remove(&link_agent_id);
            let mut child_links = self.child_links.write().await;
            if let Some(children) = child_links.get_mut(&previous_parent) {
                children.remove(&link_agent_id);
                if children.is_empty() {
                    child_links.remove(&previous_parent);
                }
            }
        }

        self.link_repository.create(LinkRecord { parent_agent_id, link_agent_id }).await?;
        parent_links.insert(link_agent_id, parent_agent_id);
        self.child_links.write().await.entry(parent_agent_id).or_default().insert(link_agent_id);
        Ok(())
    }

    /// Remove a specific pivot relationship and mark the downstream subtree inactive.
    #[instrument(skip(self, reason), fields(parent_agent_id = format_args!("0x{:08X}", parent_agent_id), link_agent_id = format_args!("0x{:08X}", link_agent_id)))]
    pub async fn disconnect_link(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
        reason: impl Into<String>,
    ) -> Result<Vec<u32>, TeamserverError> {
        let reason = reason.into();
        if self.parent_of(link_agent_id).await != Some(parent_agent_id) {
            return Ok(Vec::new());
        }

        let mut affected = vec![link_agent_id];
        affected.extend(self.child_subtree(link_agent_id).await);
        for agent_id in &affected {
            self.mark_subtree_member_dead(*agent_id, &reason).await?;
        }

        self.clear_links_for_agent(link_agent_id).await?;
        self.link_repository.delete(parent_agent_id, link_agent_id).await?;
        self.remove_link_from_memory(parent_agent_id, link_agent_id).await;
        Ok(affected)
    }

    #[cfg(test)]
    pub(super) async fn pivot_chain_depth(&self, agent_id: u32) -> usize {
        let mut depth = 0usize;
        let mut current = agent_id;
        while let Some(parent) = self.parent_of(current).await {
            depth = depth.saturating_add(1);
            if depth > MAX_PIVOT_CHAIN_DEPTH {
                break;
            }
            current = parent;
        }
        depth
    }

    pub(super) async fn child_subtree(&self, agent_id: u32) -> Vec<u32> {
        let mut descendants = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack = self.children_of(agent_id).await;

        while let Some(child_id) = stack.pop() {
            if !visited.insert(child_id) {
                continue;
            }
            descendants.push(child_id);
            stack.extend(self.children_of(child_id).await);
        }

        descendants.sort_unstable();
        descendants
    }

    pub(super) async fn clear_links_for_agent(&self, agent_id: u32) -> Result<(), TeamserverError> {
        if let Some(parent_agent_id) = self.parent_of(agent_id).await {
            self.link_repository.delete(parent_agent_id, agent_id).await?;
            self.remove_link_from_memory(parent_agent_id, agent_id).await;
        }

        let children = self.children_of(agent_id).await;
        for child_id in children {
            self.link_repository.delete(agent_id, child_id).await?;
            self.remove_link_from_memory(agent_id, child_id).await;
        }

        Ok(())
    }

    pub(super) async fn remove_link_from_memory(&self, parent_agent_id: u32, link_agent_id: u32) {
        self.parent_links.write().await.remove(&link_agent_id);
        let mut child_links = self.child_links.write().await;
        if let Some(children) = child_links.get_mut(&parent_agent_id) {
            children.remove(&link_agent_id);
            if children.is_empty() {
                child_links.remove(&parent_agent_id);
            }
        }
    }
}

pub(super) fn encode_pivot_job_payload(
    target_agent_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>, TeamserverError> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| TeamserverError::PayloadTooLarge { length: payload.len() })?;

    let mut inner = Vec::new();
    inner.extend_from_slice(&target_agent_id.to_le_bytes());
    inner.extend_from_slice(&payload_len.to_le_bytes());
    inner.extend_from_slice(payload);

    let inner_len = u32::try_from(inner.len())
        .map_err(|_| TeamserverError::PayloadTooLarge { length: inner.len() })?;

    let mut outer = Vec::new();
    outer.extend_from_slice(
        &u32::from(red_cell_common::demon::DemonPivotCommand::SmbCommand).to_le_bytes(),
    );
    outer.extend_from_slice(&target_agent_id.to_le_bytes());
    outer.extend_from_slice(&inner_len.to_le_bytes());
    outer.extend_from_slice(&inner);
    Ok(outer)
}
