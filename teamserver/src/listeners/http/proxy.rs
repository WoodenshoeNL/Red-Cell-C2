//! Trusted-proxy detection and external-IP extraction.

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::http::Request;
use red_cell_common::HttpListenerConfig;

use crate::listeners::ListenerManagerError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TrustedProxyPeer {
    Address(IpAddr),
    Network(TrustedProxyNetwork),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustedProxyNetwork {
    pub(super) network: IpAddr,
    pub(super) prefix_len: u8,
}

impl TrustedProxyNetwork {
    pub(super) fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = prefix_mask_u32(self.prefix_len);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = prefix_mask_u128(self.prefix_len);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

pub(crate) fn extract_external_ip(
    behind_redirector: bool,
    trusted_proxy_peers: &[TrustedProxyPeer],
    peer: SocketAddr,
    request: &Request<Body>,
) -> IpAddr {
    if behind_redirector && peer_is_trusted_proxy(peer.ip(), trusted_proxy_peers) {
        if let Some(ip) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| forwarded_for_client_ip(value, trusted_proxy_peers))
        {
            return ip;
        }

        if let Some(ip) = request
            .headers()
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .and_then(|value| value.parse::<IpAddr>().ok())
        {
            return ip;
        }
    }

    peer.ip()
}

pub(crate) fn parse_trusted_proxy_peer(
    value: &str,
    listener_name: &str,
) -> Result<TrustedProxyPeer, ListenerManagerError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: value must not be empty"
            ),
        });
    }

    if let Ok(address) = trimmed.parse::<IpAddr>() {
        return Ok(TrustedProxyPeer::Address(address));
    }

    let Some((network, prefix_len)) = trimmed.split_once('/') else {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` must be an IP address or CIDR"
            ),
        });
    };

    let network = network.parse::<IpAddr>().map_err(|_| ListenerManagerError::InvalidConfig {
        message: format!(
            "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` must be an IP address or CIDR"
        ),
    })?;
    let prefix_len =
        prefix_len.parse::<u8>().map_err(|_| ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` has an invalid prefix length"
            ),
        })?;
    let max_prefix_len = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len > max_prefix_len {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` has an invalid prefix length"
            ),
        });
    }

    Ok(TrustedProxyPeer::Network(TrustedProxyNetwork { network, prefix_len }))
}

/// Parse all `trusted_proxy_peers` entries from an [`HttpListenerConfig`].
pub(super) fn parse_trusted_proxy_peers(
    config: &HttpListenerConfig,
) -> Result<Vec<TrustedProxyPeer>, ListenerManagerError> {
    config
        .trusted_proxy_peers
        .iter()
        .map(|value| parse_trusted_proxy_peer(value, &config.name))
        .collect()
}

pub(super) fn peer_is_trusted_proxy(
    peer_ip: IpAddr,
    trusted_proxy_peers: &[TrustedProxyPeer],
) -> bool {
    trusted_proxy_peers.iter().any(|entry| match entry {
        TrustedProxyPeer::Address(address) => *address == peer_ip,
        TrustedProxyPeer::Network(network) => network.contains(peer_ip),
    })
}

fn prefix_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix_len)) }
}

fn prefix_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix_len)) }
}

fn forwarded_for_client_ip(
    value: &str,
    trusted_proxy_peers: &[TrustedProxyPeer],
) -> Option<IpAddr> {
    let hops = value
        .split(',')
        .map(str::trim)
        .map(|hop| (!hop.is_empty()).then_some(hop))
        .collect::<Option<Vec<_>>>()?;
    if hops.is_empty() {
        return None;
    }

    let hops =
        hops.into_iter().map(|hop| hop.parse::<IpAddr>().ok()).collect::<Option<Vec<_>>>()?;

    for hop in hops.into_iter().rev() {
        if peer_is_trusted_proxy(hop, trusted_proxy_peers) {
            continue;
        }
        return Some(hop);
    }

    None
}
