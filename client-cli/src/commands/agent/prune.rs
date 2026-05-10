//! `agent prune` — bulk-deregister stale agents from the teamserver registry.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{instrument, warn};

use super::kill::{KillMode, kill};
use super::list::list;
use super::types::PruneResult;
use crate::client::ApiClient;
use crate::error::CliError;

fn parse_timestamp(s: &str) -> Result<OffsetDateTime, CliError> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|_| CliError::InvalidArgs(format!("invalid RFC 3339 timestamp: {s:?}")))
}

fn agent_last_seen_before(last_seen: &str, cutoff: &OffsetDateTime) -> bool {
    match OffsetDateTime::parse(last_seen, &Rfc3339) {
        Ok(ts) => ts < *cutoff,
        Err(_) => {
            warn!(last_seen, "prune: could not parse agent last_seen timestamp — skipping");
            false
        }
    }
}

/// Bulk-deregister agents matching the given criteria.
///
/// Fetches the full agent list, filters by the supplied criteria, then calls
/// `DELETE /agents/{id}?deregister_only=true` for each match.  At least one
/// of `before` or `dead` must be specified; passing neither returns
/// [`CliError::InvalidArgs`].
///
/// Agents matching **any** of the supplied criteria are pruned (OR semantics).
#[instrument(skip(client))]
pub(crate) async fn prune(
    client: &ApiClient,
    before: Option<&str>,
    dead: bool,
) -> Result<PruneResult, CliError> {
    if before.is_none() && !dead {
        return Err(CliError::InvalidArgs(
            "agent prune requires at least one filter: --before <timestamp> and/or --dead"
                .to_owned(),
        ));
    }

    let cutoff = before.map(parse_timestamp).transpose()?;
    let agents = list(client).await?;

    let to_prune: Vec<_> = agents
        .into_iter()
        .filter(|a| {
            (dead && a.status == "dead")
                || cutoff.as_ref().is_some_and(|ts| agent_last_seen_before(&a.last_seen, ts))
        })
        .collect();

    let total_matched = to_prune.len() as u32;
    let mut pruned = 0u32;
    let mut failed = 0u32;

    for agent in to_prune {
        match kill(client, agent.id, KillMode::DeregisterOnly).await {
            Ok(_) => pruned += 1,
            Err(e) => {
                warn!(agent_id = %agent.id, error = %e, "prune: failed to deregister agent");
                failed += 1;
            }
        }
    }

    Ok(PruneResult { pruned, failed, total_matched })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timestamp_accepts_utc_rfc3339() {
        let ts = parse_timestamp("2026-05-10T00:00:00Z");
        assert!(ts.is_ok(), "valid UTC RFC 3339 must parse; got: {ts:?}");
    }

    #[test]
    fn parse_timestamp_accepts_offset_rfc3339() {
        let ts = parse_timestamp("2026-05-10T02:00:00+02:00");
        assert!(ts.is_ok(), "RFC 3339 with offset must parse; got: {ts:?}");
    }

    #[test]
    fn parse_timestamp_rejects_non_rfc3339() {
        let err = parse_timestamp("2026-05-10").unwrap_err();
        assert!(
            matches!(err, CliError::InvalidArgs(_)),
            "non-RFC-3339 string must return InvalidArgs; got: {err:?}"
        );
    }

    #[test]
    fn parse_timestamp_rejects_garbage() {
        let err = parse_timestamp("not-a-date").unwrap_err();
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn agent_last_seen_before_returns_true_when_older() {
        let cutoff = parse_timestamp("2026-05-10T12:00:00Z").unwrap();
        assert!(agent_last_seen_before("2026-05-10T06:00:00Z", &cutoff));
    }

    #[test]
    fn agent_last_seen_before_returns_false_when_newer() {
        let cutoff = parse_timestamp("2026-05-10T06:00:00Z").unwrap();
        assert!(!agent_last_seen_before("2026-05-10T12:00:00Z", &cutoff));
    }

    #[test]
    fn agent_last_seen_before_returns_false_when_equal() {
        let cutoff = parse_timestamp("2026-05-10T06:00:00Z").unwrap();
        assert!(!agent_last_seen_before("2026-05-10T06:00:00Z", &cutoff));
    }

    #[test]
    fn agent_last_seen_before_returns_false_on_unparseable_timestamp() {
        let cutoff = parse_timestamp("2026-05-10T12:00:00Z").unwrap();
        // malformed server timestamp must not panic and must be skipped (false)
        assert!(!agent_last_seen_before("not-a-timestamp", &cutoff));
    }

    #[test]
    fn agent_last_seen_before_handles_subsecond_precision() {
        let cutoff = parse_timestamp("2026-05-10T12:00:00Z").unwrap();
        // subsecond timestamp just before cutoff
        assert!(agent_last_seen_before("2026-05-10T11:59:59.999999999Z", &cutoff));
        // subsecond timestamp at cutoff second (still less than cutoff)
        // Note: 12:00:00.000000001 is AFTER 12:00:00, so not before
        assert!(!agent_last_seen_before("2026-05-10T12:00:00.000000001Z", &cutoff));
    }

    #[tokio::test]
    async fn prune_requires_at_least_one_filter() {
        let cfg = crate::config::ResolvedConfig {
            server: "http://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("build client");
        let err = prune(&client, None, false).await.unwrap_err();
        assert!(
            matches!(err, CliError::InvalidArgs(_)),
            "prune with no filters must return InvalidArgs; got: {err:?}"
        );
    }

    #[tokio::test]
    async fn prune_rejects_invalid_timestamp() {
        let cfg = crate::config::ResolvedConfig {
            server: "http://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("build client");
        let err = prune(&client, Some("not-a-timestamp"), false).await.unwrap_err();
        assert!(
            matches!(err, CliError::InvalidArgs(_)),
            "prune with invalid timestamp must return InvalidArgs; got: {err:?}"
        );
    }
}
