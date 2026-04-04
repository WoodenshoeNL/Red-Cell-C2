# Red Cell Client Operator Security Notes

## TOFU fingerprint storage

`red-cell-client` uses a trust-on-first-use (TOFU) workflow for pinned
teamserver TLS certificates. When an operator accepts a teamserver certificate,
the client stores the pinned SHA-256 fingerprint in:

`~/.config/red-cell-client/known_servers.toml`

On Unix this file is written with mode `0600`, but the contents are still
plaintext. Any attacker or process already running as the operator user can
read the pinned teamserver addresses and their fingerprints. Treat
`known_servers.toml` as sensitive trust material.

## Operator workstation guidance

- Use full-disk encryption on operator laptops and workstations.
- Restrict local access to the operator account and avoid running untrusted
  software in the same session.
- Include `~/.config/red-cell-client/` in any endpoint hardening or backup
  handling procedures that already protect credentials and certificate stores.

## First-use verification

TOFU only protects later connections. The first fingerprint acceptance is still
vulnerable if the operator is talking to the wrong server.

Before trusting a new teamserver certificate:

1. Obtain the expected certificate fingerprint from the teamserver operator.
2. Use a separate trusted channel for that check, such as a voice call,
   encrypted chat, or another authenticated operational channel.
3. Compare the out-of-band fingerprint with the fingerprint shown by
   `red-cell-client`.
4. Only accept and persist the server if those values match exactly.

Do not treat the initial prompt as sufficient proof by itself.

## Current limitation

There is currently no dedicated `red-cell-client verify-fingerprint` command to
review or re-confirm an already stored fingerprint. Until that exists,
operators should inspect `known_servers.toml` directly and verify entries
against the teamserver certificate over a separate trusted channel.
