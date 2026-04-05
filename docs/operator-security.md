# Operator Security Notes

This document describes known cryptographic limitations that operators must understand
before deploying Red Cell C2 in a production engagement.

---

## AES-256-CTR keystream reuse (two-time-pad) — Demon/Archon legacy mode

**Severity:** High when `AllowLegacyCtr = true` and no TLS — passive traffic analysis
can recover plaintext.  No risk for Specter/Phantom agents, which use monotonic CTR.

### Background: two CTR modes in Red Cell

Red Cell supports two AES-CTR operating modes, selected per-agent at registration time:

| Mode | Agents | Behaviour | Risk |
|---|---|---|---|
| **Monotonic CTR** (default) | Specter, Phantom | Block offset advances across the session; each packet consumes a distinct portion of the keystream | None — keystream never reused |
| **Legacy CTR** (opt-in) | Demon, Archon | Block offset resets to 0 for every packet — matches unmodified Havoc Demon behaviour | Two-time-pad: keystream identical for every packet |

The teamserver defaults to monotonic CTR.  Legacy mode is only activated when an agent
does not send the `INIT_EXT_MONOTONIC_CTR` extension flag during `DEMON_INIT`, **and**
the operator has set `AllowLegacyCtr = true` in the profile.

### What happens in legacy mode

Unmodified Havoc Demon calls `AesInit(key, IV)` at the start of every
`PackageTransmitNow` / `PackageTransmitAll` call (`agent/demon/src/core/Package.c:257`,
`:390`), resetting the AES-CTR stream to block 0.  The teamserver mirrors this by
skipping the CTR offset advance for any agent registered with `legacy_ctr = true`.

Because the counter and IV are the same for every message under the same session, the
AES keystream is **identical for every packet**.

### Why this is dangerous

If an adversary records two ciphertexts `C1` and `C2` from the same agent:

```
C1 ⊕ C2  =  (P1 ⊕ K)  ⊕  (P2 ⊕ K)  =  P1 ⊕ P2
```

This is the *two-time-pad* attack.  Because the Demon wire format is public (fixed
20-byte unencrypted header: size, `0xDEADBEEF` magic, agent ID, command ID, request
ID), an adversary can crib-drag to recover complete plaintext from as few as two
captured packets.

### Enabling Demon/Archon compatibility

To accept unmodified Demon or Archon agents, set `AllowLegacyCtr = true` in the
`Demon` block of your profile:

```hcl
Demon {
    Sleep  = 2
    Jitter = 15
    AllowLegacyCtr = true   # accept Demon/Archon agents; see operator-security.md
    ...
}
```

When this flag is `false` (the default), any `DEMON_INIT` that does not negotiate
monotonic CTR is rejected with a `LegacyCtrNotAllowed` error logged at `WARN` level.

### Risk assessment by deployment context

| Context | Risk level | Recommendation |
|---|---|---|
| Lab / isolated test environment | **None** | Enable freely; no real adversary capturing traffic |
| Production engagement over TLS | **Low** | Two-time-pad requires breaking TLS first; acceptable with awareness |
| Production engagement without TLS | **High** | Do not use Demon; use Specter (monotonic CTR) instead |
| TLS inspection appliance in-path | **High** | Treat as no-TLS; inner CTR packets are exposed to the inspecting device |

### Additional risks in legacy mode

**Replay attacks.** Without CTR advancement the server cannot detect a replayed packet
at the crypto layer.  The rate-limiter and protocol-level request IDs provide partial
protection, but a captured `GET_JOB` callback could be replayed.

**Blast radius is per-agent.** Each Demon payload is compiled with its own key+IV pair.
Recovering one agent's traffic does not expose other agents' sessions.

### Mitigations

1. **Use TLS.** Configure `Tls` in the profile and provide a valid certificate.  TLS
   wraps the entire HTTP exchange; the inner CTR reuse is only exploitable if the
   adversary can first decrypt the TLS layer.

2. **Dedicated listener for Demon.** Create a separate HTTP listener with
   `AllowLegacyCtr = true` for Demon/Archon agents, and a separate listener without
   the flag for Specter/Phantom agents.  This limits the flag's scope to the endpoints
   that actually need it.

3. **Short sessions, frequent rotation.** Fewer packets means fewer ciphertexts for an
   adversary to correlate.  Prefer Specter for long-running implants.

4. **Prefer Specter over Demon for new Windows deployments.** Specter implements the
   full Demon command set and negotiates monotonic CTR automatically.  Demon should be
   reserved for environments where deploying a Rust binary is not viable.

### Relevant code

- `agent/demon/src/core/Package.c:257,390` — per-packet `AesInit` calls (CTR reset).
- `teamserver/src/demon.rs:31` — `INIT_EXT_MONOTONIC_CTR` extension flag definition.
- `teamserver/src/agents.rs:638-644` — `advance_ctr_for_agent` no-ops in legacy mode.
- `teamserver/src/agents.rs:261-303` — security warning and insert logic for legacy CTR.
- `common/src/crypto.rs` — `encrypt_agent_data`, `decrypt_agent_data` and their
  `_at_offset` variants.
- `common::crypto::ctr_blocks_for_len` — helper for computing the block-offset
  increment after encrypting a message of a given length.
- `common/src/config.rs` — `DemonConfig::allow_legacy_ctr` profile field.

---

## Demon → Specter/Phantom migration guide

> **Deprecation notice:** `AllowLegacyCtr` support will be **removed on 2027-01-01**.
> Operators still running unmodified Havoc Demon or Archon agents should migrate to
> Specter (Windows) or Phantom (Linux) before that date.  The teamserver logs a
> `WARN`-level message at startup until the flag is removed from your profile.

### Why migrate?

Specter (Windows Rust implant) and Phantom (Linux Rust implant) implement the full
Demon command set but negotiate `INIT_EXT_MONOTONIC_CTR` automatically.  Each packet
uses a distinct portion of the AES-256-CTR keystream, eliminating the two-time-pad
vulnerability entirely.  No changes are needed on the listener or teamserver side.

### Migration steps

1. **Keep your existing listener running.** Specter and Phantom connect to the same
   HTTP(S) listener URL as Demon.  You do not need a new listener.

2. **Build a Specter (Windows) or Phantom (Linux) stager** pointing to the same
   callback URL your Demon agents use.  The listener URL, sleep, and jitter values
   can remain identical.

3. **Deploy the new stager** on each target host where a Demon/Archon agent is
   currently running.  The new agent registers under a fresh agent ID; the old Demon
   session remains alive until it is manually killed or times out.

4. **Verify** the new agent appears in the operator console and executes tasks
   correctly before terminating the legacy Demon session.

5. **Remove `AllowLegacyCtr = true`** from the profile once all Demon agents have
   been replaced.  Restart the teamserver; the `WARN` message will no longer appear.
   Any new `DEMON_INIT` from an unmodified Demon binary will then be rejected
   (the safe default).

### Compatibility notes

- **Same listener, multiple agent types.** A single listener can serve both Demon
  (legacy CTR) and Specter/Phantom (monotonic CTR) agents simultaneously while
  `AllowLegacyCtr = true`.  The protocol negotiation happens per-session during
  `DEMON_INIT`.

- **No key rotation needed.** Each agent payload is compiled with its own AES key
  and IV.  Replacing the agent generates a fresh key, so there is no need to
  coordinate a key rotation with the teamserver.

- **Canary via dedicated listener.** For high-sensitivity operations, deploy a
  dedicated listener without `AllowLegacyCtr` for Specter/Phantom and a separate one
  with `AllowLegacyCtr` only for any remaining Demon agents.  This limits the
  cryptographic risk to the subset of endpoints that still need it.
