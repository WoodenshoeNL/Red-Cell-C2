# Operator Security Notes

This document describes known cryptographic limitations that operators must understand
before deploying Red Cell C2 in a production engagement.

---

## AES-256-CTR keystream reuse (two-time-pad)

**Severity:** High — passive traffic analysis can recover plaintext.

### What happens

The Havoc Demon binary protocol assigns each agent a fixed AES-256 session key and a
fixed 16-byte IV at registration time.  Both the teamserver and the Demon reset the
AES-CTR counter to **zero at the start of every message** rather than maintaining a
running counter across the session.

Because the counter and IV are the same for every message under the same session, the
AES keystream is **identical for every message**.

### Why this is dangerous

If an adversary records two ciphertexts `C1` and `C2` produced by the same agent:

```
C1 ⊕ C2  =  (P1 ⊕ K)  ⊕  (P2 ⊕ K)  =  P1 ⊕ P2
```

This is the *two-time-pad* (or *many-time-pad*) attack.  If either plaintext is
partially known — for example, a predictable command header or a crafted response to
a known tasking — the adversary can recover portions of all other plaintexts encrypted
in that session.

### Why it is preserved

This behaviour is inherited from Havoc and is kept **intentionally** so that Red Cell
can operate unmodified Demon implants.  Changing the per-message counter offset would
break wire compatibility with all existing Demon binaries.

### Mitigations

| Scenario | Recommended action |
|---|---|
| Unmodified Demon implants (Havoc compatibility required) | Accept the limitation; rotate agent sessions frequently; keep engagement duration short so an adversary has fewer ciphertexts to correlate. |
| Custom implants (no Havoc compatibility needed) | Use `encrypt_agent_data_at_offset` with a monotonically increasing `block_offset` derived from the total bytes sent in the session.  Track this counter in agent state (`AgentCryptoMaterial` or session context). |
| New transports | Use an AEAD scheme (e.g. AES-256-GCM) instead of raw CTR.  AEAD provides confidentiality **and** ciphertext integrity, which CTR alone does not. |

### Relevant code

- `common/src/crypto.rs` — `encrypt_agent_data`, `decrypt_agent_data` and their
  `_at_offset` variants.
- `common::crypto::ctr_blocks_for_len` — helper for computing the block-offset
  increment after encrypting a message of a given length.
