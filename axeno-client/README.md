# Axeno client

Tauri + React chat client using `libsignal-protocol` for 1:1 text sessions and sealed-sender envelopes.

## Privacy model

- Private identity keys are generated locally and stored in an encrypted vault.
- Message history is encrypted at rest in the app data directory.
- Connection codes carry public Signal prekey material plus a random mailbox and delivery token. Treat them as sensitive: anyone who sees an unexpired code can attempt to send to that invite mailbox until the route is rotated or retired.
- New connection codes use a fresh local routing mailbox and fresh one-time prekey; OPKs are not silently reused.
- Imported contacts get a per-contact return mailbox instead of sharing one global mailbox across everyone.
- Safety numbers are pairwise over both local and remote identity keys and verification is persisted.

## Important limitations

Axeno is not magic anonymity dust. The relay does not see plaintext, but it can still observe destination mailbox, delivery-token proof, ciphertext size, timing, and the authenticated receive mailbox for the socket used to submit a send. Per-contact return mailboxes reduce cross-contact correlation; they do not provide mixnet-level metadata protection.

The built-in “local dev relay” is `ws://127.0.0.1:8787/ws` and is not anonymous. For real transport testing, add a self-hosted `.onion` relay.

Identity transfer is disabled until there is a real implementation. Queued relay delivery is best-effort; a relay restart loses undelivered in-memory envelopes.
