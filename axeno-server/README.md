# Axeno relay server

Minimal WebSocket relay for Axeno sealed-sender envelopes.

## Run locally

```bash
cd axeno-server
cargo run
```

By default it binds to `127.0.0.1:8787` and stores persistent relay state in `./axeno-relay-data`.

Override bind address or state directory:

```bash
AXENO_BIND=127.0.0.1:8787 AXENO_DATA_DIR=./relay-data cargo run
```

Health check:

```bash
curl http://127.0.0.1:8787/health
```

WebSocket endpoint:

```text
ws://127.0.0.1:8787/ws
```

## Protocol

Protocol version: `5` with negotiated client/server support range.

The server stores and forwards opaque envelopes only. It does not receive private keys, passphrases, contact lists, or plaintext. It **can** observe transport metadata: authenticated mailbox for the WebSocket used to submit a send, destination mailbox, ciphertext size, timing, and queue/ack activity. Axeno clients reduce cross-contact linking by using per-contact/per-invite mailboxes, but this relay is not a mixnet.

Client -> server:

```json
{"type":"hello","recipient_id":"mbx_...","auth_token":"rx_...","delivery_token":"dt_...","protocol_min":4,"protocol_max":5}
{"type":"issue_sender_certificate","request_id":"uuid","sender_uuid":"mbx_...","sender_device_id":1,"sender_cert_public_b64":"..."}
{"type":"send_envelope","client_ref":"local-message-id","to":"mbx_...","delivery_token":"dt_...","envelope_type":"axeno_sealed_signal_v1","ciphertext":"..."}
{"type":"set_delivery_tokens","tokens":["dt_current...","dt_grace..."]}
{"type":"upload_bundle","request_id":"uuid","bundle_id":"bun_...","ciphertext":"...","expires_at_ms":123}
{"type":"fetch_bundle","request_id":"uuid","bundle_id":"bun_..."}
{"type":"ack","ids":["uuid"]}
{"type":"retire_mailbox"}
{"type":"ping"}
```

Server -> client:

```json
{"type":"hello_ok","protocol_version":5,"min_supported":4,"current_protocol":5,"server_time_ms":123,"trust_root_b64":"..."}
{"type":"sender_certificate","request_id":"uuid","certificate_b64":"...","trust_root_b64":"...","expires_at_ms":123}
{"type":"bundle_uploaded","request_id":"uuid","bundle_id":"bun_...","expires_at_ms":123}
{"type":"bundle","request_id":"uuid","bundle_id":"bun_...","ciphertext":"...","expires_at_ms":123}
{"type":"envelope","envelope":{"id":"uuid","to":"mbx_...","envelope_type":"axeno_sealed_signal_v1","ciphertext":"..."}}
{"type":"send_ok","id":"uuid","queued":false,"client_ref":"local-message-id"}
{"type":"ack_ok","removed":1}
{"type":"error","code":"bad_json","message":"..."}
```

`send_ok.queued` is deliberately generic and does not reveal recipient online/offline state.

## Current limits

- Queue limit: 200 envelopes per recipient.
- Frame limit: 512 KiB.
- Total queued ciphertext limit: 64 MiB.
- Basic per-socket frame rate limiting.
- Mailbox auth and relay signing keys persist under `AXENO_DATA_DIR`; never commit or ship that directory.
- Queued envelopes are persisted to relay state and survive normal relay restarts. Treat the relay as best-effort unless the state directory is durable and backed up.
- Mailbox registration is first-write-wins for cryptographically random `mbx_` IDs only. The relay rejects short/human mailbox names; clients generate ~192-bit random mailbox IDs so pre-claiming is not practical. If a user loses their vault, the old mailbox cannot be recovered and a new identity/route is required.

## Tor onion deployment

The relay is designed to bind to localhost and be published by Tor as an onion service. This keeps the Rust relay dumb and local-only while Tor handles the public hidden-service endpoint.

Example:

```bash
AXENO_BIND=127.0.0.1:8787 AXENO_DATA_DIR=/var/lib/axeno-relay cargo run --release
```

Then configure Tor using `torrc.example`. The client should connect to the generated hostname as:

```text
ws://yourgeneratedhostname.onion/ws
```

The Axeno client routes `.onion` WebSockets through Arti. Direct WebSocket connections are only accepted for localhost development.
