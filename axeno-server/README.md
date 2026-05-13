# Axeno relay server

Minimal WebSocket relay for the current Axeno MVP.

## Run locally

```bash
cd axeno-server
cargo run
```

By default it binds to `127.0.0.1:8787`.

Override bind address:

```bash
AXENO_BIND=127.0.0.1:8787 cargo run
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

The server stores and forwards opaque envelopes only. It does not receive private keys, passphrases, contact lists, or plaintext by design. The current development panel in the client can send `dev_plaintext` envelopes only to test transport plumbing. Do not treat those as secure chat messages.

Client -> server:

```json
{"type":"hello","recipient_id":"hex-or-random-routing-id"}
{"type":"send_envelope","to":"recipient-id","envelope_type":"signal_prekey","ciphertext":"base64-or-encoded-ciphertext"}
{"type":"poll"}
{"type":"ack","ids":["uuid"]}
{"type":"ping"}
```

Server -> client:

```json
{"type":"hello_ok","protocol_version":1,"server_time_ms":123}
{"type":"envelope","envelope":{"id":"uuid","to":"recipient-id","from_hint":null,"envelope_type":"signal_prekey","ciphertext":"...","created_at_ms":123}}
{"type":"send_ok","id":"uuid","queued":true}
{"type":"ack_ok","removed":1}
{"type":"error","code":"bad_json","message":"..."}
```

## Current limits

- In-memory queues only; restart wipes queued envelopes.
- Queue limit: 1000 envelopes per recipient.
- Frame limit: 256 KiB.
- No production abuse controls yet.
- No account auth. Recipient IDs are bearer queue names for now.


## Tor onion deployment

The relay is designed to bind to localhost and be published by Tor as an onion service. This keeps the Rust relay dumb and local-only while Tor handles the public hidden-service endpoint.

Example:

```bash
AXENO_BIND=127.0.0.1:8787 cargo run
```

Then configure Tor using `torrc.example`. The client should connect to the generated hostname as:

```text
ws://yourgeneratedhostname.onion/ws
```

The Axeno client routes `.onion` WebSockets through Arti. Direct WebSocket connections are only accepted for localhost development.
