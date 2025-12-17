# TLS 1.3 (monacc)

Date: 2025-12-17

monacc includes an in-tree TLS 1.3 client implementation used to make HTTPS requests (e.g. to Wikipedia/Wikimedia).

## Scope (Current)

- TLS version: **TLS 1.3**
- Cipher suite: **TLS_AES_128_GCM_SHA256 (0x1301)**
- Key exchange: **X25519**
- AEAD: **AES-128-GCM**
- Hash/KDF: **SHA-256 / HMAC / HKDF**

The implementation covers the TLS 1.3 key schedule (HKDF-Expand-Label / Derive-Secret), transcript hashing, Finished computation/verification, and record protection (encrypt/decrypt) for handshake + application data.

## Certificate Validation

Certificate chain / hostname validation is **not implemented** (no X.509 parsing in-tree). Connections are encrypted, but peer authentication is not verified via the public PKI.

## Tooling

TLS bring-up and regression testing is done with `tls13`:

- `tls13 rec --smoke` — record-layer encrypt/decrypt smoke (stable output)
- `tls13 kdf --rfc8448-1rtt` — RFC 8448 key schedule intermediate values
- `tls13 hello --rfc8448-1rtt` — RFC 8448 ClientHello/ServerHello + transcript hash
- `tls13 hs [-W TIMEOUT_MS] [-D DNS_SERVER] [-n SNI] [-p PATH] HOST PORT` — live handshake and HTTPS GET (prints decrypted response)

Examples:

```bash
# Live HTTPS GET
tls13 hs -n en.wikipedia.org -p /api/rest_v1/page/summary/caffeine en.wikipedia.org 443

# Deterministic smokes
tls13 rec --smoke
tls13 kdf --rfc8448-1rtt
tls13 hello --rfc8448-1rtt
```

## Code Locations

- Core TLS/key-schedule/transcript helpers:
  - `core/mc_tls13.h`, `core/mc_tls13.c`
  - `core/mc_tls13_transcript.h`, `core/mc_tls13_transcript.c`
  - `core/mc_tls13_handshake.h`, `core/mc_tls13_handshake.c`
- Record protection:
  - `core/mc_tls_record.h`, `core/mc_tls_record.c`
- Tool:
  - `tools/tls13.c`

## References

- TLS 1.3: RFC 8446 https://datatracker.ietf.org/doc/html/rfc8446
- TLS 1.3 examples/vectors used for tooling: RFC 8448 https://datatracker.ietf.org/doc/html/rfc8448