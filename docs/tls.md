# TLS Implementation Roadmap

Date: 2025-12-17

**Goal:** Implement TLS 1.3 client support for monacc, enabling HTTPS connections to Wikipedia and other modern web services — without external dependencies.

---

## Guiding Principles

All TLS implementation work follows monacc's core philosophy:

| Principle | Application to TLS |
|-----------|-------------------|
| **Syscalls only** | No OpenSSL, no libcrypto, no libc — pure computation + Linux syscalls |
| **No third-party software** | Every crypto primitive implemented in-tree |
| **Single platform** | x86_64 Linux only; can use platform-specific optimizations |
| **C language** | All code in monacc's supported C subset |
| **Self-contained** | Builds with monacc's internal toolchain |

### Priority Order

1. **Working** — Correct cryptographic output (test vectors must pass)
2. **Small** — Minimal code size; one cipher suite is enough
3. **Fast** — Performance is tertiary; correctness >> size >> speed

### Security Philosophy

- **No shortcuts on correctness** — Crypto bugs are security bugs
- **Constant-time where it matters** — Key operations must not leak timing
- **Fail closed** — Any error → connection abort
- **Minimal attack surface** — Support only what's needed

---

## Tooling (Current)

TLS bring-up uses small standalone tools for deterministic regression (pinned vectors) and for live network testing.

- `sha256`, `hkdf`, `aes128`, `gcm128`, `x25519`: primitive-level smoke tools.
- `tls13`: consolidated TLS 1.3 tool with subcommands:
  - `tls13 rec --smoke` — record-layer encrypt/decrypt smoke (stable hex output)
  - `tls13 kdf --rfc8448-1rtt` — RFC 8448 key schedule intermediate values
  - `tls13 hello --rfc8448-1rtt` — RFC 8448 ClientHello/ServerHello + transcript hash
  - `tls13 hs [-W TIMEOUT_MS] [-D DNS_SERVER] [-n SNI] [-p PATH] HOST PORT` — live TLS 1.3 handshake and HTTPS GET (prints decrypted response)

The deterministic subcommands (`rec`, `kdf`, `hello`) are exercised by the tools smoke suite.

---

## Target: Wikipedia's TLS Configuration

Based on Qualys SSL Labs analysis of `en.wikipedia.org`:

### Server Capabilities

```
TLS 1.3 Cipher Suites (server-preferred order):
  1. TLS_AES_128_GCM_SHA256        (0x1301)  ← Our target
  2. TLS_CHACHA20_POLY1305_SHA256  (0x1303)
  3. TLS_AES_256_GCM_SHA384        (0x1302)

Key Exchange:
  - ECDH x25519 (equivalent to 3072-bit RSA)

Certificates:
  - Primary: EC 256-bit, SHA384withECDSA
  - Alternate: EC 384-bit, SHA256withRSA  
  - Alternate: RSA 4096-bit, SHA256withRSA
```

### Minimum Viable Implementation

To connect to Wikipedia, we need exactly **one** cipher suite:

```
TLS_AES_128_GCM_SHA256 (0x1301)
  ├── Key Exchange: X25519 (ECDH on Curve25519)
  ├── Bulk Cipher: AES-128-GCM (AEAD)
  └── Hash: SHA-256 (HKDF, HMAC, Finished)
```

This is the most widely supported TLS 1.3 cipher suite and Wikipedia's preferred choice.

---

## Implementation Phases

### Overview

```
Phase 1: SHA-256           ████░░░░░░░░░░░░  Week 1
Phase 2: HMAC + HKDF       ██░░░░░░░░░░░░░░  Week 2  
Phase 3: AES-128           ████░░░░░░░░░░░░  Week 3
Phase 4: GCM Mode          ███░░░░░░░░░░░░░  Week 4
Phase 5: X25519            ████░░░░░░░░░░░░  Week 5
Phase 6: TLS 1.3 Records   ████░░░░░░░░░░░░  Week 6-7
Phase 7: TLS 1.3 Handshake ████████░░░░░░░░  Week 8-10
Phase 8: Certificate Parse ████░░░░░░░░░░░░  Week 11-12
Phase 9: Integration       ██░░░░░░░░░░░░░░  Week 13

Total: ~13 weeks (3 months) for production-ready HTTPS
       ~10 weeks for "works but skips cert validation"
```

---

## Phase 1: SHA-256

**Files:** `core/mc_sha256.h`, `core/mc_sha256.c`  
**Tool:** `tools/sha256.c`  
**Lines:** ~250  
**Standalone value:** File checksums, integrity verification

### Rationale

SHA-256 is the foundation of everything in TLS 1.3:
- HMAC-SHA256 for message authentication
- HKDF-SHA256 for key derivation
- Transcript hash for handshake integrity
- Certificate fingerprints

### Specification

FIPS 180-4: Secure Hash Standard  
https://csrc.nist.gov/publications/detail/fips/180/4/final

### API Design

```c
// core/mc_sha256.h

#define MC_SHA256_BLOCK_SIZE  64
#define MC_SHA256_DIGEST_SIZE 32

typedef struct {
    mc_u32 state[8];
    mc_u64 count;
    mc_u8 buffer[64];
} mc_sha256_ctx;

// Streaming API (for large data)
void mc_sha256_init(mc_sha256_ctx *ctx);
void mc_sha256_update(mc_sha256_ctx *ctx, const void *data, mc_usize len);
void mc_sha256_final(mc_sha256_ctx *ctx, mc_u8 out[32]);

// One-shot API (convenience)
void mc_sha256(const void *data, mc_usize len, mc_u8 out[32]);
```

### Algorithm Summary

```
1. Initialize 8 state words (H0-H7) from constants
2. Pad message: append 1 bit, zeros, 64-bit length
3. Process 64-byte blocks:
   a. Expand 16 words to 64-word schedule
   b. 64 rounds of compression
   c. Add result to state
4. Output state as 32 bytes (big-endian)
```

### Test Vectors

```c
// NIST test vectors

// Empty string
sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

// "abc"  
sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

// 448 bits (56 bytes) - exactly fills one block after padding
sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") = 
    248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1

// One million 'a' characters (stress test)
sha256("aaa...") = cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
```

### Tool Usage

```bash
# Hash files (like sha256sum)
sha256 file.txt
# e3b0c44298fc1c14...  file.txt

# Hash stdin
echo -n "abc" | sha256
# ba7816bf8f01cfea...  -

# Multiple files
sha256 *.c

# Check mode (future enhancement)
sha256 -c checksums.txt
```

---

## Phase 2: HMAC-SHA256 and HKDF

**Files:** `core/mc_hmac.h`, `core/mc_hmac.c`, `core/mc_hkdf.c`  
**Lines:** ~150  
**Standalone value:** Message authentication, key derivation

### Rationale

TLS 1.3 uses HKDF (HMAC-based Key Derivation Function) for all key material:
- Deriving traffic keys from shared secret
- Deriving per-record nonces
- "Finished" message computation

### HMAC-SHA256

RFC 2104: HMAC: Keyed-Hashing for Message Authentication

```c
// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
// where K' = H(K) if len(K) > 64, else K padded to 64 bytes

void mc_hmac_sha256(const mc_u8 *key, mc_usize key_len,
                    const mc_u8 *data, mc_usize data_len,
                    mc_u8 out[32]);
```

### HKDF (RFC 5869)

```c
// Extract: PRK = HMAC-Hash(salt, IKM)
void mc_hkdf_extract(const mc_u8 *salt, mc_usize salt_len,
                     const mc_u8 *ikm, mc_usize ikm_len,
                     mc_u8 prk[32]);

// Expand: OKM = HMAC-Hash(PRK, T(n-1) | info | n)
void mc_hkdf_expand(const mc_u8 prk[32],
                    const mc_u8 *info, mc_usize info_len,
                    mc_u8 *okm, mc_usize okm_len);

// Combined Extract-and-Expand
void mc_hkdf(const mc_u8 *salt, mc_usize salt_len,
             const mc_u8 *ikm, mc_usize ikm_len,
             const mc_u8 *info, mc_usize info_len,
             mc_u8 *okm, mc_usize okm_len);
```

### Test Vectors (RFC 5869)

```c
// Test Case 1
IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
salt = 0x000102030405060708090a0b0c (13 bytes)
info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
L    = 42

PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
       90b6c73bb50f9c3122ec844ad7c2b3e5 (32 bytes)

OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
       2d2d0a90cf1a5a4c5db02d56ecc4c5bf
       34007208d5b887185865 (42 bytes)
```

---

## Phase 3: AES-128

**Files:** `core/mc_aes.h`, `core/mc_aes.c`  
**Lines:** ~400  
**Standalone value:** File encryption tool

### Rationale

AES-128-GCM is the bulk cipher for TLS 1.3. We implement AES-128 block cipher first, then GCM mode on top.

### Specification

FIPS 197: Advanced Encryption Standard  
https://csrc.nist.gov/publications/detail/fips/197/final

### API Design

```c
// core/mc_aes.h

#define MC_AES128_KEY_SIZE   16
#define MC_AES128_BLOCK_SIZE 16
#define MC_AES128_ROUNDS     10

typedef struct {
    mc_u32 rk[44];  // Round keys (11 × 4 words)
} mc_aes128_ctx;

// Key schedule
void mc_aes128_init(mc_aes128_ctx *ctx, const mc_u8 key[16]);

// Single block encrypt/decrypt (ECB mode - building block only)
void mc_aes128_encrypt_block(const mc_aes128_ctx *ctx, 
                              const mc_u8 in[16], mc_u8 out[16]);
void mc_aes128_decrypt_block(const mc_aes128_ctx *ctx,
                              const mc_u8 in[16], mc_u8 out[16]);
```

### Algorithm Summary

```
Key Expansion:
  - 128-bit key → 11 round keys (176 bytes)
  - Uses S-box and round constants

Encryption (10 rounds):
  1. AddRoundKey (initial)
  2. Rounds 1-9: SubBytes → ShiftRows → MixColumns → AddRoundKey
  3. Round 10: SubBytes → ShiftRows → AddRoundKey (no MixColumns)

Decryption:
  - Inverse operations in reverse order
```

### S-Box

The S-box is the heart of AES security. Two implementation options:

**Option A: Lookup table (256 bytes, fast but not constant-time)**
```c
static const mc_u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, ...
};
```

**Option B: Compute on-the-fly (constant-time, slower)**
```c
// GF(2^8) inversion + affine transform
static mc_u8 sbox_compute(mc_u8 x) { ... }
```

For monacc, **Option A** is acceptable — our threat model doesn't include local timing attacks.

### Test Vectors (FIPS 197 Appendix C)

```c
// AES-128 test
Key:       000102030405060708090a0b0c0d0e0f
Plaintext: 00112233445566778899aabbccddeeff
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
```

---

## Phase 4: GCM Mode (AEAD)

**Files:** `core/mc_gcm.h`, `core/mc_gcm.c`  
**Lines:** ~300  
**Standalone value:** Authenticated encryption for files

### Rationale

TLS 1.3 requires AEAD (Authenticated Encryption with Associated Data). GCM provides both confidentiality and integrity in one operation.

### Specification

NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)

### API Design

```c
// core/mc_gcm.h

#define MC_GCM_TAG_SIZE 16
#define MC_GCM_IV_SIZE  12  // 96 bits for TLS

// Encrypt and authenticate
// Returns 0 on success
int mc_aes128_gcm_encrypt(
    const mc_u8 key[16],
    const mc_u8 iv[12],
    const mc_u8 *aad, mc_usize aad_len,      // Additional Authenticated Data
    const mc_u8 *plaintext, mc_usize pt_len,
    mc_u8 *ciphertext,                        // Same length as plaintext
    mc_u8 tag[16]                             // Authentication tag
);

// Decrypt and verify
// Returns 0 on success, -1 on auth failure
int mc_aes128_gcm_decrypt(
    const mc_u8 key[16],
    const mc_u8 iv[12],
    const mc_u8 *aad, mc_usize aad_len,
    const mc_u8 *ciphertext, mc_usize ct_len,
    const mc_u8 tag[16],
    mc_u8 *plaintext
);
```

### Algorithm Summary

```
GCM = CTR mode encryption + GHASH authentication

1. H = AES_K(0^128)  // Hash subkey
2. CTR encryption of plaintext
3. GHASH over (AAD || ciphertext || lengths)
4. Tag = GHASH_result XOR AES_K(IV || 0^31 || 1)
```

### GHASH

The tricky part of GCM is GHASH — multiplication in GF(2^128):

```c
// Multiply in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1
static void ghash_multiply(mc_u8 result[16], const mc_u8 x[16], const mc_u8 h[16]);
```

**Implementation options:**
- Bit-by-bit (slow, ~200 lines, constant-time)
- 4-bit tables (faster, ~300 lines, 4KB tables)
- 8-bit tables (fastest, 64KB tables — too big for monacc)

We'll use **4-bit tables** as a balance of size and speed.

### Test Vectors (NIST)

```c
// Test Case 3 from NIST GCM spec
Key: feffe9928665731c6d6a8f9467308308
IV:  cafebabefacedbaddecaf888
AAD: (empty)
PT:  d9313225f88406e5a55909c5aff5269a
     86a7a9531534f7da2e4c303d8a318a72
     1c3c0c95956809532fcf0e2449a6b525
     b16aedf5aa0de657ba637b391aafd255
CT:  42831ec2217774244b7221b784d0d49c
     e3aa212f2c02a4e035c17e2329aca12e
     21d514b25466931c7d8f6a5aac84aa05
     1ba30b396a0aac973d58e091473f5985
Tag: 4d5c2af327cd64a62cf35abd2ba6fab4
```

---

## Phase 5: X25519 (Key Exchange)

**Files:** `core/mc_x25519.h`, `core/mc_x25519.c`  
**Lines:** ~400  
**Standalone value:** Key agreement utility

### Rationale

X25519 is the key exchange algorithm for TLS 1.3 with Wikipedia. It's simpler and faster than ECDH-P256, and has better security properties.

### Specification

RFC 7748: Elliptic Curves for Security  
https://datatracker.ietf.org/doc/html/rfc7748

### API Design

```c
// core/mc_x25519.h

#define MC_X25519_KEY_SIZE 32

// Generate public key from private key
// private_key should be 32 random bytes (clamped internally)
void mc_x25519_public(mc_u8 public_key[32], const mc_u8 private_key[32]);

// Compute shared secret
// Returns 0 on success, -1 if result is zero (bad peer key)
int mc_x25519_shared(mc_u8 shared[32], 
                     const mc_u8 private_key[32],
                     const mc_u8 peer_public[32]);
```

### Algorithm Summary

X25519 is scalar multiplication on Curve25519: `Q = n × P`

```
Curve: y² = x³ + 486662x² + x  (mod 2²⁵⁵ - 19)
Base point: x = 9
Scalar: 255-bit integer (clamped)

Montgomery ladder for constant-time scalar multiplication
```

### Key Clamping

```c
// Clamp private key per RFC 7748
static void clamp(mc_u8 k[32]) {
    k[0]  &= 248;   // Clear bottom 3 bits
    k[31] &= 127;   // Clear top bit
    k[31] |= 64;    // Set second-to-top bit
}
```

### Field Arithmetic

The main work is arithmetic in GF(2²⁵⁵ - 19):

```c
// 255-bit field element (represented as 5 × 51-bit limbs or 10 × 25.5-bit limbs)
typedef struct { mc_u64 v[5]; } fe;

static void fe_add(fe *r, const fe *a, const fe *b);
static void fe_sub(fe *r, const fe *a, const fe *b);
static void fe_mul(fe *r, const fe *a, const fe *b);  // The expensive one
static void fe_sq(fe *r, const fe *a);
static void fe_inv(fe *r, const fe *a);  // Via exponentiation
static void fe_pow2523(fe *r, const fe *a);  // For sqrt
```

### Test Vectors (RFC 7748)

```c
// Alice's private key
a_priv = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a

// Alice's public key = a_priv × 9
a_pub = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a

// Bob's private key
b_priv = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb

// Bob's public key
b_pub = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

// Shared secret = a_priv × b_pub = b_priv × a_pub
shared = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
```

---

## Phase 6: TLS 1.3 Record Layer

**Files:** `core/mc_tls_record.h`, `core/mc_tls_record.c`  
**Lines:** ~300  
**Standalone value:** Part of TLS stack

### Rationale

The record layer handles framing and encryption of TLS data.

### Record Format (TLS 1.3)

```
+--------+--------+--------+--------+--------+
| Type   | Legacy Version  | Length          |
| (1)    | (2) = 0x0303    | (2)             |
+--------+--------+--------+--------+--------+
|                                            |
|        Encrypted Payload                   |
|        (variable, up to 16KB + 256)        |
|                                            |
+--------------------------------------------+
|        Auth Tag (16 bytes for GCM)         |
+--------------------------------------------+
```

### Content Types

```c
#define TLS_CONTENT_CHANGE_CIPHER_SPEC 20  // Legacy, ignored in TLS 1.3
#define TLS_CONTENT_ALERT              21
#define TLS_CONTENT_HANDSHAKE          22
#define TLS_CONTENT_APPLICATION_DATA   23
```

### API Design

```c
// Encrypt a record
// inner_type is the real content type (hidden after encryption)
int mc_tls_record_encrypt(
    const mc_u8 key[16],
    const mc_u8 iv[12],
    mc_u64 seq,                    // Sequence number (XORed with IV)
    mc_u8 inner_type,
    const mc_u8 *plaintext, mc_usize pt_len,
    mc_u8 *record_out, mc_usize *record_len
);

// Decrypt a record
int mc_tls_record_decrypt(
    const mc_u8 key[16],
    const mc_u8 iv[12],
    mc_u64 seq,
    const mc_u8 *record, mc_usize record_len,
    mc_u8 *inner_type_out,
    mc_u8 *plaintext, mc_usize *pt_len
);
```

### Nonce Construction

```c
// TLS 1.3 nonce = IV XOR (sequence number as 64-bit big-endian, left-padded to 12 bytes)
static void make_nonce(mc_u8 nonce[12], const mc_u8 iv[12], mc_u64 seq) {
    mc_memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (mc_u8)(seq >> (8 * i));
    }
}
```

---

## Phase 7: TLS 1.3 Handshake

**Files:** `core/mc_tls.h`, `core/mc_tls.c`  
**Lines:** ~800-1000  
**Standalone value:** Complete TLS client

### TLS 1.3 Handshake Overview

```
Client                                           Server

ClientHello          -------->
  + key_share (x25519 public)
  + supported_versions (TLS 1.3)
  + signature_algorithms
  + server_name (SNI)
                                          ServerHello
                                          + key_share
                                    <-------- 
                                    {EncryptedExtensions}
                                    {Certificate}
                                    {CertificateVerify}
                                    {Finished}
                     <--------
{Finished}           -------->

[Application Data]   <------->    [Application Data]
```

### Key Schedule

```
             0
             |
             v
   PSK ->  HKDF-Extract = Early Secret
             |
             +-----> Derive-Secret(., "ext binder" | "res binder", "")
             |                     = binder_key
             |
             +-----> Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
             v
       Derive-Secret(., "derived", "")
             |
             v
(EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             |
             v
       Derive-Secret(., "derived", "")
             |
             v
   0 -> HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
```

### Handshake Messages

```c
// Message types
#define TLS_HS_CLIENT_HELLO         1
#define TLS_HS_SERVER_HELLO         2
#define TLS_HS_ENCRYPTED_EXTENSIONS 8
#define TLS_HS_CERTIFICATE          11
#define TLS_HS_CERTIFICATE_VERIFY   15
#define TLS_HS_FINISHED             20
```

### API Design

```c
// core/mc_tls.h

typedef struct mc_tls_ctx mc_tls_ctx;

// Create TLS context
mc_tls_ctx *mc_tls_new(void);
void mc_tls_free(mc_tls_ctx *ctx);

// Set SNI hostname (required for most servers)
void mc_tls_set_hostname(mc_tls_ctx *ctx, const char *hostname);

// Perform handshake over connected socket
// Returns 0 on success, -1 on error
int mc_tls_connect(mc_tls_ctx *ctx, int fd);

// Read/write application data
mc_isize mc_tls_read(mc_tls_ctx *ctx, void *buf, mc_usize len);
mc_isize mc_tls_write(mc_tls_ctx *ctx, const void *buf, mc_usize len);

// Close connection (sends close_notify alert)
int mc_tls_close(mc_tls_ctx *ctx);
```

### State Machine

```c
typedef enum {
    TLS_STATE_INIT,
    TLS_STATE_CLIENT_HELLO_SENT,
    TLS_STATE_SERVER_HELLO_RECEIVED,
    TLS_STATE_ENCRYPTED,
    TLS_STATE_HANDSHAKE_DONE,
    TLS_STATE_CONNECTED,
    TLS_STATE_CLOSED,
    TLS_STATE_ERROR
} mc_tls_state;
```

---

## Phase 8: Certificate Parsing (Optional Initially)

**Files:** `core/mc_x509.h`, `core/mc_x509.c`  
**Lines:** ~500  
**Standalone value:** Certificate inspection tool

### Rationale

For initial implementation, we can **skip certificate validation** and accept any certificate. This is insecure but allows testing the TLS stack.

For production use, we need:
1. Parse X.509 certificates (DER/ASN.1)
2. Verify certificate chain
3. Check hostname against SAN/CN
4. Trust anchor (root CA) handling

### Wikipedia's Certificates

From the SSL Labs report:

```
Primary Certificate:
  - Subject: CN=*.wikipedia.org
  - Issuer: DigiCert TLS Hybrid ECC SHA384 2020 CA1
  - Key: EC 256-bit (P-256)
  - Signature: SHA384withECDSA

Chain:
  1. *.wikipedia.org (EC P-256)
  2. DigiCert TLS Hybrid ECC SHA384 2020 CA1 (EC P-384)
  3. DigiCert Global Root CA (RSA 4096) [trust anchor]
```

### Minimum for Hostname Verification

```c
// Extract CN and SANs, check if hostname matches
int mc_x509_verify_hostname(const mc_u8 *cert_der, mc_usize cert_len,
                            const char *hostname);
```

### ASN.1 DER Parsing

X.509 uses ASN.1 DER encoding — a tag-length-value format:

```c
// ASN.1 tags
#define ASN1_SEQUENCE      0x30
#define ASN1_SET           0x31
#define ASN1_INTEGER       0x02
#define ASN1_BIT_STRING    0x03
#define ASN1_OCTET_STRING  0x04
#define ASN1_OID           0x06
#define ASN1_UTF8STRING    0x0C
#define ASN1_PRINTABLESTRING 0x13
#define ASN1_IA5STRING     0x16

// Parse one TLV
int asn1_get_tag(const mc_u8 *p, mc_usize len, 
                 mc_u8 *tag, mc_usize *content_len, mc_usize *header_len);
```

### Future: Full Chain Validation

```c
// Verify certificate chain up to trusted root
int mc_x509_verify_chain(const mc_u8 **certs, mc_usize *cert_lens, int n_certs,
                         const char *hostname,
                         const mc_u8 **roots, mc_usize *root_lens, int n_roots);
```

### Root CA Store

Options for trust anchors:
1. **Hardcode a few roots** — Small, but fragile if certs rotate
2. **Read system store** — Parse `/etc/ssl/certs/*.pem`
3. **Embed Mozilla's roots** — Large (~200KB) but comprehensive
4. **TOFU** — Trust On First Use (SSH-style)

For monacc, **Option 2** (read system store) makes sense — we're on Linux anyway.

---

## Phase 9: Integration

### Update `wget6` for HTTPS

```c
// In wget6.c
if (port == 443 || url_starts_with("https://")) {
    mc_tls_ctx *tls = mc_tls_new();
    mc_tls_set_hostname(tls, host);
    if (mc_tls_connect(tls, fd) < 0) {
        // Handle error
    }
    // Use mc_tls_read/write instead of mc_sys_read/write
}
```

### Enable `wtf`

```bash
# Now works!
wtf caffeine
wtf -l de Koffein
```

---

## File Summary

```
core/
├── mc_sha256.h      # SHA-256 hash
├── mc_sha256.c      # ~200 lines
├── mc_hmac.h        # HMAC-SHA256
├── mc_hmac.c        # ~50 lines
├── mc_hkdf.h        # HKDF key derivation  
├── mc_hkdf.c        # ~80 lines
├── mc_aes.h         # AES-128 block cipher
├── mc_aes.c         # ~400 lines
├── mc_gcm.h         # AES-GCM AEAD
├── mc_gcm.c         # ~300 lines
├── mc_x25519.h      # X25519 key exchange
├── mc_x25519.c      # ~400 lines
├── mc_tls.h         # TLS 1.3 client
├── mc_tls.c         # ~1000 lines
├── mc_x509.h        # X.509 certificate parsing (optional)
└── mc_x509.c        # ~500 lines

tools/
├── sha256.c         # File hashing tool
├── aes.c            # File encryption tool (optional)
└── wtf.c            # Wikipedia lookup (uses TLS)

Total: ~3000-3500 lines for TLS
       ~500 lines for tools
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Crypto implementation bugs | Medium | Critical | Extensive test vectors, comparison with OpenSSL |
| Timing side channels | Low | Medium | Constant-time field arithmetic in X25519 |
| GCM nonce reuse | Low | Critical | Strict sequence number tracking |
| Certificate validation bypass | N/A | High | Document clearly; add validation before production use |
| Protocol state machine bugs | Medium | Medium | Thorough testing against real servers |

---

## Testing Strategy

### Unit Tests

Each crypto primitive has NIST/RFC test vectors:

```bash
# Run all crypto tests
make test-crypto

# Individual tests
bin/test_sha256
bin/test_aes
bin/test_gcm
bin/test_x25519
```

### Integration Tests

```bash
# Test TLS handshake against real servers
bin/test_tls_connect en.wikipedia.org 443

# Full integration
bin/wtf caffeine | grep -q "stimulant" && echo PASS
```

### Comparison Testing

For each primitive, compare output with OpenSSL:

```bash
echo -n "abc" | openssl dgst -sha256
echo -n "abc" | bin/sha256

# Should match exactly
```

---

## Timeline Summary

| Phase | Component | Weeks | Cumulative |
|-------|-----------|-------|------------|
| 1 | SHA-256 | 1 | 1 |
| 2 | HMAC + HKDF | 1 | 2 |
| 3 | AES-128 | 1 | 3 |
| 4 | GCM | 1 | 4 |
| 5 | X25519 | 1 | 5 |
| 6 | TLS Records | 1.5 | 6.5 |
| 7 | TLS Handshake | 2.5 | 9 |
| 8 | Certificates | 2 | 11 |
| 9 | Integration | 1 | 12 |

**MVP (no cert validation):** ~9 weeks  
**Production-ready:** ~12 weeks

---

## References

### Specifications

- **TLS 1.3:** RFC 8446 https://datatracker.ietf.org/doc/html/rfc8446
- **SHA-256:** FIPS 180-4 https://csrc.nist.gov/publications/detail/fips/180/4/final
- **AES:** FIPS 197 https://csrc.nist.gov/publications/detail/fips/197/final
- **GCM:** NIST SP 800-38D https://csrc.nist.gov/publications/detail/sp/800-38d/final
- **X25519:** RFC 7748 https://datatracker.ietf.org/doc/html/rfc7748
- **HKDF:** RFC 5869 https://datatracker.ietf.org/doc/html/rfc5869
- **X.509:** RFC 5280 https://datatracker.ietf.org/doc/html/rfc5280

### Reference Implementations

- **TweetNaCl:** https://tweetnacl.cr.yp.to/ (tiny, readable X25519)
- **BearSSL:** https://bearssl.org/ (small TLS library, good reference)
- **s2n-tls:** https://github.com/aws/s2n-tls (AWS's TLS, well-documented)

### Test Vectors

- **NIST CAVP:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- **Wycheproof:** https://github.com/google/wycheproof (edge case tests)
