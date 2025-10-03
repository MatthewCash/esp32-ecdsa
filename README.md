# esp32-ecdsa

This crate provides simple signing and verification helpers for ECDSA over the NIST P-256 curve, using the ESP32 hardware acceleration peripherals (SHA, ECC, TRNG).

It is intended as an example or educational reference, **not production-ready crypto**.

## Features

-   SHA-256 hashing via ESP32 HAL `Sha` peripheral
-   Scalar × point multiplication on P-256 via ESP32 HAL `Ecc` peripheral
-   ECDSA signing with ephemeral nonce `k` from TRNG
-   ECDSA verification using a provided public key
-   Raw signature output: 64 bytes (`r || s`)

## ⚠️ Security Notes (Please Read)

I am a novice at cryptography, I cannot make any guarantees that this library is accurate or secure. I have performed very little testing and cannot make any positive claims about its security. Avoid using this crate in production or security critical environments, you are certainly better off using audited software ECDSA instead. Below are some _known_ issues that may or may not be addressed:

1. **Nonce generation:** Each signature uses a random `k`. For production systems, use [RFC 6979 deterministic nonces](https://datatracker.ietf.org/doc/html/rfc6979) or add retry logic for weak `k`.
2. **Side-channel protection:** No additional hardening beyond what the ESP32 accelerator provides.
3. **Low-S normalization:** Not enforced (may be required in some ecosystems).
4. **Signature format:** Raw `(r || s)` (64 bytes). **Not DER encoded.**
5. **Public key validation:** Assumed to be performed at provisioning.

## Limitations

-   Only P-256 (secp256r1) is supported.
-   Blocking usage of ECC and SHA peripherals (no async).

## Usage

### Signing

```rust
let mut crypto = esp32_ecdsa::CryptoContext { sha, ecc, trng, secret_key, server_public_key };
let message = b"hello world";
let sig = esp32_ecdsa::ecdsa_sign(&mut crypto, message).unwrap();
// `sig` is 64 bytes: r (32) || s (32)
```

Verification

```rust
let valid = esp32_ecdsa::ecdsa_verify(&mut crypto, b"hello world", &sig).unwrap();
assert!(valid);
```

### Errors

The API returns `CryptoError` on failure, with variants for:

-   Non-canonical scalars
-   Scalar inversion errors
-   Missing or malformed public key coordinates
-   ECC hardware multiplication failures
-   Invalid decoded points
