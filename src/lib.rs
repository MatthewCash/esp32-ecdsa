#![no_std]
#![forbid(unsafe_code)]

//! Minimal ECDSA (P-256) signing and verification helpers using esp32 hardware acceleration.
//!
//! This module demonstrates how to:
//! - Compute SHA-256 message digests with the esp32 HAL `Sha` peripheral
//! - Perform scalar * point multiplications on the P‑256 curve with the esp32 HAL `Ecc` peripheral
//! - Construct an ECDSA signature (r, s)
//! - Verify an ECDSA signature
//!
//! IMPORTANT SECURITY NOTES
//! ------------------------
//! 1. This implementation uses a purely random ephemeral nonce `k` (from TRNG) for each signature.
//!    For production systems you SHOULD strongly consider using deterministic nonces per RFC 6979,
//!    or at least add a defense-in-depth mechanism (e.g. retry if k is low / near curve order).
//! 2. There is no side‑channel hardening beyond what the hardware accelerator provides.
//!    Avoid using this code for high-assurance / certification contexts without review.
//! 3. No attempt is made to enforce low-S normalization of signatures (some ecosystems expect it).
//! 4. The code returns raw `(r || s)` concatenated bytes (64 bytes). It does NOT produce DER.
//! 5. Public key validation (e.g. ensuring it is on-curve and not the point at infinity) is
//!    assumed to have happened at provisioning time.
//!
//! LIMITATIONS
//! -----------
//! - Only P‑256 (NIST P-256 / secp256r1) is supported (as required by the underlying HAL API).
//! - Blocking usage of the ECC / SHA peripherals (no async).
//!
//! EXAMPLE (Signing)
//! -----------------
//! ```ignore
//! let mut crypto = CryptoContext { sha, ecc, trng, secret_key, server_public_key };
//! let message = b"hello world";
//! let sig = ecdsa_sign(&mut crypto, message).unwrap();
//! // sig is 64 bytes: r (32) || s (32)
//! ```
//!
//! EXAMPLE (Verification)
//! ---------------------
//! ```ignore
//! let valid = ecdsa_verify(&mut crypto, b"hello world", &sig).unwrap();
//! assert!(valid);
//! ```

use esp_hal::{
    Blocking,
    ecc::{Ecc, EllipticCurve},
    rng::Trng,
    sha::{Sha, Sha256, ShaAlgorithm},
};
use nb::block;
use p256::{
    EncodedPoint, FieldBytes, NistP256, ProjectivePoint, PublicKey, Scalar, SecretKey, U32,
    elliptic_curve::{
        Field, PrimeField,
        ops::Reduce,
        point::AffineCoordinates,
        rand_core::RngCore,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use primeorder::{PrimeCurveParams, generic_array::GenericArray};
use snafu::{OptionExt, Snafu};

/// Length (in bytes) of a raw concatenated ECDSA P‑256 signature (r || s).
pub const SIGNATURE_LEN: usize = 64;

/// Aggregates the cryptographic peripherals and key material required for signing / verification.
///
/// Fields:
/// - `sha`: SHA peripheral instance used to hash message data (SHA‑256).
/// - `ecc`: ECC hardware accelerator for scalar * point operations.
/// - `trng`: True random number generator (for ephemeral nonce `k`).
/// - `secret_key`: Local private key (d) used for signing.
/// - `server_public_key`: Expected remote public key (Q) used for verification.
///
/// Lifetime `'a` ties each peripheral reference to the HAL borrow rules.
pub struct CryptoContext<'a> {
    pub sha: Sha<'a>,
    pub ecc: Ecc<'a, Blocking>,
    pub trng: Trng<'a>,
    pub secret_key: SecretKey,
    pub server_public_key: PublicKey,
}

/// Errors that can arise during signing or verification.
///
/// Variants:
/// - `NonCanonicalScalar`: The provided 32-byte value does not decode into a canonical curve scalar.
/// - `InvertScalar`: Modular inversion failed (scalar is zero modulo n).
/// - `MissingQProjX` / `MissingQProjY`: Public key encoding missing coordinate(s).
/// - `DecodePoint`: Hardware-produced (x, y) failed to decode as a valid affine point.
/// - `EccMultiplication`: Underlying HAL ECC multiplication returned an error.
#[derive(Debug, Snafu)]
pub enum CryptoError {
    #[snafu(display("Scalar {name} is not canonical"))]
    NonCanonicalScalar { name: &'static str },

    #[snafu(display("Failed to invert scalar {name}"))]
    InvertScalar { name: &'static str },

    #[snafu(display("Server public key missing x coordinate"))]
    MissingQProjX,

    #[snafu(display("Server public key missing y coordinate"))]
    MissingQProjY,

    #[snafu(display("Failed to decode ECC point"))]
    DecodePoint,

    #[snafu(display("Failed to multiply with ECC hardware: {ecc_err:?}"))]
    EccMultiplication { ecc_err: esp_hal::ecc::Error },
}

/// Compute a SHA‑256 digest of `data` using the HAL SHA peripheral.
///
/// This function streams the entire message via repeated `update` calls to
/// accommodate potential peripheral buffering behavior.
///
/// Returns: 32-byte hash.
fn sha256_hash(sha: &mut Sha, data: &[u8]) -> [u8; Sha256::DIGEST_LENGTH] {
    let mut hasher = sha.start::<Sha256>();
    let mut hash_data = data;

    // Feed remaining data until the peripheral reports it has consumed all bytes.
    while !hash_data.is_empty() {
        hash_data = block!(hasher.update(hash_data)).unwrap();
    }

    let mut hash = [0u8; Sha256::DIGEST_LENGTH];
    block!(hasher.finish(&mut hash)).unwrap();

    hash
}

/// Produce a raw ECDSA (P‑256) signature over `msg`.
///
/// Algorithm (RFC 6979 structure, but we use random k here):
/// 1. `z = H(msg)` truncated/shifted to scalar (here: reduce hash modulo n)
/// 2. Generate random nonce `k` in [1, n-1]
/// 3. Compute point R = k * G = (x1, y1)
/// 4. `r = x1 mod n` (reduced)
/// 5. `s = k^{-1} * (z + r * d) mod n`
///
/// Returns a 64-byte array: r (first 32) || s (last 32).
///
/// SECURITY:
/// - Relies on TRNG for nonce; a biased or repeated k compromises private key d.
/// - No low-S canonicalization is applied.
/// - Panics inside if HAL update/finalize unexpectedly fails (unwraps); you may
///   want to convert these to proper error handling in production.
///
/// Errors:
/// - `InvertScalar` if k inversion fails (extremely unlikely unless k == 0 mod n).
/// - `EccMultiplication` if hardware scalar multiplication fails.
pub fn ecdsa_sign(
    crypto: &mut CryptoContext,
    msg: &[u8],
) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
    // Private scalar d (NonZeroScalar reference)
    let d = crypto.secret_key.to_nonzero_scalar();

    // Hash message and reduce into scalar field (z)
    let msg_hash = sha256_hash(&mut crypto.sha, msg);
    let z: Scalar = Scalar::reduce_bytes(&FieldBytes::from(msg_hash));

    // Generate random nonce k (retry until canonical scalar)
    let k: Scalar = {
        let mut bytes = FieldBytes::default();
        loop {
            crypto.trng.fill_bytes(&mut bytes);
            if let Some(scalar) = Scalar::from_repr(bytes).into_option() {
                break scalar;
            }
        }
    };

    // k^{-1} mod n
    let k_inv = k
        .invert()
        .into_option()
        .context(InvertScalarSnafu { name: "k" })?;

    // Compute R = k * G using ecc accelerator
    // Starts with generator coordinates to pass to hardware (The HAL expects initial (x, y) as base point)
    let mut x = NistP256::GENERATOR.0.to_bytes();
    let mut y = NistP256::GENERATOR.1.to_bytes();

    crypto
        .ecc
        .affine_point_multiplication(
            &EllipticCurve::P256,
            &k.to_bytes(),    // Scalar (k)
            x.as_mut_slice(), // In/out: x coord
            y.as_mut_slice(), // In/out: y coord
        )
        .map_err(|ecc_err| CryptoError::EccMultiplication { ecc_err })?;

    // r = x_R reduced mod n
    let r = Scalar::reduce_bytes(FieldBytes::from_slice(&x));

    // s = k^{-1}(z + r * d) mod n
    let s = k_inv * (z + (r * *d));

    // Serialize signature (r || s)
    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..SIGNATURE_LEN / 2].copy_from_slice(&r.to_repr());
    sig[SIGNATURE_LEN / 2..].copy_from_slice(&s.to_repr());

    Ok(sig)
}

/// Verify a raw ECDSA (P‑256) signature over `msg`.
///
/// Expects `sig` as 64 bytes: r (first 32) || s (last 32).
///
/// Verification algorithm:
/// 1. Parse r, s; fail if zero or non-canonical.
/// 2. Compute z = H(msg) reduced modulo n.
/// 3. Compute w = s^{-1} mod n.
/// 4. Compute u1 = z * w; u2 = r * w.
/// 5. Compute point: (X, Y) = u1 * G + u2 * Q (hardware accelerated).
/// 6. Signature valid if X reduced modulo n == r.
///
/// Returns:
/// - `Ok(true)` if signature validates
/// - `Ok(false)` if r/s is zero or X != r
///
/// Errors:
/// - `NonCanonicalScalar` if r or s fails canonical decoding
/// - `InvertScalar` if s inversion fails
/// - `MissingQProjX/Y` if public key encoding is malformed
/// - `DecodePoint` if hardware output is not a valid curve point
/// - `EccMultiplication` on hardware failures
pub fn ecdsa_verify(
    crypto: &mut CryptoContext,
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<bool, CryptoError> {
    // SEC1 uncompressed encoding of public key
    let q_proj = crypto.server_public_key.to_encoded_point(false);

    // Deserialize r, s (each 32 bytes)
    let r = Scalar::from_repr(*FieldBytes::from_slice(&sig[..32]))
        .into_option()
        .context(NonCanonicalScalarSnafu { name: "r" })?;
    let s = Scalar::from_repr(*FieldBytes::from_slice(&sig[32..]))
        .into_option()
        .context(NonCanonicalScalarSnafu { name: "s" })?;

    // Reject if r or s is zero (standard ecdsa requirement).
    if r.is_zero_vartime() || s.is_zero_vartime() {
        return Ok(false);
    }

    // Hash and reduce to scalar z
    let msg_hash = sha256_hash(&mut crypto.sha, msg);
    let z: Scalar = Scalar::reduce_bytes(&FieldBytes::from(msg_hash));

    // w = s^{-1} mod n
    let w = s
        .invert()
        .into_option()
        .context(InvertScalarSnafu { name: "s" })?;
    let u1 = z * w;
    let u2 = r * w;

    // Computes scalar * (provided base point) using ECC hardware
    let mut scalar_mul = |scalar: &GenericArray<u8, U32>,
                          x: &mut GenericArray<u8, U32>,
                          y: &mut GenericArray<u8, U32>|
     -> Result<ProjectivePoint, CryptoError> {
        crypto
            .ecc
            .affine_point_multiplication(&EllipticCurve::P256, scalar, x, y)
            .map_err(|ecc_err| CryptoError::EccMultiplication { ecc_err })?;

        // Reconstruct affine point from (x, y) bytes. If invalid, fail
        ProjectivePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(x, y, false))
            .into_option()
            .context(DecodePointSnafu)
    };

    // Compute u1 * G
    let mut x1 = NistP256::GENERATOR.0.to_bytes();
    let mut y1 = NistP256::GENERATOR.1.to_bytes();
    let p1 = scalar_mul(&u1.to_bytes(), &mut x1, &mut y1)?;

    // Extract public key coordinates for Q
    let mut qx = *q_proj.x().context(MissingQProjXSnafu)?;
    let mut qy = *q_proj.y().context(MissingQProjYSnafu)?;

    // Compute u2 * Q
    let p2 = scalar_mul(&u2.to_bytes(), &mut qx, &mut qy)?;

    // R' = (u1 * G) + (u2 * Q)
    let rprime = (p1 + p2).to_affine();

    // Extract x-coordinate as scalar
    let rprime_x = Scalar::from_repr(rprime.x())
        .into_option()
        .context(DecodePointSnafu)?;

    Ok(rprime_x == r)
}
