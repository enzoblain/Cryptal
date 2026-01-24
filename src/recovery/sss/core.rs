//! Shamir Secret Sharing (SSS) core implementation.
//!
//! This module provides the public API for **Shamir Secret Sharing**, a
//! threshold-based cryptographic scheme for splitting and recovering
//! secrets.
//!
//! A secret is divided into multiple *shares* such that:
//!
//! - Any subset of at least `threshold` shares can reconstruct the secret.
//! - Any subset of fewer than `threshold` shares reveals no information
//!   about the secret.
//!
//! The implementation operates over a finite field (GF(256)) and treats
//! the secret as a sequence of independent bytes, each protected by its own
//! randomly generated polynomial.
//!
//! ## Provided operations
//!
//! - [`split`]  
//!   Split a secret into multiple shares with a configurable threshold.
//!
//! - [`combine`]  
//!   Reconstruct the secret from a sufficient number of shares.
//!
//! - [`refresh`]  
//!   Refresh existing shares without ever reconstructing the secret.
//!
//! ## Cryptographic properties
//!
//! - All arithmetic is performed in a finite field (GF(256)).
//! - Each byte of the secret is protected independently.
//! - Polynomial coefficients are generated using a cryptographically
//!   secure pseudorandom number generator.
//! - Share refresh renews shares while keeping the underlying secret
//!   unchanged.
//!
//! ## Scope and limitations
//!
//! This module provides **confidentiality through threshold secrecy only**.
//! It does **not** provide:
//!
//! - authentication or integrity protection for shares
//! - resistance against malicious or byzantine participants
//! - serialization, storage, or transport mechanisms
//!
//! Those concerns must be handled by higher layers of the system.

use crate::{recovery::sss::field::FieldElement, rng::Csprng};

/// A single Shamir Secret Sharing share.
///
/// Each share represents an evaluation of a secret-dependent polynomial
/// at a unique, non-zero identifier.
///
/// A share is only meaningful in combination with other shares that
/// share the same `threshold` and were derived from the same secret.
#[derive(Clone)]
pub struct Share {
    /// Share identifier (x-coordinate).
    ///
    /// Must be non-zero and unique among all shares of the same secret.
    pub id: u8,

    /// Reconstruction threshold.
    ///
    /// At least this many shares are required to reconstruct the secret.
    pub threshold: u8,

    /// Share payload.
    ///
    /// This vector has the same length as the original secret and contains
    /// the polynomial evaluations for each secret byte.
    pub data: Vec<u8>,
}

/// Errors that may occur during Shamir Secret Sharing operations.
#[derive(Debug)]
pub enum SecretSharingError {
    /// The provided threshold or share count is invalid.
    InvalidThreshold,

    /// Not enough shares were provided to complete the operation.
    NotEnoughShares,

    /// Two or more shares have the same identifier.
    DuplicateShareId,

    /// Shares are inconsistent (different thresholds or data lengths).
    InconsistentShares,

    /// A share is malformed or otherwise invalid.
    InvalidShare,
}

/// Splits a secret into multiple shares using Shamir Secret Sharing.
///
/// # Arguments
///
/// - `secret`  
///   The secret to split. Must not be empty.
/// - `threshold`  
///   The minimum number of shares required to reconstruct the secret.
/// - `share_count`  
///   The total number of shares to generate.
///
/// # Returns
///
/// A vector of `share_count` shares, all of which are required to have
/// unique identifiers.
///
/// # Errors
///
/// Returns an error if:
/// - the secret is empty
/// - the threshold is zero
/// - the threshold is greater than the share count
///
/// # Cryptographic notes
///
/// - Each byte of the secret is protected by its own randomly generated
///   polynomial of degree `threshold - 1`.
/// - Polynomial coefficients are generated using a cryptographically
///   secure pseudorandom number generator.
pub fn split(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
) -> Result<Vec<Share>, SecretSharingError> {
    if secret.is_empty() {
        return Err(SecretSharingError::InvalidShare);
    }

    if threshold == 0 || threshold > share_count {
        return Err(SecretSharingError::InvalidThreshold);
    }

    let mut shares = Vec::with_capacity(share_count as usize);
    for id in 1..=share_count {
        shares.push(Share {
            id,
            threshold,
            data: vec![0u8; secret.len()],
        });
    }

    let mut r = Csprng::new();

    for (index, &s) in secret.iter().enumerate() {
        let mut coeffs = vec![FieldElement::ZERO; threshold as usize];

        coeffs[0] = FieldElement::from(s);

        for c in coeffs.iter_mut().skip(1) {
            let mut b = [0u8; 1];
            r.fill_bytes(&mut b);
            *c = FieldElement::from(b[0]);
        }

        for share in &mut shares {
            let x = FieldElement::from(share.id);
            let y = FieldElement::from_polynomial(&coeffs, x);

            share.data[index] = y.into_number();
        }
    }

    Ok(shares)
}

/// Reconstructs a secret from a set of shares.
///
/// # Arguments
///
/// - `shares`  
///   A slice of shares. At least `threshold` shares must be provided.
///
/// # Returns
///
/// The reconstructed secret as a byte vector.
///
/// # Errors
///
/// Returns an error if:
/// - fewer than `threshold` shares are provided
/// - share identifiers are duplicated
/// - shares have inconsistent thresholds or data lengths
/// - a share is malformed
///
/// # Cryptographic notes
///
/// Reconstruction is performed using Lagrange interpolation at zero,
/// without reconstructing the underlying polynomial explicitly.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, SecretSharingError> {
    if shares.is_empty() {
        return Err(SecretSharingError::NotEnoughShares);
    }

    let threshold = shares[0].threshold;

    if shares.len() < threshold as usize {
        return Err(SecretSharingError::NotEnoughShares);
    }

    let secret_len = shares[0].data.len();

    let mut seen = [false; 256];
    for s in shares.iter().take(threshold as usize) {
        if s.id == 0 {
            return Err(SecretSharingError::InvalidShare);
        }

        if seen[s.id as usize] {
            return Err(SecretSharingError::DuplicateShareId);
        }

        seen[s.id as usize] = true;

        if s.threshold != threshold || s.data.len() != secret_len {
            return Err(SecretSharingError::InconsistentShares);
        }
    }

    let mut secret = vec![0u8; secret_len];

    for (index, s) in secret.iter_mut().enumerate() {
        let mut points = Vec::with_capacity(threshold as usize);

        for s in shares.iter().take(threshold as usize) {
            points.push((FieldElement::from(s.id), FieldElement::from(s.data[index])));
        }

        *s = FieldElement::lagrange_at_zero(&points).into_number();
    }

    Ok(secret)
}

/// Refreshes a set of shares without reconstructing the secret.
///
/// This operation generates a new set of shares that correspond to the
/// same underlying secret, while rendering the old shares obsolete.
///
/// # Arguments
///
/// - `shares`  
///   A slice of valid shares derived from the same secret.
///
/// # Returns
///
/// A new vector of shares with the same identifiers and threshold.
///
/// # Errors
///
/// Returns an error if:
/// - no shares are provided
/// - share identifiers are duplicated
/// - shares are inconsistent or malformed
///
/// # Cryptographic notes
///
/// Share refresh works by adding a randomly generated polynomial with
/// zero constant term to the existing shares:
///
/// ```text
/// y' = y + g(x), where g(0) = 0
/// ```
///
/// This guarantees that the secret remains unchanged while all shares
/// are fully renewed.
pub fn refresh(shares: &[Share]) -> Result<Vec<Share>, SecretSharingError> {
    if shares.is_empty() {
        return Err(SecretSharingError::NotEnoughShares);
    }

    let threshold = shares[0].threshold;
    let secret_len = shares[0].data.len();

    let mut seen = [false; 256];
    for s in shares {
        if s.id == 0 {
            return Err(SecretSharingError::InvalidShare);
        }

        if seen[s.id as usize] {
            return Err(SecretSharingError::DuplicateShareId);
        }

        seen[s.id as usize] = true;

        if s.threshold != threshold || s.data.len() != secret_len {
            return Err(SecretSharingError::InconsistentShares);
        }
    }

    let mut new_shares: Vec<Share> = shares
        .iter()
        .map(|s| Share {
            id: s.id,
            threshold,
            data: vec![0u8; secret_len],
        })
        .collect();

    let mut r = Csprng::new();
    for byte_index in 0..secret_len {
        let mut coeffs = vec![FieldElement::ZERO; threshold as usize];

        for c in coeffs.iter_mut().skip(1) {
            let mut b = [0u8; 1];
            r.fill_bytes(&mut b);

            *c = FieldElement::from(b[0]);
        }

        for (old, new) in shares.iter().zip(new_shares.iter_mut()) {
            let x = FieldElement::from(old.id);
            let gx = FieldElement::from_polynomial(&coeffs, x);

            new.data[byte_index] = (FieldElement::from(old.data[byte_index]) + gx).into_number();
        }
    }

    Ok(new_shares)
}
