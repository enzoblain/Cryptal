//! ChaCha20-Poly1305 authenticated encryption (RFC 8439).
//!
//! This module exposes the ChaCha20-Poly1305 AEAD construction by re-exporting
//! the internal Poly1305-based implementation under a clear, unambiguous name.
//!
//! The underlying implementation is split internally for clarity and safety,
//! but users of this module interact only with the high-level AEAD API.

mod poly1305;

/// ChaCha20-Poly1305 AEAD construction.
///
/// This is a re-export of the internal Poly1305-based implementation,
/// providing authenticated encryption with associated data (AEAD)
/// as specified in RFC 8439.
///
/// # Notes
///
/// - This module combines:
///   - ChaCha20 for encryption
///   - Poly1305 for authentication
/// - The API enforces one-time Poly1305 key usage internally.
/// - Nonce reuse with the same key is catastrophic and must be avoided.
///
/// This re-export intentionally hides the internal Poly1305 structure
/// and exposes only the AEAD interface.
pub use poly1305::core as chacha20poly1305;
