/// Constant-time comparison utilities.
///
/// This trait provides constant-time primitives used in cryptographic code
/// to avoid timing side-channels. Implementations must ensure that execution
/// time does not depend on secret data.
///
/// The primary operation is equality testing (`ct_eq`). An optional
/// sign/negativity extraction (`ct_neg`) is provided for types where this
/// notion is meaningful (e.g. signed integers).
///
/// All operations are designed to compile down to branch-free code.
pub trait ConstantTimeEq {
    /// Returns `true` if `self == other`, in constant time.
    ///
    /// This method must not introduce data-dependent branches or early exits.
    fn ct_eq(&self, other: &Self) -> bool;

    /// Returns the sign bit of the value in constant time.
    ///
    /// The exact meaning depends on the implementing type:
    /// - for signed integers, this typically returns `1` if the value is
    ///   negative and `0` otherwise
    ///
    /// The default implementation is intentionally left unimplemented and
    /// must be overridden where applicable.
    fn ct_neg(&self) -> u8 {
        unimplemented!("ct_neg is not implemented for this type")
    }
}

impl ConstantTimeEq for i8 {
    /// Constant-time equality test for `i8`.
    ///
    /// This implementation uses bitwise operations and arithmetic to avoid
    /// branches. The result is independent of the actual values of the inputs.
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        let a = *self as u8;
        let b = *other as u8;
        ((((a ^ b) as u64).wrapping_sub(1) >> 63) as u8) == 1
    }

    /// Extracts the sign bit of the `i8` in constant time.
    ///
    /// Returns `1` if the value is negative, `0` otherwise.
    #[inline(always)]
    fn ct_neg(&self) -> u8 {
        ((*self as i64 as u64) >> 63) as u8
    }
}

impl ConstantTimeEq for [u8; 32] {
    /// Constant-time equality test for 32-byte arrays.
    ///
    /// All bytes are XORed and accumulated before comparison, ensuring that
    /// the execution time does not depend on where the first difference occurs.
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        self.iter()
            .zip(other)
            .map(|(a, b)| a ^ b)
            .fold(0, |acc, v| acc | v)
            == 0
    }
}
