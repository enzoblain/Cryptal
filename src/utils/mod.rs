/// System-level utilities.
///
/// This module groups low-level helpers related to the execution
/// environment. Its exact contents are intentionally kept flexible
/// and may evolve over time as the needs of the crate grow.
///
/// At the moment, this module contains system-facing functionality
/// required by some components, but it is not limited to any specific
/// operating system or platform abstraction strategy.
///
/// No cryptographic algorithms are defined here. The purpose of this
/// module is to keep environment-dependent or system-adjacent concerns
/// isolated from core cryptographic logic.
pub(crate) mod os;
