//! Operating system abstraction layer
//!
//! This module provides a unified, platform-independent interface to
//! operating system services required by the Nebula ecosystem.
//!
//! Platform-specific implementations are selected at compile time using
//! conditional compilation. Each submodule exposes the same public surface,
//! allowing higher-level code to remain fully portable.
//!
//! At present, this layer only provides access to operating system entropy,
//! but it is intentionally designed to expand over time.
//!
//! Current capabilities:
//! - cryptographically secure randomness
//!
//! Planned extensions:
//! - time primitives
//! - platform-specific cryptographic services
//! - secure system facilities
//!
//! All exposed functions are safe wrappers around low-level OS APIs.

#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(target_os = "macos")]
pub(crate) use macos::*;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::*;

#[cfg(target_os = "windows")]
pub(crate) mod windows;

#[cfg(target_os = "windows")]
pub(crate) use windows::*;
