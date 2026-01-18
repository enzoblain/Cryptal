# 🔐 Cryptal

[![License](https://img.shields.io/badge/license-SSPL-blue.svg)](LICENSE)
![Dev Rust](https://img.shields.io/badge/Developed%20with-Rust%201.92.0-orange)
[![CI](https://github.com/Nebula-ecosystem/Cryptal/actions/workflows/ci.yml/badge.svg)](https://github.com/Nebula-ecosystem/Cryptal/actions/workflows/ci.yml)

**Cryptal** is the dedicated cryptographic utility for the ***Nebula*** ecosystem, providing only the essential primitives required by the platform.

---

## 📊 Project Status

- [x] **Hashing & Arithmetic**
  - [x] U256 (large integers)
  - [x] U512 (large integers)
  - [x] SHA-256 (integrity, identifiers)
  - [] SHA-512 (integrity, identifiers)

- [ ] **Encryption**
  - [ ] ChaCha20-Poly1305 (confidentiality, integrity)

- [ ] **Key Management**
  - [ ] Argon2id (password → key)
  - [x] CSPRNG (secure randomness)

- [ ] **Public-Key Cryptography**
  - [ ] Ed25519 (signatures, identity)
  - [ ] X25519 (key exchange)

- [ ] **Secret Management**
  - [ ] Shamir’s Secret Sharing (recovery, multi-device)

---

## 🚀 Getting Started

This crate is not yet published on crates.io. Add it directly from GitHub:

``` toml
[dependencies]
cryptal = { git = "https://github.com/Nebula-ecosystem/Cryptal" }
```

---

## 📝 Example: SHA-256 Hash

Hash a message using the SHA-256 implementation:

```rust
use cryptal::hash::sha256;

fn main() {
	let input: &[u8] = b"The quick brown fox jumps over the lazy dog";
	let out: U256 = sha256(input);
}
```

---

## 🔒 Security Notice

Cryptal is **not yet audited** and should be considered **experimental**.

- Do **not** use in production environments.
- APIs and implementations may change without notice.
- Side-channel resistance is **not guaranteed** at this stage.

The crate is designed primarily for research, learning, and internal use within the Nebula ecosystem.

---

---

## 📖 Documentation

You can generate the full API documentation locally using Cargo:

```
cargo doc --open
```

This will build and open the documentation for Cadentis and all its public APIs in your browser.

## 🦀 Rust Version

- **Developed with**: Rust 1.92.0
- **MSRV**: Rust 1.92.0 (may increase in the future)

---

## 📄 License Philosophy

Cryptal is licensed under the **Server Side Public License (SSPL) v1**.

This license is intentionally chosen to protect the integrity of the Nebula ecosystem.  
While the project is fully open for **contribution, improvement, and transparency**,  
SSPL prevents third parties from creating competing platforms, proprietary versions,  
or commercial services derived from the project.

Nebula is designed to grow as **one unified, community-driven network**.  
By using SSPL, we ensure that:

- all improvements remain open and benefit the ecosystem,  
- the network does not fragment into multiple incompatible forks,  
- companies cannot exploit the project without contributing back,  
- contributors retain full access to the entire codebase.


In short, SSPL ensures that Cryptal — and the Nebula ecosystem built on top of it —  
remains **open to the community, but protected from fragmentation and exploitation**.

## 🤝 Contact

For questions, discussions, or contributions, feel free to reach out:

- **Discord**: enzoblain
- **Email**: [enzoblain@proton.me](mailto:enzoblain@proton.me)
