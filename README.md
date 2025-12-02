# 🔐 Cryptography

[![Docs.rs](https://img.shields.io/badge/docs.rs-documentation-blue.svg)](https://docs.rs/cryptography)  
[![License](https://img.shields.io/badge/license-SSPL-blue.svg)](LICENSE)

**Cryptography** is the dedicated cryptographic backend for the **Nebula** ecosystem.  
It provides fast, lightweight and minimal cryptographic primitives designed to be fully independent from the network layer.

💡 *This crate is built to evolve over time without requiring changes to Nebula itself.*

---

## ✨ Features

Current implementations:

- ⚡ **SHA-256 hashing**  
- 🔢 **U256** — a 256-bit unsigned integer type  

Planned additions:

- 🔒 More hashing algorithms  
- 🔑 Asymmetric key primitives  
- ✍️ Signature schemes  
- 🎲 Secure randomness utilities  
- 🧱 Additional building blocks for cryptographic protocols  

---

## 🚀 Getting Started

This crate is not published on crates.io.  
Add it directly from GitHub:

``` toml
[dependencies]
cryptography = { git = "https://github.com/enzoblain/cryptography" }
``` 

---

## 📚 Documentation

Generate the documentation locally:

``` 
cargo doc --open
``` 

All functions and types are documented inline for clarity and simplicity.

---

## 🤝 Contributing

Contributions are welcome — especially regarding:

- routing performance & correctness  
- async networking design  
- serialization formats  
- SDK ergonomics  
- testing infrastructure  

Standard workflow:

```bash
cargo fmt
cargo clippy
cargo test --workspace
```

Check [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## 📄 License Philosophy

Cryptography is licensed under the **Server Side Public License (SSPL) v1**.

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

In short, SSPL ensures that Cryptography — and the Nebula ecosystem built on top of it —  
remains **open to the community, but protected from fragmentation and exploitation**.

---

## 🧭 Vision

`Cryptography` aims to become a **compact, modern, and secure cryptographic toolbox** for Nebula and its derivatives.  
Focus is on:

- **clarity**  
- **performance**  
- **auditability**  
- **minimal dependencies**

A clean foundation for everything Nebula will need in the future.