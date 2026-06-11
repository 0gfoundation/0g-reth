# 0G Post-Quantum Audit Response Report (Draft)

> **Audit source**: Tectonic Labs — [0G] 1-Day Post-Quantum Audit Report (January 2026)  
> **Report date**: June 11, 2026  
> **Scope**: This document focuses on **chain-related** and **execution layer (EL)** findings only. It does not include a full inventory of Storage / DA / Compute network issues.

---

## 1. Executive Summary

The Tectonic quantum readiness audit identified **21** findings in total. Mapped to the 0G architecture, **7** findings are directly related to the chain and execution layer:

| Status | Count | Description |
|--------|-------|-------------|
| **Fixed** | 2 | TEC-09 (chain RPC TLS key exchange), TEC-16 (RLPx ECIES AES-256 handshake) |
| **Not yet fixed** | 5 | TEC-11, TEC-17–TEC-20 (EL layer) |

The remaining open EL items are not being ignored. They are constrained by **EVM ecosystem standards, protocol-level dependencies, and the maturity of post-quantum replacements**, and must be addressed in coordination with Ethereum and the broader industry migration path.

---

## 2. Layer Classification

### 2.1 Chain vs. Execution Layer

| Layer | Definition | Components |
|-------|------------|------------|
| **Chain** | Public entry points and on-chain interaction infrastructure for users and services | EVM RPC endpoints (`evmrpc.*.0g.ai`), on-chain transaction signing, etc. |
| **EL (Execution Layer)** | 0G Reth execution client and its cryptographic implementations | `0g-reth`: P2P, transaction pool, RPC signing, EIP-4844, etc. |

> **Note**: The audit report classifies TEC-09 under "0G Storage Network - Client." However, the affected endpoints `evmrpc-testnet.0g.ai` and `evmrpc.0g.ai` are **chain EVM RPC entry points**, and the DA service also uses this RPC (as noted in TEC-10). TEC-09 should therefore be treated as a **chain infrastructure issue**, not Storage-specific logic.

---

## 3. Fixed Issues

### 3.1 TEC-09 — Chain RPC TLS Key Exchange

#### Issue Overview

| Field | Details |
|-------|---------|
| **ID** | TEC-09 |
| **Title** | RPC endpoints with quantum-vulnerable TLS key exchange |
| **Severity / Urgency** | High / **Critical** |
| **Risk type** | Harvest-Now-Decrypt-Later (HNDL) |

At the time of the audit, all endpoints except RPC Testnet supported only TLS 1.2 and lacked post-quantum or hybrid key exchange:

| Endpoint | TLS version (at audit) | PQ key exchange (at audit) |
|----------|------------------------|----------------------------|
| `evmrpc-testnet.0g.ai:443` | TLS 1.3 | X25519MLKEM768 ✓ |
| `evmrpc.0g.ai:443` | TLS 1.2 | No |
| `indexer-storage-testnet-turbo.0g.ai:443` | TLS 1.2 | No |
| `indexer-storage-turbo.0g.ai:4443` | TLS 1.2 | No |

#### Remediation

**Status: Fixed**

TLS upgrades have been completed for chain-related RPC endpoints:

1. **Upgraded to TLS 1.3** with post-quantum or hybrid key exchange support (e.g., X25519MLKEM768).
2. **Covered high-risk endpoints** flagged in the audit, including mainnet RPC (`evmrpc.0g.ai`).
3. **Aligned CDN / load balancer and certificate configuration** with documentation.

---

### 3.2 TEC-16 — RLPx ECIES Handshake AES-128-CTR

#### Issue Overview

| Field | Details |
|-------|---------|
| **ID** | TEC-16 |
| **Title** | ECIES message encryption based on AES-128-CTR |
| **Location** | `crates/net/ecies/src/algorithm.rs` |
| **Severity / Urgency** | Informational / Informational |
| **Risk** | Grover's algorithm reduces AES-128 effective strength to ~128 bits; CNSA 2.0 recommends Category 5 (AES-256) |

The audit flagged AES-128-CTR usage during the **RLPx ECIES handshake** (auth/ack messages). Note that post-handshake RLPx frame encryption already used AES-256-CTR in 0G Reth.

#### Remediation

**Status: Fixed**

Because the 0G chain runs **only 0G Reth** as its execution client (no Geth or other third-party EL nodes), we upgraded the ECIES handshake to AES-256 without requiring Ethereum ecosystem coordination:

1. **Extended key derivation** from `KDF(S, 32)` to `KDF(S, 48)` — 32-byte encryption key + 16-byte MAC material.
2. **Switched handshake encryption** from `AES-128-CTR` to `AES-256-CTR` in `encrypt_message()` and `decrypt()`.
3. **Bumped RLPx handshake protocol version** from `4` to `5` to signal the 0G extension.

**Deployment note**: All EL nodes must run a build that includes this change. Nodes on protocol version 4 (AES-128 handshake) cannot complete RLPx handshakes with version 5 nodes.

---

## 4. Not Yet Fixed: EL Layer Issues

Five EL findings remain open (TEC-11, TEC-17–TEC-20). Each item below describes the issue, impact, and rationale for deferral.

---

### 4.1 TEC-11 — Blockchain Transaction Signing with ECDSA (Critical)

| Field | Details |
|-------|---------|
| **Location** | 0G Storage Client (`common/blockchain/`, `transfer/uploader.go`, etc.) |
| **Issue** | secp256k1 ECDSA is used to sign on-chain transactions |
| **Risk** | Quantum computers could break ECDSA and forge transaction signatures |
| **Severity / Urgency** | Critical / Medium |

**Why not fixed yet:**

- The 0G chain is **EVM-compatible**; account model and signature verification depend on Ethereum-standard ECDSA (EIP-155, etc.).
- No standardized EVM post-quantum account type or hard-fork path exists yet (see [Tasklist for post-quantum ETH](https://ethresear.ch/t/tasklist-for-post-quantum-eth/21296)).
- Client-side changes alone would break on-chain validation; migration must be synchronized across the ecosystem.

---

### 4.2 TEC-17 — EIP-4844 Blob Transaction Validation with KZG (High)

| Field | Details |
|-------|---------|
| **Location** | `crates/transaction-pool/src/validate/eth.rs`, `crates/rpc/rpc/src/validation.rs`, etc. |
| **Issue** | Blob integrity verification relies on KZG polynomial commitments (BN254, vulnerable to Shor's algorithm) |
| **Risk** | Attackers could forge blob commitments, affecting DA data integrity |
| **Severity / Urgency** | High / Medium |

**Why not fixed yet:**

- KZG is part of the **EIP-4844** standard; 0G Reth must implement it.
- No drop-in post-quantum polynomial commitment standard or Ethereum EIP exists yet.
- Shared with DA-layer TEC-15; requires ecosystem-wide migration.

---

### 4.3 TEC-18 — Keccak-256 Hash Usage (Informational)

| Field | Details |
|-------|---------|
| **Location** | Trie, ECIES MAC, DiscV4, transaction hashing, etc. |
| **Issue** | Keccak-256 used extensively; not aligned with CNSA 2.0 SHA3-384/512 recommendations |
| **Severity / Urgency** | Informational / Informational |

**Why not fixed yet:**

- Keccak-256 is foundational to Ethereum state trie, addresses, and transaction hashes.
- Auditors recommend **no migration** ("No migration seems required"); 128-bit post-quantum strength remains adequate.

---

### 4.4 TEC-19 — RLPx ECDH Key Exchange (Medium)

| Field | Details |
|-------|---------|
| **Location** | `crates/net/ecies/src/algorithm.rs` |
| **Issue** | RLPx P2P handshake uses secp256k1 ECDH |
| **Risk** | HNDL against encrypted P2P traffic |
| **Severity / Urgency** | Medium / Medium |

**Why not fixed yet:**

- ECDH is inherent to the RLPx protocol design.
- Post-quantum P2P (e.g., ML-KEM hybrid handshakes) is still under research ([PSE: quantum-safe P2P](https://pse.dev/blog/towards_a_quantum-safe_p2p_for_ethereum)).
- RLPx payload is ultimately public on-chain, limiting practical HNDL value.

---

### 4.5 TEC-20 — Reth Blockchain Transaction Signing with ECDSA (Critical)

| Field | Details |
|-------|---------|
| **Location** | `crates/rpc/rpc/src/eth/helpers/signer.rs`, `crates/ethereum/primitives/src/transaction.rs`, etc. |
| **Issue** | Reth uses secp256k1 ECDSA for on-chain and RPC signing |
| **Risk** | Signature forgery enabling unauthorized transactions and fund theft |
| **Severity / Urgency** | Critical / Medium |

**Why not fixed yet:**

- Same structural dependency as TEC-11; requires new account/transaction type EIPs and hard-fork activation.
- 0G will follow the Ethereum post-quantum migration path.

---

## 5. EL Layer Summary

| ID | Title | Severity | Urgency | Status | Notes |
|----|-------|----------|---------|--------|-------|
| TEC-11 | On-chain transaction ECDSA signing (Storage Client) | Critical | Medium | Open | Awaiting EVM PQ signing standard |
| TEC-16 | ECIES AES-128-CTR handshake | Info | Info | **Fixed** | Upgraded to AES-256-CTR, protocol v5 |
| TEC-17 | EIP-4844 KZG validation | High | Medium | Open | No PQ polynomial commitment standard |
| TEC-18 | Keccak-256 usage | Info | Info | Open | Auditors recommend no migration |
| TEC-19 | RLPx ECDH key exchange | Medium | Medium | Open | Ethereum PQ P2P still in research |
| TEC-20 | Reth transaction ECDSA signing | Critical | Medium | Open | Requires Ethereum hard-fork-level migration |

---

## 6. Conclusions and Next Steps

### 6.1 Completed Actions

- **TEC-09 (chain RPC TLS)**: Fixed — TLS 1.3 with post-quantum/hybrid key exchange deployed on chain RPC endpoints.
- **TEC-16 (ECIES AES-128 handshake)**: Fixed — RLPx ECIES handshake upgraded to AES-256-CTR (protocol version 5) in `0g-reth`.

### 6.2 Rationale for Open EL Items

1. **Structural dependencies (TEC-11, TEC-17, TEC-19, TEC-20)** — rooted in Ethereum / EVM standards; require ecosystem-level migration.
2. **Compliance annotation (TEC-18)** — auditors recommend no migration; lower priority than authentication findings.

### 6.3 Ongoing Tracking

| Priority | Action |
|----------|--------|
| P0 (ongoing) | Track [Ethereum Post-Quantum Tasklist](https://ethresear.ch/t/tasklist-for-post-quantum-eth/21296) and PSE progress |
| P1 (mid-term) | Monitor PQ polynomial commitments and signature aggregation (TEC-17, DA-layer TEC-15) |
| P2 (long-term) | Implement PQ account types / PQ RLPx once defined by Ethereum; coordinate hard fork |
| Operations | Maintain post-quantum TLS on chain RPC endpoints; ensure all EL nodes run AES-256 handshake builds |

---

## Appendix: Original Severity Distribution (All 21 Findings)

| Critical | High | Medium | Low | Informational |
|----------|------|--------|-----|---------------|
| 2 | 8 | 3 | 0 | 8 |

*Note: The audit assigned 0G QTRL-0 (Exposed), primarily due to HNDL vulnerabilities. TEC-09 and TEC-16 remediation reduces exposure on chain entry points and EL P2P handshake compliance. Remaining EL risk follows industry migration timelines.*
