# 🔐 Decentralized Key Recovery via Threshold Secret Sharing

> **EC8204 — Blockchain and Cyber Security**  
> University of Ruhuna, Faculty of Engineering  
> Department of Electrical & Information Engineering

---

## Table of Contents

- [Introduction](#introduction)
- [Problem Statement](#problem-statement)
- [Proposed Solution](#proposed-solution)
- [Key Concepts](#key-concepts)
  - [Shamir's Secret Sharing](#shamirs-secret-sharing)
  - [Threshold Cryptography](#threshold-cryptography)
  - [Hash Commitments](#hash-commitments)
- [System Architecture](#system-architecture)
  - [What Lives Off-Chain](#what-lives-off-chain-python)
  - [What Lives On-Chain](#what-lives-on-chain-solidity)
  - [Why This Split?](#why-this-split)
- [Recovery Flow](#recovery-flow)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [How to Run](#how-to-run)
  - [Step 1: Generate Key and Shares (Off-Chain)](#step-1-generate-key-and-shares-off-chain)
  - [Step 2: Test Key Recovery (Off-Chain)](#step-2-test-key-recovery-off-chain)
  - [Step 3: Deploy Smart Contract (Remix IDE)](#step-3-deploy-smart-contract-remix-ide)
  - [Step 4: Run Demo Scenarios in Remix](#step-4-run-demo-scenarios-in-remix)
  - [Step 5: Run Automated Tests (Hardhat)](#step-5-run-automated-tests-hardhat)
- [Smart Contract Reference](#smart-contract-reference)
  - [Constructor](#constructor)
  - [Functions](#functions)
  - [Events](#events)
- [Security Analysis](#security-analysis)
- [Known Limitations](#known-limitations)
- [Future Work](#future-work)
- [Troubleshooting](#troubleshooting)
- [References](#references)

---

## Introduction

This project implements a **Decentralized Key Recovery System** using **Shamir's Secret Sharing** and **Ethereum smart contracts**. It allows a user to split a private key (or any secret) into multiple shares distributed among trusted guardians, such that recovering the key requires a minimum number of guardians (a *threshold*) to cooperate. No single guardian can reconstruct the key alone, and no single custodian needs to be trusted.

The blockchain smart contract acts as a transparent, tamper-proof coordinator that enforces the rules of the recovery process — who the guardians are, how many must approve, and a cooldown period that lets the original owner cancel a fraudulent recovery attempt.

---

## Problem Statement

In blockchain and cryptographic systems, **private keys** are the sole means of controlling digital assets and identities. This creates two critical problems:

1. **Key Loss:** If a user loses their private key, they permanently lose access to their assets. There is no "forgot password" mechanism. Real-world examples include [James Howells' lost Bitcoin hard drive (7,500 BTC)](https://en.wikipedia.org/wiki/James_Howells_(IT_worker)) and the [QuadrigaCX exchange collapse](https://en.wikipedia.org/wiki/Quadriga_Fintech_Solutions) where the CEO's death locked $190 million in crypto assets.

2. **Single Point of Failure:** If the key is handed to a single custodian (a friend, a company, a hardware wallet), that custodian becomes a single point of failure. They could be compromised, act maliciously, or simply lose the key themselves.

**The core challenge:** How do you back up a private key without trusting any single entity?

---

## Proposed Solution

We combine two technologies to solve this:

### 1. Shamir's Secret Sharing (Off-Chain)
Split the secret key into `n` shares such that any `t` shares (the *threshold*) can reconstruct the original key, but fewer than `t` shares reveal **absolutely nothing** about the key. This is not encryption — it provides *information-theoretic security*, meaning even an attacker with infinite computing power learns nothing from `t-1` shares.

### 2. Ethereum Smart Contract (On-Chain)
A smart contract manages the recovery process transparently:
- Stores the list of guardians and their share commitments (hashes, not actual shares).
- Enforces that at least `t` guardians must approve a recovery request.
- Implements a cooldown period so the original owner can cancel a malicious recovery.
- Provides a `verifyShare` function to check that a guardian's share is genuine.

**Together:** Shamir provides the cryptographic splitting, and the blockchain provides transparent, tamper-proof governance of the recovery rules. Neither works as well alone — Shamir without blockchain requires a trusted coordinator, and blockchain without Shamir would expose the key on the public ledger.

---

## Key Concepts

### Shamir's Secret Sharing

Invented by [Adi Shamir](https://en.wikipedia.org/wiki/Adi_Shamir) in 1979, this scheme is based on the mathematical fact that a polynomial of degree `t-1` is uniquely determined by `t` points.

**How it works:**

1. **Setup:** Choose a large prime `p`. The secret `S` is an integer modulo `p`.
2. **Split:** Construct a random polynomial of degree `t-1`:
   ```
   f(x) = S + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹  (mod p)
   ```
   where `S = f(0)` is the secret, and `a₁, a₂, ..., aₜ₋₁` are random coefficients.
3. **Distribute:** Evaluate the polynomial at `n` different points: share `i` = `(i, f(i))`.
4. **Recover:** Given any `t` shares (points on the polynomial), use [Lagrange interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial) to reconstruct `f(x)` and evaluate `f(0) = S`.

**Example (3-of-5):**
- The secret is the y-intercept of a degree-2 polynomial (a parabola).
- Any 3 points uniquely define a parabola → the secret is recovered.
- With only 2 points, infinitely many parabolas pass through them → no information about the secret is leaked.

In this project, we use the [Mersenne prime](https://en.wikipedia.org/wiki/Mersenne_prime) `p = 2⁵²¹ - 1`, which is large enough for any 256-bit key.

### Threshold Cryptography

Threshold cryptography generalizes the idea: instead of one entity controlling a secret, `t` out of `n` entities must cooperate. Our system implements a `3-of-5` threshold, meaning:

- 5 guardians each hold one share.
- Any 3 guardians can reconstruct the key.
- 1 or 2 guardians learn nothing about the key.
- If 2 guardians lose their shares, the remaining 3 can still recover the key (redundancy).

The threshold `t` is a security parameter — higher `t` means more collusion resistance but less redundancy.

### Hash Commitments

A **commitment** is a hash `H(share || salt)` where:
- `share` is the actual secret share (kept private).
- `salt` is a random 32-byte value (kept private).
- `H` is SHA-256.

**Why commitments?**

| Without commitments | With commitments |
|---|---|
| Shares on blockchain = anyone can read them | Only hashes on blockchain = shares stay private |
| Guardian could submit a fake share undetected | `verifyShare()` catches fakes |

**Why the salt?**
Without a salt, an attacker could hash every possible share value and compare against the on-chain commitment (a *preimage attack* or *rainbow table attack*). The 32-byte random salt makes this computationally infeasible — there are `2²⁵⁶` possible salts for each share.

---

## System Architecture

### What Lives Off-Chain (Python)

| Component | Description |
|---|---|
| Key generation | A random 256-bit (32-byte) private key |
| Shamir split | Polynomial construction and evaluation to produce `n` shares |
| Salt generation | 32-byte random salts for each share commitment |
| Commitment computation | `SHA-256(share_bytes || salt)` |
| Share distribution | Shares and salts handed to guardians privately (not via blockchain) |
| Key reconstruction | Lagrange interpolation from `t` shares |

### What Lives On-Chain (Solidity)

| Component | Description |
|---|---|
| `owner` address | The address of the key owner who deployed the contract |
| `guardians[]` | Ethereum addresses of the trusted guardians |
| `commitments[]` | SHA-256 hashes of each share (one per guardian) |
| `threshold` | Minimum number of approvals required (`t`) |
| `cooldown` | Time window (in seconds) for the owner to cancel a recovery |
| Recovery state machine | `initiateRecovery` → `approveRecovery` → `finalizeRecovery` |
| `verifyShare()` | On-chain verification of a share against its commitment |

### Why This Split?

> **Golden Rule:** Raw shares are **never** put on the blockchain.

Blockchains are **public ledgers** — anyone can read the data stored on them. If shares were stored on-chain, anyone could reconstruct the key. Therefore:

- **Sensitive data** (shares, salts, the original key) stays off-chain.
- **Governance data** (who are the guardians, how many must approve, hash commitments for verification) goes on-chain where it is transparent and tamper-proof.

---

## Recovery Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SETUP PHASE (one-time)                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Owner generates a 256-bit private key                                   │
│       │                                                                  │
│       ▼                                                                  │
│  Shamir split: key → 5 shares (threshold = 3)                           │
│       │                                                                  │
│       ├── Share 1 + Salt 1 → Commitment 1 ─┐                            │
│       ├── Share 2 + Salt 2 → Commitment 2  │                            │
│       ├── Share 3 + Salt 3 → Commitment 3  ├── Deploy contract with     │
│       ├── Share 4 + Salt 4 → Commitment 4  │   guardian addresses +     │
│       └── Share 5 + Salt 5 → Commitment 5 ─┘   commitments              │
│                                                                          │
│  Shares + salts handed to guardians PRIVATELY (not on blockchain)        │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                       RECOVERY PHASE (when key is lost)                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Requester calls initiateRecovery()                                   │
│       │       ↳ Cooldown timer starts                                    │
│       ▼                                                                  │
│  2. Guardians verify the requester's identity (off-chain: call, video)  │
│       │                                                                  │
│       ▼                                                                  │
│  3. Guardians call approveRecovery() (need ≥ 3 approvals)              │
│       │                                                                  │
│       ▼                                                                  │
│  4. Owner can call cancelRecovery() during cooldown if it's fake        │
│       │                                                                  │
│       ▼                                                                  │
│  5. After cooldown expires AND ≥ 3 approvals:                           │
│     Requester calls finalizeRecovery()                                   │
│       │                                                                  │
│       ▼                                                                  │
│  6. Guardians send their shares to the requester (off-chain)            │
│       │                                                                  │
│       ▼                                                                  │
│  7. Requester verifies each share against its on-chain commitment       │
│     using verifyShare()                                                  │
│       │                                                                  │
│       ▼                                                                  │
│  8. Requester reconstructs the key via Lagrange interpolation           │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
key-recovery/
├── shamir.py                  # Core Shamir's Secret Sharing library
│                              #   - split(): split secret into n shares
│                              #   - recover(): Lagrange interpolation
│                              #   - share_to_bytes() / bytes_to_share()
│
├── split.py                   # Key generation and share distribution script
│                              #   - Generates random 256-bit key
│                              #   - Creates 5 shares (threshold = 3)
│                              #   - Computes salted SHA-256 commitments
│                              #   - Outputs shares.json and key_original.txt
│
├── recover.py                 # Key reconstruction script
│                              #   - Takes guardian indices as CLI arguments
│                              #   - Reconstructs key from selected shares
│                              #   - Verifies against original key
│
├── shares.json                # [Generated] Guardian data (shares, salts, commitments)
├── key_original.txt           # [Generated] Original key for verification
│
├── contracts/
│   └── KeyRecovery.sol        # Solidity smart contract
│                              #   - Guardian and commitment management
│                              #   - Recovery initiation, approval, cancellation
│                              #   - Cooldown enforcement
│                              #   - On-chain share verification
│
├── test/
│   └── KeyRecovery.test.js    # Automated Hardhat test suite (5 tests)
│
├── hardhat.config.js          # Hardhat configuration
├── package.json               # Node.js dependencies
└── README.md                  # This file
```

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| **Python** | 3.8 or newer | Shamir's Secret Sharing (uses only standard library, no pip packages needed) |
| **Node.js** | 18 or newer | Hardhat automated tests (optional) |
| **Web Browser** | Any modern browser | Remix IDE for contract deployment and demo |

**Check your versions:**
```bash
python3 --version    # Must be 3.8+
node --version       # Must be 18+ (only needed for Hardhat tests)
```

> **Note:** The Python scripts use `pow(base, -1, modulus)` for modular inverse, which requires Python 3.8+.

---

## How to Run

### Step 1: Generate Key and Shares (Off-Chain)

```bash
cd key-recovery
python3 split.py
```

**Output:**
```
Original key : a462502ec051bb96c36b32b9c1740a820a88f90b44e45242e7ac75bfab365c6b

Commitments array for the contract constructor:
["0x9eb3601a...", "0x715d416a...", "0xd9f4a7a2...", "0xc900b2c8...", "0x4e397049..."]
```

**What happens:**
1. A random 256-bit key is generated.
2. The key is split into 5 shares using a degree-2 polynomial over GF(2⁵²¹ - 1).
3. Each share is paired with a random 32-byte salt, and `SHA-256(share || salt)` is computed.
4. Everything is saved to `shares.json`.
5. The commitments array is printed — **copy this for the smart contract deployment**.

**Generated files:**
- `shares.json` — contains each guardian's index, share (hex), salt (hex), and commitment (hex).
- `key_original.txt` — the original key in hex (for demo verification only).

### Step 2: Test Key Recovery (Off-Chain)

**Successful recovery (3 shares = threshold met):**
```bash
python3 recover.py 0 1 2
```
```
Using guardians [0, 1, 2]
Recovered: a462502ec051bb96c36b32b9c1740a820a88f90b44e45242e7ac75bfab365c6b
MATCH!
```

**Try any other combination of 3:**
```bash
python3 recover.py 1 3 4
```
```
Using guardians [1, 3, 4]
Recovered: a462502ec051bb96c36b32b9c1740a820a88f90b44e45242e7ac75bfab365c6b
MATCH!
```

**Failed recovery (2 shares = below threshold):**
```bash
python3 recover.py 0 1
```
```
Using guardians [0, 1]
Recovered: <random garbage hex>
NO MATCH (not enough shares)
```

This demonstrates the **information-theoretic security** of Shamir's scheme: with fewer than `t` shares, the recovered value is completely random and unrelated to the real key.

### Step 3: Deploy Smart Contract (Remix IDE)

1. Open **[Remix IDE](https://remix.ethereum.org)** in your browser.

2. **Create the contract file:**
   - In the File Explorer (left panel), navigate to `contracts/`.
   - Create a new file named `KeyRecovery.sol`.
   - Copy and paste the contents of `contracts/KeyRecovery.sol` from this project.

3. **Compile:**
   - Go to the **Solidity Compiler** tab (left sidebar, second icon).
   - Select compiler version `0.8.20` or newer.
   - Click **Compile KeyRecovery.sol**.
   - Verify there are no errors.

4. **Prepare accounts:**
   - Go to the **Deploy & Run Transactions** tab (left sidebar, third icon).
   - Set **Environment** to `Remix VM (Shanghai)` or `Remix VM (Prague)`.
   - Remix provides 15 pre-funded test accounts. Assign roles:

   | Role | Remix Account |
   |---|---|
   | Owner (deployer) | Account 0 (first in dropdown) |
   | Guardian 0 | Account 1 |
   | Guardian 1 | Account 2 |
   | Guardian 2 | Account 3 |
   | Guardian 3 | Account 4 |
   | Guardian 4 | Account 5 |
   | Requester | Account 6 |

5. **Deploy:**
   - Select **Account 0** (the owner).
   - Expand the **Deploy** section and fill in:
     - `_guardians`: Array of 5 guardian addresses (copy from Remix):
       ```json
       ["0xAddr1","0xAddr2","0xAddr3","0xAddr4","0xAddr5"]
       ```
     - `_commitments`: Paste the commitments array from `split.py` output:
       ```json
       ["0x9eb3...","0x715d...","0xd9f4...","0xc900...","0x4e39..."]
       ```
     - `_threshold`: `3`
     - `_cooldown`: `60` (seconds; use `10` for quick testing)
   - Click **transact** (orange button).
   - The deployed contract appears under **Deployed Contracts**.

### Step 4: Run Demo Scenarios in Remix

#### Scenario A: Successful Recovery (3-of-5 Guardians Approve)

1. Switch to **Account 6** (Requester) → call `initiateRecovery`.
2. Switch to **Account 1** (Guardian 0) → call `approveRecovery`.
3. Switch to **Account 2** (Guardian 1) → call `approveRecovery`.
4. Switch to **Account 3** (Guardian 2) → call `approveRecovery`.
5. Click `approvals` (blue button) → should show `3`.
6. Switch back to **Account 6** (Requester).
7. If cooldown hasn't passed, `finalizeRecovery` will revert with `"cooldown not over"`.
8. Wait for the cooldown to expire, then call `finalizeRecovery` → **success**, emits `RecoveryFinalized` event.
9. Off-chain: run `python3 recover.py 0 1 2` → **MATCH!**

#### Scenario B: Attack Fails (Only 2 Approvals)

1. Account 6 calls `initiateRecovery`.
2. Only Accounts 1 and 2 call `approveRecovery` (only 2 guardians).
3. After cooldown, `finalizeRecovery` reverts with `"not enough approvals"`.
4. Off-chain: `python3 recover.py 0 1` → **NO MATCH**.

#### Scenario C: Owner Cancels a Fake Recovery

1. Account 6 calls `initiateRecovery`.
2. Account 0 (Owner) calls `cancelRecovery`.
3. `recoveryActive` resets to `false`. The attack is stopped.

#### Scenario D: Share Verification

1. Open `shares.json` and find Guardian 0's `share` and `salt` values.
2. In Remix, call `verifyShare`:
   - `index`: `0`
   - `share`: `0x...` (Guardian 0's share from shares.json)
   - `salt`: `0x...` (Guardian 0's salt from shares.json)
3. Returns `true` → the share is genuine.
4. Change one character in the share → returns `false` → fake share detected.

### Step 5: Run Automated Tests (Hardhat)

Install dependencies (one-time):
```bash
cd key-recovery
npm install
```

> If `node_modules` is already present, skip the install step.

Run the test suite:
```bash
node node_modules/.bin/hardhat test
```

**Expected output:**
```
Compiled 1 Solidity file successfully (evm target: paris).

  KeyRecovery
    ✔ recovers with 3 approvals after cooldown
    ✔ fails with only 2 approvals
    ✔ fails before the cooldown ends
    ✔ rejects double approval and non-guardians
    ✔ lets the owner cancel

  5 passing (612ms)
```

**What each test verifies:**

| Test | What It Proves |
|---|---|
| `recovers with 3 approvals after cooldown` | Happy path: threshold met + cooldown passed = recovery succeeds |
| `fails with only 2 approvals` | Below-threshold attack is blocked by the contract |
| `fails before the cooldown ends` | Even with enough approvals, the cooldown window must expire |
| `rejects double approval and non-guardians` | A guardian can't vote twice; non-guardians can't vote |
| `lets the owner cancel` | Owner can stop a fraudulent recovery during the cooldown |

> **Note:** The Hardhat tests use `time.increase(61)` to simulate the passage of time on the local blockchain, so you don't need to wait for the actual cooldown during testing.

---

## Smart Contract Reference

### Constructor

```solidity
constructor(
    address[] memory _guardians,     // Ethereum addresses of the guardians
    bytes32[] memory _commitments,   // SHA-256(share || salt) for each guardian
    uint8   _threshold,              // Minimum approvals needed (t)
    uint256 _cooldown                // Seconds the owner has to cancel
)
```

**Validation rules:**
- `_guardians.length == _commitments.length` (each guardian needs exactly one commitment)
- `2 <= _threshold <= _guardians.length` (threshold must be at least 2)
- No duplicate or zero-address guardians

### Functions

| Function | Access | Description |
|---|---|---|
| `initiateRecovery()` | Anyone | Starts a recovery request. Sets the requester, starts the cooldown timer, increments the round counter. Fails if a recovery is already active. |
| `approveRecovery()` | Guardians only | A guardian approves the current recovery. Increments the approval count. Fails if already approved or not a guardian. |
| `cancelRecovery()` | Owner only | Cancels the current recovery. Use during the cooldown window to stop a fake recovery. |
| `finalizeRecovery()` | Requester only | Completes the recovery. Requires `approvals >= threshold` AND `block.timestamp >= recoveryStart + cooldown`. Emits `RecoveryFinalized`. |
| `verifyShare(index, share, salt)` | Anyone (view) | Returns `true` if `sha256(share || salt) == commitments[index]`. Used off-chain to verify a guardian submitted a real share. |
| `replaceGuardian(index, newGuardian, newCommitment)` | Owner only | Swaps a guardian. Cannot be called during an active recovery. See [Known Limitations](#known-limitations). |
| `guardianCount()` | Anyone (view) | Returns the number of guardians. |

### Events

| Event | Emitted When |
|---|---|
| `RecoveryInitiated(round, requester, readyAt)` | A recovery request is started |
| `Approved(round, guardian, totalApprovals)` | A guardian approves the recovery |
| `RecoveryCancelled(round)` | The owner cancels the recovery |
| `RecoveryFinalized(round, requester)` | The recovery is completed successfully |
| `GuardianReplaced(index, oldGuardian, newGuardian)` | A guardian is swapped by the owner |

---

## Security Analysis

| Threat | Description | Mitigation in This Design |
|---|---|---|
| **Shares leaked on-chain** | If raw shares were stored on-chain, anyone could read the public ledger and reconstruct the key | Only salted SHA-256 hash commitments are stored on-chain. Raw shares are never published. |
| **Guardian collusion** | `t` guardians conspire to steal the key | Choose a high threshold `t`; the cooldown window + `cancelRecovery()` give the owner time to react; choose independent, geographically diverse guardians. |
| **Guardian loss** | Guardians lose their shares or become unreachable | `n > t` provides redundancy. With 5 guardians and threshold 3, up to 2 guardians can be lost. `replaceGuardian()` allows swapping a guardian. |
| **Malicious recovery attempt** | An attacker impersonates the owner and initiates a recovery | The cooldown period gives the real owner time to notice and call `cancelRecovery()`. Guardians should verify the requester's identity out-of-band (video call, in person). |
| **Fake share submitted** | A guardian hands over a fabricated or corrupted share | `verifyShare()` checks the share against the on-chain commitment. A fake share will produce a different hash. |
| **Double approval / replay** | A guardian votes twice, or old votes are reused in a new recovery attempt | `approved[round][guardian]` mapping prevents double voting. The `round` counter increments with each new recovery attempt, invalidating all previous approvals. |
| **Brute-forcing a commitment** | An attacker tries to guess the share by hashing all possible values | The 32-byte random salt creates a `2²⁵⁶` search space per share, making brute-force computationally infeasible. |
| **Single point of failure** | One custodian is compromised | Shamir's scheme provides information-theoretic security: `t-1` or fewer shares reveal zero information about the secret. No single guardian is a point of failure. |

---

## Known Limitations

These are honest limitations of this implementation. Understanding them demonstrates depth of knowledge.

1. **Requester identity:** The smart contract cannot verify who the requester really is in the physical world. It only knows their Ethereum address. Guardians must verify the requester's identity through out-of-band channels (phone call, video call, meeting in person). The blockchain provides transparency and timing rules, not identity verification.

2. **Off-chain share delivery:** After `finalizeRecovery()` succeeds, the guardians send their shares to the requester off-chain (e.g., via encrypted messaging). This channel is not secured by the contract. In a production system, shares would be encrypted to the requester's public key before transmission.

3. **Guardian replacement limitations:** Calling `replaceGuardian()` updates the on-chain guardian address and commitment, but it **does not invalidate the old guardian's share**. The old guardian still possesses a valid share. Proper rotation requires re-splitting the secret with a new polynomial and updating all commitments — a process called *proactive secret sharing*.

4. **Public guardian data:** Guardian addresses and their approval status are visible on the public blockchain. Anyone can see who the guardians are and whether they approved a recovery. Privacy of guardian identities is not protected.

5. **Cooldown dependency:** The cooldown protection relies on the owner actively monitoring the blockchain during the cooldown window. If the owner is unaware that a recovery has been initiated (e.g., they are offline), they cannot cancel it. A production system would add off-chain alerts or notifications.

6. **No key rotation:** Once the secret is split and the contract is deployed, the same shares and commitments are used indefinitely. A production system would support periodic re-sharing (key rotation) to limit the window of exposure if a share is compromised.

---

## Future Work

- **Encrypted share delivery:** Use the requester's public key to encrypt shares before off-chain transmission, securing the delivery channel.
- **Proactive secret sharing:** Periodically re-split the secret with a new polynomial without changing the secret itself, invalidating old shares.
- **Web-based user interface:** Build a frontend (React/Next.js) that integrates MetaMask for a user-friendly guardian management and recovery experience.
- **Testnet deployment:** Deploy the contract to an Ethereum testnet (Sepolia, Goerli) for a more realistic demonstration.
- **Multi-vault support:** Allow a single set of guardians to manage recovery for multiple keys/secrets.
- **Guardian notifications:** Off-chain alert system (email, SMS, push notifications) to notify the owner when a recovery is initiated.
- **Zero-knowledge proofs:** Allow guardians to prove they hold a valid share without revealing it, adding an extra layer of privacy.

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `pow(den, -1, PRIME)` throws `TypeError` | Python version is below 3.8 | Upgrade to Python 3.8 or newer |
| Remix: `"invalid bytes32"` | Commitment is not exactly 64 hex chars after `0x` | Each commitment must be `0x` + exactly 64 hex characters |
| Remix: constructor array errors | Wrong JSON syntax | Use double quotes, no trailing comma: `["0xabc...","0xdef..."]` |
| `finalizeRecovery` reverts | Wrong account, not enough approvals, or cooldown not passed | Ensure you call from the requester account, have ≥3 approvals, and the cooldown has elapsed |
| `verifyShare` returns `false` | Wrong index, share, or salt | Use the exact `0x...` values from `shares.json` and match the correct guardian index |
| `npx hardhat` gives `HHE22` error | npx downloads global Hardhat v3 instead of using local v2 | Use `node node_modules/.bin/hardhat test` instead |
| Hardhat `revertedWith` not found | Missing or incompatible `@nomicfoundation/hardhat-toolbox` | Install with: `npm install --save-dev hardhat@^2.22.0 "@nomicfoundation/hardhat-toolbox@^4.0.0"` |

---

## References

1. Shamir, A. (1979). *How to Share a Secret*. Communications of the ACM, 22(11), 612-613. [DOI:10.1145/359168.359176](https://doi.org/10.1145/359168.359176)
2. Ethereum Foundation. *Solidity Documentation*. [https://docs.soliditylang.org/](https://docs.soliditylang.org/)
3. Hardhat Development Environment. [https://hardhat.org/](https://hardhat.org/)
4. Remix IDE. [https://remix.ethereum.org/](https://remix.ethereum.org/)
5. Wikipedia. *Shamir's Secret Sharing*. [https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
6. Wikipedia. *Lagrange Polynomial Interpolation*. [https://en.wikipedia.org/wiki/Lagrange_polynomial](https://en.wikipedia.org/wiki/Lagrange_polynomial)
7. Wikipedia. *Threshold Cryptosystem*. [https://en.wikipedia.org/wiki/Threshold_cryptosystem](https://en.wikipedia.org/wiki/Threshold_cryptosystem)

---

<p align="center">
  <b>EC8204 — Blockchain and Cyber Security</b><br>
  University of Ruhuna · Faculty of Engineering · Department of Electrical & Information Engineering
</p>
