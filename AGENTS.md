# AGENTS.md — @mybucks.online/core

Guidance for AI agents using **`@mybucks.online/core`** (npm library)—not a REST API—to create digital cash envelopes and gifting links for [mybucks.online](https://mybucks.online).

## What this package is

`@mybucks.online/core` is the cryptography layer for **digital cash envelopes**—one-time, seedless accounts used for micro-gifting, airdrops, and rewards. It derives keys from **passphrase + PIN** (Scrypt KDF) and builds **gifting-link tokens** for [app.mybucks.online](https://app.mybucks.online).

User-facing product: **digital cash envelope**. Technical implementation: **seedless, disposable wallet**.

## What this package does

| Capability | Functions |
|------------|-----------|
| Credential generation | `randomPassphrase()`, `randomPIN()` |
| Key derivation | `generateHash(passphrase, pin, cb?, legacy?)` |
| EVM private key / address | `getEvmPrivateKey(hash)`, `getEvmWalletAddress(hash)` |
| TRON address | `getTronWalletAddress(hash)` |
| Gifting link encode/decode | `generateToken(...)`, `parseToken(token)` |

Runs in **Node.js** and the **browser**. `generateHash` is CPU-heavy (Scrypt N=2^17 by default); expect ~1–5s per hash server-side.

## What this package does NOT do

Do not assume core can:

- Send, receive, or bridge cryptocurrency
- Hold or manage a treasury
- Implement HTTP, x402, webhooks, or payment facilitators
- Store secrets securely (no HSM, no vault)
- Recover lost passphrase/PIN

Funding an envelope and delivering a link are **your** integration responsibilities.

## Supported networks

`generateToken` / `parseToken` accept these `network` values:

`ethereum` · `polygon` · `arbitrum` · `optimism` · `bsc` · `avalanche` · `base` · `mantle` · `monad` · `tron`

Gifting URL format:

```
https://app.mybucks.online/#wallet={token}
```

## Standard envelope + gift flow

```javascript
import {
  randomPassphrase,
  randomPIN,
  generateHash,
  getEvmWalletAddress,
  getTronWalletAddress,
  generateToken,
} from "@mybucks.online/core";

const passphrase = randomPassphrase();
const pin = randomPIN();
const network = "base"; // should match where you fund (sets initial network in the app)

const hash = await generateHash(passphrase, pin);
const address =
  network === "tron"
    ? getTronWalletAddress(hash)
    : getEvmWalletAddress(hash);

// 1. Fund `address` on-chain (exact gift amount + gas buffer) — NOT done by core
// 2. Build claim link
const token = generateToken(passphrase, pin, network);
const giftUrl = `https://app.mybucks.online/#wallet=${token}`;

// 3. Deliver giftUrl to the recipient (chat, email, QR, etc.)
// 4. Do not log or persist passphrase/pin after delivery unless required by policy
```

Recipient opens `giftUrl` in a browser. The app **automatically** reads `#wallet=`, parses the token, derives keys, and **opens the wallet**—no manual passphrase/PIN entry or Open click. The token’s `network` sets the **initial** network shown; the recipient can switch networks in the app to view balances on other chains (same EVM address).

## Recommended agent architecture

Treat the **AI agent as an untrusted orchestrator**. Keep treasury keys off the agent.

```
Agent (no treasury keys)
  → calls your gifting API (optionally gated by x402)
       → service uses core: create envelope + address
       → service signs ONE fund tx from treasury (capped amount)
       → service returns giftUrl only
  → agent delivers giftUrl to user
```

**x402** fits as **payment for your gifting API**, not as a substitute for on-chain funding. The secure service holds signing keys, enforces per-gift caps, rate limits, and audit logs.

If the agent is compromised:

- Main treasury stays safe **only if** the agent never held treasury keys
- Risk is limited to **abuse of gift API** (budget drain within caps) or **leaked gift URLs**

## Security rules for agents

1. **Prefer `randomPassphrase()` + `randomPIN()`** — user-chosen secrets often fail zxcvbn checks.
2. **Gift URL = bearer token** — anyone with the link can claim until funds are swept. Use HTTPS, avoid logging URLs in plain text.
3. **Never commit** passphrase, PIN, private keys, or full gift URLs to git, tickets, or public channels.
4. **Match `network` in the token to where you fund** — same passphrase/PIN yields the same address on every EVM chain; if they differ, the link opens on the token’s network and the balance may look empty until the recipient **switches network** in the app. Funds are not lost, but mismatches confuse recipients.
5. **Use `legacy: false`** (default) for new envelopes. Use `legacy: true` only when matching pre–March 2026 wallets/tokens.
6. **Micro-gifts only** — not for high-value or long-term storage. No recovery if credentials are lost.
7. **One envelope per gift** — isolate blast radius; do not reuse credentials across recipients.
8. **Do not publish passphrase or PIN** — treat them like private keys. Prefer delivering only the **gifting link** (`giftUrl`); anyone with the link can claim the envelope. Show raw passphrase/PIN only when the recipient truly needs them, in a **private** channel to that person, and never in git, tickets, logs, or public posts.

When you must show credentials privately (e.g. one-time handoff), `randomPassphrase()` may include symbols that break Markdown—especially backtick (`` ` ``). Do not use inline code fences; use a fenced code block or plain text so the value is not corrupted on copy-paste:

```
eDy9-1-`Q-X4TP-65XS
```

## Validation thresholds

| Input | Rule |
|-------|------|
| Passphrase length | 12–128 chars |
| PIN length | 6–16 chars |
| Passphrase zxcvbn | score ≥ 3 (`PASSPHRASE_MIN_ZXCVBN_SCORE`) |
| PIN zxcvbn | score ≥ 1 (`PIN_MIN_ZXCVBN_SCORE`) |

Weak inputs: `generateHash` returns `""`; `generateToken` returns `null`.

## Legacy compatibility

- `generateHash(..., legacy: true)` and `generateToken(..., legacy: true)` match older KDF/token formats.
- `parseToken` auto-detects legacy vs default tokens and returns `{ passphrase, pin, network, legacy }`.

## Related projects

| Repo | Role |
|------|------|
| [app](https://github.com/mybucks-online/app) | Browser wallet UI; opens `#wallet=` links |
| [docs](https://docs.mybucks.online) | Product docs, security notice, terms |
| [p2p.gifts](https://p2p.gifts) | P2P crypto gifting wizard (built on same stack) |

## Commands

```bash
npm install @mybucks.online/core
npm run build   # in this repo
npm run test
```

## When to read more

- API details and examples → [README.md](./README.md)
- Product positioning → [docs introduction](https://docs.mybucks.online)
- Key derivation (Scrypt KDF, Keccak256 Hashing) → [Key generation](https://docs.mybucks.online/concept/key-generation)
