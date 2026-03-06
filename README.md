# @mybucks.online/core

This is a core part of [mybucks.online](https://mybucks.online) crypto wallet, involving hash and private key generation, generate and parse transfer-link token.

## mybucks.online

[Mybucks.online](https://mybucks.online) is a **seedless, disposable crypto wallet** designed for **speed and convenience**. It generates a private key from your **passphrase and PIN** using an industry-standard, verified **one-way hash function**. Your private key forms your account, allowing you to transfer, receive, and hold your crypto assets instantly.

As a hash function, the **Scrypt** Key Derivation Function (KDF) increases the computational effort required to crack credentials, effectively delaying **brute-force** attacks and making them impractical.

It fully runs on your **browser side** without using any storage or invoking any 3rd-party APIs for key management. It instantly generates your private key from your credentials input, and whenever you close or refresh, there is **no footprint**. This absolutely protects your privacy.

With mybucks.online, you can send cryptocurrency and even **wallet itself via a URL**. The recipient simply clicks the link to open the wallet and take full ownership. This feature allows you to create a one-time wallet and put stablecoins or memecoins into it. You can **transfer full ownership as a gift** without ever asking for a recipient's wallet address. These serve as a "starter" wallet for the recipients, who can then easily withdraw the funds into their own personal pockets or primary wallets.

This is a powerful tool for **bulk distribution** and **massive airdrops** to many people simultaneously. You no longer need to ask for a wallet address or force users to connect their wallet to your app for a small $5 referral fee. You simply share the unique links through any messaging platform, social media, or email.

### Zero Footprint  
- No servers, no databases, no storage and no tracking.
- 100% browser-based.
- Your credentials never leave your device.
- Your account is generated whenever you open it. Closing or refreshing your browser erases all traces/history.

### Fast and Easy
- No app installs, no browser extensions, no registration and no KYC.
- You can create or open your wallet in seconds - all you need is your browser.
- Passphrase is easier to handle and remember than seed phrases.

### 1-Click Gifting
- Stop asking your friends for their wallet addresses.
- Send a wallet as a URL rather than just sending coins.
- The recipient clicks the URL and takes full ownership instantly.
- This makes **gifting or airdropping perfectly easy** and enables massive micro-gifting in seconds.

By integrating this library, you can programmatically generate thousands of unique wallet links and distribute them via your own marketing platforms, email lists, or social media campaigns.

## Quick start

### 1. Install

```bash
npm install @mybucks.online/core
```

### 2. Generate hash, private-key and wallet address

Passphrase and PIN are validated with **zxcvbn** before hashing. Weak passphrase or PIN will yield an empty hash or `null` token.

```javascript
import { 
  getEvmPrivateKey, 
  getEvmWalletAddress, 
  getTronWalletAddress,
  generateHash
} from "@mybucks.online/core";

const showProgress = (p) => {
  console.log(`progress: ${p * 100}%`);
};

const hash = await generateHash(passphrase, pin, showProgress);

const privateKey = getEvmPrivateKey(hash);
console.log("Private key: ", privateKey);

const address1 = getEvmWalletAddress(hash);
console.log("EVM Address: ", address1);

const address2 = getTronWalletAddress(hash);
console.log("TRON Address: ", address2);
```

### 3. Generate and parse (transfer-link's)token
```javascript
import { generateToken } from "@mybucks.online/core";
const token = generateToken(passphrase, pin, network);

console.log("https://app.mybucks.online/#wallet=" + token);
```

```javascript
import { parseToken } from "@mybucks.online/core";
const [passphrase, pin, network] = parseToken(token);
console.log("Account credentials are: ", passphrase, pin);
console.log("Network: ", network);
```

## Changes (default vs legacy)

To make the wallet more secure and resilient against attacks, and to meet standards and follow best practices (e.g. NIST SP 800-132, OWASP, RFC 7914), we introduced a new version that is now the default. A **`legacy`** flag is available for backward compatibility with existing wallets and tokens.

**Scrypt parameters (default)**  
- **N** is increased from 2^15 to **2^17** to raise the memory cost and make GPU/ASIC brute-force attacks much harder.  
- **p** is reduced from 5 to **1** so hashing time stays the same or lower for users while resistance to brute-force is improved.

**Salt generation (default)**  
- Legacy used only the **last 4 characters of the passphrase** plus the pin, which discarded most of the passphrase entropy.  
- The default now derives the salt from the **full passphrase and pin** via a structured encoding and adds a **domain separator** so hashes are bound to this KDF and not reusable in other protocols or versions.

**Token generation (default)**  
- Legacy encoded the transfer-link token by **concatenating** passphrase, pin and network with a delimiter, which is ambiguous for some inputs.  
- The default uses **ABI encoding** for the payload so there is no concatenation ambiguity.  
- `parseToken` accepts both legacy and default token formats automatically.

Use `generateHash(passphrase, pin, cb, true)` or `generateToken(passphrase, pin, network, true)` only when you need to match existing legacy wallets or tokens.

## Test
```bash
npm run test
```

## Docs

Find the docs [here](https://docs.mybucks.online).

## Live example

- https://github.com/mybucks-online/app
- https://app.mybucks.online  
  passphrase: **DemoAccount5&**  
  PIN: **112324**
- https://app.mybucks.online/#wallet=VWnsSGRGVtb0FjY291bnQ1JgIxMTIzMjQCb3B0aW1pc20=_wNovT
- https://app.mybucks.online/#wallet=1jpFD8RGVtb0FjY291bnQ1JgIxMTIzMjQCYmFzZQ==fhk-GL
- https://codesandbox.io/p/sandbox/mybucks-online-key-generation-sandbox-lt53c3
