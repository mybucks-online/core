# @mybucks.online/core

This is a core part of [mybucks.online](https://mybucks.online) crypto wallet, involving hash and private key generation, generate and parse transfer-link token.

## mybucks.online

[Mybucks.online](https://mybucks.online) is a **password-only, self-custodial and browser-based cryptocurrency wallet** built with Javascript. It generates a private key from your password and passcode using an industry-standard, verified **one-way hash function**. Your private key forms your account, allowing you to transfer, receive, and hold your crypto assets instantly.

As a hash function, the **scrypt** Key Derivation Function (KDF) increases the computational effort required to crack passwords, effectively delaying **brute-force** attacks and making them impractical.

It fully runs on your **browser side** without using any storage or invoking any 3rd-party APIs for key management. It instantly generates your private key from your password input, and whenever you close or refresh, there is no footprint. This absolutely protects your privacy.

## Quick start

### 1. Install

```bash
npm install @mybucks.online/core
```

### 2. Generate hash and private-key

```javascript
import { getEvmPrivateKey, generateHash } from "@mybucks.online/core";

const showProgress = (p) => {
  console.log(`progress: ${p * 100}%`);
};

const hash = await generateHash(password, passcode, showProgress);
const privateKey = getEvmPrivateKey(hash);

console.log("Private key: ", privateKey);
```

### 3. Generate and parse (transfer-link's)token
```javascript
import { generateToken } from "@mybucks.online/core";
const token = generateToken(password, passcode, network);

console.log("https://app.mybucks.online?wallet=" + token);
```

```javascript
import { parseToken } from "@mybucks.online/core";
const [password, passcode, network] = parseToken(token);
console.log("Account credentials are: ", password, passcode);
console.log("Network: ", network);
```

## Test
```bash
npm run test
```

## Docs

Find the docs [here](https://docs.mybucks.online).

## Live example

- https://github.com/mybucks.online/app
- https://app.mybucks.online  
  password: **DemoAccount5&**  
  passcode: **112324**
- https://app.mybucks.online/?wallet=VWnsSGRGVtb0FjY291bnQ1JgIxMTIzMjQCb3B0aW1pc20=_wNovT
