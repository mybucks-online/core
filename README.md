# @mybucks.online/core

This is a core part of [mybucks.online](https://mybucks.online) crypto wallet, involving hashing and private key generation.

## mybucks.online

[Mybucks.online](https://mybucks.online) is a **password-only, self-custodial and browser-based cryptocurrency wallet** built with Javascript. It generates a private key from your password and passcode using an industry-standard, verified **one-way hash function**. Your private key forms your account, allowing you to transfer, receive, and hold your crypto assets permanently.

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

## Test
```bash
npm run test
```

## Docs

Find the docs [here](https://docs.mybucks.online).

## Live example

- https://github.com/mybucks.online/app
- https://app.mybucks.online
