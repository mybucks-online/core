# @mybucks.online/core

This is a core part of [mybucks.online](https://mybucks.online) crypto wallet, involving hash and private key generation, generate and parse transfer-link token.

## mybucks.online

[Mybucks.online](https://mybucks.online) is a **seedless, disposable crypto wallet** designed for **speed and convenience**. It generates a private key from your password and passcode using an industry-standard, verified **one-way hash function**. Your private key forms your account, allowing you to transfer, receive, and hold your crypto assets instantly.

As a hash function, the **scrypt** Key Derivation Function (KDF) increases the computational effort required to crack passwords, effectively delaying **brute-force** attacks and making them impractical.

It fully runs on your **browser side** without using any storage or invoking any 3rd-party APIs for key management. It instantly generates your private key from your password input, and whenever you close or refresh, there is **no footprint**. This absolutely protects your privacy.

### Zero Footprint  
- No servers, no databases, no storage and no tracking.
- 100% browser-based.
- Your credentials never leave your device.
- Your account is generated whenever you open it. Closing or refreshing your browser erases all traces/history.

### Fast and Easy
- No app installs, no browser extensions, no registration and no KYC.
- You can create or open your wallet in seconds - all you need is your browser.
- Password is easier to handle and remember than seed phrases

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

const hash = await generateHash(password, passcode, showProgress);

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

- https://github.com/mybucks-online/app
- https://app.mybucks.online  
  password: **DemoAccount5&**  
  passcode: **112324**
- https://app.mybucks.online/?wallet=VWnsSGRGVtb0FjY291bnQ1JgIxMTIzMjQCb3B0aW1pc20=_wNovT
- https://app.mybucks.online/?wallet=1jpFD8RGVtb0FjY291bnQ1JgIxMTIzMjQCYmFzZQ==fhk-GL
- https://codesandbox.io/p/sandbox/mybucks-online-key-generation-sandbox-lt53c3
