import assert from "node:assert";
import { describe, test } from "node:test";
import {
  generateHash,
  getEvmPrivateKey,
  getEvmWalletAddress,
  getTronWalletAddress,
  generateToken,
  parseToken,
} from "../index.js";

const DEMO_PASSWORD = "DemoAccount5&";
const DEMO_PASSCODE = "112324";
const DEMO_NETWORK = "optimism";

const DEMO_HASH =
  "af9a22d75f8f69d33fe8fc294e8f413219d9c75374dec07fda2e4a66868599609887a10e04981e17356d2c07432fc89c11089172fdf91c0015b9a4beef11e447";
const DEMO_PRIVATE_KEY =
  "0x71743de900c63ed741263a2a4513c1b1829e80bd9f18d5d3a593e651b914cb3b";
const DEMO_WALLET_EVM_ADDRESS = "0x347CEB6Bf002Ee1819009bA07d8dCAA95Efe6465";
const DEMO_WALLET_TRON_ADDRESS = "TEkjnbpr2cTgRFgmrbv2Gb7GdgupZ5Sh3A";

const DEMO_TRANSFER_TOKEN =
  "VWnsSGRGVtb0FjY291bnQ1JgIxMTIzMjQCb3B0aW1pc20=_wNovT";

describe("generateHash", () => {
  test("should return empty string if password or passcode is blank", async () => {
    const hash = await generateHash("", "");
    assert.strictEqual(hash, "");
  });

  test("should return scrypt hash result", async () => {
    const hash = await generateHash(DEMO_PASSWORD, DEMO_PASSCODE);
    assert.strictEqual(hash, DEMO_HASH);
  });
});

describe("getEvmPrivateKey", () => {
  test("should return 256bit private key", async () => {
    const hash = await generateHash(DEMO_PASSWORD, DEMO_PASSCODE);
    const privateKey = getEvmPrivateKey(hash);

    assert.strictEqual(privateKey, DEMO_PRIVATE_KEY);
  });
});

describe("getEvmWalletAddress", () => {
  test("should return a valid wallet address", async () => {
    const hash = await generateHash(DEMO_PASSWORD, DEMO_PASSCODE);
    const address = getEvmWalletAddress(hash);

    assert.strictEqual(address, DEMO_WALLET_EVM_ADDRESS);
  });
});

describe("getTronWalletAddress", () => {
  test("should return a valid wallet address", async () => {
    const hash = await generateHash(DEMO_PASSWORD, DEMO_PASSCODE);
    const address = getTronWalletAddress(hash);

    assert.strictEqual(address, DEMO_WALLET_TRON_ADDRESS);
  });
});

describe("generateToken", () => {
  test("should return null if password, passcode or network is invalid", () => {
    assert.strictEqual(generateToken("", "123345", "ethereum"), null);
    assert.strictEqual(generateToken("", "123345"), null);
    assert.strictEqual(generateToken("password", "", "ethereum"), null);
    assert.strictEqual(generateToken("password", "123456", ""), null);
    assert.strictEqual(generateToken("password", "123456", "invalid"), null);
  });

  test("should return valid token", async () => {
    const token = generateToken(DEMO_PASSWORD, DEMO_PASSCODE, DEMO_NETWORK);

    // The first and last 6 characters serve as random padding.
    assert.strictEqual(
      token.slice(6, token.length - 6),
      DEMO_TRANSFER_TOKEN.slice(6, DEMO_TRANSFER_TOKEN.length - 6)
    );
  });

  test("should return valid token for all networks", async () => {
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "ethereum"),
      null
    );
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "polygon"),
      null
    );
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "arbitrum"),
      null
    );
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "optimism"),
      null
    );
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "bsc"),
      null
    );
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "avalanche"),
      null
    );
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "base"),
      null
    );
    assert.notStrictEqual(
      generateToken(DEMO_PASSWORD, DEMO_PASSCODE, "tron"),
      null
    );
  });
});

describe("parseToken", () => {
  test("should return array of password, passcode, and network", () => {
    const [password, passcode, network] = parseToken(DEMO_TRANSFER_TOKEN);

    assert.strictEqual(password, DEMO_PASSWORD);
    assert.strictEqual(passcode, DEMO_PASSCODE);
    assert.strictEqual(network, DEMO_NETWORK);
  });
});

describe("generateToken and parseToken", () => {
  test("should be compatible and return correct result", () => {
    const testPassword = "random^Password9";
    const testPasscode = "909011";
    const testNetwork = "polygon";
    const token = generateToken(testPassword, testPasscode, testNetwork);

    const [password, passcode, network] = parseToken(token);
    assert.strictEqual(password, testPassword);
    assert.strictEqual(passcode, testPasscode);
    assert.strictEqual(network, testNetwork);
  });
});
