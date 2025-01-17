import assert from "node:assert";
import { describe, test } from "node:test";
import {
  generateHash,
  getEvmPrivateKey,
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
const DEMO_TOKEN =
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

describe("generateToken", () => {
  test("should return null if password, passcode or network is invalid", async () => {
    assert.strictEqual(generateToken("", "123345", "ethereum"), null);
    assert.strictEqual(generateToken("", "123345"), null);
    assert.strictEqual(generateToken("password", "", "ethereum"), null);
    assert.strictEqual(generateToken("password", "123456", ""), null);
    assert.strictEqual(generateToken("password", "123456", "invalid"), null);
  });
});

describe("parseToken", () => {
  test("should return array of password, passcode, and network", () => {
    const [password, passcode, network] = parseToken(DEMO_TOKEN);

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
