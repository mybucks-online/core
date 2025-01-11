const assert = require("node:assert");
const { describe, test } = require("node:test");
const { generateHash, getEvmPrivateKey } = require("../index.js");

const DEMO_PASSWORD = "DemoAccount5&";
const DEMO_PASSCODE = "112324";
const DEMO_HASH =
  "af9a22d75f8f69d33fe8fc294e8f413219d9c75374dec07fda2e4a66868599609887a10e04981e17356d2c07432fc89c11089172fdf91c0015b9a4beef11e447";
const DEMO_PRIVATE_KEY =
  "0x71743de900c63ed741263a2a4513c1b1829e80bd9f18d5d3a593e651b914cb3b";

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
