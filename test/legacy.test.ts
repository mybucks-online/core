import assert from "node:assert";
import { describe, test } from "node:test";
import {
  generateHash,
  getEvmPrivateKey,
  getEvmWalletAddress,
  getTronWalletAddress,
} from "../index.js";

const DEMO_PASSPHRASE = "DemoAccount5&";
const DEMO_PIN = "112324";

const DEMO_HASH =
  "af9a22d75f8f69d33fe8fc294e8f413219d9c75374dec07fda2e4a66868599609887a10e04981e17356d2c07432fc89c11089172fdf91c0015b9a4beef11e447";
const DEMO_PRIVATE_KEY =
  "0x71743de900c63ed741263a2a4513c1b1829e80bd9f18d5d3a593e651b914cb3b";
const DEMO_WALLET_EVM_ADDRESS = "0x347CEB6Bf002Ee1819009bA07d8dCAA95Efe6465";
const DEMO_WALLET_TRON_ADDRESS = "TEkjnbpr2cTgRFgmrbv2Gb7GdgupZ5Sh3A";

describe("generateHash (legacy)", () => {
  test("should return empty string if passphrase or pin is blank", async () => {
    const hash = await generateHash("", "", () => {}, true);
    assert.strictEqual(hash, "");
  });

  test("should return empty string for weak passphrase (zxcvbn score < 3)", async () => {
    const weakPassphrases = [
      "password",
      "asdfasdf",
      "123123123",
      "P@ssw0rd",
      "London123",
      "oxford2024",
      "John19821012",
      "asdfASDFaSdf",
      "qwerqwerqwer",
      "1234567890",
      "Julia18921012",
    ];
    for (const passphrase of weakPassphrases) {
      const hash = await generateHash(passphrase, DEMO_PIN, () => {}, true);
      assert.strictEqual(hash, "");
    }
  });

  test("should return empty string for weak pin (zxcvbn score < 1)", async () => {
    const weakPins = [
      "111111",
      "111111111111111",
      "12341234",
      "aaaaaaaaaa",
      "asdfasdf",
    ];
    for (const pin of weakPins) {
      const hash = await generateHash(DEMO_PASSPHRASE, pin, () => {}, true);
      assert.strictEqual(hash, "", `Expected "" for weak pin "${pin}"`);
    }
  });

  test("should return scrypt hash result", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN, () => {}, true);
    assert.strictEqual(hash, DEMO_HASH);
  });
});

describe("getEvmPrivateKey (legacy)", () => {
  test("should return 256bit private key", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN, () => {}, true);
    const privateKey = getEvmPrivateKey(hash);

    assert.strictEqual(privateKey, DEMO_PRIVATE_KEY);
  });
});

describe("getEvmWalletAddress (legacy)", () => {
  test("should return a valid wallet address", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN, () => {}, true);
    const address = getEvmWalletAddress(hash);

    assert.strictEqual(address, DEMO_WALLET_EVM_ADDRESS);
  });
});

describe("getTronWalletAddress (legacy)", () => {
  test("should return a valid wallet address", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN, () => {}, true);
    const address = getTronWalletAddress(hash);

    assert.strictEqual(address, DEMO_WALLET_TRON_ADDRESS);
  });
});
