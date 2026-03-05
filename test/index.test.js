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

const DEMO_PASSPHRASE = "DemoAccount5&";
const DEMO_PIN = "112324";
const DEMO_NETWORK = "optimism";

const DEMO_HASH =
  "f3700823c7161aea1153ad7a5aba2634f45271f7fa9536e3b39789a7978f5f5df55678df94d4a407b7c6b4ab367293be671953c9e63d8c6d821cdaa70083c315";
const DEMO_PRIVATE_KEY =
  "0xd06fcd946e193fffff5771f50ac9c89c7d8bd2f46620edc78fbe860fa02088dc";
const DEMO_WALLET_EVM_ADDRESS = "0xdbb151163216f62353BE9689c0FD37DAd7f20cab";
const DEMO_WALLET_TRON_ADDRESS = "TVzqQFeJrWJqafjMUntKh8aopkXssbxkFb";

describe("generateHash (default)", () => {
  test("should return empty string if passphrase or pin is blank", async () => {
    const hash = await generateHash("", "");
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
      const hash = await generateHash(passphrase, DEMO_PIN);
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
      const hash = await generateHash(DEMO_PASSPHRASE, pin);
      assert.strictEqual(hash, "", `Expected "" for weak pin "${pin}"`);
    }
  });

  test("should return empty string if passphrase length is out of range", async () => {
    const tooShort = "Abc!23xy"; // strong-ish but below min length
    const tooLong = "Str0ng-and-L0ng-Passphrase-!".repeat(6); // strong but above max length

    const hashShort = await generateHash(tooShort, DEMO_PIN);
    const hashLong = await generateHash(tooLong, DEMO_PIN);

    assert.strictEqual(hashShort, "");
    assert.strictEqual(hashLong, "");
  });

  test("should return empty string if pin length is out of range", async () => {
    const tooShort = "12aB!"; // strong-ish but below min length
    const tooLong = "9aB!9aB!9aB!9aB!9"; // strong but above max length (> 16 chars)

    const hashShort = await generateHash(DEMO_PASSPHRASE, tooShort);
    const hashLong = await generateHash(DEMO_PASSPHRASE, tooLong);

    assert.strictEqual(hashShort, "");
    assert.strictEqual(hashLong, "");
  });

  test("should return valid scrypt hash result", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN);
    assert.strictEqual(hash, DEMO_HASH);
  });

  test("should return same hash for same passphrase and pin (deterministic)", async () => {
    const hash1 = await generateHash(DEMO_PASSPHRASE, DEMO_PIN);
    const hash2 = await generateHash(DEMO_PASSPHRASE, DEMO_PIN);
    assert.strictEqual(hash1, hash2);
  });

  test("should generate different results for same naive concatenation", async () => {
    // These two pairs share the same concatenated string
    // passphrase1 + pin1 === passphrase2 + pin2
    const passphrase1 = "My-1st-car-was-a-red-Ford-2005!";
    const pin1 = "909011";
    const passphrase2 = "My-1st-car-was-a-red-Ford-";
    const pin2 = "2005!909011";

    const hash1 = await generateHash(passphrase1, pin1);
    const hash2 = await generateHash(passphrase2, pin2);

    assert.notStrictEqual(hash1, "");
    assert.notStrictEqual(hash2, "");
    assert.notStrictEqual(
      hash1,
      hash2,
      "hashes must differ even when naive concatenation matches"
    );
  });
});

describe("getEvmPrivateKey (default)", () => {
  test("should return 256bit private key from default hash", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN);
    const privateKey = getEvmPrivateKey(hash);
    assert.strictEqual(privateKey, DEMO_PRIVATE_KEY);
  });
});

describe("getEvmWalletAddress (default)", () => {
  test("should return a valid wallet address from default hash", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN);
    const address = getEvmWalletAddress(hash);
    assert.strictEqual(address, DEMO_WALLET_EVM_ADDRESS);
  });
});

describe("getTronWalletAddress (default)", () => {
  test("should return a valid TRON wallet address from default hash", async () => {
    const hash = await generateHash(DEMO_PASSPHRASE, DEMO_PIN);
    const address = getTronWalletAddress(hash);
    assert.strictEqual(address, DEMO_WALLET_TRON_ADDRESS);
  });
});

describe("generateToken", () => {
  test("should return null if passphrase, pin or network is invalid", () => {
    assert.strictEqual(generateToken("", "123345", "ethereum"), null);
    assert.strictEqual(generateToken("", "123345"), null);
    assert.strictEqual(generateToken("passphrase", "", "ethereum"), null);
    assert.strictEqual(generateToken("passphrase", "123456", ""), null);
    assert.strictEqual(generateToken("passphrase", "123456", "invalid"), null);
  });

  test("should return null if passphrase length is out of range", () => {
    const tooShort = "Abc!23xy"; // strong-ish but below min length
    const tooLong = "Str0ng-and-L0ng-Passphrase-!".repeat(6); // strong but above max length
    assert.strictEqual(generateToken(tooShort, DEMO_PIN, DEMO_NETWORK), null);
    assert.strictEqual(generateToken(tooLong, DEMO_PIN, DEMO_NETWORK), null);
  });

  test("should return null if pin length is out of range", () => {
    const tooShort = "12aB!"; // strong-ish but below min length
    const tooLong = "9aB!9aB!9aB!9aB!9"; // strong but above max length (> 16 chars)
    assert.strictEqual(generateToken(DEMO_PASSPHRASE, tooShort, DEMO_NETWORK), null);
    assert.strictEqual(generateToken(DEMO_PASSPHRASE, tooLong, DEMO_NETWORK), null);
  });

  test("should return null for weak passphrase (zxcvbn score < 3)", () => {
    const weakPassphrases = [
      "password",
      "asdfasdf",
      "123123123",
      "P@ssw0rd",
      "London123",
      "oxford2024",
      "asdfASDFaSdf",
      "qwerqwerqwer",
      "1234567890",
    ];
    for (const passphrase of weakPassphrases) {
      assert.strictEqual(
        generateToken(passphrase, DEMO_PIN, DEMO_NETWORK),
        null
      );
    }
  });

  test("should return null for weak pin (zxcvbn score < 1)", () => {
    const weakPins = [
      "111111",
      "111111111111111",
      "12341234",
      "aaaaaaaaaa",
      "asdfasdf",
    ];
    for (const pin of weakPins) {
      assert.strictEqual(
        generateToken(DEMO_PASSPHRASE, pin, DEMO_NETWORK),
        null
      );
    }
  });

  test("should return valid token with padding", () => {
    const token = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK);
    assert.ok(token !== null);
    assert.ok(token.length >= 6 + 6, "token has 6-char prefix and suffix padding");
  });

  test("should return valid token for all networks", () => {
    const networks = [
      "ethereum",
      "polygon",
      "arbitrum",
      "optimism",
      "bsc",
      "avalanche",
      "base",
      "tron",
    ];
    for (const network of networks) {
      assert.notStrictEqual(
        generateToken(DEMO_PASSPHRASE, DEMO_PIN, network),
        null
      );
    }
  });
});

describe("parseToken", () => {
  test("should return array of passphrase, pin, and network", () => {
    const token = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK);
    const [passphrase, pin, network] = parseToken(token);
    assert.strictEqual(passphrase, DEMO_PASSPHRASE);
    assert.strictEqual(pin, DEMO_PIN);
    assert.strictEqual(network, DEMO_NETWORK);
  });
});

describe("generateToken and parseToken", () => {
  test("should be compatible and return correct result", () => {
    const testPassphrase = "My-1st-car-was-a-red-Ford-2005!";
    const testPin = "909011";
    const testNetwork = "polygon";
    const token = generateToken(testPassphrase, testPin, testNetwork);

    const [passphrase, pin, network] = parseToken(token);
    assert.strictEqual(passphrase, testPassphrase);
    assert.strictEqual(pin, testPin);
    assert.strictEqual(network, testNetwork);
  });
});
