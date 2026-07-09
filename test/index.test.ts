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
import { randomPassphrase, randomPIN } from "../src/random.js";

const DEMO_PASSPHRASE = "DemoAccount5&";
const DEMO_PIN = "112324";
const DEMO_NETWORK = "optimism";

const DEMO_HASH =
  "70198936dedf67b784a0a7271fca9e562467754eb012a8c9f3a97aaf4e2be725b0995ebfc9112a18395214b3357368f7e2812a23d013c2b42dec0701bc44dd68";
const DEMO_PRIVATE_KEY =
  "0x942d4f1a0e4bc3b525db81eacba59131ceef498e401142b821613e20539b89e7";
const DEMO_WALLET_EVM_ADDRESS = "0xC3Bb18Ed137577e5482fA7C6AEaca8b3F68Dafba";
const DEMO_WALLET_TRON_ADDRESS = "TTp8uDeig42XdefAoTGWTj61uNMYvEVnXR";

const DEMO_LEGACY_TOKEN = "VWnsSGRGVtb0FjY291bnQ1JgIxMTIzMjQCb3B0aW1pc20=_wNovT";
const DEMO_DEFAULT_TOKEN = "Db1zfXAg1EZW1vQWNjb3VudDUmBjExMjMyNAhvcHRpbWlzbQ==mlUEbO";

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
      "hashes must differ even when naive concatenation matches",
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
    assert.strictEqual(generateToken("", "123345", ""), null);
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
        null,
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
        null,
      );
    }
  });

  test("should return valid token without outer padding (legacy=false, v3)", () => {
    const token = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, false);
    if (token === null) assert.fail("expected token");
    assert.ok(
      token.length < DEMO_DEFAULT_TOKEN.length,
      "v3 token should be shorter than padded v2 demo token",
    );
    const decoded = parseToken(token);
    assert.strictEqual(decoded.version, 3);
  });

  test("should return valid token with padding (legacy=true, v1)", () => {
    const token = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, true);
    if (token === null) assert.fail("expected token");
    assert.ok(token.length >= 6 + 6, "token has 6-char prefix and suffix padding");
    assert.strictEqual(parseToken(token).version, 1);
  });

  test("should return stable v3 token for same inputs", () => {
    const token1 = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, false);
    const token2 = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, false);
    if (token1 === null || token2 === null) assert.fail("expected tokens");
    assert.strictEqual(token1, token2, "v3 tokens must be deterministic");
  });

  test("should return different token for same inputs when legacy true vs false", () => {
    const tokenLegacy = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, true);
    const tokenAbi = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, false);
    if (tokenLegacy === null || tokenAbi === null) assert.fail("expected tokens");
    const payloadLegacy = tokenLegacy.slice(6, tokenLegacy.length - 6);
    const payloadAbi = tokenAbi;
    assert.notStrictEqual(payloadLegacy, payloadAbi, "payloads must differ (legacy vs compact encoding)");
  });

  test("should generate different results for same naive concatenation (legacy=false)", () => {
    const network = "polygon";
    const passphrase1 = "My-1st-car-was-a-red-Ford-2005!";
    const pin1 = "909011";
    const passphrase2 = "My-1st-car-was-a-red-Ford-";
    const pin2 = "2005!909011";
    assert.strictEqual(
      passphrase1 + pin1 + network,
      passphrase2 + pin2 + network,
      "same naive concatenation",
    );

    const token1 = generateToken(passphrase1, pin1, network, false);
    const token2 = generateToken(passphrase2, pin2, network, false);

    if (token1 === null || token2 === null) assert.fail("expected tokens");
    assert.notStrictEqual(token1, token2, "v3 payloads must differ even when naive concatenation matches");
  });

  test("should return valid token for all networks (legacy=false)", () => {
    const networks = [
      "ethereum",
      "polygon",
      "arbitrum",
      "optimism",
      "bsc",
      "avalanche",
      "base",
      "mantle",
      "monad",
      "tron",
    ];
    for (const network of networks) {
      assert.notStrictEqual(
        generateToken(DEMO_PASSPHRASE, DEMO_PIN, network, false),
        null,
      );
    }
  });

  test("should return valid token for all networks (legacy=true)", () => {
    const networks = [
      "ethereum",
      "polygon",
      "arbitrum",
      "optimism",
      "bsc",
      "avalanche",
      "base",
      "mantle",
      "monad",
      "tron",
    ];
    for (const network of networks) {
      assert.notStrictEqual(
        generateToken(DEMO_PASSPHRASE, DEMO_PIN, network, true),
        null,
      );
    }
  });

  test("should handle passphrase containing URL_DELIMITER when legacy=false", () => {
    const delimiter = String.fromCharCode(2);
    const trickyPassphrase = `Demo${delimiter}Account5&`;
    const token = generateToken(trickyPassphrase, DEMO_PIN, DEMO_NETWORK, false);
    if (token === null) assert.fail("expected token");
    assert.ok(token.length > 0);
  });
});

describe("parseToken", () => {
  test("should return { passphrase, pin, network, legacy, version } for token generated with legacy=false (v3)", () => {
    const token = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, false);
    if (token === null) assert.fail("expected token");
    const { passphrase, pin, network, legacy, version } = parseToken(token);
    assert.strictEqual(passphrase, DEMO_PASSPHRASE);
    assert.strictEqual(pin, DEMO_PIN);
    assert.strictEqual(network, DEMO_NETWORK);
    assert.strictEqual(legacy, false);
    assert.strictEqual(version, 3);
  });

  test("should return { passphrase, pin, network, legacy, version } for token generated with legacy=true (v1)", () => {
    const token = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, true);
    if (token === null) assert.fail("expected token");
    const { passphrase, pin, network, legacy, version } = parseToken(token);
    assert.strictEqual(passphrase, DEMO_PASSPHRASE);
    assert.strictEqual(pin, DEMO_PIN);
    assert.strictEqual(network, DEMO_NETWORK);
    assert.strictEqual(legacy, true);
    assert.strictEqual(version, 1);
  });

  test("should parse DEMO_LEGACY_TOKEN as v1", () => {
    const { passphrase, pin, network, legacy, version } = parseToken(DEMO_LEGACY_TOKEN);
    assert.strictEqual(passphrase, DEMO_PASSPHRASE);
    assert.strictEqual(pin, DEMO_PIN);
    assert.strictEqual(network, DEMO_NETWORK);
    assert.strictEqual(legacy, true);
    assert.strictEqual(version, 1);
  });

  test("should parse DEMO_DEFAULT_TOKEN as v2", () => {
    const { passphrase, pin, network, legacy, version } = parseToken(DEMO_DEFAULT_TOKEN);
    assert.strictEqual(passphrase, DEMO_PASSPHRASE);
    assert.strictEqual(pin, DEMO_PIN);
    assert.strictEqual(network, DEMO_NETWORK);
    assert.strictEqual(legacy, false);
    assert.strictEqual(version, 2);
  });

  test("should classify padded delimiter token as v1 when inner starts with 0x02", () => {
    const delimiter = String.fromCharCode(2);
    const passphrase = `${delimiter}MyAccount12!`;
    const pin = "909011";
    const network = "polygon";
    const token = generateToken(passphrase, pin, network, true);
    if (token === null) assert.fail("expected token");

    const parsed = parseToken(token);
    assert.strictEqual(parsed.version, 1);
    assert.strictEqual(parsed.legacy, true);
    // v1 delimiter encoding cannot round-trip when passphrase starts with the delimiter byte
    assert.notStrictEqual(parsed.passphrase, passphrase);
  });

  test("should not misclassify padded v1 tokens as v3 when full decode starts with 0x03", () => {
    for (let i = 0; i < 200; i++) {
      const token = generateToken(DEMO_PASSPHRASE, DEMO_PIN, DEMO_NETWORK, true);
      if (token === null) assert.fail("expected token");

      const parsed = parseToken(token);
      assert.strictEqual(parsed.version, 1, `token ${token}`);
      assert.strictEqual(parsed.passphrase, DEMO_PASSPHRASE);
      assert.strictEqual(parsed.pin, DEMO_PIN);
      assert.strictEqual(parsed.network, DEMO_NETWORK);
    }
  });

  test("should parse token after hash-fragment character normalization", () => {
    const plusToken =
      "tmeNhvAhsxe1lhSWwtJyhZLkQ+LUk2dzZeLi1TI0FPQzwIMWNuZ3I0ZTkHcG9seWdvbg==GB_ha6";
    const spaceToken =
      "tmeNhvAhsxe1lhSWwtJyhZLkQ LUk2dzZeLi1TI0FPQzwIMWNuZ3I0ZTkHcG9seWdvbg==GB_ha6";
    assert.deepStrictEqual(
      parseToken(spaceToken),
      parseToken(plusToken),
      "space should be treated as '+'",
    );

    const plusToken2 =
      "gUerR9AhtTbmhANnYtST08PnFRLUMsZyUxMy1+OHc8byIINXJ6cG5oamkHcG9seWdvbg==2lSvB2";
    const dashToken2 =
      "gUerR9AhtTbmhANnYtST08PnFRLUMsZyUxMy1-OHc8byIINXJ6cG5oamkHcG9seWdvbg==2lSvB2";
    assert.deepStrictEqual(
      parseToken(dashToken2),
      parseToken(plusToken2),
      "'-' should be treated as '+' in payload normalization",
    );
  });

  test("should parse token when base64 padding is stripped", () => {
    const tokenWithPadding =
      "tmeNhvAhsxe1lhSWwtJyhZLkQ+LUk2dzZeLi1TI0FPQzwIMWNuZ3I0ZTkHcG9seWdvbg==GB_ha6";
    const tokenWithoutPadding =
      "tmeNhvAhsxe1lhSWwtJyhZLkQ+LUk2dzZeLi1TI0FPQzwIMWNuZ3I0ZTkHcG9seWdvbgGB_ha6";
    assert.deepStrictEqual(
      parseToken(tokenWithoutPadding),
      parseToken(tokenWithPadding),
      "missing '=' padding should be recovered",
    );
  });
});

describe("generateToken and parseToken", () => {
  test("should round-trip when legacy=false", () => {
    const testPassphrase = "My-1st-car-was-a-red-Ford-2005!";
    const testPin = "909011";
    const testNetwork = "polygon";
    const token = generateToken(testPassphrase, testPin, testNetwork, false);
    if (token === null) assert.fail("expected token");

    const { passphrase, pin, network } = parseToken(token);
    assert.strictEqual(passphrase, testPassphrase);
    assert.strictEqual(pin, testPin);
    assert.strictEqual(network, testNetwork);
  });

  test("should round-trip passphrase containing URL_DELIMITER when legacy=false", () => {
    const delimiter = String.fromCharCode(2);
    const testPassphrase = `My${delimiter}-1st-car-was-a-red-Ford-2005!`;
    const testPin = "909011";
    const testNetwork = "polygon";
    const token = generateToken(testPassphrase, testPin, testNetwork, false);
    if (token === null) assert.fail("expected token");

    const { passphrase, pin, network, legacy } = parseToken(token);
    assert.strictEqual(passphrase, testPassphrase);
    assert.strictEqual(pin, testPin);
    assert.strictEqual(network, testNetwork);
    assert.strictEqual(legacy, false);
  });

  test("should round-trip when legacy=true", () => {
    const testPassphrase = "My-1st-car-was-a-red-Ford-2005!";
    const testPin = "909011";
    const testNetwork = "polygon";
    const token = generateToken(testPassphrase, testPin, testNetwork, true);
    if (token === null) assert.fail("expected token");

    const { passphrase, pin, network } = parseToken(token);
    assert.strictEqual(passphrase, testPassphrase);
    assert.strictEqual(pin, testPin);
    assert.strictEqual(network, testNetwork);
  });

  test("should not safely round-trip passphrase containing URL_DELIMITER when legacy=true", () => {
    const delimiter = String.fromCharCode(2);
    const testPassphrase = `My${delimiter}-1st-car-was-a-red-Ford-2005!`;
    const testPin = "909011";
    const testNetwork = "polygon";
    const token = generateToken(testPassphrase, testPin, testNetwork, true);
    if (token === null) assert.fail("expected token");

    const { passphrase, legacy } = parseToken(token);
    assert.notStrictEqual(
      passphrase,
      testPassphrase,
      "legacy format cannot safely encode passphrase containing URL_DELIMITER",
    );
    assert.strictEqual(legacy, true);
  });

  test("should round-trip random passphrase and PIN for 100 cases (integration)", () => {
    const testNetwork = "polygon";

    for (let i = 0; i < 100; i++) {
      const testPassphrase = randomPassphrase();
      const testPin = randomPIN();
      const token = generateToken(testPassphrase, testPin, testNetwork, false);
      if (token === null) assert.fail(`expected token at case ${i}`);

      const { passphrase, pin, network, legacy } = parseToken(token);
      assert.strictEqual(
        passphrase,
        testPassphrase,
        `passphrase mismatch at case ${i}`,
      );
      assert.strictEqual(pin, testPin, `pin mismatch at case ${i}`);
      assert.strictEqual(network, testNetwork, `network mismatch at case ${i}`);
      assert.strictEqual(legacy, false, `legacy flag mismatch at case ${i}`);
    }
  });
});
