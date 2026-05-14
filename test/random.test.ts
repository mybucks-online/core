import assert from "node:assert";
import { describe, test } from "node:test";
import zxcvbn from "zxcvbn";
import { randomPassphrase, randomPIN } from "../index.js";
import {
  PASSPHRASE_MIN_ZXCVBN_SCORE,
  PIN_MIN_ZXCVBN_SCORE,
} from "../src/credentials.js";

describe("randomPassphrase", () => {
  test("should return a string", () => {
    const passphrase = randomPassphrase();
    assert.strictEqual(typeof passphrase, "string");
  });

  test("should have correct total length", () => {
    const passphrase = randomPassphrase(4, 4);
    // blockLength * numBlocks + (numBlocks - 1) hyphens as separators
    assert.strictEqual(passphrase.length, 4 * 4 + 3);
  });

  test("should respect custom blockLength and numBlocks", () => {
    const passphrase = randomPassphrase(6, 3);
    assert.strictEqual(passphrase.length, 6 * 3 + 2);
  });

  test("should have zxcvbn score >= 3", () => {
    const passphrase = randomPassphrase();
    assert.ok(
      zxcvbn(passphrase).score >= PASSPHRASE_MIN_ZXCVBN_SCORE,
      `passphrase zxcvbn score is below ${PASSPHRASE_MIN_ZXCVBN_SCORE}`,
    );
  });

  test("should return different values on each call", () => {
    const results = Array.from({ length: 10 }, () => randomPassphrase());
    results.forEach((p, i) => console.log(`  passphrase[${i}]: ${p}`));
    assert.strictEqual(
      new Set(results).size,
      results.length,
      "randomPassphrase returned duplicate values",
    );
  });
});

describe("randomPIN", () => {
  test("should return a string", () => {
    const pin = randomPIN();
    assert.strictEqual(typeof pin, "string");
  });

  test("should default to length 6", () => {
    const pin = randomPIN();
    assert.strictEqual(pin.length, 6);
  });

  test("should respect custom length", () => {
    const pin = randomPIN(10);
    assert.strictEqual(pin.length, 10);
  });

  test("should only contain digits and lowercase letters", () => {
    const pin = randomPIN(32);
    assert.ok(/^[0-9a-z]+$/.test(pin), "PIN contains invalid characters");
  });

  test("should have zxcvbn score >= 1", () => {
    const pin = randomPIN();
    assert.ok(
      zxcvbn(pin).score >= PIN_MIN_ZXCVBN_SCORE,
      `PIN zxcvbn score is below ${PIN_MIN_ZXCVBN_SCORE}`,
    );
  });

  test("should return different values on each call", () => {
    const results = Array.from({ length: 10 }, () => randomPIN());
    results.forEach((p, i) => console.log(`  pin[${i}]: ${p}`));
    assert.strictEqual(
      new Set(results).size,
      results.length,
      "randomPIN returned duplicate values",
    );
  });
});
