import assert from "node:assert";
import { describe, test } from "node:test";
import { randomPassphrase, randomPIN } from "../index.js";

const SYMBOLS = "`~!@#$%^&*()-_+={}[]\\|:;\"'<>,.?/";

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

  test("should contain at least one uppercase letter", () => {
    const passphrase = randomPassphrase();
    assert.ok(/[A-Z]/.test(passphrase), "missing uppercase letter");
  });

  test("should contain at least one lowercase letter", () => {
    const passphrase = randomPassphrase();
    assert.ok(/[a-z]/.test(passphrase), "missing lowercase letter");
  });

  test("should contain at least one digit", () => {
    const passphrase = randomPassphrase();
    assert.ok(/[0-9]/.test(passphrase), "missing digit");
  });

  test("should contain at least one symbol from SYMBOLS", () => {
    const passphrase = randomPassphrase();
    const hasSymbol = passphrase.split("").some((c) => SYMBOLS.includes(c));
    assert.ok(hasSymbol, "missing symbol");
  });

  test("should return different values on each call", () => {
    const results = Array.from({ length: 10 }, () => randomPassphrase());
    assert.strictEqual(new Set(results).size, results.length, "randomPassphrase returned duplicate values");
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

  test("should return different values on each call", () => {
    const results = Array.from({ length: 10 }, () => randomPIN());
    assert.strictEqual(new Set(results).size, results.length, "randomPIN returned duplicate values");
  });
});
