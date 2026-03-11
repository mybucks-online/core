import { randomInt } from "crypto";

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SYMBOLS = "`~!@#$%^&*()-_+={}[]\\|:;\"'<>,.?/";

function randomChar(charset) {
  return charset[randomInt(charset.length)];
}

function generateSegment(length, charset) {
  return Array.from({ length }, () => randomChar(charset)).join("");
}

/**
 * Generates a random passphrase in a UUID-inspired hyphen-separated block format (e.g. "xxxx-xxxx-xxxx-xxxx").
 * Each block is composed of characters from uppercase, lowercase, digits, and symbols.
 * Guaranteed to contain at least one uppercase letter, one lowercase letter, one digit, and one symbol.
 * Retries recursively until all character class requirements are met.
 *
 * @param {number} blockLength - Number of characters per block (default: 4)
 * @param {number} numBlocks - Number of blocks (default: 4)
 * @returns {string} A randomly generated passphrase string
 */
export function randomPassphrase(blockLength = 4, numBlocks = 4) {
  const segments = Array.from({ length: numBlocks }, () =>
    generateSegment(blockLength, UPPER + LOWER + DIGITS + SYMBOLS),
  );
  const passphrase = segments.join("-");

  const hasUpper = /[A-Z]/.test(passphrase);
  const hasLower = /[a-z]/.test(passphrase);
  const hasDigit = /[0-9]/.test(passphrase);
  const hasSymbol = passphrase.split("").some((c) => SYMBOLS.includes(c));

  if (!hasUpper || !hasLower || !hasDigit || !hasSymbol) {
    return randomPassphrase(blockLength, numBlocks);
  }

  return passphrase;
}

/**
 * Generates a random PIN composed of digits and lowercase letters.
 *
 * @param {number} length - Number of characters in the PIN (default: 6)
 * @returns {string} A randomly generated PIN string
 */
export function randomPIN(length = 6) {
  return generateSegment(length, DIGITS + LOWER);
}

