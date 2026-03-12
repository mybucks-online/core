import { randomInt } from "crypto";
import zxcvbn from "zxcvbn";
import {
  PASSPHRASE_MIN_ZXCVBN_SCORE,
  PIN_MIN_ZXCVBN_SCORE,
} from "./credentials.js";

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
 * Retries recursively until zxcvbn score >= 3 (required by generateHash).
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

  if (zxcvbn(passphrase).score < PASSPHRASE_MIN_ZXCVBN_SCORE) {
    return randomPassphrase(blockLength, numBlocks);
  }

  return passphrase;
}

/**
 * Generates a random PIN composed of digits and lowercase letters.
 * Retries until the PIN passes zxcvbn score >= 1 (required by generateHash).
 *
 * @param {number} length - Number of characters in the PIN (default: 6)
 * @returns {string} A randomly generated PIN string
 */
export function randomPIN(length = 6) {
  const pin = generateSegment(length, DIGITS + LOWER);

  if (zxcvbn(pin).score < PIN_MIN_ZXCVBN_SCORE) {
    return randomPIN(length);
  }

  return pin;
}
