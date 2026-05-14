import zxcvbn from "zxcvbn";
import {
  PASSPHRASE_MIN_ZXCVBN_SCORE,
  PIN_MIN_ZXCVBN_SCORE,
} from "./credentials.js";

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SYMBOLS = "`~!@#$%^&*()-_+={}[]\\|:;\"'<>,.?/";

function randomInt(max: number): number {
  if (max > 255) {
    throw new RangeError(`max must be <= 255, got ${max}`);
  }
  const arr = new Uint8Array(1);
  const limit = 256 - (256 % max);
  do {
    globalThis.crypto.getRandomValues(arr);
  } while (arr[0] >= limit);
  return arr[0] % max;
}

function randomChar(charset: string): string {
  return charset[randomInt(charset.length)] as string;
}

function generateSegment(length: number, charset: string): string {
  return Array.from({ length }, () => randomChar(charset)).join("");
}

/**
 * Generates a random passphrase in a UUID-inspired hyphen-separated block format (e.g. "xxxx-xxxx-xxxx-xxxx").
 * Each block uses uppercase, lowercase, digits, and symbols.
 * Retries recursively until zxcvbn score >= 3 (required by generateHash).
 *
 * @param blockLength - Characters per block (default: 4)
 * @param numBlocks - Number of blocks (default: 4)
 */
export function randomPassphrase(blockLength = 4, numBlocks = 4): string {
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
 * Generates a random PIN of digits and lowercase letters.
 * Retries until zxcvbn score >= 1 (required by generateHash).
 *
 * @param length - Number of characters (default: 6)
 */
export function randomPIN(length = 6): string {
  const pin = generateSegment(length, DIGITS + LOWER);

  if (zxcvbn(pin).score < PIN_MIN_ZXCVBN_SCORE) {
    return randomPIN(length);
  }

  return pin;
}
