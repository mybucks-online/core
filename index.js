import { Buffer } from "buffer";
import { ethers } from "ethers";
import scryptJS from "scrypt-js";
import { nanoid } from "nanoid";
import { TronWeb } from "tronweb";
import zxcvbn from "zxcvbn";

const { scrypt } = scryptJS;
const abi = new ethers.AbiCoder();

const HASH_OPTIONS_LEGACY = {
  N: 32768, // CPU/memory cost parameter, 2^15
  r: 8, // block size parameter
  p: 5, // parallelization parameter
  keyLen: 64,
};

const HASH_OPTIONS = {
  N: 131072, // CPU/memory cost parameter, 2^17, OWASP recommendation
  r: 8, // block size parameter
  p: 1, // parallelization parameter
  keyLen: 64,
};

export const PASSPHRASE_MIN_LENGTH = 12;
export const PASSPHRASE_MAX_LENGTH = 128;
export const PIN_MIN_LENGTH = 6;
export const PIN_MAX_LENGTH = 16;

/**
 * This function computes the scrypt hash using provided passphrase and pin inputs.
 * Passphrase and pin are validated by length (see PASSPHRASE_MIN/MAX_LENGTH, PIN_MIN/MAX_LENGTH) and zxcvbn; invalid or weak values are rejected (returns "").
 *
 * @param {string} passphrase - Length in [PASSPHRASE_MIN_LENGTH, PASSPHRASE_MAX_LENGTH], zxcvbn score >= 3
 * @param {string} pin - Length in [PIN_MIN_LENGTH, PIN_MAX_LENGTH], zxcvbn score >= 1
 * @param {*} cb a callback function designed to receive the progress updates during the scrypt hashing process.
 * @param {boolean} legacy - when true, uses the legacy behavior (HASH_OPTIONS_LEGACY and the original salt generation using the last 4 characters of passphrase plus the full pin); when false, uses HASH_OPTIONS and a keccak256-based salt derived from ABI-encoding passphrase and pin
 * @returns hash result as string format, or "" if passphrase/pin missing or too weak
 */
export async function generateHash(passphrase, pin, cb = () => {}, legacy = false) {
  if (!passphrase || !pin) {
    return "";
  }

  const passphraseLen = passphrase.length;
  if (passphraseLen < PASSPHRASE_MIN_LENGTH || passphraseLen > PASSPHRASE_MAX_LENGTH) {
    return "";
  }

  const pinLen = pin.length;
  if (pinLen < PIN_MIN_LENGTH || pinLen > PIN_MAX_LENGTH) {
    return "";
  }

  const passphraseResult = zxcvbn(passphrase);
  if (passphraseResult.score < 3) {
    return "";
  }

  const pinResult = zxcvbn(pin);
  if (pinResult.score < 1) {
    return "";
  }

  const passwordBuffer = Buffer.from(passphrase);
  let saltBuffer;

  if (legacy) {
    const legacySalt = `${passphrase.slice(-4)}${pin}`;
    saltBuffer = Buffer.from(legacySalt);
  } else {
    const encoded = abi.encode(["string", "string"], [passphrase, pin]);
    const saltHash = ethers.keccak256(encoded);
    saltBuffer = Buffer.from(saltHash.slice(2), "hex");
  }

  const options = legacy ? HASH_OPTIONS_LEGACY : HASH_OPTIONS;

  const hashBuffer = await scrypt(
    passwordBuffer,
    saltBuffer,
    options.N,
    options.r,
    options.p,
    options.keyLen,
    cb
  );

  return Buffer.from(hashBuffer).toString("hex");
}

/**
 * This function derives the EVM private key from a result of the scrypt hash.
 * @param {*} hash scrypt hash result
 * @returns private key as string format
 */
export function getEvmPrivateKey(hash) {
  return ethers.keccak256(abi.encode(["string"], [hash]));
}

/**
 * This function returns the EVM wallet address from a result of the scrypt hash.
 * @param {*} hash scrypt hash result
 * @returns address as string format
 */
export function getEvmWalletAddress(hash) {
  const privateKey = getEvmPrivateKey(hash);
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
}

/**
 * This function returns the TRON wallet address from a result of the scrypt hash.
 * @param {*} hash scrypt hash result
 * @returns address as string format
 */
export function getTronWalletAddress(hash) {
  const privateKey = getEvmPrivateKey(hash);
  return TronWeb.address.fromPrivateKey(privateKey.slice(2));
}

const URL_DELIMITER = "\u0002";
const NETWORKS = [
  "ethereum",
  "polygon",
  "arbitrum",
  "optimism",
  "bsc",
  "avalanche",
  "base",
  "tron",
];
/**
 * This function generates a transfer-link token by encoding passphrase and PIN by Base64 and adding random padding.
 * The transfer-link enables users to send their full ownership of a wallet account to another user for gifting or airdropping.
 * Passphrase and PIN are validated with zxcvbn; weak values are rejected (returns null).
 *
 * @param {*} passphrase - Must have zxcvbn score >= 3
 * @param {*} PIN - Must have zxcvbn score >= 1
 * @param {*} network ethereum | polygon | arbitrum | optimism | bsc | avalanche | base | tron
 * @returns A string formatted as a transfer-link token, which can be appended to `https://app.mybucks.online#wallet=`, or null if invalid/weak
 */
export function generateToken(passphrase, pin, network) {
  if (!passphrase || !pin || !network) {
    return null;
  }
  if (!NETWORKS.find((n) => n === network)) {
    return null;
  }

  if (zxcvbn(passphrase).score < 3) {
    return null;
  }
  if (zxcvbn(pin).score < 1) {
    return null;
  }

  const merged = Buffer.from(
    passphrase + URL_DELIMITER + pin + URL_DELIMITER + network,
    "utf-8"
  );
  const base64Encoded = merged.toString("base64");
  const padding = nanoid(12);
  return padding.slice(0, 6) + base64Encoded + padding.slice(6);
}

/**
 * This function parses a transfer-link token generated by generateToken().
 * @param {*} token
 * @returns an array of strings, including the passphrase, pin and network.
 */
export function parseToken(token) {
  const payload = token.slice(6, token.length - 6);
  const base64Decoded = Buffer.from(payload, "base64").toString("utf-8");
  const [passphrase, pin, network] = base64Decoded.split(URL_DELIMITER);
  return [passphrase, pin, network];
}
