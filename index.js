import { Buffer } from "buffer";
import { ethers } from "ethers";
import scryptJS from "scrypt-js";
import { nanoid } from "nanoid";
import { TronWeb } from "tronweb";
import zxcvbn from "zxcvbn";

const { scrypt } = scryptJS;
const abi = new ethers.AbiCoder();

// Domain separator for the default (non-legacy) KDF path to prevent
// cross-protocol and cross-version hash reuse.
const KDF_DOMAIN_SEPARATOR = "mybucks.online-core.generateHash.v2";

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
export async function generateHash(
  passphrase,
  pin,
  cb = () => {},
  legacy = false,
) {
  if (!passphrase || !pin) {
    return "";
  }

  const passphraseLen = passphrase.length;
  if (
    passphraseLen < PASSPHRASE_MIN_LENGTH ||
    passphraseLen > PASSPHRASE_MAX_LENGTH
  ) {
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
    const encoded = abi.encode(
      ["string", "string", "string"],
      [KDF_DOMAIN_SEPARATOR, passphrase, pin],
    );
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
    cb,
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
const TOKEN_VERSION_ABI = 0x02;

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
 * This function generates a transfer-link token by encoding passphrase, pin and network, and adding random padding.
 * The transfer-link enables users to send their full ownership of a wallet account to another user for gifting or airdropping.
 * Passphrase and PIN are validated by length (see PASSPHRASE_MIN/MAX_LENGTH, PIN_MIN/MAX_LENGTH) and zxcvbn; invalid or weak values are rejected (returns null).
 * When legacy is false, payload is ABI-encoded to avoid concatenation ambiguity; when true, uses URL_DELIMITER concatenation.
 *
 * @param {string} passphrase - Length in [PASSPHRASE_MIN_LENGTH, PASSPHRASE_MAX_LENGTH], zxcvbn score >= 3
 * @param {string} pin - Length in [PIN_MIN_LENGTH, PIN_MAX_LENGTH], zxcvbn score >= 1
 * @param {string} network - ethereum | polygon | arbitrum | optimism | bsc | avalanche | base | tron
 * @param {boolean} legacy - when true, use URL_DELIMITER concatenation; when false, use ABI encoding for the payload
 * @returns A string formatted as a transfer-link token, which can be appended to `https://app.mybucks.online#wallet=`, or null if invalid/weak
 */
export function generateToken(passphrase, pin, network, legacy = false) {
  if (!passphrase || !pin || !network) {
    return null;
  }
  if (!NETWORKS.find((n) => n === network)) {
    return null;
  }

  const passphraseLen = passphrase.length;
  if (
    passphraseLen < PASSPHRASE_MIN_LENGTH ||
    passphraseLen > PASSPHRASE_MAX_LENGTH
  ) {
    return null;
  }

  const pinLen = pin.length;
  if (pinLen < PIN_MIN_LENGTH || pinLen > PIN_MAX_LENGTH) {
    return null;
  }

  if (zxcvbn(passphrase).score < 3) {
    return null;
  }
  if (zxcvbn(pin).score < 1) {
    return null;
  }

  let payloadBuffer;
  if (legacy) {
    payloadBuffer = Buffer.from(
      passphrase + URL_DELIMITER + pin + URL_DELIMITER + network,
      "utf-8",
    );
  } else {
    const encoded = abi.encode(
      ["string", "string", "string"],
      [passphrase, pin, network],
    );
    const encodedBuffer = Buffer.from(encoded.slice(2), "hex");
    payloadBuffer = Buffer.concat([
      Buffer.from([TOKEN_VERSION_ABI]),
      encodedBuffer,
    ]);
  }

  const base64Encoded = payloadBuffer.toString("base64");
  const padding = nanoid(12);
  return padding.slice(0, 6) + base64Encoded + padding.slice(6);
}

/**
 * This function parses a transfer-link token generated by generateToken().
 * Tokens with version byte 0x02 are ABI-decoded; otherwise payload is treated as legacy (UTF-8 + URL_DELIMITER).
 * @param {string} token - token string returned by generateToken()
 * @returns {[string, string, string]} [passphrase, pin, network]
 */
export function parseToken(token) {
  const payload = token.slice(6, token.length - 6);
  const decoded = Buffer.from(payload, "base64");

  if (decoded[0] === TOKEN_VERSION_ABI) {
    const hex = "0x" + decoded.subarray(1).toString("hex");
    const [passphrase, pin, network] = abi.decode(
      ["string", "string", "string"],
      hex,
    );
    return [passphrase, pin, network];
  }
  const str = decoded.toString("utf-8");
  const [passphrase, pin, network] = str.split(URL_DELIMITER);
  return [passphrase, pin, network];
}
