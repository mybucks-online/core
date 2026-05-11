import { Buffer } from "buffer";
import { ethers } from "ethers";
import scryptJS from "scrypt-js";
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

export const PASSPHRASE_MIN_ZXCVBN_SCORE = 3;
export const PIN_MIN_ZXCVBN_SCORE = 1;

export const PASSPHRASE_MIN_LENGTH = 12;
export const PASSPHRASE_MAX_LENGTH = 128;
export const PIN_MIN_LENGTH = 6;
export const PIN_MAX_LENGTH = 16;

export type ScryptProgressCallback = (progress: number) => void;

/**
 * Computes the scrypt hash from passphrase and pin.
 * Passphrase and pin are validated by length (see PASSPHRASE_MIN/MAX_LENGTH, PIN_MIN/MAX_LENGTH) and zxcvbn; invalid or weak values are rejected (returns "").
 *
 * @param passphrase - Length in [PASSPHRASE_MIN_LENGTH, PASSPHRASE_MAX_LENGTH], zxcvbn score >= 3
 * @param pin - Length in [PIN_MIN_LENGTH, PIN_MAX_LENGTH], zxcvbn score >= 1
 * @param cb - Callback receiving progress updates during the scrypt hashing process
 * @param legacy - When true, uses HASH_OPTIONS_LEGACY and the original salt (last 4 characters of passphrase plus full pin). When false, uses HASH_OPTIONS and a keccak256-based salt from ABI-encoding the domain separator, passphrase, and pin
 * @returns Hash as hex string, or "" if passphrase/pin missing or too weak
 */
export async function generateHash(
  passphrase: string,
  pin: string,
  cb: ScryptProgressCallback = () => {},
  legacy = false,
): Promise<string> {
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
  if (passphraseResult.score < PASSPHRASE_MIN_ZXCVBN_SCORE) {
    return "";
  }

  const pinResult = zxcvbn(pin);
  if (pinResult.score < PIN_MIN_ZXCVBN_SCORE) {
    return "";
  }

  const passwordBuffer = Buffer.from(passphrase);
  let saltBuffer: Buffer;

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
 * Derives the EVM private key from a scrypt hash result.
 * @param hash - Scrypt hash result (hex string)
 * @returns Private key as hex string
 */
export function getEvmPrivateKey(hash: string): string {
  return ethers.keccak256(abi.encode(["string"], [hash]));
}

/**
 * Returns the EVM wallet address derived from a scrypt hash result.
 * @param hash - Scrypt hash result
 * @returns EVM address (checksummed)
 */
export function getEvmWalletAddress(hash: string): string {
  const privateKey = getEvmPrivateKey(hash);
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
}

/**
 * Returns the TRON wallet address derived from a scrypt hash result.
 * @param hash - Scrypt hash result
 * @returns TRON base58 address, or false if TronWeb rejects the derived key
 */
export function getTronWalletAddress(hash: string): string | false {
  const privateKey = getEvmPrivateKey(hash);
  return TronWeb.address.fromPrivateKey(privateKey.slice(2));
}
