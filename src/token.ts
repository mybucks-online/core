import { Buffer } from "buffer";
import { nanoid } from "nanoid";
import zxcvbn from "zxcvbn";
import {
  PASSPHRASE_MIN_LENGTH,
  PASSPHRASE_MAX_LENGTH,
  PIN_MIN_LENGTH,
  PIN_MAX_LENGTH,
} from "./credentials.js";

const LEGACY_URL_DELIMITER = "\u0002";
// Version byte for the default (non-legacy) token format.
// Uses a compact length-prefixed encoding for passphrase, pin and network.
const TOKEN_VERSION_COMPACT = 0x02;

const NETWORKS = [
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
] as const;

export type ParsedToken = {
  passphrase: string;
  pin: string;
  network: string;
  legacy: boolean;
};

/**
 * Generates a gifting-link token by encoding passphrase, pin and network, with random padding.
 * The gifting-link lets recipients claim full ownership of a one-time digital cash envelope (e.g. gifting or airdrops).
 * Passphrase and PIN are validated by length (see PASSPHRASE_MIN/MAX_LENGTH, PIN_MIN/MAX_LENGTH) and zxcvbn; invalid or weak values return null.
 * When legacy is false, payload is compact length-prefixed (version 0x02) to avoid concatenation ambiguity and keep the URL fragment short; when true, uses LEGACY_URL_DELIMITER concatenation.
 *
 * @param passphrase - Length in [PASSPHRASE_MIN_LENGTH, PASSPHRASE_MAX_LENGTH], zxcvbn score >= 3
 * @param pin - Length in [PIN_MIN_LENGTH, PIN_MAX_LENGTH], zxcvbn score >= 1
 * @param network - ethereum | polygon | arbitrum | optimism | bsc | avalanche | base | mantle | monad | tron
 * @param legacy - When true, LEGACY_URL_DELIMITER concatenation; when false, compact length-prefixed encoding
 * @returns Token string suitable to append to `https://app.mybucks.online#wallet=`, or null if invalid/weak
 */
export function generateToken(
  passphrase: string,
  pin: string,
  network: string,
  legacy = false,
): string | null {
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

  let payloadBuffer: Buffer;
  if (legacy) {
    payloadBuffer = Buffer.from(
      passphrase + LEGACY_URL_DELIMITER + pin + LEGACY_URL_DELIMITER + network,
      "utf-8",
    );
  } else {
    // Default format: compact length-prefixed encoding.
    const passphraseBytes = Buffer.from(passphrase, "utf-8");
    const pinBytes = Buffer.from(pin, "utf-8");
    const networkBytes = Buffer.from(network, "utf-8");

    payloadBuffer = Buffer.concat([
      Buffer.from([TOKEN_VERSION_COMPACT]),
      Buffer.from([passphraseBytes.length]),
      passphraseBytes,
      Buffer.from([pinBytes.length]),
      pinBytes,
      Buffer.from([networkBytes.length]),
      networkBytes,
    ]);
  }

  // Convert Base64 to Base64URL so token remains safe in URL hash/query contexts.
  const base64Encoded = payloadBuffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  const padding = nanoid(12);
  return padding.slice(0, 6) + base64Encoded + padding.slice(6);
}

/**
 * Parses a gifting-link token produced by {@link generateToken}.
 * Tokens whose payload starts with 0x02 are decoded as compact length-prefixed; otherwise payload is treated as legacy (UTF-8 + LEGACY_URL_DELIMITER).
 *
 * @param token - Token string returned by generateToken()
 * @returns `{ passphrase, pin, network, legacy }` — legacy is true if token used legacy format, false if compact-encoded
 */
export function parseToken(token: string): ParsedToken {
  const payload = token.slice(6, token.length - 6);
  // Normalize payload for robust URL transport:
  // - URLSearchParams converts "+" to " "
  // - base64url may use "-" and "_" and omit padding
  const normalized = payload
    .replace(/ /g, "+")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const decoded = Buffer.from(padded, "base64");

  if (decoded[0] === TOKEN_VERSION_COMPACT) {
    let i = 1;
    const lenP = decoded[i++] as number;
    const passphrase = decoded.subarray(i, i + lenP).toString("utf-8");
    i += lenP;
    const lenI = decoded[i++] as number;
    const pin = decoded.subarray(i, i + lenI).toString("utf-8");
    i += lenI;
    const lenN = decoded[i++] as number;
    const network = decoded.subarray(i, i + lenN).toString("utf-8");
    return { passphrase, pin, network, legacy: false };
  }

  const str = decoded.toString("utf-8");
  const [passphrase, pin, network] = str.split(LEGACY_URL_DELIMITER);
  return {
    passphrase: passphrase ?? "",
    pin: pin ?? "",
    network: network ?? "",
    legacy: true,
  };
}
