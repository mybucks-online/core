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
const TOKEN_PADDING_LENGTH = 6;

/** v2: compact length-prefixed payload wrapped in 6+6 random padding (deprecated for new links). */
const TOKEN_VERSION_COMPACT_PADDED = 0x02;
/** v3: compact length-prefixed payload without outer padding (current default). */
const TOKEN_VERSION_COMPACT = 0x03;

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

export type TokenFormatVersion = 1 | 2 | 3;

export type ParsedToken = {
  passphrase: string;
  pin: string;
  network: string;
  /** @deprecated Use `version === 1` instead. */
  legacy: boolean;
  version: TokenFormatVersion;
};

function encodePayloadBase64Url(payloadBuffer: Buffer): string {
  return payloadBuffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodePayloadBase64Url(payload: string): Buffer {
  const normalized = payload
    .replace(/ /g, "+")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

function buildCompactPayload(
  versionByte: number,
  passphrase: string,
  pin: string,
  network: string,
): Buffer {
  const passphraseBytes = Buffer.from(passphrase, "utf-8");
  const pinBytes = Buffer.from(pin, "utf-8");
  const networkBytes = Buffer.from(network, "utf-8");

  return Buffer.concat([
    Buffer.from([versionByte]),
    Buffer.from([passphraseBytes.length]),
    passphraseBytes,
    Buffer.from([pinBytes.length]),
    pinBytes,
    Buffer.from([networkBytes.length]),
    networkBytes,
  ]);
}

function parseCompactPayload(decoded: Buffer): {
  passphrase: string;
  pin: string;
  network: string;
} {
  let i = 1;
  const lenP = decoded[i++] as number;
  const passphrase = decoded.subarray(i, i + lenP).toString("utf-8");
  i += lenP;
  const lenI = decoded[i++] as number;
  const pin = decoded.subarray(i, i + lenI).toString("utf-8");
  i += lenI;
  const lenN = decoded[i++] as number;
  const network = decoded.subarray(i, i + lenN).toString("utf-8");
  return { passphrase, pin, network };
}

function parseLegacyDelimiterPayload(decoded: Buffer): {
  passphrase: string;
  pin: string;
  network: string;
} {
  const str = decoded.toString("utf-8");
  const [passphrase, pin, network] = str.split(LEGACY_URL_DELIMITER);
  return {
    passphrase: passphrase ?? "",
    pin: pin ?? "",
    network: network ?? "",
  };
}

function wrapWithPadding(base64Encoded: string): string {
  const padding = nanoid(TOKEN_PADDING_LENGTH * 2);
  return padding.slice(0, TOKEN_PADDING_LENGTH) + base64Encoded + padding.slice(TOKEN_PADDING_LENGTH);
}

/**
 * Generates a gifting-link token by encoding passphrase, pin and network.
 * The gifting-link lets recipients claim full ownership of a one-time digital cash envelope (e.g. gifting or airdrops).
 * Passphrase and PIN are validated by length (see PASSPHRASE_MIN/MAX_LENGTH, PIN_MIN/MAX_LENGTH) and zxcvbn; invalid or weak values return null.
 *
 * Token formats:
 * - `legacy: false` → **v3** compact encoding (0x03), no outer padding — stable for the same credentials.
 * - `legacy: true` → **v1** delimiter encoding inside 6+6 padding (legacy KDF compatibility).
 *
 * @param passphrase - Length in [PASSPHRASE_MIN_LENGTH, PASSPHRASE_MAX_LENGTH], zxcvbn score >= 3
 * @param pin - Length in [PIN_MIN_LENGTH, PIN_MAX_LENGTH], zxcvbn score >= 1
 * @param network - ethereum | polygon | arbitrum | optimism | bsc | avalanche | base | mantle | monad | tron
 * @param legacy - When true, v1 delimiter format; when false, v3 compact format
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
    payloadBuffer = buildCompactPayload(
      TOKEN_VERSION_COMPACT,
      passphrase,
      pin,
      network,
    );
  }

  const base64Encoded = encodePayloadBase64Url(payloadBuffer);
  if (legacy) {
    return wrapWithPadding(base64Encoded);
  }
  return base64Encoded;
}

/**
 * Parses a gifting-link token produced by {@link generateToken} or older formats.
 *
 * Format detection:
 * - **v3** — compact (0x03), no outer padding (current default)
 * - **v2** — compact (0x02) with 6+6 outer padding (older default links)
 * - **v1** — delimiter payload with 6+6 outer padding (`legacy: true` generation)
 *
 * @param token - Token string from the `#wallet=` URL fragment
 */
export function parseToken(token: string): ParsedToken {
  const tryDecode = (payload: string): Buffer | null => {
    try {
      return decodePayloadBase64Url(payload);
    } catch {
      return null;
    }
  };

  const decodedFull = tryDecode(token);
  if (decodedFull && decodedFull[0] === TOKEN_VERSION_COMPACT) {
    return {
      ...parseCompactPayload(decodedFull),
      legacy: false,
      version: 3,
    };
  }

  if (token.length >= TOKEN_PADDING_LENGTH * 2) {
    const inner = token.slice(TOKEN_PADDING_LENGTH, token.length - TOKEN_PADDING_LENGTH);
    const decodedInner = tryDecode(inner);
    if (decodedInner) {
      if (decodedInner[0] === TOKEN_VERSION_COMPACT_PADDED) {
        return {
          ...parseCompactPayload(decodedInner),
          legacy: false,
          version: 2,
        };
      }

      return {
        ...parseLegacyDelimiterPayload(decodedInner),
        legacy: true,
        version: 1,
      };
    }
  }

  if (decodedFull) {
    return {
      ...parseLegacyDelimiterPayload(decodedFull),
      legacy: true,
      version: 1,
    };
  }

  return {
    passphrase: "",
    pin: "",
    network: "",
    legacy: true,
    version: 1,
  };
}
