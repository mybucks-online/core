const { Buffer } = require("buffer");
const { ethers } = require("ethers");
const { scrypt } = require("scrypt-js");

const abi = new ethers.AbiCoder();

/**
 * [CRITICAL] DON'T CHANGE FOREVER!!!
 * Reference:
 *    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
 */
const HASH_OPTIONS = {
  N: 32768, // CPU/memory cost parameter, 2^15
  r: 8, // block size parameter
  p: 5, // parallelization parameter
  keyLen: 64,
};

/**
 * This function computes the scrypt hash using provided password and passcode inputs.
 *
 * @param {*} password
 * @param {*} passcode
 * @param {*} cb a callback function designed to receive the progress updates during the scrypt hashing process.
 * @returns hash result as string format
 */
async function generateHash(password, passcode, cb = () => {}) {
  if (!password || !passcode) {
    return "";
  }

  const salt = `${password.slice(-4)}${passcode}`;

  const passwordBuffer = Buffer.from(password);
  const saltBuffer = Buffer.from(salt);

  const hashBuffer = await scrypt(
    passwordBuffer,
    saltBuffer,
    HASH_OPTIONS.N,
    HASH_OPTIONS.r,
    HASH_OPTIONS.p,
    HASH_OPTIONS.keyLen,
    cb
  );

  return Buffer.from(hashBuffer).toString("hex");
}

/**
 * This function derives the EVM private key from the result of the scrypt hash.
 * @param {*} hash
 * @returns private key as string format
 */
function getEvmPrivateKey(hash) {
  return ethers.keccak256(abi.encode(["string"], [hash]));
}

module.exports = {
  generateHash,
  getEvmPrivateKey,
};
