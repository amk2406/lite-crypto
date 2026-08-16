/**
 * lite-crypto
 * A simple, lightweight, zero-dependency crypto library for the browser
 * (and Node.js) built on top of the native Web Crypto API.
 *
 * API is intentionally simple and close to the most commonly used
 * Node.js crypto features.
 *
 * @license MIT
 */

(function (global, factory) {
  if (typeof module === "object" && typeof module.exports === "object") {
    module.exports = factory();
  } else if (typeof define === "function" && define.amd) {
    define(factory);
  } else {
    global.LiteCrypto = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const crypto = globalThis.crypto;
  if (!crypto || !crypto.subtle) {
    throw new Error("Web Crypto API is not available. Use a modern browser or Node.js >= 15.");
  }
  const subtle = crypto.subtle;

  // ---------------------------------------------------------------------------
  // Encoding helpers
  // ---------------------------------------------------------------------------
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function toBytes(data) {
    if (data == null) throw new TypeError("data is required");
    if (typeof data === "string") return textEncoder.encode(data);
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    throw new TypeError("data must be a string, ArrayBuffer, or TypedArray");
  }

  function toHex(bytes) {
    const b = toBytes(bytes);
    let hex = "";
    for (let i = 0; i < b.length; i++) {
      hex += b[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function fromHex(hex) {
    if (typeof hex !== "string") throw new TypeError("hex must be a string");
    const clean = hex.replace(/\s+/g, "").toLowerCase();
    if (clean.length % 2 !== 0) throw new Error("Invalid hex string length");
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      const byte = parseInt(clean.substr(i * 2, 2), 16);
      if (Number.isNaN(byte)) throw new Error("Invalid hex character");
      bytes[i] = byte;
    }
    return bytes;
  }

  function toBase64(bytes) {
    const b = toBytes(bytes);
    let binary = "";
    for (let i = 0; i < b.length; i++) binary += String.fromCharCode(b[i]);
    return btoa(binary);
  }

  function fromBase64(b64) {
    if (typeof b64 !== "string") throw new TypeError("base64 must be a string");
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function toUtf8(bytes) {
    return textDecoder.decode(toBytes(bytes));
  }

  // ---------------------------------------------------------------------------
  // Random
  // ---------------------------------------------------------------------------
  function randomBytes(size) {
    if (!Number.isInteger(size) || size < 0) {
      throw new TypeError("size must be a non-negative integer");
    }
    const buf = new Uint8Array(size);
    crypto.getRandomValues(buf);
    return buf;
  }

  function randomUUID() {
    if (typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
    // Fallback for older environments
    const bytes = randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = toHex(bytes);
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  // ---------------------------------------------------------------------------
  // Hashing
  // ---------------------------------------------------------------------------
  const HASH_ALGOS = {
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
  };

  function normalizeHashAlgo(algo) {
    const key = String(algo).toLowerCase().replace(/_/g, "-");
    const normalized = HASH_ALGOS[key];
    if (!normalized) {
      throw new Error(`Unsupported hash algorithm: ${algo}. Supported: sha1, sha256, sha384, sha512`);
    }
    return normalized;
  }

  /**
   * One-shot hash. Returns hex string by default.
   * @param {string} algorithm - sha1 | sha256 | sha384 | sha512
   * @param {string|ArrayBuffer|TypedArray} data
   * @param {"hex"|"base64"|"raw"} [encoding="hex"]
   */
  async function hash(algorithm, data, encoding = "hex") {
    const algo = normalizeHashAlgo(algorithm);
    const bytes = toBytes(data);
    const digest = await subtle.digest(algo, bytes);
    if (encoding === "raw") return new Uint8Array(digest);
    if (encoding === "base64") return toBase64(digest);
    return toHex(digest);
  }

  /**
   * Node-style createHash (non-streaming for simplicity & lightness).
   * Usage:
   *   const h = createHash("sha256");
   *   h.update("hello");
   *   h.update(" world");
   *   const digest = await h.digest("hex");
   */
  function createHash(algorithm) {
    const algo = normalizeHashAlgo(algorithm);
    const chunks = [];

    return {
      update(data) {
        chunks.push(toBytes(data));
        return this;
      },
      async digest(encoding = "hex") {
        // Concatenate all chunks
        let total = 0;
        for (const c of chunks) total += c.length;
        const data = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
          data.set(c, offset);
          offset += c.length;
        }
        const digest = await subtle.digest(algo, data);
        if (encoding === "raw" || encoding === "buffer") return new Uint8Array(digest);
        if (encoding === "base64") return toBase64(digest);
        return toHex(digest);
      },
    };
  }

  // ---------------------------------------------------------------------------
  // HMAC
  // ---------------------------------------------------------------------------
  /**
   * One-shot HMAC
   * @param {string} algorithm - sha1 | sha256 | sha384 | sha512
   * @param {string|ArrayBuffer|TypedArray} key
   * @param {string|ArrayBuffer|TypedArray} data
   * @param {"hex"|"base64"|"raw"} [encoding="hex"]
   */
  async function hmac(algorithm, key, data, encoding = "hex") {
    const hashAlgo = normalizeHashAlgo(algorithm);
    const keyBytes = toBytes(key);
    const dataBytes = toBytes(data);

    const cryptoKey = await subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: hashAlgo },
      false,
      ["sign"]
    );

    const signature = await subtle.sign("HMAC", cryptoKey, dataBytes);
    if (encoding === "raw") return new Uint8Array(signature);
    if (encoding === "base64") return toBase64(signature);
    return toHex(signature);
  }

  /**
   * Node-style createHmac
   */
  function createHmac(algorithm, key) {
    const hashAlgo = normalizeHashAlgo(algorithm);
    const keyBytes = toBytes(key);
    const chunks = [];
    let cryptoKeyPromise = null;

    async function getKey() {
      if (!cryptoKeyPromise) {
        cryptoKeyPromise = subtle.importKey(
          "raw",
          keyBytes,
          { name: "HMAC", hash: hashAlgo },
          false,
          ["sign"]
        );
      }
      return cryptoKeyPromise;
    }

    return {
      update(data) {
        chunks.push(toBytes(data));
        return this;
      },
      async digest(encoding = "hex") {
        let total = 0;
        for (const c of chunks) total += c.length;
        const data = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
          data.set(c, offset);
          offset += c.length;
        }
        const cryptoKey = await getKey();
        const signature = await subtle.sign("HMAC", cryptoKey, data);
        if (encoding === "raw" || encoding === "buffer") return new Uint8Array(signature);
        if (encoding === "base64") return toBase64(signature);
        return toHex(signature);
      },
    };
  }

  // ---------------------------------------------------------------------------
  // AES helpers
  // ---------------------------------------------------------------------------
  async function importAesKey(key, algorithm, usages) {
    const keyBytes = toBytes(key);
    if (![16, 24, 32].includes(keyBytes.length)) {
      throw new Error("AES key must be 16, 24 or 32 bytes (128/192/256 bit)");
    }
    return subtle.importKey("raw", keyBytes, algorithm, false, usages);
  }

  /**
   * Encrypt with AES-GCM (recommended) or AES-CBC.
   * Returns { iv, ciphertext, tag? }  (tag is part of ciphertext for GCM)
   *
   * @param {object} options
   * @param {"aes-gcm"|"aes-cbc"} [options.algorithm="aes-gcm"]
   * @param {string|Uint8Array} options.key - 16/24/32 bytes
   * @param {string|Uint8Array} options.data
   * @param {Uint8Array} [options.iv] - optional, will be generated if missing
   * @param {Uint8Array} [options.additionalData] - for GCM only
   * @param {number} [options.tagLength=128] - for GCM only
   */
  async function encrypt(options) {
    const {
      algorithm = "aes-gcm",
      key,
      data,
      iv: providedIv,
      additionalData,
      tagLength = 128,
    } = options;

    const algoName = algorithm.toLowerCase() === "aes-cbc" ? "AES-CBC" : "AES-GCM";
    const ivLength = algoName === "AES-GCM" ? 12 : 16;
    const iv = providedIv ? toBytes(providedIv) : randomBytes(ivLength);

    if (iv.length !== ivLength) {
      throw new Error(`IV must be ${ivLength} bytes for ${algoName}`);
    }

    const cryptoKey = await importAesKey(key, { name: algoName }, ["encrypt"]);
    const dataBytes = toBytes(data);

    const params = algoName === "AES-GCM"
      ? { name: "AES-GCM", iv, additionalData: additionalData ? toBytes(additionalData) : undefined, tagLength }
      : { name: "AES-CBC", iv };

    const ciphertext = await subtle.encrypt(params, cryptoKey, dataBytes);

    return {
      iv: new Uint8Array(iv),
      ciphertext: new Uint8Array(ciphertext),
      algorithm: algoName,
    };
  }

  /**
   * Decrypt data produced by encrypt()
   */
  async function decrypt(options) {
    const {
      algorithm = "aes-gcm",
      key,
      iv,
      ciphertext,
      additionalData,
      tagLength = 128,
    } = options;

    const algoName = algorithm.toLowerCase() === "aes-cbc" ? "AES-CBC" : "AES-GCM";
    const cryptoKey = await importAesKey(key, { name: algoName }, ["decrypt"]);

    const params = algoName === "AES-GCM"
      ? { name: "AES-GCM", iv: toBytes(iv), additionalData: additionalData ? toBytes(additionalData) : undefined, tagLength }
      : { name: "AES-CBC", iv: toBytes(iv) };

    const plain = await subtle.decrypt(params, cryptoKey, toBytes(ciphertext));
    return new Uint8Array(plain);
  }

  /**
   * Convenience: encrypt and return a single base64 string "iv.ciphertext"
   */
  async function encryptToString(key, data, algorithm = "aes-gcm") {
    const result = await encrypt({ algorithm, key, data });
    return `${toBase64(result.iv)}.${toBase64(result.ciphertext)}`;
  }

  /**
   * Convenience: decrypt a string produced by encryptToString
   */
  async function decryptFromString(key, packed, algorithm = "aes-gcm") {
    const parts = packed.split(".");
    if (parts.length !== 2) throw new Error("Invalid packed ciphertext format");
    const plain = await decrypt({
      algorithm,
      key,
      iv: fromBase64(parts[0]),
      ciphertext: fromBase64(parts[1]),
    });
    return plain;
  }

  // ---------------------------------------------------------------------------
  // Key derivation
  // ---------------------------------------------------------------------------
  /**
   * PBKDF2
   * @param {string|Uint8Array} password
   * @param {string|Uint8Array} salt
   * @param {number} iterations
   * @param {number} keylen - bytes
   * @param {string} [digest="sha256"]
   * @returns {Promise<Uint8Array>}
   */
  async function pbkdf2(password, salt, iterations, keylen, digest = "sha256") {
    if (!Number.isInteger(iterations) || iterations < 1) {
      throw new TypeError("iterations must be a positive integer");
    }
    if (!Number.isInteger(keylen) || keylen < 1) {
      throw new TypeError("keylen must be a positive integer");
    }

    const hashAlgo = normalizeHashAlgo(digest);
    const passwordKey = await subtle.importKey(
      "raw",
      toBytes(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: toBytes(salt),
        iterations,
        hash: hashAlgo,
      },
      passwordKey,
      keylen * 8
    );

    return new Uint8Array(bits);
  }

  /**
   * HKDF
   */
  async function hkdf(ikm, salt, info, keylen, digest = "sha256") {
    const hashAlgo = normalizeHashAlgo(digest);
    const baseKey = await subtle.importKey(
      "raw",
      toBytes(ikm),
      "HKDF",
      false,
      ["deriveBits"]
    );

    const bits = await subtle.deriveBits(
      {
        name: "HKDF",
        hash: hashAlgo,
        salt: salt ? toBytes(salt) : new Uint8Array(0),
        info: info ? toBytes(info) : new Uint8Array(0),
      },
      baseKey,
      keylen * 8
    );

    return new Uint8Array(bits);
  }

  // ---------------------------------------------------------------------------
  // RSA
  // ---------------------------------------------------------------------------
  /**
   * Generate RSA key pair (RSA-OAEP for encryption, or RSASSA-PKCS1-v1_5 / RSA-PSS for signing)
   * @param {object} [options]
   * @param {number} [options.modulusLength=2048]
   * @param {"RSA-OAEP"|"RSASSA-PKCS1-v1_5"|"RSA-PSS"} [options.name="RSA-OAEP"]
   * @param {string} [options.hash="SHA-256"]
   */
  async function generateRSAKeyPair(options = {}) {
    const {
      modulusLength = 2048,
      name = "RSA-OAEP",
      hash = "SHA-256",
      publicExponent = new Uint8Array([1, 0, 1]),
    } = options;

    const algorithm = {
      name,
      modulusLength,
      publicExponent,
      hash: normalizeHashAlgo(hash),
    };

    const usages = name === "RSA-OAEP"
      ? ["encrypt", "decrypt"]
      : ["sign", "verify"];

    const keyPair = await subtle.generateKey(algorithm, true, usages);

    // Export for convenience
    const publicKey = await subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeySpki: new Uint8Array(publicKey),
      privateKeyPkcs8: new Uint8Array(privateKey),
      publicKeyBase64: toBase64(publicKey),
      privateKeyBase64: toBase64(privateKey),
    };
  }

  async function importRSAPublicKey(spki, algorithm = { name: "RSA-OAEP", hash: "SHA-256" }, usages = ["encrypt"]) {
    return subtle.importKey("spki", toBytes(spki), algorithm, true, usages);
  }

  async function importRSAPrivateKey(pkcs8, algorithm = { name: "RSA-OAEP", hash: "SHA-256" }, usages = ["decrypt"]) {
    return subtle.importKey("pkcs8", toBytes(pkcs8), algorithm, true, usages);
  }

  async function rsaEncrypt(publicKey, data) {
    const cipher = await subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      toBytes(data)
    );
    return new Uint8Array(cipher);
  }

  async function rsaDecrypt(privateKey, ciphertext) {
    const plain = await subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      toBytes(ciphertext)
    );
    return new Uint8Array(plain);
  }

  async function rsaSign(privateKey, data, algorithm = { name: "RSASSA-PKCS1-v1_5" }) {
    const signature = await subtle.sign(algorithm, privateKey, toBytes(data));
    return new Uint8Array(signature);
  }

  async function rsaVerify(publicKey, signature, data, algorithm = { name: "RSASSA-PKCS1-v1_5" }) {
    return subtle.verify(algorithm, publicKey, toBytes(signature), toBytes(data));
  }

  // ---------------------------------------------------------------------------
  // ECDSA / ECDH (P-256 by default)
  // ---------------------------------------------------------------------------
  async function generateECDSAKeyPair(namedCurve = "P-256") {
    const keyPair = await subtle.generateKey(
      { name: "ECDSA", namedCurve },
      true,
      ["sign", "verify"]
    );

    const publicKey = await subtle.exportKey("raw", keyPair.publicKey);
    const privateKey = await subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyRaw: new Uint8Array(publicKey),
      privateKeyPkcs8: new Uint8Array(privateKey),
    };
  }

  async function ecdsaSign(privateKey, data, hash = "SHA-256") {
    const signature = await subtle.sign(
      { name: "ECDSA", hash: normalizeHashAlgo(hash) },
      privateKey,
      toBytes(data)
    );
    return new Uint8Array(signature);
  }

  async function ecdsaVerify(publicKey, signature, data, hash = "SHA-256") {
    return subtle.verify(
      { name: "ECDSA", hash: normalizeHashAlgo(hash) },
      publicKey,
      toBytes(signature),
      toBytes(data)
    );
  }

  async function generateECDHKeyPair(namedCurve = "P-256") {
    const keyPair = await subtle.generateKey(
      { name: "ECDH", namedCurve },
      true,
      ["deriveBits", "deriveKey"]
    );

    const publicKey = await subtle.exportKey("raw", keyPair.publicKey);
    const privateKey = await subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyRaw: new Uint8Array(publicKey),
      privateKeyPkcs8: new Uint8Array(privateKey),
    };
  }

  async function deriveECDHSharedSecret(privateKey, publicKey, bitLength = 256) {
    const bits = await subtle.deriveBits(
      { name: "ECDH", public: publicKey },
      privateKey,
      bitLength
    );
    return new Uint8Array(bits);
  }

  // ---------------------------------------------------------------------------
  // Utility
  // ---------------------------------------------------------------------------
  function timingSafeEqual(a, b) {
    const aa = toBytes(a);
    const bb = toBytes(b);
    if (aa.length !== bb.length) return false;
    let result = 0;
    for (let i = 0; i < aa.length; i++) {
      result |= aa[i] ^ bb[i];
    }
    return result === 0;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------
  return {
    // Random
    randomBytes,
    randomUUID,
    getRandomValues: crypto.getRandomValues.bind(crypto),

    // Hash
    hash,
    createHash,

    // HMAC
    hmac,
    createHmac,

    // AES
    encrypt,
    decrypt,
    encryptToString,
    decryptFromString,

    // KDF
    pbkdf2,
    hkdf,

    // RSA
    generateRSAKeyPair,
    importRSAPublicKey,
    importRSAPrivateKey,
    rsaEncrypt,
    rsaDecrypt,
    rsaSign,
    rsaVerify,

    // Elliptic curves
    generateECDSAKeyPair,
    ecdsaSign,
    ecdsaVerify,
    generateECDHKeyPair,
    deriveECDHSharedSecret,

    // Utils
    timingSafeEqual,
    toBytes,
    toHex,
    fromHex,
    toBase64,
    fromBase64,
    toUtf8,

    // Direct access if needed
    subtle,
    crypto,
  };
});
