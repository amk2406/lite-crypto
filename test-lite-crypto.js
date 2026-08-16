/**
 * Comprehensive test suite for lite-crypto
 */

const assert = require("assert");
const crypto = require("./lite-crypto.js");

let passed = 0;
let failed = 0;

function test(name, fn) {
  return fn()
    .then(() => {
      console.log(`  ✓ ${name}`);
      passed++;
    })
    .catch((err) => {
      console.error(`  ✗ ${name}`);
      console.error(`    ${err.message}`);
      if (err.stack) console.error(err.stack.split("\n").slice(1, 3).join("\n"));
      failed++;
    });
}

async function run() {
  console.log("\n=== lite-crypto test suite ===\n");

  // Random
  console.log("Random:");
  await test("randomBytes(32) returns 32 bytes", async () => {
    const b = crypto.randomBytes(32);
    assert.strictEqual(b.length, 32);
    assert.ok(b instanceof Uint8Array);
  });

  await test("randomBytes different each call", async () => {
    const a = crypto.randomBytes(16);
    const b = crypto.randomBytes(16);
    assert.ok(!crypto.timingSafeEqual(a, b));
  });

  await test("randomUUID format", async () => {
    const uuid = crypto.randomUUID();
    assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  // Encoding
  console.log("\nEncoding:");
  await test("toHex / fromHex roundtrip", async () => {
    const original = crypto.randomBytes(20);
    const hex = crypto.toHex(original);
    const back = crypto.fromHex(hex);
    assert.ok(crypto.timingSafeEqual(original, back));
  });

  await test("toBase64 / fromBase64 roundtrip", async () => {
    const original = crypto.randomBytes(20);
    const b64 = crypto.toBase64(original);
    const back = crypto.fromBase64(b64);
    assert.ok(crypto.timingSafeEqual(original, back));
  });

  await test("toUtf8", async () => {
    const str = "Hello, 世界 🌍";
    const bytes = crypto.toBytes(str);
    assert.strictEqual(crypto.toUtf8(bytes), str);
  });

  // Hash
  console.log("\nHash:");
  await test("hash sha256 known value", async () => {
    // "hello" -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    const h = await crypto.hash("sha256", "hello");
    assert.strictEqual(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });

  await test("hash sha256 with encoding=raw", async () => {
    const h = await crypto.hash("sha256", "hello", "raw");
    assert.strictEqual(h.length, 32);
  });

  await test("createHash multi-update", async () => {
    const h = crypto.createHash("sha256");
    h.update("hel");
    h.update("lo");
    const digest = await h.digest("hex");
    assert.strictEqual(digest, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });

  await test("hash sha512", async () => {
    const h = await crypto.hash("sha512", "test");
    assert.strictEqual(h.length, 128); // 64 bytes = 128 hex chars
  });

  // HMAC
  console.log("\nHMAC:");
  await test("hmac sha256 known value", async () => {
    // HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
    // = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
    const h = await crypto.hmac("sha256", "key", "The quick brown fox jumps over the lazy dog");
    assert.strictEqual(h, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
  });

  await test("createHmac multi-update", async () => {
    const h = crypto.createHmac("sha256", "key");
    h.update("The quick brown fox ");
    h.update("jumps over the lazy dog");
    const digest = await h.digest("hex");
    assert.strictEqual(digest, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
  });

  // AES-GCM
  console.log("\nAES-GCM:");
  await test("AES-GCM encrypt/decrypt roundtrip", async () => {
    const key = crypto.randomBytes(32);
    const data = "Secret message 🔐 with unicode";
    const encrypted = await crypto.encrypt({ algorithm: "aes-gcm", key, data });
    assert.strictEqual(encrypted.iv.length, 12);
    assert.ok(encrypted.ciphertext.length > 0);

    const decrypted = await crypto.decrypt({
      algorithm: "aes-gcm",
      key,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
    });
    assert.strictEqual(crypto.toUtf8(decrypted), data);
  });

  await test("AES-GCM with additionalData", async () => {
    const key = crypto.randomBytes(32);
    const data = "payload";
    const aad = "authenticated but not encrypted";
    const encrypted = await crypto.encrypt({
      algorithm: "aes-gcm",
      key,
      data,
      additionalData: aad,
    });
    const decrypted = await crypto.decrypt({
      algorithm: "aes-gcm",
      key,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
      additionalData: aad,
    });
    assert.strictEqual(crypto.toUtf8(decrypted), data);

    // Wrong AAD should fail
    let failed = false;
    try {
      await crypto.decrypt({
        algorithm: "aes-gcm",
        key,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        additionalData: "wrong",
      });
    } catch {
      failed = true;
    }
    assert.ok(failed, "Should reject wrong additionalData");
  });

  await test("encryptToString / decryptFromString", async () => {
    const key = crypto.randomBytes(32);
    const packed = await crypto.encryptToString(key, "hello world");
    assert.ok(packed.includes("."));
    const plain = await crypto.decryptFromString(key, packed);
    assert.strictEqual(crypto.toUtf8(plain), "hello world");
  });

  // AES-CBC
  console.log("\nAES-CBC:");
  await test("AES-CBC encrypt/decrypt roundtrip", async () => {
    const key = crypto.randomBytes(32);
    const data = "CBC mode test data that is longer than one block!!!!!!!!";
    const encrypted = await crypto.encrypt({ algorithm: "aes-cbc", key, data });
    assert.strictEqual(encrypted.iv.length, 16);

    const decrypted = await crypto.decrypt({
      algorithm: "aes-cbc",
      key,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
    });
    assert.strictEqual(crypto.toUtf8(decrypted), data);
  });

  // PBKDF2
  console.log("\nPBKDF2:");
  await test("pbkdf2 basic", async () => {
    const derived = await crypto.pbkdf2("password", "salt", 1000, 32, "sha256");
    assert.strictEqual(derived.length, 32);
  });

  await test("pbkdf2 deterministic", async () => {
    const a = await crypto.pbkdf2("password", "salt", 1000, 32, "sha256");
    const b = await crypto.pbkdf2("password", "salt", 1000, 32, "sha256");
    assert.ok(crypto.timingSafeEqual(a, b));
  });

  await test("pbkdf2 different salt different key", async () => {
    const a = await crypto.pbkdf2("password", "salt1", 1000, 32);
    const b = await crypto.pbkdf2("password", "salt2", 1000, 32);
    assert.ok(!crypto.timingSafeEqual(a, b));
  });

  // HKDF
  console.log("\nHKDF:");
  await test("hkdf basic", async () => {
    const ikm = crypto.randomBytes(32);
    const derived = await crypto.hkdf(ikm, "salt", "info", 32);
    assert.strictEqual(derived.length, 32);
  });

  // RSA
  console.log("\nRSA:");
  await test("RSA-OAEP encrypt/decrypt", async () => {
    const keys = await crypto.generateRSAKeyPair({ modulusLength: 2048, name: "RSA-OAEP" });
    const message = "RSA secret message";
    const ciphertext = await crypto.rsaEncrypt(keys.publicKey, message);
    const plain = await crypto.rsaDecrypt(keys.privateKey, ciphertext);
    assert.strictEqual(crypto.toUtf8(plain), message);
  });

  await test("RSA sign / verify (RSASSA-PKCS1-v1_5)", async () => {
    const keys = await crypto.generateRSAKeyPair({
      modulusLength: 2048,
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    });
    const data = "data to sign";
    const signature = await crypto.rsaSign(keys.privateKey, data);
    const valid = await crypto.rsaVerify(keys.publicKey, signature, data);
    assert.strictEqual(valid, true);

    const invalid = await crypto.rsaVerify(keys.publicKey, signature, "tampered");
    assert.strictEqual(invalid, false);
  });

  // ECDSA
  console.log("\nECDSA:");
  await test("ECDSA sign / verify", async () => {
    const keys = await crypto.generateECDSAKeyPair("P-256");
    const data = "ecdsa test message";
    const signature = await crypto.ecdsaSign(keys.privateKey, data);
    const valid = await crypto.ecdsaVerify(keys.publicKey, signature, data);
    assert.strictEqual(valid, true);

    const invalid = await crypto.ecdsaVerify(keys.publicKey, signature, "wrong");
    assert.strictEqual(invalid, false);
  });

  // ECDH
  console.log("\nECDH:");
  await test("ECDH shared secret", async () => {
    const alice = await crypto.generateECDHKeyPair("P-256");
    const bob = await crypto.generateECDHKeyPair("P-256");

    const secretAlice = await crypto.deriveECDHSharedSecret(alice.privateKey, bob.publicKey);
    const secretBob = await crypto.deriveECDHSharedSecret(bob.privateKey, alice.publicKey);

    assert.strictEqual(secretAlice.length, 32);
    assert.ok(crypto.timingSafeEqual(secretAlice, secretBob));
  });

  // timingSafeEqual
  console.log("\nUtils:");
  await test("timingSafeEqual", async () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    const c = new Uint8Array([1, 2, 3, 5]);
    assert.strictEqual(crypto.timingSafeEqual(a, b), true);
    assert.strictEqual(crypto.timingSafeEqual(a, c), false);
  });

  // Error cases
  console.log("\nError handling:");
  await test("unsupported hash throws", async () => {
    let threw = false;
    try {
      await crypto.hash("md5", "test");
    } catch {
      threw = true;
    }
    assert.ok(threw);
  });

  await test("bad AES key length throws", async () => {
    let threw = false;
    try {
      await crypto.encrypt({ key: crypto.randomBytes(10), data: "x" });
    } catch {
      threw = true;
    }
    assert.ok(threw);
  });

  // Summary
  console.log("\n========================================");
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log("========================================\n");

  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
