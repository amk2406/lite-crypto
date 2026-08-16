# lite-crypto

**Simple, lightweight, zero-dependency crypto library for the browser** (and Node.js).

Built entirely on the native **Web Crypto API**. No pure-JS crypto implementations, no large dependencies.

### Size
~8–9 KB minified (extremely small).

### Features
| Feature              | Status | Notes                                      |
|----------------------|--------|--------------------------------------------|
| `randomBytes`        | ✅     | Cryptographically secure                   |
| `randomUUID`         | ✅     | RFC 4122 v4                                |
| Hash (SHA-1/256/384/512) | ✅ | One-shot + `createHash` style             |
| HMAC                 | ✅     | One-shot + `createHmac` style              |
| AES-GCM              | ✅     | Recommended authenticated encryption       |
| AES-CBC              | ✅     | Available if needed                        |
| PBKDF2               | ✅     | Password-based key derivation              |
| HKDF                 | ✅     |                                          |
| RSA-OAEP encrypt/decrypt | ✅ |                                          |
| RSA sign/verify      | ✅     | RSASSA-PKCS1-v1_5                          |
| ECDSA sign/verify    | ✅     | P-256 (default)                            |
| ECDH key exchange    | ✅     |                                            |
| Encoding helpers     | ✅     | hex, base64, utf8                          |
| `timingSafeEqual`    | ✅     |                                            |

---

## Installation / Usage

### Browser (ES Module)
```html
<script type="module">
  import LiteCrypto from './lite-crypto.js';
  // or if you prefer the global:
  // <script src="lite-crypto.js"></script>
  // then use window.LiteCrypto
</script>
```

### Node.js
```js
const crypto = require('./lite-crypto.js');
// or
import crypto from './lite-crypto.js';
```

---

## Quick Examples

### Random
```js
const bytes = crypto.randomBytes(32);          // Uint8Array(32)
const uuid  = crypto.randomUUID();             // "f47ac10b-58cc-4372-a567-0e02b2c3d479"
```

### Hashing
```js
// One-shot
const hash = await crypto.hash('sha256', 'hello');
// → "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

// Node-style
const h = crypto.createHash('sha256');
h.update('hel');
h.update('lo');
const digest = await h.digest('hex');
```

### HMAC
```js
const mac = await crypto.hmac('sha256', 'secret-key', 'message');

// or
const h = crypto.createHmac('sha256', 'secret-key');
h.update('message');
const mac2 = await h.digest('hex');
```

### AES-GCM (recommended)
```js
const key = crypto.randomBytes(32); // 256-bit key

// Encrypt
const { iv, ciphertext } = await crypto.encrypt({
  algorithm: 'aes-gcm',
  key,
  data: 'Secret message 🔐'
});

// Decrypt
const plain = await crypto.decrypt({
  algorithm: 'aes-gcm',
  key,
  iv,
  ciphertext
});
console.log(crypto.toUtf8(plain)); // "Secret message 🔐"

// Super simple string version
const packed = await crypto.encryptToString(key, 'hello');
const restored = await crypto.decryptFromString(key, packed);
```

### Password-based encryption (PBKDF2 + AES)
```js
const password = 'my-strong-password';
const salt = crypto.randomBytes(16);

// Derive a key
const key = await crypto.pbkdf2(password, salt, 100000, 32, 'sha256');

// Then use with AES as usual
const packed = await crypto.encryptToString(key, 'sensitive data');
```

### RSA
```js
// Generate key pair
const keys = await crypto.generateRSAKeyPair({
  modulusLength: 2048,
  name: 'RSA-OAEP'
});

// Encrypt with public key
const ciphertext = await crypto.rsaEncrypt(keys.publicKey, 'secret');

// Decrypt with private key
const plain = await crypto.rsaDecrypt(keys.privateKey, ciphertext);
```

### Sign / Verify (RSA or ECDSA)
```js
// ECDSA (recommended for signatures)
const keys = await crypto.generateECDSAKeyPair('P-256');
const signature = await crypto.ecdsaSign(keys.privateKey, 'data to sign');
const valid = await crypto.ecdsaVerify(keys.publicKey, signature, 'data to sign');
// → true
```

### ECDH Shared Secret
```js
const alice = await crypto.generateECDHKeyPair();
const bob   = await crypto.generateECDHKeyPair();

const secretA = await crypto.deriveECDHSharedSecret(alice.privateKey, bob.publicKey);
const secretB = await crypto.deriveECDHSharedSecret(bob.privateKey, alice.publicKey);
// secretA === secretB
```

### Encoding helpers
```js
crypto.toHex(bytes)
crypto.fromHex('a1b2c3...')
crypto.toBase64(bytes)
crypto.fromBase64('...')
crypto.toUtf8(bytes)
crypto.toBytes('string or buffer')
```

---

## API Summary

```js
// Random
randomBytes(size) → Uint8Array
randomUUID() → string

// Hash
hash(algo, data, encoding?) → Promise<string|Uint8Array>
createHash(algo) → { update(), digest() }

// HMAC
hmac(algo, key, data, encoding?) → Promise<string|Uint8Array>
createHmac(algo, key) → { update(), digest() }

// AES
encrypt({ algorithm, key, data, iv?, additionalData? }) → Promise<{iv, ciphertext}>
decrypt({ algorithm, key, iv, ciphertext, additionalData? }) → Promise<Uint8Array>
encryptToString(key, data) → Promise<string>
decryptFromString(key, packed) → Promise<Uint8Array>

// KDF
pbkdf2(password, salt, iterations, keylen, digest?) → Promise<Uint8Array>
hkdf(ikm, salt, info, keylen, digest?) → Promise<Uint8Array>

// RSA
generateRSAKeyPair(options?) → Promise<KeyPair>
rsaEncrypt(publicKey, data) → Promise<Uint8Array>
rsaDecrypt(privateKey, ciphertext) → Promise<Uint8Array>
rsaSign(privateKey, data) → Promise<Uint8Array>
rsaVerify(publicKey, signature, data) → Promise<boolean>

// Elliptic
generateECDSAKeyPair(curve?) → Promise<KeyPair>
ecdsaSign(privateKey, data) → Promise<Uint8Array>
ecdsaVerify(publicKey, signature, data) → Promise<boolean>
generateECDHKeyPair(curve?) → Promise<KeyPair>
deriveECDHSharedSecret(privateKey, publicKey) → Promise<Uint8Array>

// Utils
timingSafeEqual(a, b) → boolean
toHex / fromHex / toBase64 / fromBase64 / toUtf8 / toBytes
```

---

## Notes

- All cryptographic operations are **async** (they return Promises) because the Web Crypto API is async.
- Uses only native browser/Node crypto – **no pure-JS fallbacks**. This keeps the library tiny and as secure as the platform.
- Requires a secure context in browsers (HTTPS or localhost).
- Supported algorithms are limited to what Web Crypto supports (no MD5, no DES, no RC4, etc. – which is a good thing).

## License

MIT
