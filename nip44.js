/**
 * NIP-44 v2 encryption (secp256k1 ECDH → HKDF → ChaCha20 + HMAC-SHA256).
 *
 * Zero extra dependencies: ChaCha20 comes from Node's built-in crypto,
 * HKDF/HMAC/SHA-256 and the ECDH from @noble (already used elsewhere here).
 *
 * Spec: https://github.com/nostr-protocol/nips/blob/master/44.md
 */

"use strict";

const { createCipheriv, randomBytes, timingSafeEqual } = require("crypto"),
    { secp256k1 } = require("@noble/curves/secp256k1.js"),
    { sha256 } = require("@noble/hashes/sha2.js"),
    { hmac } = require("@noble/hashes/hmac.js"),
    { extract, expand } = require("@noble/hashes/hkdf.js");

const SALT = Buffer.from("nip44-v2", "utf8");

// conversation_key = HKDF-extract(salt="nip44-v2", ikm = ECDH shared x-coord).
// Peer pubkey is x-only (32-byte hex); lift with even-y ("02" prefix) as NIP-44 requires.
function conversationKey(privkeyHex, pubkeyHex) {
    const shared = secp256k1.getSharedSecret(
        Buffer.from(privkeyHex, "hex"),
        Buffer.from("02" + pubkeyHex, "hex")
    );
    const sharedX = Buffer.from(shared.slice(1, 33));
    return Buffer.from(extract(sha256, sharedX, SALT));
}

// HKDF-expand(prk=conversation_key, info=nonce, L=76) → chacha_key|chacha_nonce|hmac_key.
function messageKeys(convKey, nonce) {
    const k = Buffer.from(expand(sha256, convKey, nonce, 76));
    return {
        chachaKey: k.subarray(0, 32),
        chachaNonce: k.subarray(32, 44),
        hmacKey: k.subarray(44, 76)
    };
}

function calcPaddedLen(len) {
    if (len <= 32) return 32;
    const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
    const chunk = nextPower <= 256 ? 32 : nextPower / 8;
    return chunk * (Math.floor((len - 1) / chunk) + 1);
}

function pad(plaintext) {
    const unpadded = Buffer.from(plaintext, "utf8"),
        len = unpadded.length;
    if (len < 1 || len > 65535) throw new Error("nip44: plaintext must be 1..65535 bytes");
    const prefix = Buffer.alloc(2);
    prefix.writeUInt16BE(len, 0);
    const padded = Buffer.alloc(calcPaddedLen(len));
    unpadded.copy(padded, 0);
    return Buffer.concat([prefix, padded]);
}

function unpad(padded) {
    const len = padded.readUInt16BE(0),
        unpadded = padded.subarray(2, 2 + len);
    if (len < 1 || len > 65535 || unpadded.length !== len || padded.length !== 2 + calcPaddedLen(len)) {
        throw new Error("nip44: invalid padding");
    }
    return unpadded.toString("utf8");
}

// ChaCha20 is a stream cipher, so the same call decrypts. Node's IV is
// 4-byte little-endian counter (0) || 12-byte nonce.
function chacha20(key, nonce12, data) {
    const iv = Buffer.concat([Buffer.alloc(4), nonce12]),
        c = createCipheriv("chacha20", key, iv);
    return Buffer.concat([c.update(data), c.final()]);
}

function encrypt(plaintext, privkeyHex, pubkeyHex, nonceOverride) {
    const ck = conversationKey(privkeyHex, pubkeyHex),
        nonce = nonceOverride || randomBytes(32),
        { chachaKey, chachaNonce, hmacKey } = messageKeys(ck, nonce),
        ciphertext = chacha20(chachaKey, chachaNonce, pad(plaintext)),
        mac = Buffer.from(hmac(sha256, hmacKey, Buffer.concat([nonce, ciphertext])));
    return Buffer.concat([Buffer.from([2]), nonce, ciphertext, mac]).toString("base64");
}

function decrypt(payloadB64, privkeyHex, pubkeyHex) {
    if (typeof payloadB64 !== "string" || payloadB64.length < 1 || payloadB64[0] === "#") {
        throw new Error("nip44: unsupported payload");
    }
    const data = Buffer.from(payloadB64, "base64");
    if (data.length < 99 || data[0] !== 2) throw new Error("nip44: bad version/length");
    const nonce = data.subarray(1, 33),
        mac = data.subarray(data.length - 32),
        ciphertext = data.subarray(33, data.length - 32),
        ck = conversationKey(privkeyHex, pubkeyHex),
        { chachaKey, chachaNonce, hmacKey } = messageKeys(ck, nonce),
        calcMac = Buffer.from(hmac(sha256, hmacKey, Buffer.concat([nonce, ciphertext])));
    if (calcMac.length !== mac.length || !timingSafeEqual(calcMac, mac)) {
        throw new Error("nip44: invalid MAC");
    }
    return unpad(chacha20(chachaKey, chachaNonce, ciphertext));
}

module.exports = { encrypt, decrypt, conversationKey, messageKeys, calcPaddedLen };
