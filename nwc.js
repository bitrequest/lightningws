/**
 * NWC (Nostr Wallet Connect) endpoint for Express
 *
 * Supported methods:
 *   make_invoice   — params: { amount (msats), description }
 *   lookup_invoice — params: { payment_hash }
 */

"use strict";

const WebSocket = require("ws");
const { secp256k1, schnorr } = require("@noble/curves/secp256k1.js");
const { randomBytes, createCipheriv, createDecipheriv } = require("crypto");
const { sha256 } = require("@noble/hashes/sha2.js");

// ─── NIP-04 ───────────────────────────────────────────────────────────────────

function nip04SharedSecret(privkeyHex, pubkeyHex) {
    const shared = secp256k1.getSharedSecret(
        Buffer.from(privkeyHex, "hex"),
        Buffer.from("02" + pubkeyHex, "hex")
    );
    return Buffer.from(shared.slice(1, 33));
}

function nip04Encrypt(plaintext, privkeyHex, pubkeyHex) {
    const secret = nip04SharedSecret(privkeyHex, pubkeyHex);
    const iv     = randomBytes(16);
    const cipher = createCipheriv("aes-256-cbc", secret, iv);
    const ct     = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return ct.toString("base64") + "?iv=" + iv.toString("base64");
}

function nip04Decrypt(ciphertext, privkeyHex, pubkeyHex) {
    const [ct, ivB64] = ciphertext.split("?iv=");
    const secret      = nip04SharedSecret(privkeyHex, pubkeyHex);
    const decipher    = createDecipheriv("aes-256-cbc", secret, Buffer.from(ivB64, "base64"));
    return Buffer.concat([
        decipher.update(Buffer.from(ct, "base64")),
        decipher.final()
    ]).toString("utf8");
}

// ─── Nostr event ──────────────────────────────────────────────────────────────

function buildEvent(method, params, privkeyHex, walletPubkey) {
    const privBytes  = Buffer.from(privkeyHex, "hex");
    const pubkey     = Buffer.from(schnorr.getPublicKey(privBytes)).toString("hex");
    const content    = nip04Encrypt(JSON.stringify({ method, params }), privkeyHex, walletPubkey);
    const created_at = Math.floor(Date.now() / 1000);
    const kind       = 23194;
    const tags       = [["p", walletPubkey]];

    const serialized = JSON.stringify([0, pubkey, created_at, kind, tags, content]);
    const id         = Buffer.from(sha256(Buffer.from(serialized))).toString("hex");
    const sig        = Buffer.from(schnorr.sign(Buffer.from(id, "hex"), privBytes)).toString("hex");

    return { id, pubkey, created_at, kind, tags, content, sig };
}

// ─── NWC relay request ────────────────────────────────────────────────────────

function nwcRequest(uri, method, params) {
    return new Promise((resolve, reject) => {
        // Parse URI
        const match = uri.match(/^nostr\+walletconnect:\/\/([^?]+)\?(.+)$/);
        if (!match) return reject(new Error("Invalid NWC URI"));
        const walletPubkey = match[1];
        const qs           = new URLSearchParams(match[2]);
        const relay        = qs.get("relay");
        const secret       = qs.get("secret");
        if (!relay || !secret) return reject(new Error("Missing relay or secret in NWC URI"));

        const event  = buildEvent(method, params, secret, walletPubkey);
        const subId  = randomBytes(8).toString("hex");
        const myPub  = event.pubkey;

        const ws      = new WebSocket(relay);
        let settled   = false;
        const timeout = setTimeout(() => {
            if (!settled) {
                settled = true;
                ws.close();
                reject(new Error("NWC timeout — no response from wallet"));
            }
        }, 30000);

        ws.on("open", () => {
            // Subscribe for responses directed at our pubkey
            ws.send(JSON.stringify(["REQ", subId, {
                kinds: [23195],
                since: Math.floor(Date.now() / 1000) - 10,
                "#p": [myPub]
            }]));
            // Publish request event
            ws.send(JSON.stringify(["EVENT", event]));
        });

        ws.on("message", (data) => {
            let msg;
            try { msg = JSON.parse(data.toString()); } catch { return; }

            if (msg[0] === "OK" && msg[1] === event.id && !msg[2]) {
                if (!settled) {
                    settled = true;
                    clearTimeout(timeout);
                    ws.close();
                    reject(new Error("Relay rejected event: " + (msg[3] ?? "")));
                }
                return;
            }

            if (msg[0] === "EVENT" && msg[2]?.kind === 23195) {
                try {
                    const decrypted = nip04Decrypt(msg[2].content, secret, walletPubkey);
                    const result    = JSON.parse(decrypted);
                    if (!settled) {
                        settled = true;
                        clearTimeout(timeout);
                        ws.close();
                        if (result.error) {
                            reject(new Error("NWC error: " + result.error.message));
                        } else {
                            resolve(result.result);
                        }
                    }
                } catch (e) {
                    if (!settled) {
                        settled = true;
                        clearTimeout(timeout);
                        ws.close();
                        reject(new Error("Decrypt failed: " + e.message));
                    }
                }
            }
        });

        ws.on("error", (e) => {
            if (!settled) {
                settled = true;
                clearTimeout(timeout);
                reject(new Error("WebSocket error: " + e.message));
            }
        });
    });
}

// ─── Express endpoint ─────────────────────────────────────────────────────────

function register(app) {
    // Parse JSON bodies for /nwc only
    const express = require("express");
    app.use("/nwc", express.json());

    app.post("/nwc", async (req, res) => {
        const { uri, method, params } = req.body ?? {};

        if (!uri || !method) {
            return res.status(400).json({ ok: false, error: "Missing uri or method" });
        }

        try {
            const result = await nwcRequest(uri, method, params ?? {});
            res.json({ ok: true, result });
        } catch (e) {
            res.status(500).json({ ok: false, error: e.message });
        }
    });

    console.log("NWC endpoint registered at POST /nwc");
}

// ─── Spark ECIES endpoint ─────────────────────────────────────────────────────

function sparkEciesEncrypt(plaintextHex, recipientPubkeyHex) {
    const plaintext      = Buffer.from(plaintextHex, "hex");
    const ephPriv        = randomBytes(32);
    const ephPubHex      = Buffer.from(secp256k1.getPublicKey(ephPriv, false)).toString("hex"); // uncompressed

    // ECDH: shared secret x coordinate
    const sharedCompressed = secp256k1.getSharedSecret(ephPriv, Buffer.from(recipientPubkeyHex, "hex"));
    const sharedX          = Buffer.from(sharedCompressed.slice(1, 33));

    // Reconstruct uncompressed shared point for HKDF (matches spark_preimage.php)
    // We need full uncompressed point — derive y from x
    const sharedPoint = secp256k1.ProjectivePoint
        ? secp256k1.ProjectivePoint.fromHex(Buffer.from(sharedCompressed).toString("hex"))
        : null;

    let sharedUncompressed;
    if (sharedPoint) {
        sharedUncompressed = Buffer.from(sharedPoint.toRawBytes(false));
    } else {
        // Fallback: use only x (some versions don't expose ProjectivePoint)
        const sharedFull = secp256k1.getSharedSecret(ephPriv, Buffer.from(recipientPubkeyHex, "hex"), false);
        sharedUncompressed = Buffer.from(sharedFull);
    }

    // HKDF key derivation (matches spark_preimage.php)
    const { hkdf } = require("@noble/hashes/hkdf.js");
    const { sha256 } = require("@noble/hashes/sha2.js");
    const ikm    = Buffer.concat([Buffer.from(ephPubHex, "hex"), sharedUncompressed]);
    const aesKey = Buffer.from(hkdf(sha256, ikm, undefined, undefined, 32));

    // AES-256-GCM with 16-byte nonce (matches spark_preimage.php)
    const { createCipheriv: cipher } = require("crypto");
    const nonce    = randomBytes(16);
    const c        = cipher("aes-256-gcm", aesKey, nonce);
    const ct       = Buffer.concat([c.update(plaintext), c.final()]);
    const tag      = c.getAuthTag();

    // Output: ephPub(65) + nonce(16) + tag(16) + ct
    return Buffer.concat([Buffer.from(ephPubHex, "hex"), nonce, tag, ct]).toString("hex");
}

function registerSpark(app) {
    const express = require("express");
    app.use("/spark-ecies", express.json());

    app.post("/spark-ecies", (req, res) => {
        const { plaintext_hex, recipient_pubkey_hex } = req.body ?? {};
        if (!plaintext_hex || !recipient_pubkey_hex) {
            return res.status(400).json({ ok: false, error: "Missing plaintext_hex or recipient_pubkey_hex" });
        }
        try {
            const ciphertext_hex = sparkEciesEncrypt(plaintext_hex, recipient_pubkey_hex);
            res.json({ ok: true, ciphertext_hex });
        } catch (e) {
            res.status(500).json({ ok: false, error: e.message });
        }
    });

    console.log("Spark ECIES endpoint registered at POST /spark-ecies");
}

module.exports = { register, registerSpark, nwcRequest };
