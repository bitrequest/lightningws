/**
 * NWC (Nostr Wallet Connect) endpoint for Express
 *
 * Supported methods:
 *   make_invoice   — params: { amount (msats), description }
 *   lookup_invoice — params: { payment_hash }
 *
 * Encryption: NIP-44 v2 by default (NIP-04 is deprecated in NIP-47). Responses
 * are decrypted by detecting the scheme, so a wallet replying in either works.
 * POST body may set "encryption":"nip04" to force the legacy scheme.
 */

"use strict";

const WebSocket = require("ws"),
    {secp256k1, schnorr } = require("@noble/curves/secp256k1.js"),
    {randomBytes, createCipheriv, createDecipheriv } = require("crypto"),
    {sha256} = require("@noble/hashes/sha2.js"),
    nip44 = require("./nip44.js"),
    dns = require("dns"),
    net = require("net");

const blocked = new net.BlockList();
[["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4]].forEach(([a, p]) => blocked.addSubnet(a, p, "ipv4"));
[["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8]].forEach(([a, p]) => blocked.addSubnet(a, p, "ipv6"));

function isPublicIp(ip) {
    return !blocked.check(ip, net.isIPv6(ip) ? "ipv6" : "ipv4");
}

function safeLookup(hostname, options, cb) {
    dns.lookup(hostname, {...options, "all": true}, (err, addrs) => {
        if (err) return cb(err);
        if (!addrs.length || addrs.some(a => !isPublicIp(a.address))) return cb(new Error("Relay host not allowed"));
        if (options.all) return cb(null, addrs);
        cb(null, addrs[0].address, addrs[0].family);
    });
}

function checkRelay(relay) {
    let u;
    try { u = new URL(relay);} catch { throw new Error("Invalid relay URL");}
    if (u.protocol !== "wss:" || u.username || u.password) throw new Error("Relay must be a plain wss:// URL");
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (net.isIP(host) && !isPublicIp(host)) throw new Error("Relay host not allowed");
    return u.href;
}

// ─── NIP-04 ───────────────────────────────────────────────────────────────────

function nip04SharedSecret(privkeyHex, pubkeyHex) {
    const shared = secp256k1.getSharedSecret(
        Buffer.from(privkeyHex, "hex"),
        Buffer.from("02" + pubkeyHex, "hex")
    );
    return Buffer.from(shared.slice(1, 33));
}

// NIP-04 (unauthenticated AES-CBC) is deprecated in NIP-47. We now default to
// NIP-44 (see buildEvent) and keep NIP-04 only to (a) read responses from wallets
// that still reply in it and (b) allow an explicit nip04 override for a legacy
// wallet that can't do NIP-44.
function nip04Encrypt(plaintext, privkeyHex, pubkeyHex) {
    const secret = nip04SharedSecret(privkeyHex, pubkeyHex),
        iv = randomBytes(16),
        cipher = createCipheriv("aes-256-cbc", secret, iv),
        ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return ct.toString("base64") + "?iv=" + iv.toString("base64");
}

function nip04Decrypt(ciphertext, privkeyHex, pubkeyHex) {
    const [ct, ivB64] = ciphertext.split("?iv="),
        secret = nip04SharedSecret(privkeyHex, pubkeyHex),
        decipher = createDecipheriv("aes-256-cbc", secret, Buffer.from(ivB64, "base64"));
    return Buffer.concat([
        decipher.update(Buffer.from(ct, "base64")),
        decipher.final()
    ]).toString("utf8");
}

// Decrypt a response by sniffing the scheme: NIP-04 payloads carry a "?iv="
// separator, NIP-44 payloads don't. Lets us read whatever the wallet replied with,
// regardless of which scheme we requested.
function decryptContent(content, privkeyHex, walletPubkey) {
    return content.includes("?iv=")
        ? nip04Decrypt(content, privkeyHex, walletPubkey)
        : nip44.decrypt(content, privkeyHex, walletPubkey);
}

// ─── Nostr event ──────────────────────────────────────────────────────────────

// encryption: "nip44" (default) | "nip04". NIP-44 adds the negotiated encryption
// tag per NIP-47; NIP-04 is the deprecated legacy path.
function buildEvent(method, params, privkeyHex, walletPubkey, encryption) {
    const privBytes = Buffer.from(privkeyHex, "hex"),
        pubkey = Buffer.from(schnorr.getPublicKey(privBytes)).toString("hex"),
        useNip44 = encryption !== "nip04",
        plaintext = JSON.stringify({ method, params }),
        content = useNip44
            ? nip44.encrypt(plaintext, privkeyHex, walletPubkey)
            : nip04Encrypt(plaintext, privkeyHex, walletPubkey),
        created_at = Math.floor(Date.now() / 1000),
        kind = 23194,
        tags = useNip44 ? [["p", walletPubkey], ["encryption", "nip44_v2"]] : [["p", walletPubkey]],
        serialized = JSON.stringify([0, pubkey, created_at, kind, tags, content]),
        id = Buffer.from(sha256(Buffer.from(serialized))).toString("hex"),
        sig = Buffer.from(schnorr.sign(Buffer.from(id, "hex"), privBytes)).toString("hex");
    return {id, pubkey, created_at, kind, tags, content, sig};
}

// ─── NWC relay request ────────────────────────────────────────────────────────

// A response counts only when it comes from the wallet and, if it has e tags, answers this request
function isReply(ev, walletPubkey, requestId) {
    if (String(ev.pubkey ?? "").toLowerCase() !== walletPubkey.toLowerCase()) return false;
    const eTags = (Array.isArray(ev.tags) ? ev.tags : []).filter(t => Array.isArray(t) && t[0] === "e").map(t => t[1]);
    return !eTags.length || eTags.includes(requestId);
}

function nwcRequest(uri, method, params, encryption) {
    return new Promise((resolve, reject) => {
        // Parse URI
        const match = uri.match(/^nostr\+walletconnect:\/\/([^?]+)\?(.+)$/);
        if (!match) return reject(new Error("Invalid NWC URI"));
        const walletPubkey = match[1],
            qs = new URLSearchParams(match[2]),
            relay = qs.get("relay"),
            secret = qs.get("secret");
        if (!relay || !secret) return reject(new Error("Missing relay or secret in NWC URI"));
        if (!/^[0-9a-f]{64}$/i.test(walletPubkey) || !/^[0-9a-f]{64}$/i.test(secret)) return reject(new Error("Invalid pubkey or secret in NWC URI"));
        let relayUrl;
        try { relayUrl = checkRelay(relay);} catch (e) { return reject(e);}
        const event = buildEvent(method, params, secret, walletPubkey, encryption),
            subId = randomBytes(8).toString("hex"),
            myPub = event.pubkey,
            ws = new WebSocket(relayUrl, {"lookup": safeLookup, "handshakeTimeout": 10000, "maxPayload": 1048576});
        let settled = false;
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
                "kinds": [23195],
                "since": Math.floor(Date.now() / 1000) - 10,
                "#p": [myPub]
            }]));
            // Publish request event
            ws.send(JSON.stringify(["EVENT", event]));
        });
        ws.on("message", (data) => {
            let msg;
            try { msg = JSON.parse(data.toString());} catch {return;}
            if (msg[0] === "OK" && msg[1] === event.id && !msg[2]) {
                if (!settled) {
                    settled = true;
                    clearTimeout(timeout);
                    ws.close();
                    reject(new Error("Relay rejected event: " + (msg[3] ?? "")));
                }
                return;
            }
            if (msg[0] === "EVENT" && msg[2]?.kind === 23195 && isReply(msg[2], walletPubkey, event.id)) {
                let decrypted;
                try {
                    decrypted = decryptContent(msg[2].content, secret, walletPubkey);
                } catch {
                    return; // someone else's event
                }
                try {
                    const result = JSON.parse(decrypted);
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
                        reject(new Error("NWC: invalid response JSON"));
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
        const {uri, method, params, encryption} = req.body ?? {};
        if (typeof uri !== "string" || !["make_invoice", "lookup_invoice", "get_info", "list_transactions"].includes(method)) {
            return res.status(400).json({"ok": false, "error": "Missing uri or method"});
        }
        try {
            const result = await nwcRequest(uri, method, params ?? {}, encryption);
            res.json({ok: true, result});
        } catch (e) {
            res.status(500).json({"ok": false, "error": e.message});
        }
    });
    console.log("NWC endpoint registered at POST /nwc");
}

// ─── Spark ECIES endpoint ─────────────────────────────────────────────────────

function sparkEciesEncrypt(plaintextHex, recipientPubkeyHex) {
    const plaintext = Buffer.from(plaintextHex, "hex"),
        ephPriv = randomBytes(32),
        ephPubHex = Buffer.from(secp256k1.getPublicKey(ephPriv, false)).toString("hex"); // uncompressed
    // ECDH: shared secret x coordinate
    const sharedCompressed = secp256k1.getSharedSecret(ephPriv, Buffer.from(recipientPubkeyHex, "hex")),
        sharedX = Buffer.from(sharedCompressed.slice(1, 33));
    // Reconstruct uncompressed shared point for HKDF (matches spark_preimage.php)
    // We need full uncompressed point — derive y from x
    const sharedPoint = secp256k1.ProjectivePoint
        ? secp256k1.ProjectivePoint.fromHex(Buffer.from(sharedCompressed).toString("hex")) : null;
    let sharedUncompressed;
    if (sharedPoint) {
        sharedUncompressed = Buffer.from(sharedPoint.toRawBytes(false));
    } else {
        // Fallback: use only x (some versions don't expose ProjectivePoint)
        const sharedFull = secp256k1.getSharedSecret(ephPriv, Buffer.from(recipientPubkeyHex, "hex"), false);
        sharedUncompressed = Buffer.from(sharedFull);
    }
    // HKDF key derivation (matches spark_preimage.php)
    const {hkdf} = require("@noble/hashes/hkdf.js"),
        {sha256} = require("@noble/hashes/sha2.js"),
        ikm = Buffer.concat([Buffer.from(ephPubHex, "hex"), sharedUncompressed]),
        aesKey = Buffer.from(hkdf(sha256, ikm, undefined, undefined, 32));
    // AES-256-GCM with 16-byte nonce (matches spark_preimage.php)
    const {"createCipheriv": cipher} = require("crypto"),
        nonce = randomBytes(16),
        c = cipher("aes-256-gcm", aesKey, nonce),
        ct = Buffer.concat([c.update(plaintext), c.final()]),
        tag = c.getAuthTag();
    // Output: ephPub(65) + nonce(16) + tag(16) + ct
    return Buffer.concat([Buffer.from(ephPubHex, "hex"), nonce, tag, ct]).toString("hex");
}

function registerSpark(app) {
    const express = require("express");
    app.use("/spark-ecies", express.json());
    app.post("/spark-ecies", (req, res) => {
        const { plaintext_hex, recipient_pubkey_hex } = req.body ?? {};
        if (!plaintext_hex || !recipient_pubkey_hex) {
            return res.status(400).json({"ok": false, "error": "Missing plaintext_hex or recipient_pubkey_hex" });
        }
        try {
            const ciphertext_hex = sparkEciesEncrypt(plaintext_hex, recipient_pubkey_hex);
            res.json({"ok": true, ciphertext_hex});
        } catch (e) {
            res.status(500).json({ ok: false, error: e.message });
        }
    });
    console.log("Spark ECIES endpoint registered at POST /spark-ecies");
}
module.exports = { register, registerSpark, nwcRequest };
