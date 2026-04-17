"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildAuthUrl = buildAuthUrl;
exports.buildShareUrl = buildShareUrl;
const keyPair_1 = require("../crypto/keyPair");
const encrypt_1 = require("../crypto/encrypt");
const signing_1 = require("../crypto/signing");
const nonceStore_1 = require("../session/nonceStore");
function generateRequestId() {
    // UUID v4 via random bytes (crypto.getRandomValues available in RN)
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = (Math.random() * 16) | 0;
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}
/**
 * Build a signed, encrypted authify://auth/v1 deep link.
 * URL format: authify://auth/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 * where sig = HMAC-SHA256("/auth/v1?pk=...&c=...")
 */
function buildAuthUrl(appId, returnScheme, userIdentifier) {
    const keyPair = (0, keyPair_1.generateEphemeralKeyPair)();
    const requestId = generateRequestId();
    const request = {
        v: 1,
        type: 'auth',
        appId,
        requestId,
        nonce: (0, nonceStore_1.generateNonce)(),
        ts: Math.floor(Date.now() / 1000),
        returnScheme,
        ...(userIdentifier ? { userIdentifier } : {}),
    };
    const ciphertext = (0, encrypt_1.encryptRequest)(JSON.stringify(request), keyPair.privateKeyHex);
    const unsigned = `authify://auth/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
    const sig = (0, signing_1.sign)(unsigned);
    return {
        url: `${unsigned}&s=${sig}`,
        requestId,
        keyPair,
    };
}
/**
 * Build a signed, encrypted authify://share/v1 deep link.
 * URL format: authify://share/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 */
function buildShareUrl(appId, returnScheme, fields) {
    const keyPair = (0, keyPair_1.generateEphemeralKeyPair)();
    const requestId = generateRequestId();
    const request = {
        v: 1,
        type: 'identity',
        appId,
        requestId,
        nonce: (0, nonceStore_1.generateNonce)(),
        ts: Math.floor(Date.now() / 1000),
        returnScheme,
        fields,
    };
    const ciphertext = (0, encrypt_1.encryptRequest)(JSON.stringify(request), keyPair.privateKeyHex);
    const unsigned = `authify://share/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
    const sig = (0, signing_1.sign)(unsigned);
    return {
        url: `${unsigned}&s=${sig}`,
        requestId,
        keyPair,
    };
}
//# sourceMappingURL=builder.js.map