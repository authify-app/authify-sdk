"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateNonce = generateNonce;
exports.addNonce = addNonce;
exports.hasNonce = hasNonce;
exports.clearNonces = clearNonces;
const utils_1 = require("@noble/hashes/utils");
const NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const store = new Map();
/** Generate a fresh 32-byte random nonce as a hex string. */
function generateNonce() {
    return (0, utils_1.bytesToHex)((0, utils_1.randomBytes)(32));
}
/**
 * Record a nonce as seen. Returns false if the nonce was already present
 * (replay attack detected). Prunes expired entries on each call.
 */
function addNonce(nonce) {
    pruneExpired();
    if (store.has(nonce))
        return false;
    store.set(nonce, { ts: Date.now() });
    return true;
}
/** Check if a nonce has been seen (without recording it). */
function hasNonce(nonce) {
    pruneExpired();
    return store.has(nonce);
}
function pruneExpired() {
    const cutoff = Date.now() - NONCE_TTL_MS;
    for (const [nonce, entry] of store.entries()) {
        if (entry.ts < cutoff)
            store.delete(nonce);
    }
}
/** Clear all stored nonces (for testing only). */
function clearNonces() {
    store.clear();
}
//# sourceMappingURL=nonceStore.js.map