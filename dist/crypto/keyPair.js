"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateEphemeralKeyPair = generateEphemeralKeyPair;
exports.computeSharedSecret = computeSharedSecret;
const ed25519_1 = require("@noble/curves/ed25519");
const utils_1 = require("@noble/hashes/utils");
/** Generate a fresh X25519 ephemeral keypair for a single request. */
function generateEphemeralKeyPair() {
    const privateKey = ed25519_1.x25519.utils.randomPrivateKey();
    const publicKey = ed25519_1.x25519.getPublicKey(privateKey);
    return {
        privateKeyHex: (0, utils_1.bytesToHex)(privateKey),
        publicKeyHex: (0, utils_1.bytesToHex)(publicKey),
    };
}
/** Derive a shared secret from our private key and the peer's public key. */
function computeSharedSecret(ourPrivKeyHex, theirPubKeyHex) {
    return ed25519_1.x25519.getSharedSecret((0, utils_1.hexToBytes)(ourPrivKeyHex), (0, utils_1.hexToBytes)(theirPubKeyHex));
}
//# sourceMappingURL=keyPair.js.map