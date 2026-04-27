"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = sign;
exports.verify = verify;
const hmac_1 = require("@noble/hashes/hmac");
const sha2_1 = require("@noble/hashes/sha2");
const utils_1 = require("@noble/hashes/utils");
const devKeys_1 = require("./devKeys");
// Ephemeral key used only for constant-time HMAC comparison inside verify().
// Never exported; regenerated per process start. Prevents an attacker who
// learns the signing key from predicting comparison results.
const COMPARISON_KEY = (0, utils_1.randomBytes)(32);
/**
 * HMAC-SHA256 sign a message string. Returns hex-encoded MAC.
 * The signed message is typically the URL path+query before the `&s=` param.
 * Pass keyHex to use a per-app signing key; omit to fall back to the DEV_ONLY key.
 */
function sign(message, keyHex) {
    const key = (0, utils_1.hexToBytes)(keyHex ?? devKeys_1.DEV_SIGNING_KEY);
    const mac = (0, hmac_1.hmac)(sha2_1.sha256, key, (0, utils_1.utf8ToBytes)(message));
    return (0, utils_1.bytesToHex)(mac);
}
/**
 * Constant-time verify. Returns true iff the signature is valid.
 * Uses hmac() twice and compares to avoid timing attacks.
 * Pass keyHex to use a per-app signing key; omit to fall back to the DEV_ONLY key.
 */
function verify(message, sig, keyHex) {
    const key = (0, utils_1.hexToBytes)(keyHex ?? devKeys_1.DEV_SIGNING_KEY);
    const expected = (0, hmac_1.hmac)(sha2_1.sha256, key, (0, utils_1.utf8ToBytes)(message));
    try {
        const provided = (0, utils_1.hexToBytes)(sig);
        if (provided.length !== expected.length)
            return false;
        // Constant-time comparison via HMAC under a separate module-private key
        const expectedHmac = (0, hmac_1.hmac)(sha2_1.sha256, COMPARISON_KEY, expected);
        const providedHmac = (0, hmac_1.hmac)(sha2_1.sha256, COMPARISON_KEY, provided);
        return (0, utils_1.bytesToHex)(expectedHmac) === (0, utils_1.bytesToHex)(providedHmac);
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=signing.js.map