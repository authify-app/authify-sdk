"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackendClient = void 0;
const backendCrypto_1 = require("./backendCrypto");
const hmac_1 = require("@noble/hashes/hmac");
const sha2_1 = require("@noble/hashes/sha2");
const utils_1 = require("@noble/hashes/utils");
function sha256Hex(str) {
    return (0, utils_1.bytesToHex)((0, sha2_1.sha256)((0, utils_1.utf8ToBytes)(str)));
}
function hmacSign(data, secret) {
    // Matches backend's createHmac('sha256', secret) — secret is UTF-8 encoded key
    return (0, utils_1.bytesToHex)((0, hmac_1.hmac)(sha2_1.sha256, (0, utils_1.utf8ToBytes)(secret), (0, utils_1.utf8ToBytes)(data)));
}
class BackendClient {
    constructor(config) {
        this.backendPubKey = null;
        this.config = config;
    }
    async getBackendPublicKey() {
        if (this.backendPubKey)
            return this.backendPubKey;
        const res = await fetch(`${this.config.url}/public-key`);
        if (!res.ok)
            throw new Error(`Failed to fetch public key: ${res.status}`);
        const body = await res.json();
        this.backendPubKey = body.publicKey;
        return this.backendPubKey;
    }
    async postEncrypted(path, body, timeoutMs = 30000) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const backendPubKey = await this.getBackendPublicKey();
            const { encryptedBody } = (0, backendCrypto_1.encryptHttpRequest)(body, backendPubKey);
            const encryptedBodyStr = JSON.stringify(encryptedBody);
            const timestamp = Date.now().toString();
            const bodyHash = sha256Hex(encryptedBodyStr);
            const signature = hmacSign(`${this.config.appId}:${timestamp}:${bodyHash}`, this.config.appSecret);
            const res = await fetch(`${this.config.url}${path}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Authify-App-Id': this.config.appId,
                    'X-Authify-Timestamp': timestamp,
                    'X-Authify-Signature': signature,
                },
                body: encryptedBodyStr,
                signal: controller.signal,
            });
            if (!res.ok) {
                console.warn(`[authify-sdk] ${path} failed: ${res.status}`);
            }
        }
        catch (err) {
            console.warn(`[authify-sdk] ${path} error: ${String(err)}`);
        }
        finally {
            clearTimeout(timer);
        }
    }
    async initiateRequest(requestId, requestedFields) {
        await this.postEncrypted('/requests/initiate', {
            request_id: requestId,
            requested_fields: requestedFields,
        });
    }
    async completeRequest(requestId, status) {
        await this.postEncrypted('/requests/complete', {
            request_id: requestId,
            status,
        });
    }
}
exports.BackendClient = BackendClient;
//# sourceMappingURL=backendClient.js.map