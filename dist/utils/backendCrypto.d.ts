/**
 * Encrypt a request body for the backend.
 * Returns the encrypted envelope and the SDK ephemeral private key
 * needed to decrypt the backend's response.
 */
export declare function encryptHttpRequest(body: unknown, backendPubKeyHex: string): {
    encryptedBody: {
        pk: string;
        c: string;
    };
    sdkEphPrivKeyHex: string;
};
/**
 * Decrypt a response envelope from the backend.
 * Uses the SDK ephemeral private key retained from the matching request.
 */
export declare function decryptHttpResponse(response: {
    pk: string;
    c: string;
}, sdkEphPrivKeyHex: string): unknown;
//# sourceMappingURL=backendCrypto.d.ts.map