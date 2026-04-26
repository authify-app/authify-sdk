import { AuthifyResponse, AuthifyError } from '../types';
export interface PendingEntry {
    privateKeyHex: string;
    expiresAt: number;
}
export type ParseResult = {
    ok: true;
    response: AuthifyResponse;
} | {
    ok: false;
    error: AuthifyError;
};
/**
 * Parse and validate an incoming authify-callback deep link URL.
 * Expected format: {scheme}://authify-callback?pk={ephPubKey}&c={ciphertext}&s={sig}
 *
 * @param url  The raw deep link URL received by the caller app
 * @param pendingRequests  Map of requestId → sdkEphemeralPrivKeyHex (held by AuthifyClient)
 * @param signingKey  Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export declare function parseCallback(url: string, pendingRequests: Map<string, PendingEntry>, signingKey?: string): ParseResult;
//# sourceMappingURL=parser.d.ts.map