import { AuthifyResponse, AuthifyError } from '../types';
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
 */
export declare function parseCallback(url: string, pendingRequests: Map<string, string>): ParseResult;
//# sourceMappingURL=parser.d.ts.map