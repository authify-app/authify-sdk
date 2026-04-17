import { EphemeralKeyPair } from '../crypto/keyPair';
import { IdentityField } from '../types';
export interface BuiltRequest {
    url: string;
    requestId: string;
    keyPair: EphemeralKeyPair;
}
/**
 * Build a signed, encrypted authify://auth/v1 deep link.
 * URL format: authify://auth/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 * where sig = HMAC-SHA256("/auth/v1?pk=...&c=...")
 */
export declare function buildAuthUrl(appId: string, returnScheme: string, userIdentifier?: string): BuiltRequest;
/**
 * Build a signed, encrypted authify://share/v1 deep link.
 * URL format: authify://share/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 */
export declare function buildShareUrl(appId: string, returnScheme: string, fields: IdentityField[]): BuiltRequest;
//# sourceMappingURL=builder.d.ts.map