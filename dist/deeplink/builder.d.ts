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
 *
 * @param authifyPublicKey  Per-app Authify public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export declare function buildAuthUrl(appId: string, returnScheme: string, userIdentifier?: string, authifyPublicKey?: string, signingKey?: string): BuiltRequest;
/**
 * Build a signed, encrypted authify://share/v1 deep link.
 * URL format: authify://share/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 *
 * @param authifyPublicKey  Per-app Authify public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export declare function buildShareUrl(appId: string, returnScheme: string, fields: IdentityField[], authifyPublicKey?: string, signingKey?: string): BuiltRequest;
//# sourceMappingURL=builder.d.ts.map