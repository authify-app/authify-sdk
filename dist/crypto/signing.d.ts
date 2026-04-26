/**
 * HMAC-SHA256 sign a message string. Returns hex-encoded MAC.
 * The signed message is typically the URL path+query before the `&s=` param.
 * Pass keyHex to use a per-app signing key; omit to fall back to the DEV_ONLY key.
 */
export declare function sign(message: string, keyHex?: string): string;
/**
 * Constant-time verify. Returns true iff the signature is valid.
 * Uses hmac() twice and compares to avoid timing attacks.
 * Pass keyHex to use a per-app signing key; omit to fall back to the DEV_ONLY key.
 */
export declare function verify(message: string, sig: string, keyHex?: string): boolean;
//# sourceMappingURL=signing.d.ts.map