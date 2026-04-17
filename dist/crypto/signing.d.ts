/**
 * HMAC-SHA256 sign a message string. Returns hex-encoded MAC.
 * The signed message is typically the URL path+query before the `&s=` param.
 */
export declare function sign(message: string): string;
/**
 * Constant-time verify. Returns true iff the signature is valid.
 * Uses hmac() twice and compares to avoid timing attacks.
 */
export declare function verify(message: string, sig: string): boolean;
//# sourceMappingURL=signing.d.ts.map