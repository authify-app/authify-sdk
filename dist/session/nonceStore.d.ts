/** Generate a fresh 32-byte random nonce as a hex string. */
export declare function generateNonce(): string;
/**
 * Record a nonce as seen. Returns false if the nonce was already present
 * (replay attack detected). Prunes expired entries on each call.
 */
export declare function addNonce(nonce: string): boolean;
/** Check if a nonce has been seen (without recording it). */
export declare function hasNonce(nonce: string): boolean;
/** Clear all stored nonces (for testing only). */
export declare function clearNonces(): void;
//# sourceMappingURL=nonceStore.d.ts.map