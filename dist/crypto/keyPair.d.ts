export interface EphemeralKeyPair {
    privateKeyHex: string;
    publicKeyHex: string;
}
/** Generate a fresh X25519 ephemeral keypair for a single request. */
export declare function generateEphemeralKeyPair(): EphemeralKeyPair;
/** Derive a shared secret from our private key and the peer's public key. */
export declare function computeSharedSecret(ourPrivKeyHex: string, theirPubKeyHex: string): Uint8Array;
//# sourceMappingURL=keyPair.d.ts.map