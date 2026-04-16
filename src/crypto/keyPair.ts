import { x25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export interface EphemeralKeyPair {
  privateKeyHex: string; // 32-byte hex — keep in memory, never serialized
  publicKeyHex: string;  // 32-byte hex — included in URL (pk= param)
}

/** Generate a fresh X25519 ephemeral keypair for a single request. */
export function generateEphemeralKeyPair(): EphemeralKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
  };
}

/** Derive a shared secret from our private key and the peer's public key. */
export function computeSharedSecret(ourPrivKeyHex: string, theirPubKeyHex: string): Uint8Array {
  return x25519.getSharedSecret(hexToBytes(ourPrivKeyHex), hexToBytes(theirPubKeyHex));
}
