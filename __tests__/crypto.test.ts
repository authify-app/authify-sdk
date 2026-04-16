import { generateEphemeralKeyPair, computeSharedSecret } from '../src/crypto/keyPair';
import { encryptRequest, decryptResponse, toBase64Url, fromBase64Url } from '../src/crypto/encrypt';
import { AUTHIFY_DEV_PUBLIC_KEY } from '../src/crypto/devKeys';
import { x25519 } from '@noble/curves/ed25519';
import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes, concatBytes } from '@noble/hashes/utils';

// Simulate what Authify does server-side to encrypt a response
function encryptResponseForSdk(
  plaintext: string,
  sdkEphPubKeyHex: string,
  authifyEphPrivKeyHex: string,
): { ciphertextB64: string; authifyEphPubKeyHex: string } {
  const authifyEphPubKey = x25519.getPublicKey(hexToBytes(authifyEphPrivKeyHex));
  const sharedSecret = x25519.getSharedSecret(hexToBytes(authifyEphPrivKeyHex), hexToBytes(sdkEphPubKeyHex));
  const encKey = hkdf(sha256, sharedSecret, undefined, utf8ToBytes('authify-response-v1'), 32);
  const nonce = randomBytes(12);
  const stream = gcm(encKey, nonce);
  const ciphertext = stream.encrypt(utf8ToBytes(plaintext));
  const combined = concatBytes(nonce, ciphertext);
  return {
    ciphertextB64: toBase64Url(combined),
    authifyEphPubKeyHex: bytesToHex(authifyEphPubKey),
  };
}

describe('Crypto: X25519 ECDH key generation', () => {
  it('generates a valid ephemeral keypair', () => {
    const kp = generateEphemeralKeyPair();
    expect(kp.privateKeyHex).toHaveLength(64);
    expect(kp.publicKeyHex).toHaveLength(64);
    expect(kp.privateKeyHex).not.toEqual(kp.publicKeyHex);
  });

  it('generates unique keypairs on each call', () => {
    const kp1 = generateEphemeralKeyPair();
    const kp2 = generateEphemeralKeyPair();
    expect(kp1.privateKeyHex).not.toEqual(kp2.privateKeyHex);
    expect(kp1.publicKeyHex).not.toEqual(kp2.publicKeyHex);
  });

  it('ECDH produces the same shared secret on both sides', () => {
    const sdkKP = generateEphemeralKeyPair();
    const authifyPrivHex = '0519e36c6c261cc08cfa68f2f403ed27981696e4f77478e7f90de566c6f3003f';

    const sdkShared = computeSharedSecret(sdkKP.privateKeyHex, AUTHIFY_DEV_PUBLIC_KEY);
    const authifyShared = x25519.getSharedSecret(
      hexToBytes(authifyPrivHex),
      hexToBytes(sdkKP.publicKeyHex),
    );

    expect(bytesToHex(sdkShared)).toEqual(bytesToHex(authifyShared));
  });
});

describe('Crypto: request encryption', () => {
  it('encryptRequest produces non-empty base64url ciphertext', () => {
    const sdkKP = generateEphemeralKeyPair();
    const plaintext = JSON.stringify({ v: 1, type: 'auth', requestId: 'test-123' });
    const ciphertext = encryptRequest(plaintext, sdkKP.privateKeyHex);
    expect(typeof ciphertext).toBe('string');
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(ciphertext).not.toContain(plaintext);
  });

  it('two calls with same plaintext produce different ciphertexts (random nonce)', () => {
    const sdkKP = generateEphemeralKeyPair();
    const plaintext = 'same plaintext';
    const c1 = encryptRequest(plaintext, sdkKP.privateKeyHex);
    const c2 = encryptRequest(plaintext, sdkKP.privateKeyHex);
    expect(c1).not.toEqual(c2);
  });
});

describe('Crypto: response decryption round-trip', () => {
  it('SDK can decrypt a response encrypted by Authify using ECDH', () => {
    const sdkKP = generateEphemeralKeyPair();
    const authifyEphPriv = generateEphemeralKeyPair();

    const responsePayload = JSON.stringify({
      v: 1, type: 'response', requestId: 'test-abc',
      nonce: 'aabbcc', ts: 9999, status: 'success',
      data: { firstName: 'Jane' },
    });

    // Authify encrypts response for SDK
    const { ciphertextB64, authifyEphPubKeyHex } = encryptResponseForSdk(
      responsePayload,
      sdkKP.publicKeyHex,
      authifyEphPriv.privateKeyHex,
    );

    // SDK decrypts
    const decrypted = decryptResponse(ciphertextB64, authifyEphPubKeyHex, sdkKP.privateKeyHex);
    expect(decrypted).toEqual(responsePayload);
  });

  it('decryptResponse throws on tampered ciphertext', () => {
    const sdkKP = generateEphemeralKeyPair();
    const authifyEphPriv = generateEphemeralKeyPair();
    const { ciphertextB64, authifyEphPubKeyHex } = encryptResponseForSdk(
      '{"v":1}',
      sdkKP.publicKeyHex,
      authifyEphPriv.privateKeyHex,
    );
    // Tamper: flip a byte in the middle of the ciphertext
    const bytes = Array.from(fromBase64Url(ciphertextB64));
    const mid = Math.floor(bytes.length / 2);
    bytes[mid] = (bytes[mid]! ^ 0xff);
    const tampered = toBase64Url(new Uint8Array(bytes));
    expect(() => decryptResponse(tampered, authifyEphPubKeyHex, sdkKP.privateKeyHex)).toThrow();
  });
});
