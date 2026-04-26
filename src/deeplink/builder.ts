import { generateEphemeralKeyPair, EphemeralKeyPair } from '../crypto/keyPair';
import { encryptRequest, toBase64Url } from '../crypto/encrypt';
import { sign } from '../crypto/signing';
import { generateNonce } from '../session/nonceStore';
import { SdkAuthRequest, SdkIdentityRequest, IdentityField } from '../types';

function generateRequestId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6]! & 0x0f) | 0x40; // version 4
  b[8] = (b[8]! & 0x3f) | 0x80; // variant
  const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export interface BuiltRequest {
  url: string;
  requestId: string;
  keyPair: EphemeralKeyPair; // store privately; needed to decrypt the response
}

/**
 * Build a signed, encrypted authify://auth/v1 deep link.
 * URL format: authify://auth/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 * where sig = HMAC-SHA256("/auth/v1?pk=...&c=...")
 *
 * @param authifyPublicKey  Per-app Authify public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export function buildAuthUrl(
  appId: string,
  returnScheme: string,
  userIdentifier?: string,
  authifyPublicKey?: string,
  signingKey?: string,
): BuiltRequest {
  const keyPair = generateEphemeralKeyPair();
  const requestId = generateRequestId();

  const request: SdkAuthRequest = {
    v: 1,
    type: 'auth',
    appId,
    requestId,
    nonce: generateNonce(),
    ts: Math.floor(Date.now() / 1000),
    returnScheme,
    ...(userIdentifier ? { userIdentifier } : {}),
  };

  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex, authifyPublicKey);
  const unsigned = `authify://auth/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned, signingKey);

  return {
    url: `${unsigned}&s=${sig}`,
    requestId,
    keyPair,
  };
}

/**
 * Build a signed, encrypted authify://share/v1 deep link.
 * URL format: authify://share/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 *
 * @param authifyPublicKey  Per-app Authify public key (hex). Omit to use the DEV_ONLY key.
 * @param signingKey        Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export function buildShareUrl(
  appId: string,
  returnScheme: string,
  fields: IdentityField[],
  authifyPublicKey?: string,
  signingKey?: string,
): BuiltRequest {
  const keyPair = generateEphemeralKeyPair();
  const requestId = generateRequestId();

  const request: SdkIdentityRequest = {
    v: 1,
    type: 'identity',
    appId,
    requestId,
    nonce: generateNonce(),
    ts: Math.floor(Date.now() / 1000),
    returnScheme,
    fields,
  };

  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex, authifyPublicKey);
  const unsigned = `authify://share/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned, signingKey);

  return {
    url: `${unsigned}&s=${sig}`,
    requestId,
    keyPair,
  };
}
