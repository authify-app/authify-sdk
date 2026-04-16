import { generateEphemeralKeyPair, EphemeralKeyPair } from '../crypto/keyPair';
import { encryptRequest, toBase64Url } from '../crypto/encrypt';
import { sign } from '../crypto/signing';
import { generateNonce } from '../session/nonceStore';
import { SdkAuthRequest, SdkIdentityRequest, IdentityField } from '../types';

function generateRequestId(): string {
  // UUID v4 via random bytes (crypto.getRandomValues available in RN)
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
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
 */
export function buildAuthUrl(appId: string, returnScheme: string, userIdentifier?: string): BuiltRequest {
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

  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex);
  const unsigned = `authify://auth/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned);

  return {
    url: `${unsigned}&s=${sig}`,
    requestId,
    keyPair,
  };
}

/**
 * Build a signed, encrypted authify://share/v1 deep link.
 * URL format: authify://share/v1?pk={ephPubKey}&c={ciphertext}&s={sig}
 */
export function buildShareUrl(appId: string, returnScheme: string, fields: IdentityField[]): BuiltRequest {
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

  const ciphertext = encryptRequest(JSON.stringify(request), keyPair.privateKeyHex);
  const unsigned = `authify://share/v1?pk=${keyPair.publicKeyHex}&c=${ciphertext}`;
  const sig = sign(unsigned);

  return {
    url: `${unsigned}&s=${sig}`,
    requestId,
    keyPair,
  };
}
