export { AuthifyClient } from './AuthifyClient';
export type {
  AuthifyConfig,
  BackendConfig,
  AuthifyResponse,
  AuthifyError,
  IdentityField,
  SdkAuthRequest,
  SdkIdentityRequest,
  SdkRequest,
  SdkResponse,
} from './types';

// Crypto utilities needed by the Authify host app (re-exported for reuse)
export { generateEphemeralKeyPair, computeSharedSecret } from './crypto/keyPair';
export { toBase64Url, fromBase64Url } from './crypto/encrypt';
export { sign, verify } from './crypto/signing';
export { generateNonce, addNonce, hasNonce } from './session/nonceStore';

// Deep link helpers (for testing/advanced use)
export { buildAuthUrl, buildShareUrl } from './deeplink/builder';
export { parseCallback } from './deeplink/parser';
export type { PendingEntry } from './deeplink/parser';
