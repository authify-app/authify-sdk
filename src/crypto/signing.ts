import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { hexToBytes, bytesToHex, utf8ToBytes, randomBytes } from '@noble/hashes/utils';
import { DEV_SIGNING_KEY } from './devKeys';

// Ephemeral key used only for constant-time HMAC comparison inside verify().
// Never exported; regenerated per process start. Prevents an attacker who
// learns the signing key from predicting comparison results.
const COMPARISON_KEY = randomBytes(32);

/**
 * HMAC-SHA256 sign a message string. Returns hex-encoded MAC.
 * The signed message is typically the URL path+query before the `&s=` param.
 * Pass keyHex to use a per-app signing key; omit to fall back to the DEV_ONLY key.
 */
export function sign(message: string, keyHex?: string): string {
  const key = hexToBytes(keyHex ?? DEV_SIGNING_KEY);
  const mac = hmac(sha256, key, utf8ToBytes(message));
  return bytesToHex(mac);
}

/**
 * Constant-time verify. Returns true iff the signature is valid.
 * Uses hmac() twice and compares to avoid timing attacks.
 * Pass keyHex to use a per-app signing key; omit to fall back to the DEV_ONLY key.
 */
export function verify(message: string, sig: string, keyHex?: string): boolean {
  const key = hexToBytes(keyHex ?? DEV_SIGNING_KEY);
  const expected = hmac(sha256, key, utf8ToBytes(message));
  try {
    const provided = hexToBytes(sig);
    if (provided.length !== expected.length) return false;
    // Constant-time comparison via HMAC under a separate module-private key
    const expectedHmac = hmac(sha256, COMPARISON_KEY, expected);
    const providedHmac = hmac(sha256, COMPARISON_KEY, provided);
    return bytesToHex(expectedHmac) === bytesToHex(providedHmac);
  } catch {
    return false;
  }
}
