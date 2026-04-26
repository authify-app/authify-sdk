import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { DEV_SIGNING_KEY } from './devKeys';

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
    // Constant-time comparison via HMAC of both values
    const expectedHmac = hmac(sha256, key, expected);
    const providedHmac = hmac(sha256, key, provided);
    return bytesToHex(expectedHmac) === bytesToHex(providedHmac);
  } catch {
    return false;
  }
}
