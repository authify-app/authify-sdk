import { randomBytes, bytesToHex } from '@noble/hashes/utils';

const NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface NonceEntry {
  ts: number; // unix milliseconds when nonce was recorded
}

const store = new Map<string, NonceEntry>();

/** Generate a fresh 32-byte random nonce as a hex string. */
export function generateNonce(): string {
  return bytesToHex(randomBytes(32));
}

/**
 * Record a nonce as seen. Returns false if the nonce was already present
 * (replay attack detected). Prunes expired entries on each call.
 */
export function addNonce(nonce: string): boolean {
  pruneExpired();
  if (store.has(nonce)) return false;
  store.set(nonce, { ts: Date.now() });
  return true;
}

/** Check if a nonce has been seen (without recording it). */
export function hasNonce(nonce: string): boolean {
  pruneExpired();
  return store.has(nonce);
}

function pruneExpired(): void {
  const cutoff = Date.now() - NONCE_TTL_MS;
  for (const [nonce, entry] of store.entries()) {
    if (entry.ts < cutoff) store.delete(nonce);
  }
}

/** Clear all stored nonces (for testing only). */
export function clearNonces(): void {
  store.clear();
}
