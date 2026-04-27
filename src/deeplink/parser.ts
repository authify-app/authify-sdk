import { verify } from '../crypto/signing';
import { decryptResponse } from '../crypto/encrypt';
import { addNonce } from '../session/nonceStore';
import { SdkResponse, AuthifyResponse, AuthifyError } from '../types';

const MAX_AGE_SECONDS = 300; // 5 minutes

export interface PendingEntry {
  privateKeyHex: string;
  expiresAt: number;
}

export type ParseResult =
  | { ok: true; response: AuthifyResponse }
  | { ok: false; error: AuthifyError };

/**
 * Parse and validate an incoming authify-callback deep link URL.
 * Expected format: {scheme}://authify-callback?pk={ephPubKey}&c={ciphertext}&s={sig}
 *
 * @param url  The raw deep link URL received by the caller app
 * @param pendingRequests  Map of requestId → sdkEphemeralPrivKeyHex (held by AuthifyClient)
 * @param signingKey  Per-app HMAC signing key (hex). Omit to use the DEV_ONLY key.
 */
export function parseCallback(
  url: string,
  pendingRequests: Map<string, PendingEntry>,
  signingKey?: string,
): ParseResult {
  try {
    if (!url.includes('authify-callback')) {
      return { ok: false, error: { code: 'UNKNOWN', message: 'Not an authify callback URL' } };
    }

    const queryStart = url.indexOf('?');
    if (queryStart === -1) {
      return { ok: false, error: { code: 'UNKNOWN', message: 'Missing query params' } };
    }

    const params = parseParams(url.slice(queryStart + 1));

    // Error callback format: ?error=...&s=... (no pk/c — sent by Authify for rate-limit etc.)
    if (params['error'] && !params['pk']) {
      const unsigned = url.slice(0, url.lastIndexOf('&s='));
      const s = params['s'] ?? '';
      if (!verify(unsigned, s, signingKey)) {
        return { ok: false, error: { code: 'INVALID_SIGNATURE', message: 'HMAC verification failed on error callback' } };
      }
      return { ok: false, error: { code: 'UNKNOWN', message: params['error'] } };
    }

    const pk = params['pk'];
    const c = params['c'];
    const s = params['s'];

    if (!pk || !c || !s) {
      return { ok: false, error: { code: 'UNKNOWN', message: 'Missing pk, c, or s param' } };
    }

    // 1. Verify HMAC signature — signs the full URL up to (not including) &s=
    if (!verify(url.slice(0, url.lastIndexOf('&s=')), s, signingKey)) {
      return { ok: false, error: { code: 'INVALID_SIGNATURE', message: 'HMAC verification failed' } };
    }

    // 2. Find a pending request to determine which ephemeral key to use for decryption.
    //    We try each pending request; the matching one will decrypt successfully.
    let decrypted: SdkResponse | null = null;
    let matchedRequestId: string | null = null;

    for (const [requestId, entry] of pendingRequests.entries()) {
      try {
        const plaintext = decryptResponse(c, pk, entry.privateKeyHex);
        const parsed = JSON.parse(plaintext) as SdkResponse;
        if (parsed.requestId === requestId) {
          decrypted = parsed;
          matchedRequestId = requestId;
          break;
        }
      } catch {
        // Decryption with this key failed — try next
      }
    }

    if (!decrypted || !matchedRequestId) {
      return { ok: false, error: { code: 'DECRYPTION_FAILED', message: 'Could not decrypt response' } };
    }

    // 3. Version check
    if (decrypted.v !== 1) {
      return { ok: false, error: { code: 'UNKNOWN', message: `Unsupported response version: ${decrypted.v}` } };
    }

    // 4. Timestamp check
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSeconds - decrypted.ts) > MAX_AGE_SECONDS) {
      return { ok: false, error: { code: 'EXPIRED', message: 'Response timestamp out of range' } };
    }

    // 5. Replay prevention
    if (!addNonce(decrypted.nonce)) {
      return { ok: false, error: { code: 'REPLAY_DETECTED', message: 'Duplicate nonce detected' } };
    }

    // 6. Remove from pending
    pendingRequests.delete(matchedRequestId);

    if (decrypted.status === 'error') {
      return {
        ok: false,
        error: { code: 'UNKNOWN', message: decrypted.message ?? 'Authify returned an error' },
      };
    }

    return {
      ok: true,
      response: {
        status: decrypted.status,
        data: decrypted.data,
        requestId: decrypted.requestId,
        ts: decrypted.ts,
      },
    };
  } catch (err) {
    return {
      ok: false,
      error: { code: 'UNKNOWN', message: err instanceof Error ? err.message : 'Unknown parse error' },
    };
  }
}

function parseParams(query: string): Record<string, string> {
  const params: Record<string, string> = {};
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    if (eq < 1) continue;
    params[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1));
  }
  return params;
}
