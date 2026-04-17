You are a principal mobile and security engineer working on the @authify/sdk npm package.

This is a standalone TypeScript package that provides a typed client for the Authify deep-link protocol. It has no react-native dependency — the openUrl function is injected by the caller.

## Purpose

Third-party apps install this SDK to:
1. Build encrypted, signed deep-link requests to Authify
2. Decrypt and verify encrypted callback responses from Authify

## Package Info

Name: `@authify/sdk`
Version: `0.1.0`
Location: `auth/authify-sdk/` (monorepo; referenced by TestAuthify as `file:../authify-sdk`)

## Crypto Stack

Library versions: `@noble/curves` v1.8.x, `@noble/ciphers` v0.6.0, `@noble/hashes` (matching)
Note: Authify app uses `@noble/curves` v2.x and `@noble/ciphers` v2.x — different major versions but the crypto output is compatible.

Request encryption (SDK → Authify):
- Ephemeral X25519 keypair generated per request
- `sharedSecret = ECDH(sdkEphPriv, AUTHIFY_DEV_PUBLIC_KEY)`
- `encKey = HKDF-SHA256(sharedSecret, salt="authify-request-v1", length=32)`
- `ciphertext = AES-256-GCM(encKey, 12-byte-nonce, JSON(request))`
- URL carries `pk={sdkEphPubKeyHex}` so Authify can perform ECDH on its side

Response decryption (Authify → SDK):
- Authify sends `pk={authifyEphPubKeyHex}` in callback
- `sharedSecret = ECDH(sdkEphPriv, authifyEphPub)` — same secret as Authify used
- `encKey = HKDF-SHA256(sharedSecret, salt="authify-response-v1", length=32)`
- SDK decrypts using its stored sdkEphPrivKey for the matching requestId

Signing: HMAC-SHA256 over full URL before `&s=`. Double-HMAC for constant-time verify.

Replay prevention: 32-byte hex nonce + Unix ts; `|now - ts| > 300s` → reject; duplicate nonce within 5 min → reject.

## Source Structure

```
src/
  index.ts              ← public exports
  AuthifyClient.ts      ← stateful client; Map<requestId, sdkEphPrivKeyHex>
  types.ts              ← SdkAuthRequest, SdkIdentityRequest, SdkResponse, AuthifyResponse
  crypto/
    devKeys.ts          ← DEV_ONLY: AUTHIFY_DEV_PUBLIC_KEY + DEV_SIGNING_KEY
    keyPair.ts          ← generateEphemeralKeyPair()
    encrypt.ts          ← encryptRequest(), decryptResponse(), toBase64Url()
    signing.ts          ← sign(), verify() (double-HMAC)
  deeplink/
    builder.ts          ← buildAuthUrl(), buildShareUrl() → BuiltRequest
    parser.ts           ← parseCallback(url, pendingRequests) → ParseResult
  session/
    nonceStore.ts       ← 5-min TTL nonce set
  monetization/
    stubs.ts            ← registerApp(), trackEvent(), setPlan() — no-ops, TODO(PHASE_2)
```

## AuthifyClient API

```typescript
const sdk = new AuthifyClient(
  { appId: 'com.myapp', returnScheme: 'myapp' },
  Linking.openURL.bind(Linking),   // or any (url: string) => Promise<void>
);

sdk.onSuccess(response => { /* response.status, response.data, response.requestId */ });
sdk.onError(error => { /* error.code, error.message */ });

sdk.login({ userIdentifier: 'user@example.com' });              // → authify://auth/v1?...
sdk.requestIdentity(['firstName', 'lastName', 'dob']);          // → authify://share/v1?...

// In your deep link handler:
const handled = sdk.handleCallback(url);   // returns true if URL was an authify-callback
```

## DEV_ONLY Keys — MUST Replace in Phase 2

`src/crypto/devKeys.ts` contains hardcoded keys shared with Authify:
- `AUTHIFY_DEV_PUBLIC_KEY` — matches `AUTHIFY_DEV_PRIVATE_KEY` in authify app
- `DEV_SIGNING_KEY` — same on both sides

These are labeled `// DEV_ONLY` with `// TODO(PHASE_2)` comments. Phase 2 migration:
`SDK.initialize(apiKey)` fetches per-app keypair from control plane at runtime.

## Testing

26 unit tests in `__tests__/`. Pure Node.js — no RN mocks needed.
```
npm test
npx tsc --noEmit
```

## Known Limitations

- `pendingRequests` Map is in-memory — lost on app cold start. A request sent before the app backgrounded and killed will not be decryptable after restart.
- DEV_ONLY keypair provides no defense against an attacker who reads the SDK bundle.
