# @authify/sdk

**The official SDK for integrating [Authify](https://authify.app) identity verification into your React Native app.**

Authify is a privacy-first mobile identity wallet. Users enroll once by scanning a government-issued ID and completing face verification. Your app can then request authentication or specific identity attributes — the user sees a consent screen on their phone and approves exactly what to share. No data ever leaves the user's device or passes through a server.

---

## Status

> **Early Access — Phase 1**
>
> The Authify app is not yet publicly available. To request access to the Authify app for testing and integration, contact **hello@authify.app**.

---

## How it works

```
Your App                              Authify (on user's phone)
─────────────────────────────────────────────────────────────────
sdk.login({ userIdentifier })
  → encrypted deep link ──────────────▶  shows consent screen
                                          user authenticates
                                          user approves
  ◀── encrypted callback ──────────────  dispatches response

sdk.onSuccess(response => {
  // response.data contains approved fields
})
```

All payloads are **end-to-end encrypted** (X25519 ECDH + AES-256-GCM) and **signed** (HMAC-SHA256). Nothing is readable in transit. Authify never sends data to a server — the callback goes directly from the Authify app to your app via deep link.

---

## Installation

```bash
npm install @authify/sdk
# or
yarn add @authify/sdk
```

### Peer requirements

- React Native ≥ 0.70
- iOS 15+ / Android API 26+

### iOS — register your callback URL scheme

In `ios/<YourApp>/Info.plist`, add your scheme to `CFBundleURLTypes`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>yourapp</string>
    </array>
  </dict>
</array>
```

### Android — register your callback URL scheme

In `android/app/src/main/AndroidManifest.xml`, add an intent filter to your main activity:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="yourapp" />
</intent-filter>
```

---

## Quick Start

### 1. Create the SDK client (once, at app startup)

```typescript
// sdk.ts
import { Linking } from 'react-native';
import { AuthifyClient } from '@authify/sdk';

export const authify = new AuthifyClient(
  {
    appId: 'com.yourcompany.yourapp',
    returnScheme: 'yourapp',       // must match your registered URL scheme
  },
  Linking.openURL.bind(Linking),   // injected so the SDK has no RN dependency
);
```

### 2. Register callbacks (in your root component)

```typescript
import { authify } from './sdk';

useEffect(() => {
  const unsubSuccess = authify.onSuccess(response => {
    console.log('Status:', response.status);   // 'success' | 'denied'
    console.log('Data:', response.data);        // approved identity fields
  });

  const unsubError = authify.onError(error => {
    console.error(`[${error.code}] ${error.message}`);
  });

  // Route incoming deep links through the SDK
  const listener = Linking.addEventListener('url', ({ url }) => {
    authify.handleCallback(url);
  });

  // Handle cold-start deep links
  Linking.getInitialURL().then(url => {
    if (url) authify.handleCallback(url);
  });

  return () => {
    unsubSuccess();
    unsubError();
    listener.remove();
  };
}, []);
```

### 3. Make requests

```typescript
// Authentication — verify the user is who they say they are
authify.login({ userIdentifier: 'user@example.com' });

// Identity attributes — request specific fields
authify.requestIdentity(['firstName', 'lastName', 'dob']);

// Age verification only
authify.requestIdentity(['age_over_18']);

// Multiple fields — user can toggle each one individually
authify.requestIdentity(['firstName', 'lastName', 'email', 'phone', 'dob']);
```

---

## API Reference

### `new AuthifyClient(config, openUrl)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `config.appId` | `string` | Your app's bundle identifier (e.g. `com.yourcompany.yourapp`) |
| `config.returnScheme` | `string` | Your registered deep link scheme (e.g. `yourapp`) |
| `openUrl` | `(url: string) => Promise<void>` | URL opener — pass `Linking.openURL.bind(Linking)` |

---

### `client.login(opts?)`

Requests authentication. Authify verifies the user's enrolled identity matches the provided identifier.

```typescript
authify.login({ userIdentifier: 'user@example.com' });
authify.login({ userIdentifier: '+14155552671' });
authify.login(); // no identifier — Authify prompts user to confirm their identity
```

---

### `client.requestIdentity(fields)`

Requests specific identity attributes. The user sees per-field consent toggles and can approve or deny each field individually.

```typescript
authify.requestIdentity(fields: IdentityField[])
```

**Available fields:**

| Field | Type | Description |
|-------|------|-------------|
| `firstName` | `string` | First name from enrolled ID |
| `lastName` | `string` | Last name from enrolled ID |
| `email` | `string` | Email address |
| `phone` | `string` | Phone number |
| `dob` | `string` | Date of birth (ISO 8601) |
| `age_over_18` | `boolean` | `true` / `false` — DOB is never exposed |
| `document_number` | `string` | Government ID document number |
| `selfie_photo` | `string` | Enrollment selfie (base64 JPEG) |

---

### `client.handleCallback(url)`

Call this from your deep link handler. Returns `true` if the URL was an Authify callback (handled); `false` if unrelated.

```typescript
const handled = authify.handleCallback(url);
if (!handled) {
  // your own deep link routing
}
```

---

### `client.onSuccess(callback)` / `client.onError(callback)`

Register response handlers. Both return an unsubscribe function.

```typescript
const unsub = authify.onSuccess((response: AuthifyResponse) => {
  // response.status   — 'success' | 'denied'
  // response.data     — Record<string, unknown> — approved fields
  // response.requestId — correlates to the originating request
  // response.ts       — Unix timestamp
});

const unsubErr = authify.onError((error: AuthifyError) => {
  // error.code     — 'INVALID_SIGNATURE' | 'DECRYPTION_FAILED' | 'EXPIRED' | 'REPLAY_DETECTED' | 'UNKNOWN'
  // error.message  — human-readable description
});

// Clean up
unsub();
unsubErr();
```

---

## Security

### Encryption

Every request and response is end-to-end encrypted using a fresh ephemeral keypair:

```
Request:  ECDH(sdkEphPriv, authifyPub) → HKDF-SHA256("authify-request-v1")  → AES-256-GCM
Response: ECDH(authifyEphPriv, sdkPub) → HKDF-SHA256("authify-response-v1") → AES-256-GCM
```

Every URL is HMAC-SHA256 signed. Tampered or replayed URLs are rejected.

### Replay prevention

Each payload includes a 32-byte random nonce and a Unix timestamp. Authify rejects:
- Requests older than 5 minutes
- Any nonce seen more than once

### Phase 1 limitation — shared dev keys

Phase 1 uses a **shared hardcoded keypair** for development and testing. This means:
- All apps in Phase 1 share the same encryption keys
- The keys provide tamper detection and confidentiality in transit
- They do **not** provide per-app isolation or billing enforcement

**Phase 2** will introduce per-app keypairs fetched from the Authify control plane via `SDK.initialize(apiKey)`. Contact **hello@authify.app** to get on the Phase 2 waitlist.

### No server, no tracking

The SDK has zero network requests. All data flows directly between your app and the user's Authify app via encrypted deep links. Authify never sees your users' data.

---

## Full Integration Example

```typescript
import React, { useEffect, useState } from 'react';
import { View, Text, Button, Linking } from 'react-native';
import { AuthifyClient, AuthifyResponse } from '@authify/sdk';

const authify = new AuthifyClient(
  { appId: 'com.example.myapp', returnScheme: 'myapp' },
  Linking.openURL.bind(Linking),
);

export default function App() {
  const [result, setResult] = useState<AuthifyResponse | null>(null);

  useEffect(() => {
    const unsubOk  = authify.onSuccess(r => setResult(r));
    const unsubErr = authify.onError(e => console.error(e));
    const listener = Linking.addEventListener('url', ({ url }) => authify.handleCallback(url));
    Linking.getInitialURL().then(url => { if (url) authify.handleCallback(url); });

    return () => { unsubOk(); unsubErr(); listener.remove(); };
  }, []);

  return (
    <View>
      <Button title="Verify Age (18+)"    onPress={() => authify.requestIdentity(['age_over_18'])} />
      <Button title="Get Name + Email"    onPress={() => authify.requestIdentity(['firstName', 'lastName', 'email'])} />
      <Button title="Authenticate User"   onPress={() => authify.login({ userIdentifier: 'user@example.com' })} />
      {result && <Text>{JSON.stringify(result.data, null, 2)}</Text>}
    </View>
  );
}
```

---

## Releases

Pre-built SDK packages are available on the [Releases](https://github.com/authify-app/authify-sdk/releases) page.

Each release includes:
- `authify-sdk-{version}.tgz` — installable npm tarball (`npm install ./authify-sdk-{version}.tgz`)
- TypeScript type declarations (`.d.ts`)
- Compiled CommonJS + ESM bundles

---

## Requirements

| Requirement | Version |
|-------------|---------|
| React Native | ≥ 0.70 |
| iOS | 15+ |
| Android API | 26+ |
| TypeScript | ≥ 5.0 (optional but recommended) |
| Node.js (build) | ≥ 18 |

---

## Early Access

**The Authify app is currently in private early access.**

To request access for your app:

📧 **hello@authify.app**

Include:
- Your app name and bundle ID
- Platform (iOS / Android / both)
- Estimated user count
- Your use case (age verification, authentication, identity attributes, etc.)

We'll get back to you within 48 hours.

---

## License

MIT © 2026 Authify

---

*Built with privacy first. No servers. No tracking. User consent always required.*
