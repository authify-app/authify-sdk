/** Supported identity fields that can be requested via requestIdentity(). */
export type IdentityField =
  | 'full_name'
  | 'firstName'
  | 'lastName'
  | 'dob'
  | 'age_over_18'
  | 'document_number'
  | 'selfie_photo'
  | 'email'
  | 'phone'
  | 'street'
  | 'city'
  | 'state'
  | 'zipCode';

// ── Request schemas (encrypted inside the c= URL param) ──────────────────────

export interface SdkAuthRequest {
  v: 1;
  type: 'auth';
  appId: string;
  requestId: string;   // UUID v4 — correlates request to response
  nonce: string;       // 32-byte hex random — replay prevention
  ts: number;          // unix seconds
  returnScheme: string;
  userIdentifier?: string;
}

export interface SdkIdentityRequest {
  v: 1;
  type: 'identity';
  appId: string;
  requestId: string;
  nonce: string;
  ts: number;
  returnScheme: string;
  fields: IdentityField[];
}

export type SdkRequest = SdkAuthRequest | SdkIdentityRequest;

// ── Response schema (encrypted inside the c= callback param) ─────────────────

export interface SdkResponse {
  v: 1;
  type: 'response';
  requestId: string;   // must match the original request requestId
  nonce: string;
  ts: number;
  status: 'success' | 'denied' | 'error';
  data?: Record<string, unknown>;
  message?: string;
}

// ── SDK public types ──────────────────────────────────────────────────────────

export interface AuthifyResponse {
  status: 'success' | 'denied';
  data?: Record<string, unknown>;
  requestId: string;
  ts: number;
}

export interface AuthifyError {
  code:
    | 'INVALID_SIGNATURE'
    | 'DECRYPTION_FAILED'
    | 'REPLAY_DETECTED'
    | 'EXPIRED'
    | 'REQUEST_ID_MISMATCH'
    | 'CANCELLED'
    | 'TIMEOUT'
    | 'UNKNOWN';
  message: string;
}

export interface AuthifyConfig {
  appId: string;
  returnScheme: string; // URL scheme your app handles, e.g. "testauthify"
}
