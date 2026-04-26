import { buildAuthUrl, buildShareUrl } from './deeplink/builder';
import { parseCallback, PendingEntry } from './deeplink/parser';
import { registerApp, trackEvent, setPlan } from './monetization/stubs';
import { BackendClient } from './utils/backendClient';
import { AuthifyConfig, AuthifyResponse, AuthifyError, IdentityField } from './types';

type SuccessCallback = (response: AuthifyResponse) => void;
type ErrorCallback = (error: AuthifyError) => void;

/** Function that opens a URL. Defaults to React Native's Linking.openURL but injectable for testing. */
export type OpenUrlFn = (url: string) => Promise<void>;

/**
 * AuthifyClient — main entry point for the Authify SDK.
 *
 * Usage:
 *   import { Linking } from 'react-native';
 *   const sdk = new AuthifyClient({ appId: 'com.myapp', returnScheme: 'myapp' }, Linking.openURL.bind(Linking));
 *   sdk.onSuccess(r => console.log(r.data));
 *   sdk.onError(e => console.error(e.code));
 *   sdk.login({ userIdentifier: 'user@example.com' });
 *
 *   // In your app's deep link handler:
 *   sdk.handleCallback(url);
 */
export class AuthifyClient {
  private readonly config: AuthifyConfig;
  private readonly openUrl: OpenUrlFn;
  private readonly backendClient: BackendClient | null;

  private static readonly PENDING_TTL_MS = 5 * 60 * 1000;

  /**
   * Map of requestId → PendingEntry (ephemeral private key + expiry).
   * Held in memory for the lifetime of a pending request.
   * Used by parseCallback to decrypt the matched response.
   * Entries older than PENDING_TTL_MS are pruned on the next login/handleCallback call.
   */
  private readonly pendingRequests = new Map<string, PendingEntry>();

  private successCallbacks: SuccessCallback[] = [];
  private errorCallbacks: ErrorCallback[] = [];

  constructor(config: AuthifyConfig, openUrl: OpenUrlFn) {
    this.config = config;
    this.openUrl = openUrl;
    this.backendClient = config.backend ? new BackendClient(config.backend) : null;
    // TODO(PHASE_2): call registerApp() here after exchanging apiKey for signing credentials
    registerApp(config.appId);
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /** Initiate a login / authentication request against Authify. */
  login(opts: { userIdentifier?: string } = {}): void {
    const built = buildAuthUrl(this.config.appId, this.config.returnScheme, opts.userIdentifier);
    this.prunePendingRequests();
    this.pendingRequests.set(built.requestId, {
      privateKeyHex: built.keyPair.privateKeyHex,
      expiresAt: Date.now() + AuthifyClient.PENDING_TTL_MS,
    });
    trackEvent('auth_request', { appId: this.config.appId });

    if (this.backendClient) {
      void this.backendClient.initiateRequest(built.requestId, []).catch((err: unknown) => {
        this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
      });
    }

    void this.openUrl(built.url).catch((err: unknown) => {
      this.pendingRequests.delete(built.requestId);
      this.emitError({ code: 'UNKNOWN', message: `Failed to open Authify: ${String(err)}` });
    });
  }

  /** Initiate an identity attribute request against Authify. */
  requestIdentity(fields: IdentityField[]): void {
    const built = buildShareUrl(this.config.appId, this.config.returnScheme, fields);
    this.prunePendingRequests();
    this.pendingRequests.set(built.requestId, {
      privateKeyHex: built.keyPair.privateKeyHex,
      expiresAt: Date.now() + AuthifyClient.PENDING_TTL_MS,
    });
    trackEvent('identity_request', { appId: this.config.appId, fields });

    if (this.backendClient) {
      void this.backendClient.initiateRequest(built.requestId, fields).catch((err: unknown) => {
        this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
      });
    }

    void this.openUrl(built.url).catch((err: unknown) => {
      this.pendingRequests.delete(built.requestId);
      this.emitError({ code: 'UNKNOWN', message: `Failed to open Authify: ${String(err)}` });
    });
  }

  /**
   * Call this from your app's deep link handler whenever a URL arrives.
   * Returns true if the URL was an authify-callback handled by this SDK;
   * returns false if the URL is unrelated (let your app handle it normally).
   */
  handleCallback(url: string): boolean {
    if (!url.includes('authify-callback')) return false;
    this.prunePendingRequests();
    const result = parseCallback(url, this.pendingRequests);
    if (result.ok) {
      trackEvent('callback_success', { appId: this.config.appId, requestId: result.response.requestId });
      if (this.backendClient) {
        void this.backendClient.completeRequest(result.response.requestId, 'completed');
      }
      this.emitSuccess(result.response);
    } else {
      trackEvent('callback_error', { appId: this.config.appId, code: result.error.code });
      const requestId = (result as { requestId?: string }).requestId ?? '';
      if (this.backendClient && requestId) {
        void this.backendClient.completeRequest(requestId, 'failed');
      }
      this.emitError(result.error);
    }
    return true;
  }

  /**
   * Register a success handler. Returns an unsubscribe function.
   * Multiple handlers are supported.
   */
  onSuccess(cb: SuccessCallback): () => void {
    this.successCallbacks.push(cb);
    return () => {
      this.successCallbacks = this.successCallbacks.filter(fn => fn !== cb);
    };
  }

  /**
   * Register an error handler. Returns an unsubscribe function.
   * Multiple handlers are supported.
   */
  onError(cb: ErrorCallback): () => void {
    this.errorCallbacks.push(cb);
    return () => {
      this.errorCallbacks = this.errorCallbacks.filter(fn => fn !== cb);
    };
  }

  // ── Monetization stubs ──────────────────────────────────────────────────────

  /**
   * Register this app with the Authify control plane.
   * TODO(PHASE_2): pass apiKey; exchange for per-app signing credentials
   */
  registerApp(): void {
    registerApp(this.config.appId);
  }

  /** Track a usage event for billing metering. No-op in Phase 1. */
  trackEvent(type: string, payload?: Record<string, unknown>): void {
    trackEvent(type, payload);
  }

  /**
   * Set the billing plan for this app.
   * TODO(PHASE_2): call control plane POST /v1/apps/{appId}/plan
   */
  setPlan(planId: string): void {
    setPlan(planId);
  }

  // ── Private ─────────────────────────────────────────────────────────────────

  private prunePendingRequests(): void {
    const now = Date.now();
    for (const [id, entry] of this.pendingRequests) {
      if (now > entry.expiresAt) this.pendingRequests.delete(id);
    }
  }

  private emitSuccess(response: AuthifyResponse): void {
    for (const cb of this.successCallbacks) cb(response);
  }

  private emitError(error: AuthifyError): void {
    for (const cb of this.errorCallbacks) cb(error);
  }
}
