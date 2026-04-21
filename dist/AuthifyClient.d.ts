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
export declare class AuthifyClient {
    private readonly config;
    private readonly openUrl;
    private readonly backendClient;
    /**
     * Map of requestId → SDK ephemeral private key hex.
     * Held in memory for the lifetime of a pending request.
     * Used by parseCallback to decrypt the matched response.
     */
    private readonly pendingRequests;
    private successCallbacks;
    private errorCallbacks;
    constructor(config: AuthifyConfig, openUrl: OpenUrlFn);
    /** Initiate a login / authentication request against Authify. */
    login(opts?: {
        userIdentifier?: string;
    }): void;
    /** Initiate an identity attribute request against Authify. */
    requestIdentity(fields: IdentityField[]): void;
    /**
     * Call this from your app's deep link handler whenever a URL arrives.
     * Returns true if the URL was an authify-callback handled by this SDK;
     * returns false if the URL is unrelated (let your app handle it normally).
     */
    handleCallback(url: string): boolean;
    /**
     * Register a success handler. Returns an unsubscribe function.
     * Multiple handlers are supported.
     */
    onSuccess(cb: SuccessCallback): () => void;
    /**
     * Register an error handler. Returns an unsubscribe function.
     * Multiple handlers are supported.
     */
    onError(cb: ErrorCallback): () => void;
    /**
     * Register this app with the Authify control plane.
     * TODO(PHASE_2): pass apiKey; exchange for per-app signing credentials
     */
    registerApp(): void;
    /** Track a usage event for billing metering. No-op in Phase 1. */
    trackEvent(type: string, payload?: Record<string, unknown>): void;
    /**
     * Set the billing plan for this app.
     * TODO(PHASE_2): call control plane POST /v1/apps/{appId}/plan
     */
    setPlan(planId: string): void;
    private emitSuccess;
    private emitError;
}
export {};
//# sourceMappingURL=AuthifyClient.d.ts.map