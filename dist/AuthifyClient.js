"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthifyClient = void 0;
const builder_1 = require("./deeplink/builder");
const parser_1 = require("./deeplink/parser");
const stubs_1 = require("./monetization/stubs");
const backendClient_1 = require("./utils/backendClient");
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
class AuthifyClient {
    constructor(config, openUrl) {
        /**
         * Map of requestId → SDK ephemeral private key hex.
         * Held in memory for the lifetime of a pending request.
         * Used by parseCallback to decrypt the matched response.
         */
        this.pendingRequests = new Map();
        this.successCallbacks = [];
        this.errorCallbacks = [];
        this.config = config;
        this.openUrl = openUrl;
        this.backendClient = config.backend ? new backendClient_1.BackendClient(config.backend) : null;
        // TODO(PHASE_2): call registerApp() here after exchanging apiKey for signing credentials
        (0, stubs_1.registerApp)(config.appId);
    }
    // ── Public API ──────────────────────────────────────────────────────────────
    /** Initiate a login / authentication request against Authify. */
    login(opts = {}) {
        const built = (0, builder_1.buildAuthUrl)(this.config.appId, this.config.returnScheme, opts.userIdentifier);
        this.pendingRequests.set(built.requestId, built.keyPair.privateKeyHex);
        (0, stubs_1.trackEvent)('auth_request', { appId: this.config.appId });
        if (this.backendClient) {
            void this.backendClient.initiateRequest(built.requestId, []).catch((err) => {
                this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
            });
        }
        void this.openUrl(built.url).catch((err) => {
            this.pendingRequests.delete(built.requestId);
            this.emitError({ code: 'UNKNOWN', message: `Failed to open Authify: ${String(err)}` });
        });
    }
    /** Initiate an identity attribute request against Authify. */
    requestIdentity(fields) {
        const built = (0, builder_1.buildShareUrl)(this.config.appId, this.config.returnScheme, fields);
        this.pendingRequests.set(built.requestId, built.keyPair.privateKeyHex);
        (0, stubs_1.trackEvent)('identity_request', { appId: this.config.appId, fields });
        if (this.backendClient) {
            void this.backendClient.initiateRequest(built.requestId, fields).catch((err) => {
                this.emitError({ code: 'UNKNOWN', message: `Backend initiate failed: ${String(err)}` });
            });
        }
        void this.openUrl(built.url).catch((err) => {
            this.pendingRequests.delete(built.requestId);
            this.emitError({ code: 'UNKNOWN', message: `Failed to open Authify: ${String(err)}` });
        });
    }
    /**
     * Call this from your app's deep link handler whenever a URL arrives.
     * Returns true if the URL was an authify-callback handled by this SDK;
     * returns false if the URL is unrelated (let your app handle it normally).
     */
    handleCallback(url) {
        if (!url.includes('authify-callback'))
            return false;
        const result = (0, parser_1.parseCallback)(url, this.pendingRequests);
        if (result.ok) {
            (0, stubs_1.trackEvent)('callback_success', { appId: this.config.appId, requestId: result.response.requestId });
            if (this.backendClient) {
                void this.backendClient.completeRequest(result.response.requestId, 'completed');
            }
            this.emitSuccess(result.response);
        }
        else {
            (0, stubs_1.trackEvent)('callback_error', { appId: this.config.appId, code: result.error.code });
            const requestId = result.requestId ?? '';
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
    onSuccess(cb) {
        this.successCallbacks.push(cb);
        return () => {
            this.successCallbacks = this.successCallbacks.filter(fn => fn !== cb);
        };
    }
    /**
     * Register an error handler. Returns an unsubscribe function.
     * Multiple handlers are supported.
     */
    onError(cb) {
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
    registerApp() {
        (0, stubs_1.registerApp)(this.config.appId);
    }
    /** Track a usage event for billing metering. No-op in Phase 1. */
    trackEvent(type, payload) {
        (0, stubs_1.trackEvent)(type, payload);
    }
    /**
     * Set the billing plan for this app.
     * TODO(PHASE_2): call control plane POST /v1/apps/{appId}/plan
     */
    setPlan(planId) {
        (0, stubs_1.setPlan)(planId);
    }
    // ── Private ─────────────────────────────────────────────────────────────────
    emitSuccess(response) {
        for (const cb of this.successCallbacks)
            cb(response);
    }
    emitError(error) {
        for (const cb of this.errorCallbacks)
            cb(error);
    }
}
exports.AuthifyClient = AuthifyClient;
//# sourceMappingURL=AuthifyClient.js.map