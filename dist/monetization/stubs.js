"use strict";
/**
 * Monetization stubs — Phase 1 no-ops.
 *
 * TODO(PHASE_2): Implement registerApp to POST to the Authify control plane:
 *   POST /v1/apps/register { appId, apiKey } → returns { planId, signingKey, authifyPublicKey }
 *   The returned authifyPublicKey replaces AUTHIFY_DEV_PUBLIC_KEY in devKeys.ts.
 *
 * TODO(PHASE_2): Implement trackEvent to POST usage events for billing metering:
 *   POST /v1/events { appId, type, payload, ts }
 *
 * TODO(PHASE_2): Implement setPlan to upgrade/downgrade the app's billing plan:
 *   POST /v1/apps/{appId}/plan { planId }
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerApp = registerApp;
exports.trackEvent = trackEvent;
exports.setPlan = setPlan;
function registerApp(_appId) {
    // TODO(PHASE_2): call control plane to register app and exchange API key for signing key
    console.log('[AuthifySDK] registerApp() — no-op in Phase 1');
}
function trackEvent(type, _payload) {
    // TODO(PHASE_2): send usage event to billing backend
    console.log(`[AuthifySDK] trackEvent(${type}) — no-op in Phase 1`);
}
function setPlan(planId) {
    // TODO(PHASE_2): call control plane to set billing plan
    console.log(`[AuthifySDK] setPlan(${planId}) — no-op in Phase 1`);
}
//# sourceMappingURL=stubs.js.map