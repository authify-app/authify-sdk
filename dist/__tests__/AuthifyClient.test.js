"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const AuthifyClient_1 = require("../../src/AuthifyClient");
const BACKEND_PUB = '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f';
describe('AuthifyClient with backend config', () => {
    const backendConfig = {
        url: 'http://localhost:9999',
        appId: '123e4567-e89b-12d3-a456-426614174000',
        appSecret: '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3',
    };
    let mockOpenUrl;
    let client;
    let originalFetch;
    beforeEach(() => {
        originalFetch = global.fetch;
        mockOpenUrl = jest.fn().mockResolvedValue(undefined);
        client = new AuthifyClient_1.AuthifyClient({ appId: 'com.test', returnScheme: 'test', backend: backendConfig }, mockOpenUrl);
    });
    afterEach(() => {
        global.fetch = originalFetch;
    });
    it('login() calls backendClient.initiateRequest (non-blocking)', async () => {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ publicKey: BACKEND_PUB }) })
            .mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ pk: 'a', c: 'b' }) });
        client.login();
        // openUrl called synchronously
        expect(mockOpenUrl).toHaveBeenCalled();
        // Allow fetch promises to settle
        await new Promise(r => setTimeout(r, 50));
        expect(global.fetch).toHaveBeenCalledTimes(2); // /public-key + /requests/initiate
    });
    it('login() does not throw if backend call fails', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('network'));
        const errors = [];
        client.onError(e => errors.push(e));
        client.login();
        await new Promise(r => setTimeout(r, 50));
        // openUrl still called
        expect(mockOpenUrl).toHaveBeenCalled();
    });
    it('without backend config, no fetch calls are made', async () => {
        const clientNoBe = new AuthifyClient_1.AuthifyClient({ appId: 'com.test', returnScheme: 'test' }, mockOpenUrl);
        global.fetch = jest.fn();
        clientNoBe.login();
        await new Promise(r => setTimeout(r, 10));
        expect(global.fetch).not.toHaveBeenCalled();
    });
});
//# sourceMappingURL=AuthifyClient.test.js.map