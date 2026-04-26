import { AuthifyClient } from '../../src/AuthifyClient';
import { AuthifyError } from '../../src/types';

const BACKEND_PUB = '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f';

describe('AuthifyClient with backend config', () => {
  const backendConfig = {
    url: 'http://localhost:9999',
    appId: '123e4567-e89b-12d3-a456-426614174000',
    appSecret: '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3',
  };

  let mockOpenUrl: jest.Mock;
  let client: AuthifyClient;
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    mockOpenUrl = jest.fn().mockResolvedValue(undefined);
    client = new AuthifyClient(
      { appId: 'com.test', returnScheme: 'test', backend: backendConfig },
      mockOpenUrl,
    );
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('login() calls backendClient.initiateRequest (non-blocking)', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ publicKey: BACKEND_PUB }) })
      .mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ pk: 'a', c: 'b' }) }) as unknown as typeof fetch;

    client.login();

    // openUrl called synchronously
    expect(mockOpenUrl).toHaveBeenCalled();

    // Allow fetch promises to settle
    await new Promise(r => setTimeout(r, 50));
    expect(global.fetch).toHaveBeenCalledTimes(2); // /public-key + /requests/initiate
  });

  it('login() does not throw if backend call fails', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network')) as unknown as typeof fetch;
    const errors: AuthifyError[] = [];
    client.onError(e => errors.push(e));

    client.login();
    await new Promise(r => setTimeout(r, 50));

    // openUrl still called
    expect(mockOpenUrl).toHaveBeenCalled();
  });

  it('without backend config, no fetch calls are made', async () => {
    const clientNoBe = new AuthifyClient(
      { appId: 'com.test', returnScheme: 'test' },
      mockOpenUrl,
    );
    global.fetch = jest.fn() as unknown as typeof fetch;
    clientNoBe.login();
    await new Promise(r => setTimeout(r, 10));
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('pendingRequests TTL', () => {
  let mockOpenUrl: jest.Mock;
  let client: AuthifyClient;

  beforeEach(() => {
    mockOpenUrl = jest.fn().mockResolvedValue(undefined);
    client = new AuthifyClient(
      { appId: 'com.test', returnScheme: 'test' },
      mockOpenUrl,
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('entries within TTL survive pruning', () => {
    client.login();
    const map = (client as unknown as { pendingRequests: Map<string, unknown> }).pendingRequests;
    expect(map.size).toBe(1);
    // Second login triggers prune — fresh entry survives
    client.login();
    expect(map.size).toBe(2);
  });

  it('entries older than 5 minutes are pruned on next login()', () => {
    const realNow = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(realNow - 6 * 60 * 1000);
    client.login();
    jest.spyOn(Date, 'now').mockReturnValue(realNow);

    const map = (client as unknown as { pendingRequests: Map<string, unknown> }).pendingRequests;
    expect(map.size).toBe(1);
    client.login(); // triggers prune
    expect(map.size).toBe(1); // stale pruned, new one added
  });

  it('stale entries are pruned on handleCallback()', () => {
    const realNow = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(realNow - 6 * 60 * 1000);
    client.login();
    jest.spyOn(Date, 'now').mockReturnValue(realNow);

    const map = (client as unknown as { pendingRequests: Map<string, unknown> }).pendingRequests;
    expect(map.size).toBe(1);
    client.handleCallback('myapp://authify-callback?pk=x&c=y&s=z');
    expect(map.size).toBe(0); // pruned by handleCallback
  });
});

describe('AuthifyClient.initialize()', () => {
  const backendConfig = {
    url: 'http://localhost:9999',
    appId: '123e4567-e89b-12d3-a456-426614174000',
    appSecret: '77076d0a7318a57d3c16c17251b26645df2f294e7c7a1f3e89bba6f3a33ad7c3',
  };
  let mockOpenUrl: jest.Mock;
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    mockOpenUrl = jest.fn().mockResolvedValue(undefined);
  });

  afterEach(() => { global.fetch = originalFetch; });

  it('fetches and stores authifyPublicKey and signingKey', async () => {
    const client = new AuthifyClient(
      { appId: 'com.test', returnScheme: 'test', backend: backendConfig },
      mockOpenUrl,
    );

    global.fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        authifyPublicKey: '026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f',
        signingKey: '1d69f40e6c2e302fd0bd091800df4171343717582f13d1a265bbc4230be7829a',
      }),
    }) as unknown as typeof fetch;

    await client.initialize();

    const priv = client as unknown as { authifyPublicKey: string | null; signingKey: string | null };
    expect(priv.authifyPublicKey).toBe('026b8a39bc37c4e0c49c4cadd8194db65d6089be5ed9866b370714b48b92561f');
    expect(priv.signingKey).toBe('1d69f40e6c2e302fd0bd091800df4171343717582f13d1a265bbc4230be7829a');
    expect(() => client.login()).not.toThrow();
  });

  it('resolves silently in dev mode without backend config', async () => {
    const client = new AuthifyClient(
      { appId: 'com.test', returnScheme: 'test' },
      mockOpenUrl,
    );
    await expect(client.initialize()).resolves.toBeUndefined();
  });

  it('throws in production without backend config', async () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    const client = new AuthifyClient(
      { appId: 'com.test', returnScheme: 'test' },
      mockOpenUrl,
    );
    await expect(client.initialize()).rejects.toThrow('requires backend config');
    process.env.NODE_ENV = orig;
  });
});
