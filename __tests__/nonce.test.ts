import { generateNonce, addNonce, hasNonce, clearNonces } from '../src/session/nonceStore';

beforeEach(() => clearNonces());

describe('NonceStore', () => {
  it('generates unique nonces', () => {
    const n1 = generateNonce();
    const n2 = generateNonce();
    expect(n1).toHaveLength(64);
    expect(n1).not.toEqual(n2);
  });

  it('addNonce returns true for a fresh nonce', () => {
    const nonce = generateNonce();
    expect(addNonce(nonce)).toBe(true);
  });

  it('addNonce returns false for a duplicate nonce (replay detected)', () => {
    const nonce = generateNonce();
    expect(addNonce(nonce)).toBe(true);
    expect(addNonce(nonce)).toBe(false);
  });

  it('hasNonce returns true after adding', () => {
    const nonce = generateNonce();
    addNonce(nonce);
    expect(hasNonce(nonce)).toBe(true);
  });

  it('hasNonce returns false for unseen nonce', () => {
    expect(hasNonce('000000')).toBe(false);
  });

  it('clearNonces removes all stored nonces', () => {
    const nonce = generateNonce();
    addNonce(nonce);
    clearNonces();
    expect(hasNonce(nonce)).toBe(false);
    // Fresh add after clear succeeds
    expect(addNonce(nonce)).toBe(true);
  });
});
