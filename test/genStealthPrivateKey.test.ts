import { describe, it, expect } from 'vitest';
import { genStealthPrivateKey } from '../src/client/genStealthPrivateKey';
import { privateKeyToAccount } from 'viem/accounts';

describe('genStealthPrivateKey', () => {
  it('should generate the expected stealth private key for known inputs', () => {
    const p_spend =
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const { p_stealth } = genStealthPrivateKey({ p_spend, P_derived });

    const expectedP_stealth =
      '0x4248960a98e7a00f99dd282953c0914f39747917d8446737c07b4cafc7ab2aa8';

    expect(p_stealth).toEqual(expectedP_stealth);
  });

  it('should generate different stealth keys for different P_derived', () => {
    const p_spend =
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7';
    const P_derived1 =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';
    const P_derived2 =
      '0x0417fa0d4fdbee6f6f0747a67dafbdcccd7de6281fe694e1b84a426621f3a329e94f8936f0c39aa780fb3588d2043c597ff3e4205cf54cdb83e131b7bd37a0699f';

    const { p_stealth: p_stealth1 } = genStealthPrivateKey({
      p_spend,
      P_derived: P_derived1,
    });
    const { p_stealth: p_stealth2 } = genStealthPrivateKey({
      p_spend,
      P_derived: P_derived2,
    });

    expect(p_stealth1).not.toEqual(p_stealth2);
  });

  it('should generate different stealth keys for different p_spend', () => {
    const p_spend1 =
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7';
    const p_spend2 =
      '0x16988506fc3aa66bad0f3f231aa9552a1639b7c05477e6d59f8044adb3155322';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const { p_stealth: p_stealth1 } = genStealthPrivateKey({
      p_spend: p_spend1,
      P_derived,
    });
    const { p_stealth: p_stealth2 } = genStealthPrivateKey({
      p_spend: p_spend2,
      P_derived,
    });

    expect(p_stealth1).not.toEqual(p_stealth2);
  });

  it('should generate consistent stealth keys for the same inputs', () => {
    const p_spend =
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const result1 = genStealthPrivateKey({ p_spend, P_derived });
    const result2 = genStealthPrivateKey({ p_spend, P_derived });

    expect(result1).toEqual(result2);
  });

  it('should return a private key with correct length (66 hex chars)', () => {
    const p_spend =
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const { p_stealth } = genStealthPrivateKey({ p_spend, P_derived });

    expect(p_stealth.length).toBe(66); // 0x + 32 bytes = 66 chars
    expect(p_stealth).toMatch(/^0x[0-9a-f]{64}$/i);
  });

  it('should return a valid private key that can be used to derive a public key', () => {
    const p_spend =
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const { p_stealth } = genStealthPrivateKey({ p_spend, P_derived });

    // Verify the stealth private key can be used to create an account
    const account = privateKeyToAccount(p_stealth);
    expect(account.address).toBeDefined();
    expect(account.address).toMatch(/^0x[0-9a-f]{40}$/i);
  });

  it('should handle edge case with minimum private key', () => {
    const p_spend =
      '0x0000000000000000000000000000000000000000000000000000000000000001';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const { p_stealth } = genStealthPrivateKey({ p_spend, P_derived });

    expect(p_stealth).toMatch(/^0x[0-9a-f]{64}$/i);
    expect(p_stealth.length).toBe(66);
  });

  it('should handle edge case with maximum private key (just below curve order)', () => {
    // Maximum valid private key is CURVE.n - 1
    const p_spend =
      '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const { p_stealth } = genStealthPrivateKey({ p_spend, P_derived });

    expect(p_stealth).toMatch(/^0x[0-9a-f]{64}$/i);
    expect(p_stealth.length).toBe(66);
  });

  it('should return a properly padded private key', () => {
    // Use a small but valid 32-byte private key (padded with zeros)
    const p_spend =
      '0x0000000000000000000000000000000000000000000000000000000000000001';
    const P_derived =
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8';

    const { p_stealth } = genStealthPrivateKey({ p_spend, P_derived });

    // Should be padded to 64 hex characters (32 bytes)
    expect(p_stealth.length).toBe(66);
    expect(p_stealth).toMatch(/^0x[0-9a-f]{64}$/i);
  });
});
