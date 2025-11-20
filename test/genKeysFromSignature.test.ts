import { describe, it, expect } from 'vitest';
import { genKeysFromSignature } from '../src/client/genKeysFromSignature';

describe('genKeysFromSignature', () => {
  it('should generate key pairs from a valid signature', () => {
    // Test case from https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/3bab3b158e4d9164dd96bd3d247c835328f1063c/test/generateKeysFromSignature.test.ts
    const signature =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';
    const { p_view, P_view, p_spend, P_spend } =
      genKeysFromSignature(signature);

    expect(p_spend).toEqual(
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7'
    );
    expect(p_view).toEqual(
      '0x16988506fc3aa66bad0f3f231aa9552a1639b7c05477e6d59f8044adb3155322'
    );
    expect(P_spend).toEqual(
      '0x0417fa0d4fdbee6f6f0747a67dafbdcccd7de6281fe694e1b84a426621f3a329e94f8936f0c39aa780fb3588d2043c597ff3e4205cf54cdb83e131b7bd37a0699f'
    );
    expect(P_view).toEqual(
      '0x042581ca15a8f6e1678bcc50fa0259568e3f9c1324c272ea0b960e5ef1b5c6f4de36ba7b1de7658377f934b55fe3672c1808a3f52c43d8ddde61da8d7a4dab95f8'
    );
  });

  it('should throw an error for a signature that does not have the correct length', () => {
    const signature = ('0x' + 'a'.repeat(128)) as `0x${string}`;
    expect(() => genKeysFromSignature(signature)).toThrow(
      'Signature is not valid.'
    );
  });

  it('should throw an error for a signature missing 0x', () => {
    const signature = 'a'.repeat(132) as `0x${string}`;
    expect(() => genKeysFromSignature(signature)).toThrow(
      'Signature is not valid.'
    );
  });

  it('should throw an error for a signature that is too short', () => {
    const signature = ('0x' + 'a'.repeat(120)) as `0x${string}`;
    expect(() => genKeysFromSignature(signature)).toThrow(
      'Signature is not valid.'
    );
  });

  it('should throw an error for a signature that is too long', () => {
    const signature = ('0x' + 'a'.repeat(140)) as `0x${string}`;
    expect(() => genKeysFromSignature(signature)).toThrow(
      'Signature is not valid.'
    );
  });

  it('should throw an error for an empty signature', () => {
    const signature = '0x' as `0x${string}`;
    expect(() => genKeysFromSignature(signature)).toThrow(
      'Signature is not valid.'
    );
  });

  it('should generate different private keys for different signatures', () => {
    const signature1 =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';
    const signature2 =
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';

    const {
      p_view: p_view1,
      P_view: P_view1,
      p_spend: p_spend1,
      P_spend: P_spend1,
    } = genKeysFromSignature(signature1);
    const {
      p_view: p_view2,
      P_view: P_view2,
      p_spend: p_spend2,
      P_spend: P_spend2,
    } = genKeysFromSignature(signature2);

    expect(p_view1).not.toEqual(p_view2);
    expect(p_spend1).not.toEqual(p_spend2);
    expect(P_view1).not.toEqual(P_view2);
    expect(P_spend1).not.toEqual(P_spend2);
  });

  it('should generate different p_view and p_spend from the same signature', () => {
    const signature =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';
    const { p_view, P_view, p_spend, P_spend } =
      genKeysFromSignature(signature);

    expect(p_view).not.toEqual(p_spend);
    expect(P_view).not.toEqual(P_spend);
  });

  it('should return public keys in uncompressed format (starting with 0x04)', () => {
    const signature =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';
    const { p_view, P_view, p_spend, P_spend } =
      genKeysFromSignature(signature);

    expect(P_view.startsWith('0x04')).toBe(true);
    expect(P_spend.startsWith('0x04')).toBe(true);
  });

  it('should return public keys with correct length (132 chars total for uncompressed)', () => {
    const signature =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';
    const { p_view, P_view, p_spend, P_spend } =
      genKeysFromSignature(signature);

    // Uncompressed public key: 0x (2) + 04 prefix (2) + 32 bytes x (64) + 32 bytes y (64) = 132 chars total
    expect(P_view.length).toBe(132);
    expect(P_spend.length).toBe(132);
  });

  it('should return private keys with correct length (66 hex chars)', () => {
    const signature =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';
    const { p_view, P_view, p_spend, P_spend } =
      genKeysFromSignature(signature);

    // Private key: 0x + 32 bytes = 66 chars
    expect(p_view.length).toBe(66);
    expect(p_spend.length).toBe(66);
  });

  it('should return keys in the correct object structure', () => {
    const signature =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';
    const result = genKeysFromSignature(signature);

    expect(typeof result).toBe('object');
    expect(result).toHaveProperty('p_view');
    expect(result).toHaveProperty('P_view');
    expect(result).toHaveProperty('p_spend');
    expect(result).toHaveProperty('P_spend');
  });

  it('should generate consistent keys for the same signature', () => {
    const signature =
      '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c21b';

    const result1 = genKeysFromSignature(signature);
    const result2 = genKeysFromSignature(signature);

    expect(result1).toEqual(result2);
  });
});
