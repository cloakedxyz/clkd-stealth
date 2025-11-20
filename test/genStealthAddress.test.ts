import { describe, it, expect } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { isAddress } from 'viem';

import {
  genStealthAddress,
  genStealthAddresses,
} from '../src/shared/genStealthAddress';

/**
 * Test cases adapted from Fluidkey's implementation:
 * https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/main/test/generateStealthAddresses.test.ts
 */
describe('genStealthAddress', () => {
  it('should generate the correct stealth addresses', () => {
    const spendingPublicKeys = [
      privateKeyToAccount(
        '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7'
      ).publicKey,
      privateKeyToAccount(
        '0xef01af02e46bea24d45e909d3c219cbc5122e1cafd13f914deea1237ea0b01a6'
      ).publicKey,
    ];

    const p_derived =
      '0x4f80725f967e22f2597e363f977bb563de45c5e22e9c3594ebc0de8bdccf8945';

    const result = spendingPublicKeys.map((publicKey) =>
      genStealthAddress(publicKey, p_derived)
    );

    expect(isAddress(result[0])).toBe(true);
    expect(isAddress(result[1])).toBe(true);

    // Checksummed addresses
    expect(result).toEqual([
      '0xf4126489Ac2F0df6441d0B72EFcC760EF0C19706',
      '0x566953Fb7A022F8C7f6421464Ab700590F2b3464',
    ]);
  });

  it('should handle a variety of valid private keys without crashing', () => {
    const privateKeys: `0x${string}`[] = [
      '0x0000000000000000000000000000000000000000000000000000000000000001',
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      '0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
      '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      '0x1111111111111111111111111111111111111111111111111111111111111111',
    ];

    const derivedKeys: `0x${string}`[] = [
      '0x2222222222222222222222222222222222222222222222222222222222222222',
      '0x3333333333333333333333333333333333333333333333333333333333333333',
      '0x4444444444444444444444444444444444444444444444444444444444444444',
    ];

    privateKeys.forEach((privateKey) => {
      const { publicKey: spendingPublicKey } = privateKeyToAccount(privateKey);

      derivedKeys.forEach((derivedKey) => {
        const stealthAddress = genStealthAddress(spendingPublicKey, derivedKey);

        expect(stealthAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
        expect(stealthAddress).toHaveLength(42);

        expect(isAddress(stealthAddress)).toBe(true);
      });
    });
  });

  it('should throw when P_spend is not valid', () => {
    const invalidPublicKey = 'not-a-hex-value' as `0x${string}`;
    const validDerived =
      '0x4f80725f967e22f2597e363f977bb563de45c5e22e9c3594ebc0de8bdccf8945';

    expect(() => genStealthAddress(invalidPublicKey, validDerived)).toThrow(
      'P_spend is not valid.'
    );
  });

  it('should throw when p_derived is not valid', () => {
    const validPublicKey = privateKeyToAccount(
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7'
    ).publicKey;

    const invalidDerived = '0xnothexvalue' as `0x${string}`;

    expect(() => genStealthAddress(validPublicKey, invalidDerived)).toThrow(
      'p_derived is not valid.'
    );
  });
});

describe('genStealthAddresses', () => {
  it('should generate the correct stealth addresses', () => {
    const spendingPublicKeys = [
      privateKeyToAccount(
        '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7'
      ).publicKey,
      privateKeyToAccount(
        '0xef01af02e46bea24d45e909d3c219cbc5122e1cafd13f914deea1237ea0b01a6'
      ).publicKey,
    ];
    const p_derived =
      '0x4f80725f967e22f2597e363f977bb563de45c5e22e9c3594ebc0de8bdccf8945';

    const result = genStealthAddresses({
      P_spendSet: spendingPublicKeys,
      p_derived,
    });

    expect(result.stealthAddresses).toHaveLength(2);
    expect(result.stealthAddresses).toEqual([
      '0xf4126489Ac2F0df6441d0B72EFcC760EF0C19706',
      '0x566953Fb7A022F8C7f6421464Ab700590F2b3464',
    ]);
  });
});
