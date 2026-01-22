import { describe, it, expect } from 'vitest';
import { deriveDeterministicEphemeralKey } from '../src/shared/deriveDeterministicEphemeralKey';
import { deriveChildViewingNode } from '../src/shared/deriveChildViewingNode';

describe('deriveDeterministicEphemeralKey', () => {
  const privateViewingKey =
    '0xe377059c0f7d594f953672d99706109ef69b9044a6d009daf6e3066e179dd42d';

  describe('impl', () => {
    it('should return a valid ephemeralPrivateKey with a low nonce', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      const { p_derived } = deriveDeterministicEphemeralKey(
        childViewingNode,
        BigInt(0)
      );

      expect(p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
    });

    it('should return the correct ephemeralPrivateKey with a nonce greater than 0x80000000', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      const { p_derived } = deriveDeterministicEphemeralKey(
        childViewingNode,
        BigInt(2147483649) // 0x80000001 - just above 0x80000000
      );

      expect(p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
    });

    it('should throw an error if the nonce is too high', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      expect(() =>
        deriveDeterministicEphemeralKey(
          childViewingNode,
          BigInt('576460752303423488')
        )
      ).toThrow('Nonce is too large. Max value is 0x7FFFFFFFFFFFFFF.');
    });

    it('should handle a variety of valid private viewing keys and nonces without crashing', () => {
      const validKeys = [
        '0x0000000000000000000000000000000000000000000000000000000000000000',
        '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        '0x1111111111111111111111111111111111111111111111111111111111111111',
      ];

      const nonces = [
        BigInt(0),
        BigInt(1),
        BigInt(100),
        BigInt(2147483648), // 0x80000000
        BigInt(2147483649), // 0x80000001
        BigInt('0x7ffffffffffffff') - BigInt(1), // Max - 1
      ];

      validKeys.forEach((key) => {
        const childViewingNode = deriveChildViewingNode(key as `0x${string}`);
        nonces.forEach((nonce) => {
          const { p_derived } = deriveDeterministicEphemeralKey(
            childViewingNode,
            nonce
          );
          expect(p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
        });
      });
    });

    it('should correctly split nonce into parentNonce and nonce when nonce exceeds MAX_NONCE', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);
      const MAX_NONCE = BigInt('0xfffffff'); // 268,435,455

      // Test nonce exactly at MAX_NONCE (should have parentNonce = 0)
      const atMax = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE
      );

      // Test nonce just above MAX_NONCE (should have parentNonce = 1, nonce = 0)
      const justAbove = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE + BigInt(1) // 268,435,456 = 0x10000000
      );

      // Test nonce that requires parentNonce = 2
      const withParentNonce2 = deriveDeterministicEphemeralKey(
        childViewingNode,
        (MAX_NONCE + BigInt(1)) * BigInt(2) // 536,870,912 = 0x20000000
      );

      // Test nonce in the middle of a chunk (parentNonce = 1, nonce = some value)
      const middleOfChunk = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE + BigInt(1) + BigInt(100) // parentNonce = 1, nonce = 100
      );

      // All should produce valid keys
      expect(atMax.p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(justAbove.p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(withParentNonce2.p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(middleOfChunk.p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);

      // They should all be different
      expect(atMax.p_derived).not.toEqual(justAbove.p_derived);
      expect(justAbove.p_derived).not.toEqual(withParentNonce2.p_derived);
      expect(justAbove.p_derived).not.toEqual(middleOfChunk.p_derived);
    });
  });
});
