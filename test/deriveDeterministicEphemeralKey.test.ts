import { describe, it, expect } from 'vitest';
import { deriveDeterministicEphemeralKey } from '../src/shared/deriveDeterministicEphemeralKey';
import { deriveChildViewingNode } from '../src/shared/deriveChildViewingNode';

/**
 * Cross referencing tests with Fluidkey's implementation:
 * https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/main/test/generateEphemeralPrivateKey.test.ts
 */
describe('deriveDeterministicEphemeralKey', () => {
  const privateViewingKey =
    '0xe377059c0f7d594f953672d99706109ef69b9044a6d009daf6e3066e179dd42d';

  describe('fluidKeyImpl (default)', () => {
    it('should return the correct ephemeralPrivateKey with a low nonce', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      const { p_derived } = deriveDeterministicEphemeralKey(
        childViewingNode,
        BigInt(0),
        10
      );

      expect(p_derived).toEqual(
        '0xe0b00bde074552abedf968bdbfbcaab4d7a2c85a2251ef7cd6c29df9d9cf13b7'
      );
    });

    it('should return the correct ephemeralPrivateKey with a nonce greater than 0x80000000', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      const { p_derived } = deriveDeterministicEphemeralKey(
        childViewingNode,
        BigInt(2147483649), // 0x80000001 - just above 0x80000000
        10
      );

      expect(p_derived).toEqual(
        '0x51bbb418b9c5743db6ea0419002b7da4bf3e0232adde05fc2d23334b388a726e'
      );
    });

    it('should return the correct ephemeralPrivateKey with a coinType as parameter', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      const { p_derived } = deriveDeterministicEphemeralKey(
        childViewingNode,
        BigInt(0),
        undefined,
        2147483658
      );

      expect(p_derived).toEqual(
        '0xe0b00bde074552abedf968bdbfbcaab4d7a2c85a2251ef7cd6c29df9d9cf13b7'
      );
    });

    it('should throw an error if the nonce is too high', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      expect(() =>
        deriveDeterministicEphemeralKey(
          childViewingNode,
          BigInt('576460752303423488'),
          10
        )
      ).toThrow('Nonce is too large. Max value is 0x7FFFFFFFFFFFFFF.');
    });

    it('should throw an error if no coinType or chainId is provided', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      expect(() =>
        deriveDeterministicEphemeralKey(childViewingNode, BigInt(0))
      ).toThrow('coinType or chainId must be defined.');
    });

    it('should correctly split nonce into parentNonce and nonce when nonce exceeds MAX_NONCE', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);
      const MAX_NONCE = BigInt('0xfffffff'); // 268,435,455

      // Test nonce exactly at MAX_NONCE (should have parentNonce = 0)
      const atMax = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE,
        10
      );

      // Test nonce just above MAX_NONCE (should have parentNonce = 1, nonce = 0)
      const justAbove = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE + BigInt(1), // 268,435,456 = 0x10000000
        10
      );

      // Test nonce that requires parentNonce = 2
      const withParentNonce2 = deriveDeterministicEphemeralKey(
        childViewingNode,
        (MAX_NONCE + BigInt(1)) * BigInt(2), // 536,870,912 = 0x20000000
        10
      );

      // Test nonce in the middle of a chunk (parentNonce = 1, nonce = some value)
      const middleOfChunk = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE + BigInt(1) + BigInt(100), // parentNonce = 1, nonce = 100
        10
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
            nonce,
            10
          );
          expect(p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
        });
      });
    });
  });

  describe('cloakedImpl', () => {
    it('should return a valid ephemeralPrivateKey with a low nonce', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      const { p_derived } = deriveDeterministicEphemeralKey(
        childViewingNode,
        BigInt(0),
        undefined,
        undefined,
        true // useCloakedImpl
      );

      expect(p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(p_derived).not.toEqual(
        '0xe0b00bde074552abedf968bdbfbcaab4d7a2c85a2251ef7cd6c29df9d9cf13b7' // Different from fluidkey
      );
    });

    it('should return the correct ephemeralPrivateKey with a nonce greater than 0x80000000', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      const { p_derived } = deriveDeterministicEphemeralKey(
        childViewingNode,
        BigInt(2147483649), // 0x80000001 - just above 0x80000000
        undefined,
        undefined,
        true // useCloakedImpl
      );

      expect(p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(p_derived).not.toEqual(
        '0x51bbb418b9c5743db6ea0419002b7da4bf3e0232adde05fc2d23334b388a726e' // Different from fluidkey
      );
    });

    it('should throw an error if the nonce is too high', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);

      expect(() =>
        deriveDeterministicEphemeralKey(
          childViewingNode,
          BigInt('576460752303423488'),
          undefined,
          undefined,
          true // useCloakedImpl
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
            nonce,
            undefined,
            undefined,
            true // useCloakedImpl
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
        MAX_NONCE,
        undefined,
        undefined,
        true // useCloakedImpl
      );

      // Test nonce just above MAX_NONCE (should have parentNonce = 1, nonce = 0)
      const justAbove = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE + BigInt(1), // 268,435,456 = 0x10000000
        undefined,
        undefined,
        true // useCloakedImpl
      );

      // Test nonce that requires parentNonce = 2
      const withParentNonce2 = deriveDeterministicEphemeralKey(
        childViewingNode,
        (MAX_NONCE + BigInt(1)) * BigInt(2), // 536,870,912 = 0x20000000
        undefined,
        undefined,
        true // useCloakedImpl
      );

      // Test nonce in the middle of a chunk (parentNonce = 1, nonce = some value)
      const middleOfChunk = deriveDeterministicEphemeralKey(
        childViewingNode,
        MAX_NONCE + BigInt(1) + BigInt(100), // parentNonce = 1, nonce = 100
        undefined,
        undefined,
        true // useCloakedImpl
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

    it('should produce different keys than fluidKeyImpl for the same inputs', () => {
      const childViewingNode = deriveChildViewingNode(privateViewingKey);
      const nonce = BigInt(0);

      const fluidKeyResult = deriveDeterministicEphemeralKey(
        childViewingNode,
        nonce,
        10,
        undefined,
        false // fluidKeyImpl
      );

      const cloakedResult = deriveDeterministicEphemeralKey(
        childViewingNode,
        nonce,
        undefined,
        undefined,
        true // cloakedImpl
      );

      expect(cloakedResult.p_derived).not.toEqual(fluidKeyResult.p_derived);
      expect(cloakedResult.p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(fluidKeyResult.p_derived).toMatch(/^0x[0-9a-fA-F]{64}$/);
    });
  });
});
