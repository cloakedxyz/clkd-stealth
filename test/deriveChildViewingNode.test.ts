import { describe, it, expect } from 'vitest';
import { bytesToHex } from 'viem';
import { HDKey } from 'viem/accounts';
import { deriveChildViewingNode } from '../src/shared/deriveChildViewingNode';

/**
 * Cross referencing tests with Fluidkey's implementation:
 * https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/3bab3b158e4d9164dd96bd3d247c835328f1063c/test/extractViewingPrivateKeyNode.test.ts
 */
describe('deriveChildViewingNode', () => {
  const privateViewingKey =
    '0xe377059c0f7d594f953672d99706109ef69b9044a6d009daf6e3066e179dd42d';
  const expectedDepth = 2;
  const expectedIndex = 2147483648;
  const expectedChainCode =
    '0xf108041bd0aa1ba64ea82f94676213de3d039411179223fb4dfe1181fd430cbc';
  const expectedParentFingerprint = 105519527;
  const expectedVersions = { private: 76066276, public: 76067358 };
  const expectedPrivateKey =
    '0xff99fb02c84beb1e4937e4c3624b9a8b4011feaaf84483a4c2ca6c64e0fcfe42';
  const expectedPublicKey =
    '0x030d4fdabc988746e6b0288a1278ca792c191cc5cd1d09d671ba8927538b3424c8';

  it('should generate the correct HDKey from a given private viewing key and node', () => {
    const result = deriveChildViewingNode(privateViewingKey, 0);

    // Check that the result is an instance of HDKey
    expect(result).toBeInstanceOf(HDKey);

    // Check that the result has the correct properties
    expect(result.depth).toEqual(expectedDepth);
    expect(result.index).toEqual(expectedIndex);
    expect(bytesToHex(result.chainCode!)).toEqual(expectedChainCode);
    expect(result.parentFingerprint).toEqual(expectedParentFingerprint);
    expect(result.versions).toEqual(expectedVersions);
    expect(bytesToHex(result.privateKey!)).toEqual(expectedPrivateKey);
    expect(bytesToHex(result.publicKey!)).toEqual(expectedPublicKey);
  });

  it('should use a default node of 0 if no node is provided', () => {
    const result = deriveChildViewingNode(privateViewingKey);

    // Check that the result is an instance of HDKey
    expect(result).toBeInstanceOf(HDKey);

    // Check that the result has the correct properties (same as node 0)
    expect(result.depth).toEqual(expectedDepth);
    expect(result.index).toEqual(expectedIndex);
    expect(bytesToHex(result.chainCode!)).toEqual(expectedChainCode);
    expect(result.parentFingerprint).toEqual(expectedParentFingerprint);
    expect(result.versions).toEqual(expectedVersions);
    expect(bytesToHex(result.privateKey!)).toEqual(expectedPrivateKey);
    expect(bytesToHex(result.publicKey!)).toEqual(expectedPublicKey);
  });

  it('should produce different results for different node values', () => {
    const result0 = deriveChildViewingNode(privateViewingKey, 0);
    const result1 = deriveChildViewingNode(privateViewingKey, 1);

    // Different nodes should produce different keys
    expect(bytesToHex(result0.privateKey!)).not.toEqual(
      bytesToHex(result1.privateKey!)
    );
    expect(bytesToHex(result0.publicKey!)).not.toEqual(
      bytesToHex(result1.publicKey!)
    );
  });

  it('should throw an error if the private viewing key is not a valid hex string', () => {
    expect(() => deriveChildViewingNode('0xinvalid' as `0x${string}`)).toThrow(
      'Private viewing key is not valid.'
    );
  });

  it('should throw an error for a private viewing key that is too short', () => {
    expect(() => deriveChildViewingNode('0x1234' as `0x${string}`)).toThrow(
      'Private viewing key is not valid.'
    );
  });

  it('should work with a valid 64-character hex string', () => {
    const validKey =
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const result = deriveChildViewingNode(validKey);

    expect(result).toBeInstanceOf(HDKey);
    expect(result.depth).toBe(2);
    expect(result.privateKey).toBeDefined();
    expect(result.publicKey).toBeDefined();
  });

  it('should handle a variety of valid private viewing keys without crashing', () => {
    const validKeys = [
      '0x0000000000000000000000000000000000000000000000000000000000000000',
      '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      '0x1111111111111111111111111111111111111111111111111111111111111111',
    ];

    validKeys.forEach((key) => {
      const result = deriveChildViewingNode(key as `0x${string}`, 0);
      expect(result).toBeInstanceOf(HDKey);
      expect(result.depth).toBe(2);
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
    });
  });

  it('should throw an error for a variety of invalid private viewing keys', () => {
    const invalidKeys = [
      '0xinvalid', // non-hex characters
      '0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG', // invalid hex
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg', // invalid character at end
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde', // too short (63 chars)
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1', // too long (65 chars)
    ];

    invalidKeys.forEach((key) => {
      expect(() => deriveChildViewingNode(key as `0x${string}`)).toThrow(
        'Private viewing key is not valid.'
      );
    });
  });
});
