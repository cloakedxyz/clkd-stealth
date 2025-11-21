import { describe, it, expect } from 'vitest';
import { privateKeyToAccount, HDKey } from 'viem/accounts';
import { bytesToHex } from 'viem';
import { deriveServerBoundKeys } from '../src/client/deriveServerBoundKeys';
import { genCloakedMessage } from '../src/client/genCloakedMessage';
import { genKeysFromSignature } from '../src/client/genKeysFromSignature';
import { deriveChildViewingNode } from '../src/shared/deriveChildViewingNode';

describe('deriveServerBoundKeys', () => {
  const userPrivateKey =
    '0x8575420a19052cf9bbe9ef4ac755a9abaaefa3f1f2e35d14c04f38829182e9ba';
  const userPin = '1234';
  const account = privateKeyToAccount(userPrivateKey);
  const userAddress = account.address;

  it('should return the correct structure with P_view, P_spend, and child_p_view', async () => {
    const result = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });

    expect(result).toHaveProperty('P_view');
    expect(result).toHaveProperty('P_spend');
    expect(result).toHaveProperty('child_p_view');
    expect(typeof result.P_view).toBe('string');
    expect(typeof result.P_spend).toBe('string');
    expect(result.child_p_view).toBeInstanceOf(HDKey);
  });

  it('should generate consistent results for the same inputs', async () => {
    const result1 = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });
    const result2 = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });

    expect(result1.P_view).toEqual(result2.P_view);
    expect(result1.P_spend).toEqual(result2.P_spend);
    expect(bytesToHex(result1.child_p_view.privateKey!)).toEqual(
      bytesToHex(result2.child_p_view.privateKey!)
    );
  });

  it('should generate different results for different pins', async () => {
    const result1 = await deriveServerBoundKeys({
      account,
      pin: '1234',
    });
    const result2 = await deriveServerBoundKeys({
      account,
      pin: '5678',
    });

    expect(result1.P_view).not.toEqual(result2.P_view);
    expect(result1.P_spend).not.toEqual(result2.P_spend);
    expect(bytesToHex(result1.child_p_view.privateKey!)).not.toEqual(
      bytesToHex(result2.child_p_view.privateKey!)
    );
  });

  it('should generate different results for different accounts', async () => {
    const account2 = privateKeyToAccount(
      '0x16988506fc3aa66bad0f3f231aa9552a1639b7c05477e6d59f8044adb3155322'
    );

    const result1 = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });
    const result2 = await deriveServerBoundKeys({
      account: account2,
      pin: userPin,
    });

    expect(result1.P_view).not.toEqual(result2.P_view);
    expect(result1.P_spend).not.toEqual(result2.P_spend);
    expect(bytesToHex(result1.child_p_view.privateKey!)).not.toEqual(
      bytesToHex(result2.child_p_view.privateKey!)
    );
  });

  it('should return public keys in uncompressed format (starting with 0x04)', async () => {
    const result = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });

    expect(result.P_view.startsWith('0x04')).toBe(true);
    expect(result.P_spend.startsWith('0x04')).toBe(true);
  });

  it('should return public keys with correct length (132 chars total for uncompressed)', async () => {
    const result = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });

    // Uncompressed public key: 0x (2) + 04 prefix (2) + 32 bytes x (64) + 32 bytes y (64) = 132 chars total
    expect(result.P_view.length).toBe(132);
    expect(result.P_spend.length).toBe(132);
  });

  it('should return a valid HDKey for child_p_view', async () => {
    const result = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });

    expect(result.child_p_view).toBeInstanceOf(HDKey);
    expect(result.child_p_view.privateKey).toBeDefined();
    expect(result.child_p_view.publicKey).toBeDefined();
    expect(result.child_p_view.depth).toBe(2);
    expect(result.child_p_view.index).toBe(2147483648); // 0' (hardened)
  });

  it('should match the expected flow: genCloakedMessage -> sign -> genKeysFromSignature -> deriveChildViewingNode', async () => {
    // Step 1: Generate the cloaked message
    const { message } = genCloakedMessage({
      pin: userPin,
      address: userAddress,
    });

    // Step 2: Sign the message
    const signature = await account.signMessage({
      message: message,
    });

    // Step 3: Generate keys from signature
    const { p_view, P_view, P_spend } = genKeysFromSignature(signature);

    // Step 4: Derive child viewing node
    const child_p_view = deriveChildViewingNode(p_view, 0);

    // Step 5: Call deriveServerBoundKeys and compare
    const result = await deriveServerBoundKeys({
      account,
      pin: userPin,
      viewingPrivateKeyNodeNumber: 0,
    });

    expect(result.P_view).toEqual(P_view);
    expect(result.P_spend).toEqual(P_spend);
    expect(bytesToHex(result.child_p_view.privateKey!)).toEqual(
      bytesToHex(child_p_view.privateKey!)
    );
  });

  it('should work with various valid PINs', async () => {
    const validPins = ['0000', '1234', '5678', '9999'];

    for (const pin of validPins) {
      const result = await deriveServerBoundKeys({
        account,
        pin,
      });

      expect(result.P_view).toBeDefined();
      expect(result.P_spend).toBeDefined();
      expect(result.child_p_view).toBeInstanceOf(HDKey);
      expect(result.P_view.startsWith('0x04')).toBe(true);
      expect(result.P_spend.startsWith('0x04')).toBe(true);
    }
  });

  it('should work with various viewingPrivateKeyNodeNumbers', async () => {
    const nodeNumbers = [0, 1, 5, 10, 42, 100];

    for (const nodeNumber of nodeNumbers) {
      const result = await deriveServerBoundKeys({
        account,
        pin: userPin,
        viewingPrivateKeyNodeNumber: nodeNumber,
      });

      expect(result.P_view).toBeDefined();
      expect(result.P_spend).toBeDefined();
      expect(result.child_p_view).toBeInstanceOf(HDKey);
      expect(result.child_p_view.depth).toBe(2);
    }
  });

  it('should throw an error for an invalid PIN (too short)', async () => {
    await expect(
      deriveServerBoundKeys({
        account,
        pin: '123',
      })
    ).rejects.toThrow('PIN must be exactly 4 digits.');
  });

  it('should throw an error for an invalid PIN (too long)', async () => {
    await expect(
      deriveServerBoundKeys({
        account,
        pin: '12345',
      })
    ).rejects.toThrow('PIN must be exactly 4 digits.');
  });

  it('should throw an error for an invalid PIN (non-numeric)', async () => {
    await expect(
      deriveServerBoundKeys({
        account,
        pin: '12ab',
      })
    ).rejects.toThrow('PIN must be exactly 4 digits.');
  });

  it('should throw an error for an empty PIN', async () => {
    await expect(
      deriveServerBoundKeys({
        account,
        pin: '',
      })
    ).rejects.toThrow('PIN must be exactly 4 digits.');
  });

  it('should work with different account types (different private keys)', async () => {
    const privateKeys = [
      '0x8575420a19052cf9bbe9ef4ac755a9abaaefa3f1f2e35d14c04f38829182e9ba',
      '0x16988506fc3aa66bad0f3f231aa9552a1639b7c05477e6d59f8044adb3155322',
      '0x641f9f8b285fa1d22b009ea8c947bb6d88129b320b729d98810b40b51e8572c7',
    ];

    for (const privateKey of privateKeys) {
      const testAccount = privateKeyToAccount(privateKey as `0x${string}`);
      const result = await deriveServerBoundKeys({
        account: testAccount,
        pin: userPin,
      });

      expect(result.P_view).toBeDefined();
      expect(result.P_spend).toBeDefined();
      expect(result.child_p_view).toBeInstanceOf(HDKey);
    }
  });

  it('should produce deterministic results: same account + same pin + same node = same output', async () => {
    const nodeNumber = 5;
    const result1 = await deriveServerBoundKeys({
      account,
      pin: userPin,
      viewingPrivateKeyNodeNumber: nodeNumber,
    });
    const result2 = await deriveServerBoundKeys({
      account,
      pin: userPin,
      viewingPrivateKeyNodeNumber: nodeNumber,
    });

    expect(result1).toEqual(result2);
    expect(result1.P_view).toEqual(result2.P_view);
    expect(result1.P_spend).toEqual(result2.P_spend);
    expect(bytesToHex(result1.child_p_view.privateKey!)).toEqual(
      bytesToHex(result2.child_p_view.privateKey!)
    );
    expect(bytesToHex(result1.child_p_view.publicKey!)).toEqual(
      bytesToHex(result2.child_p_view.publicKey!)
    );
  });

  it('should return P_view and P_spend that are different from each other', async () => {
    const result = await deriveServerBoundKeys({
      account,
      pin: userPin,
    });

    expect(result.P_view).not.toEqual(result.P_spend);
  });
});
