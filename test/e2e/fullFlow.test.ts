import { describe, it, expect } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';

import {
  deriveChildViewingNode,
  deriveDeterministicEphemeralKey,
  genStealthAddress,
} from '../../src/shared/index';
import {
  genKeysFromSignature,
  genStealthPrivateKey,
  genCloakedMessage,
} from '../../src/client/index';
import { keccak256, toHex } from 'viem';

/**
 * End-to-end test of generating stealth accounts based on the user's private key and the key generation message to be signed.
 *
 * @param userPrivateKey
 * @param message
 * @param viewingPrivateKeyNodeNumber
 * @param startNonce
 * @param endNonce
 * @param chainId
 * @returns an array of objects containing the nonce, the corresponding stealth address, and the private key controlling the stealth account at that address
 */
export async function runFullFlow({
  userPrivateKey,
  message,
  viewingPrivateKeyNodeNumber = 0,
  startNonce = BigInt(0),
  endNonce = BigInt(10),
  chainId = 0,
}: {
  userPrivateKey: `0x${string}`;
  message: string;
  viewingPrivateKeyNodeNumber?: number;
  startNonce?: bigint;
  endNonce?: bigint;
  chainId?: number;
}): Promise<
  {
    nonce: bigint;
    stealthAddress: `0x${string}`;
    stealthPrivateKey: `0x${string}`;
  }[]
> {
  // Create an empty array to store the results
  const results: {
    nonce: bigint;
    stealthAddress: `0x${string}`;
    stealthPrivateKey: `0x${string}`;
  }[] = [];

  // Generate the signature from which the private keys will be derived
  const account = privateKeyToAccount(userPrivateKey);

  const signature = await account.signMessage({
    message,
  });

  // Generate the private keys from the signature
  const { p_view, P_view, p_spend, P_spend } = genKeysFromSignature(signature);

  // Extract the node required to generate the pseudo-random input for stealth address generation
  const childViewingNode = deriveChildViewingNode(
    p_view,
    viewingPrivateKeyNodeNumber
  );

  for (let nonce = startNonce; nonce <= endNonce; nonce++) {
    // Generate the ephemeral private key
    const { p_derived } = deriveDeterministicEphemeralKey(
      childViewingNode,
      nonce,
      chainId
    );

    // Generate the stealth address
    const stealthAddress = genStealthAddress(P_spend, p_derived);

    const P_derived = privateKeyToAccount(p_derived).publicKey;

    // Generate the stealth private key controlling the stealth account
    const { p_stealth } = genStealthPrivateKey({
      p_spend,
      P_derived: P_derived,
    });

    // Add the result to the results array
    results.push({
      nonce,
      stealthAddress: stealthAddress,
      stealthPrivateKey: p_stealth,
    });
  }

  // Return the results
  return results;
}

describe('fullFlow', () => {
  const userPrivateKey =
    '0x8575420a19052cf9bbe9ef4ac755a9abaaefa3f1f2e35d14c04f38829182e9ba';
  const userPin = '1234';
  const userAddress = privateKeyToAccount(userPrivateKey).address;

  it('should generate the correct stealth addresses starting from a private key and pin', async () => {
    const expectedResults = [
      {
        nonce: BigInt(0),
        stealthAddress: '0xF9306213aF3ed8B42BF923D1519deC0bc657F735',
        stealthPrivateKey:
          '0xde25081883411999baf0eecf5b7bd2b325c0c202ae0e9b9aeab29d55f93752a5',
      },
      {
        nonce: BigInt(1),
        stealthAddress: '0x3FA8571c117Abf183a65b75E4e9E2d6942b5131c',
        stealthPrivateKey:
          '0x0436732a5981e0cdd2ee638146b29a5290d416e875f4931ca9ce227f519a54c0',
      },
      {
        nonce: BigInt(2),
        stealthAddress: '0x8BAa105Dc7B0B8f03A595Dc2d13BDaC8d41A46Ea',
        stealthPrivateKey:
          '0xea41d9300a7348aa8c804b644c0db43123a58734972360c7c91fd881cc79b7de',
      },
      {
        nonce: BigInt(3),
        stealthAddress: '0x2A10741F666ea5E6303dA75C8F9720ADb54b28A0',
        stealthPrivateKey:
          '0x735d4e2f5a7ca6d45356fc1eedd5bd6e4f182a5fc2419e5e24e595e78d8438ef',
      },
      {
        nonce: BigInt(4),
        stealthAddress: '0x0C454543E7D13eDF35879E0650e6cADCE0aC2c1F',
        stealthPrivateKey:
          '0xa10593e45796623823306074667597bec4b203c2cf730ec3d33471d08a5a8b21',
      },
      {
        nonce: BigInt(5),
        stealthAddress: '0xC49A2Ee8Cf9915D6fE7427a22474C17bDFaafAb1',
        stealthPrivateKey:
          '0x3a9505c2096adebd29a7e60c81ac3cac00c4e255d5617ee11516a25315de4fbc',
      },
      {
        nonce: BigInt(6),
        stealthAddress: '0x65Ce0410f5B58b1b166C9ae9140674c9316569A9',
        stealthPrivateKey:
          '0xbfb79d758063c87437852525548d0e5da81d746da9810378d03fa35d712a55e7',
      },
      {
        nonce: BigInt(7),
        stealthAddress: '0xbf3F1D32400A8a954210aF4afb7221e5BcCBE7B2',
        stealthPrivateKey:
          '0x1411e0dacfb432d0a5ade131d753a839d2bada950e1cf5109f4f944f8ddc9d47',
      },
      {
        nonce: BigInt(8),
        stealthAddress: '0x9F5bBcf9eE616Ac05Cb9C986b04E648015BcFBBD',
        stealthPrivateKey:
          '0x0ca3facaa495d830c1f273220c1170b8725ad5016ab3bd1331aca236111cd9d1',
      },
      {
        nonce: BigInt(9),
        stealthAddress: '0x14646C3be8d6646c329A7897aaC7f5A767EB5755',
        stealthPrivateKey:
          '0x309285c8318ab79998351a11e1b84f2cec796a34137947160676ba18b7dfa55d',
      },
      {
        nonce: BigInt(10),
        stealthAddress: '0xE1b5A3388C02C526AC98dbD5fEB012e79fF69B61',
        stealthPrivateKey:
          '0xc02ab3055ec5f507a1149d4bdc4e9c5c2ec81a6bfd3124ebfc7395cdaa8382e7',
      },
    ];

    const { message } = genCloakedMessage({
      pin: userPin,
      address: userAddress,
    });

    const result = await runFullFlow({
      userPrivateKey,
      message,
    });

    // Check that the result is correct
    expect(result).toEqual(expectedResults);

    // Ensure that the received stealth address can be derived from the stealth private key
    for (const { stealthPrivateKey, stealthAddress } of result) {
      const stealthAccount = privateKeyToAccount(stealthPrivateKey);
      expect(stealthAddress).toEqual(stealthAccount.address);
    }
  }, 60000);

  it('should generate the correct stealth addresses starting from a private key and pi for fluid key test cases', async () => {
    const expectedResults = [
      {
        nonce: BigInt(0),
        stealthAddress: '0x98C8E0E53b8f6A3C381676FC23A1834265091C2D',
        stealthPrivateKey:
          '0x977488a3c87ff389828ee014fef69b2f3b329d10035fd090df3acf4c218d3434',
      },
      {
        nonce: BigInt(1),
        stealthAddress: '0xda5A90B94843Fa4D055A6e28fF807d93FF4911Fd',
        stealthPrivateKey:
          '0x434f1f64c6e8c51f8189b76777699ff332a49d336634c938a5ffb9a8beb3934a',
      },
      {
        nonce: BigInt(2),
        stealthAddress: '0x3a54626E4c267F6d573F8287892F9d65b09Bcd00',
        stealthPrivateKey:
          '0xece65dead04ccc3d8278ac47e6e3274919d2bb340e021780a73fb507e5417641',
      },
      {
        nonce: BigInt(3),
        stealthAddress: '0x9a278383EbA21D36A39389722f70C78cCbfF5322',
        stealthPrivateKey:
          '0x4e17ac913efdaf685d9b71631e05b8c3920377be581f68c4ba63e80a5a22dd74',
      },
      {
        nonce: BigInt(4),
        stealthAddress: '0x49264d38274e3712D70a9951AEA3AED63FC2b7BB',
        stealthPrivateKey:
          '0x44e12f695834f79018e95b8bfcc65ad01c388bd56c5c1dedfabf6ef0ca09014b',
      },
      {
        nonce: BigInt(5),
        stealthAddress: '0xECBCA19444622F855443973458617d575B729285',
        stealthPrivateKey:
          '0x3a949be84a4f598140532b3ddec20d0083b733e0a79968f5e3fb6d83b3b9b062',
      },
      {
        nonce: BigInt(6),
        stealthAddress: '0x0E50F9D0550e9a3420cBE20876Ebd653B85a081C',
        stealthPrivateKey:
          '0x10fadd47095c5ee64e50ba68324b9ee0e2e174bfd72cfd11932644ec634ee8fe',
      },
      {
        nonce: BigInt(7),
        stealthAddress: '0xAea0078f4Daff6Fee9f550a7D6cA073B3D98c180',
        stealthPrivateKey:
          '0xf3c5db10250574e5ad234e76117a5ebffa79a4a481f8d8d366c2afe828484374',
      },
      {
        nonce: BigInt(8),
        stealthAddress: '0x9f19e0C654EC88dD92a31769048B1c7897C4b520',
        stealthPrivateKey:
          '0xc1f310d608075c692b89d7f05e1e0e59f1867881bfc4b5e23ace28b47dfa51c8',
      },
      {
        nonce: BigInt(9),
        stealthAddress: '0x2F80a6E1edC4C57806F7DBC66b126D0cF330CF59',
        stealthPrivateKey:
          '0xa803bf08af9b5ee92640fe17b39c28f879e8edc120f2b128b99b899149fcd558',
      },
      {
        nonce: BigInt(10),
        stealthAddress: '0xF8D7311197722cA7eAf71E4eD7a4D6CCD28D432b',
        stealthPrivateKey:
          '0x3285354d0414a3b175f40574482cdb9250bbaa2dfb2675c6e903102b830c6640',
      },
    ];

    function genFluidkeyMessage({
      pin,
      address,
    }: {
      pin: string;
      address: string;
    }): { message: string } {
      // Generate the secret based on the user's PIN and address
      const secret = keccak256(toHex(address + pin)).replace('0x', '');

      // Compose the message
      const message = `Sign this message to generate your Fluidkey private payment keys.

WARNING: Only sign this message within a trusted website or platform to avoid loss of funds.

Secret: ${secret}`;

      // Return the message
      return { message };
    }

    const { message } = genFluidkeyMessage({
      pin: userPin,
      address: userAddress,
    });

    const result = await runFullFlow({
      userPrivateKey,
      message,
    });

    // Check that the result is correct
    expect(result).toEqual(expectedResults);

    // Ensure that the received stealth address can be derived from the stealth private key
    for (const { stealthPrivateKey, stealthAddress } of result) {
      const stealthAccount = privateKeyToAccount(stealthPrivateKey);
      expect(stealthAddress).toEqual(stealthAccount.address);
    }
  }, 60000);

  it('should generate stealth addresses for a variety of viewingPrivateKeyNodeNumbers, startNonces, endNonces, and chainIds', async () => {
    const scenarios = [
      {
        viewingPrivateKeyNodeNumber: 0,
        startNonce: 0n,
        endNonce: 0n,
        chainId: 0,
      },
      {
        viewingPrivateKeyNodeNumber: 7,
        startNonce: 2n,
        endNonce: 4n,
        chainId: 1,
      },
      {
        viewingPrivateKeyNodeNumber: 42,
        startNonce: 10n,
        endNonce: 12n,
        chainId: 8453,
      },
    ];

    for (const scenario of scenarios) {
      const { message } = genCloakedMessage({
        pin: userPin,
        address: userAddress,
      });
      const result = await runFullFlow({
        userPrivateKey,
        message,
        viewingPrivateKeyNodeNumber: scenario.viewingPrivateKeyNodeNumber,
        startNonce: scenario.startNonce,
        endNonce: scenario.endNonce,
        chainId: scenario.chainId,
      });

      const expectedCount = Number(
        scenario.endNonce - scenario.startNonce + 1n
      );
      expect(result).toHaveLength(expectedCount);

      result.forEach(({ nonce, stealthPrivateKey, stealthAddress }, index) => {
        const expectedNonce = scenario.startNonce + BigInt(index);
        expect(nonce).toBe(expectedNonce);
        const derivedAddress = privateKeyToAccount(stealthPrivateKey).address;
        expect(stealthAddress).toEqual(derivedAddress);
      });
    }
  }, 60000);
});
