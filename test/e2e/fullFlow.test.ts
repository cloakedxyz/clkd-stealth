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
  const { p_view, P_view, p_spend, P_spend } =
    genKeysFromSignature(signature);

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
        stealthAddress: '0x4743bBffceBfa75301f128D81CB4fD6a53408AB9',
        stealthPrivateKey:
          '0xe3bae99ce361c5d0a83fc1e1c946282cd15ded4288e16ace87cd407b33122eac',
      },
      {
        nonce: BigInt(1),
        stealthAddress: '0xA6d0B9FAe89c32a044e5E7C769D77b1F19edC90F',
        stealthPrivateKey:
          '0xe9c005fe066b7e78db616abd668820e13525948553abd9f5d819f36c4bdbb4ca',
      },
      {
        nonce: BigInt(2),
        stealthAddress: '0xf010e0f737169BEc49Bde64A99032D18498BB8a4',
        stealthPrivateKey:
          '0x286a218825a3f9934611ce81b0d4bd07091b364f67fdbf40e9251a186512039f',
      },
      {
        nonce: BigInt(3),
        stealthAddress: '0x0E9d1F0d4F417DD416c296BE01f12d9639263e14',
        stealthPrivateKey:
          '0x127d8e535640f5282645ead7cf7bbe3aa0a63b92370dcf22ccfc986fb092eaae',
      },
      {
        nonce: BigInt(4),
        stealthAddress: '0x8061Cac430911f3f4876c7B985Bd4F9bea659325',
        stealthPrivateKey:
          '0xcdb48f5bd28fd04033923d4ab41d573c02b960757b966c58e31ef144d592844e',
      },
      {
        nonce: BigInt(5),
        stealthAddress: '0xA543237E4aA8C802aC0b1D441E6989a3d03bb66C',
        stealthPrivateKey:
          '0x7e7b8382658aef4fb441ff91ac030434f446704c8f32d77674e90a951168fa7a',
      },
      {
        nonce: BigInt(6),
        stealthAddress: '0x5516520CFC508855369F9bfa22D8BcD174049A26',
        stealthPrivateKey:
          '0xba08baf8d98d6b2de21c95cf2db36dd0361fc8f3dcb89d3bb92a0c752cc997df',
      },
      {
        nonce: BigInt(7),
        stealthAddress: '0xc432743d42C56a692F9da94857e3f88c267AE2DD',
        stealthPrivateKey:
          '0xa70785cde85833fc5b26136547838b3fe9539ac50688340bbe5f64123719c6f4',
      },
      {
        nonce: BigInt(8),
        stealthAddress: '0xa188C2B413c1749184CF123103F30B89E44E0894',
        stealthPrivateKey:
          '0xbb177768be66e1a7710f085a8f38482671bff0ce8abf51af87c79828ae162498',
      },
      {
        nonce: BigInt(9),
        stealthAddress: '0xB16Bc81F82befA4b35413818d36C2855da87dcAe',
        stealthPrivateKey:
          '0xc185850d9f299fb86e5bd391dc6ef27cd3e20e22b984db8ace7b157ac8c6af35',
      },
      {
        nonce: BigInt(10),
        stealthAddress: '0xa9Fa64D60F0Ea6bf8c8b17d8464d246974A5f7EF',
        stealthPrivateKey:
          '0x3ada0042fa8d4af46b19277f8e8943a975e00ffab15142e808dca6880b71b08e',
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

  // Test cases adapted from Fluidkey's implementation:
  // https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/main/test/generateStealthAddresses.test.ts
  // Note: The nonce and stealth private keys match Fluidkey's expected values, but the stealth address differs.
  // In our implementation, the stealth address is the address directly derived from the stealth private key,
  // whereas Fluidkey uses a stealth safe address. We omit the safe address step in our implementation.
  it('should generate the correct stealth addresses starting from a private key and pi for fluid key test cases', async () => {
    const expectedResults = [
        {
          nonce: BigInt(0),
          stealthAddress: '0x020D4Ae941F4E52465E7a454E86F97E9b6F69F5e',
          stealthPrivateKey: '0xc3496b0b8564827706bd71a9a7c147adcd29e044f525e8002416172f4c24db5f',
        },
        {
          nonce: BigInt(1),
          stealthAddress: '0xaBAf813e06CEa74c1b61fE78399fEd63bd720d16',
          stealthPrivateKey: '0x9144dea9bca79a4a300e94b8e1a4979d501159c9adc4b10364bfaafea3c34139',
        },
        {
          nonce: BigInt(2),
          stealthAddress: '0xbC7764eE5bd12263a35f4cF23728a86b35349994',
          stealthPrivateKey: '0xfdfd59cc5b2feb553a5f4c1a97e7f00458402fa9f4e205687bf7d0a8a85f1b4e',
        },
        {
          nonce: BigInt(3),
          stealthAddress: '0x62b99620407F33732DFC1A39AA018F187641644C',
          stealthPrivateKey: '0x4f3e1be745773ca6577b37f8da935f0c8245dc872a23b42af93cf3937ab56fe2',
        },
        {
          nonce: BigInt(4),
          stealthAddress: '0xADa00af959C347d4e8e96594c8AD973a3ecc2053',
          stealthPrivateKey: '0xf4910a0b5ed9e9ab8709cbe85435cff10a4e1a9707687dd1fd633ea890337ab0',
        },
        {
          nonce: BigInt(5),
          stealthAddress: '0x616BEBe0dE2d584D337585a59356620f0b9A8d80',
          stealthPrivateKey: '0x6c5d4bbe26f1db6ed6523be8cf987935232ca5d32317854dd70031408261a621',
        },
        {
          nonce: BigInt(6),
          stealthAddress: '0x2BAAE5A852CA632eD4aB8a8743949F19dcC892Af',
          stealthPrivateKey: '0x4bbe8b6b45ea6febb6316f6f64cf595e81514d67aece0bdd01fd549b0c4ed525',
        },
        {
          nonce: BigInt(7),
          stealthAddress: '0x23005432f052f3b720e09BbAF85486b40AaaF59F',
          stealthPrivateKey: '0xfb92ddb354c4c3fb696a84eb217402940bba4a30919e150606be462adda0a113',
        },
        {
          nonce: BigInt(8),
          stealthAddress: '0xe4fB01c7d4d344Db4cac03d8dd4211Fb8283088f',
          stealthPrivateKey: '0xacfde69e98dcf6dd41fd9a89897c7898abc3faed21195e5fe97dc89469d97556',
        },
        {
          nonce: BigInt(9),
          stealthAddress: '0xDad3c9E83B52DeD3313838450Af15B1498f97999',
          stealthPrivateKey: '0xcca098b0704d16e5750b27603fe5ea356986e53e8f05a8fedcfb8ecb31befae2',
        },
        {
          nonce: BigInt(10),
          stealthAddress: '0x222382b03c17fbE5C317A388c020913b2cDcF987',
          stealthPrivateKey: '0x65d4c59647bf0e86f01f9373e7f354c45484eb09008e7f891a8593801581ff6f',
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
        const secret = keccak256(toHex(address + pin)).replace(
          '0x',
          '',
        );
      
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
