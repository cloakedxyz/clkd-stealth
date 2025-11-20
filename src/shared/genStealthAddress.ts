import { keccak256, hexToBytes, toHex, isHex } from 'viem';
import * as secp from '@noble/secp256k1';
import { publicKeyToAddress } from 'viem/utils';

/**
 * Generates a stealth address from a spending public key and a derived private key.
 * Credit: https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/3bab3b158e4d9164dd96bd3d247c835328f1063c/src/generateStealthAddresses.ts
 * @param P_spend - The spending public key. Must be an uncompressed public key (0x04 + 65 bytes).
 * @param p_derived - Derived private key from the derivation path. Must be a 32-byte hex string (0x + 64 chars).
 * @returns The stealth address.
 */
export function genStealthAddress(
  P_spend: `0x${string}`,
  p_derived: `0x${string}`
): `0x${string}` {
  if (
    !isHex(P_spend, { strict: true }) ||
    !P_spend.startsWith('0x04') ||
    P_spend.length !== 132
  ) {
    throw new Error('P_spend is not valid.');
  }

  if (!isHex(p_derived, { strict: true }) || p_derived.length !== 66) {
    throw new Error('p_derived is not valid.');
  }

  // Compute shared secret
  const S = secp.getSharedSecret(
    hexToBytes(p_derived),
    hexToBytes(P_spend),
    false
  );

  // Remove the 0x04 prefix (first byte) and hash the remaining 64 bytes
  const hashedSharedSecret = keccak256(toHex(S.slice(1)));

  // Convert the spending public key from hex to a point on the elliptic curve
  const P_spendPoint = secp.Point.fromHex(P_spend.slice(2));

  // Multiply the public key point by the hashed shared secret to get the stealth public key
  const P_stealth = P_spendPoint.multiply(BigInt(hashedSharedSecret));

  // Get the stealth address from the stealth public key
  return publicKeyToAddress(`0x${P_stealth.toHex(false)}`);
}

/**
 * Generates multiple stealth addresses for a set of spending public keys using a single derived private key.
 * @param P_spendSet - An array of spending public keys. Each must be an uncompressed public key (0x04 + 65 bytes).
 * @param p_derived - Derived private key from the derivation path. Must be a 32-byte hex string (0x + 64 chars).
 * @returns An object containing an array of stealth addresses.
 */
export function genStealthAddresses({
  P_spendSet,
  p_derived,
}: {
  P_spendSet: `0x${string}`[];
  p_derived: `0x${string}`;
}): { stealthAddresses: `0x${string}`[] } {
  return {
    stealthAddresses: P_spendSet.map((P_spend) =>
      genStealthAddress(P_spend, p_derived)
    ),
  };
}
