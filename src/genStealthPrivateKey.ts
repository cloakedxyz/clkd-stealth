import { keccak256, hexToBytes } from 'viem';
import * as secp from '@noble/secp256k1';
import * as Hex from 'ox/Hex';

/**
 * Derives p_stealth from p_spend and P_derived.
 * 
 * @param p_spend - The private key of the spending account.
 * @param P_derived - The derived public key (stand in for the ephemeral public key).
 * @returns The private key of the stealth account: p_stealth.
 */
export function genStealthPrivateKey({
  p_spend,
  P_derived,
}: {
  p_spend: `0x${string}`;
  P_derived: `0x${string}`;
}): { p_stealth: `0x${string}` } {
  // Compute shared secret 
  const S = secp.getSharedSecret(hexToBytes(p_spend), hexToBytes(P_derived), false);

  // Remove the 0x04 prefix (first byte) and hash the remaining 64 bytes
  const hashedSharedSecret = keccak256(S.slice(1));

  // Compute: (p_spend * hashedSharedSecret) mod CURVE.n
  const CURVE_ORDER = secp.Point.CURVE().n;
  const p_stealthBigInt = (BigInt(p_spend) * BigInt(hashedSharedSecret)) % CURVE_ORDER;

  const p_stealthHex = `0x${p_stealthBigInt.toString(16)}` as `0x${string}`;
  const p_stealth = Hex.padLeft(p_stealthHex, 32) as `0x${string}`;

  return { p_stealth };
}
