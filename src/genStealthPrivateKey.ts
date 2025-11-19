import { keccak256, pad, toHex, hexToBytes } from 'viem';
import * as secp from '@noble/secp256k1';

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
  const S = secp.getSharedSecret(
    hexToBytes(p_spend),
    hexToBytes(P_derived),
    false
  );

  // Remove the 0x04 prefix (first byte) and hash the remaining 64 bytes
  const hashedSharedSecret = keccak256(S.slice(1));

  // Compute: (p_spend * hashedSharedSecret) mod CURVE.n
  const CURVE_ORDER = secp.Point.CURVE().n;
  const p_stealthBigInt =
    (BigInt(p_spend) * BigInt(hashedSharedSecret)) % CURVE_ORDER;

  return { p_stealth: pad(toHex(p_stealthBigInt)) };
}
