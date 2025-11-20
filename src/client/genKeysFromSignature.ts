import { keccak256, hexToBytes, slice } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

/**
 * Derives p_spend, P_spend, p_view, and P_view keys from a signature.
 * Credit: https://github.com/ScopeLift/umbra-protocol/blob/fb4481c547e420415aac6f84cdd6ea7d5fc2c3f7/umbra-js/src/classes/Umbra.ts#L603
 *
 * @param signature - The signature (hex string) to derive keys from. Must be 0x + 130 hex characters (132 total).
 * @returns An object containing p_view, P_view, p_spend, and P_spend key pairs
 * @throws If signature is not valid (wrong length or missing 0x prefix)
 */
export function genKeysFromSignature(signature: `0x${string}`): {
  p_view: `0x${string}`;
  P_view: `0x${string}`;
  p_spend: `0x${string}`;
  P_spend: `0x${string}`;
} {
  // Validate signature format
  if (!signature.startsWith('0x')) {
    throw new Error('Signature is not valid.');
  }

  // Signature should be 0x + 130 hex characters = 132 total characters
  if (signature.length !== 132) {
    throw new Error('Signature is not valid.');
  }

  // Strip 0x prefix and convert to bytes
  const signatureBytes = hexToBytes(signature);

  // Generates p_spend by hashing the first 32 bytes of the signature
  const first32Bytes = slice(signatureBytes, 0, 32);
  const p_spend = keccak256(first32Bytes) as `0x${string}`;

  // Generates p_view by hashing bytes 32-64 of the signature
  const middle32Bytes = slice(signatureBytes, 32, 64);
  const p_view = keccak256(middle32Bytes) as `0x${string}`;

  // Derive public keys from private keys
  const P_spend = privateKeyToAccount(p_spend).publicKey;
  const P_view = privateKeyToAccount(p_view).publicKey;

  return {
    p_view,
    P_view,
    p_spend,
    P_spend,
  };
}
