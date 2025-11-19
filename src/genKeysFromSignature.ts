import { keccak256, hexToBytes, slice } from 'viem';

/**
 * Generates stealth account keys from a signature.
 * This function derives spending and viewing private keys from a signature using keccak256 hashing.
 *
 * @param signature - The signature (hex string) to derive keys from. Must be 0x + 130 hex characters (132 total).
 * @returns An object containing the derived spendingPrivateKey and viewingPrivateKey
 * @throws Error if signature is not valid (wrong length or missing 0x prefix)
 */
export function generateKeysFromSignature(signature: `0x${string}`): {
  spendingPrivateKey: `0x${string}`; // p_spend
  viewingPrivateKey: `0x${string}`; // p_view
} {
  // Validate signature format
  if (!signature.startsWith('0x')) {
    throw new Error('Signature is not valid.');
  }

  // Signature should be 0x + 130 hex characters = 132 total characters
  if (signature.length !== 132) {
    throw new Error('Signature is not valid.');
  }

  // Convert signature to bytes (65 bytes total for a signature)
  const signatureBytes = hexToBytes(signature);

  // Generate spending private key by hashing the first 32 bytes of the signature
  const first32Bytes = slice(signatureBytes, 0, 32);
  const spendingPrivateKey = keccak256(first32Bytes) as `0x${string}`;

  // Generate viewing private key by hashing bytes 32-64 of the signature
  const middle32Bytes = slice(signatureBytes, 32, 64);
  const viewingPrivateKey = keccak256(middle32Bytes) as `0x${string}`;

  return {
    spendingPrivateKey,
    viewingPrivateKey,
  };
}
