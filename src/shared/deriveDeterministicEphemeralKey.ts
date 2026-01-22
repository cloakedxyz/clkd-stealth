import { type HDKey } from 'viem/accounts';
import { toHex } from 'viem';

/**
 * Generate an ephemeral private key using simplified derivation path: m/5564'/N'/ensip11ChainID'/0'/p'/n'
 *
 * This uses the full ENSIP-11 coinType directly instead of splitting it into c0'/c1'.
 * The derivation path uses the chainId directly and lets scure-bip32's hardened derivation (') convert it to the ENSIP-11 coinType.
 *
 * @param childViewingNode - HDKey viewing node derived at m/5564'/N'
 * @param nonce - Unique nonce for this ephemeral key (max: 0x7FFFFFFFFFFFFFF)
 * @param chainId - Will be converted to ENSIP-11 coinType via hardened derivation (default: 0 for cross-chain compatibility)
 * @returns p_derived - derived private key from the derivation path
 */
export function deriveDeterministicEphemeralKey(
  childViewingNode: HDKey, // m/5564'/0'
  nonce: bigint,
  chainId: number = 0
): { p_derived: `0x${string}` } {
  return impl(childViewingNode, nonce, chainId);
}

/**
 * Generate an ephemeral private key using simplified derivation path: m/chainId'/0'/p'/n'
 *
 * @param childViewingNode - HDKey viewing node derived at m/5564'/0'
 * @param nonce - Unique nonce for this ephemeral key (max: 0x7FFFFFFFFFFFFFF)
 * @param chainId - Will be converted to ENSIP-11 coinType via hardened derivation (default: 0 for cross-chain compatibility)
 * @returns p_derived - derived private key from the derivation path
 */
const impl = (
  childViewingNode: HDKey, // m/5564'/0'
  nonce: bigint,
  chainId: number = 0
): { p_derived: `0x${string}` } => {
  if (nonce >= BigInt('0x7ffffffffffffff')) {
    throw new Error('Nonce is too large. Max value is 0x7FFFFFFFFFFFFFF.');
  }

  const MAX_NONCE = BigInt('0xfffffff');
  let parentNonce = BigInt(0);
  if (nonce > MAX_NONCE) {
    parentNonce = nonce / (MAX_NONCE + BigInt(1));
    nonce = nonce % (MAX_NONCE + BigInt(1));
  }

  // Simplified derivation path: m/chainId'/0'/p'/n'
  // Unlike Fluidkey's path (m/c0'/c1'/0'/p'/n'), this uses the chainId directly
  // and lets scure-bip32's hardened derivation (') convert it to the ENSIP-11 coinType.
  // For chainId=0, this becomes m/0'/0'/p'/n' where 0' internally becomes 0x80000000.
  // Note: Pass the raw chainId value (e.g. 0, 1, 10), not the ENSIP-11 coinType.
  // The apostrophe (') triggers hardening, which adds 0x80000000 to create the coinType.
  const index = `m/${chainId}'/0'/${parentNonce}'/${nonce}'`;

  // Derive the child private key based on the index
  const childPrivateKey = childViewingNode.derive(index);

  // Ensure the child private key was derived successfully
  /* istanbul ignore next */
  if (childPrivateKey.privateKey == null) {
    throw new Error('Could not derive child private key.');
  }

  // Convert the child private key to hex and return it
  return {
    p_derived: toHex(childPrivateKey.privateKey),
  };
};
