import { type HDKey } from 'viem/accounts';
import { toHex } from 'viem';

export function deriveDeterministicEphemeralKey(
  childViewingNode: HDKey, // m/5564'/0'
  nonce: bigint,
  chainId?: number,
  coinType?: number,
  useCloakedImpl: boolean = false
): { p_derived: `0x${string}` } {
  if (useCloakedImpl) {
    return cloakedImpl(
      childViewingNode,
      nonce,
      0 // ensip11chainId default to 0 for cross-chain compatibility
    );
  }
  return fluidKeyImpl({
    childViewingNode,
    nonce,
    chainId,
    coinType,
  });
}

/**
 * Generate an ephemeral private key using simplified derivation path: m/5564'/N'/ensip11ChainID'/0'/p'/n'
 *
 * This uses the full ENSIP-11 coinType directly instead of splitting it into c0'/c1'.
 * Note: This path is NOT compatible with Fluidkey's standard path (m/5564'/N'/c0'/c1'/0'/p'/n').
 *
 * @param childViewingNode - HDKey viewing node derived at m/5564'/N'
 * @param nonce - Unique nonce for this ephemeral key (max: 0x7FFFFFFFFFFFFFF)
 * @param chainId - Will be converted to ENSIP-11 coinType via hardened derivation (default: 0 for cross-chain compatibility)
 * @returns p_derived - derived private key from the derivation path
 */
const cloakedImpl = (
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

/**
 * Code taken from Fluidkey's implementation: https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/3bab3b158e4d9164dd96bd3d247c835328f1063c/src/generateEphemeralPrivateKey.ts
 * Derivation path: m/5564'/N'/c0'/c1'/0'/p'/n'
 */
const fluidKeyImpl = ({
  childViewingNode, // m/5564'/0'
  nonce,
  chainId,
  coinType,
}: {
  childViewingNode: HDKey; // m/5564'/0'
  nonce: bigint;
  chainId?: number;
  coinType?: number;
}): { p_derived: `0x${string}` } => {
  // p_derived
  // Convert the chainId to a coinType if no coinType was provided
  if (coinType == null && chainId != null) {
    coinType = (0x80000000 | chainId) >>> 0;
  }

  // Ensure either the coinType or the chainId has been provided
  if (coinType == null) {
    throw new Error('coinType or chainId must be defined.');
  }

  // Slice the coinType into two parts, the first byte and the rest, to ensure no number above 0x80000000 is used in the derivation path
  const coinTypeString = coinType.toString(16).padStart(8, '0');
  const coinTypePart1 = parseInt(coinTypeString.slice(0, 1), 16);
  const coinTypePart2 = parseInt(coinTypeString.slice(1), 16);

  // key derivation structure is m/5564'/N'/c0'/c1'/0'/p'/n'

  // 5564 is the purpose as defined in BIP-43 and aligns with the stealth address EIP number, EIP-5564:
  // https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
  // https://eips.ethereum.org/EIPS/eip-5564

  // N is the number of the node shared with the stealth address generator

  // c is the coinType as derived in ENSIP-11 for EVM chains: https://docs.ens.domains/ens-improvement-proposals/ensip-11-evmchain-address-resolution
  // as it is a number above 0x80000000, which is not allowed in scure-bip32 (see HARDENED_OFFSET), it is split into two parts:
  // c0, the first byte of c
  // c1, the remaining bytes of c

  // only the node m/5564'/0' of the private viewing key is shared with the stealth address generator (see extractPrivateKeyNode)
  // the stealth address generator then generates pseudo-random addresses by incrementing n
  // since each value cannot be larger than 2^31 - 1 (0x7FFFFFFF)
  // we therefore introduce a parent nonce p to allow for more addresses to be generated.
  // If the nonce is bigger than MAX_NONCE, we put the overflow part into a parentNonce. To simplify
  // the creation of parentNonce, we set MAX_NONCE to be 0xFFFFFFF. With this schema the combination of nonce
  // and parent nonce has a max value of 0x7FFFFFFFFFFFFFF-1 = 576460752303423486₁₀

  // Split the nonce into two parts to ensure no number above 0x80000000 is used in the derivation path
  if (nonce >= BigInt('0x7ffffffffffffff')) {
    throw new Error('Nonce is too large. Max value is 0x7FFFFFFFFFFFFFF.');
  }
  const MAX_NONCE = BigInt('0xfffffff');
  let parentNonce = BigInt(0);
  if (nonce > MAX_NONCE) {
    parentNonce = nonce / (MAX_NONCE + BigInt(1));
    nonce = nonce % (MAX_NONCE + BigInt(1));
  }

  // Create the derivation path
  const index = `m/${coinTypePart1}'/${coinTypePart2}'/0'/${parentNonce}'/${nonce}'`;

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
