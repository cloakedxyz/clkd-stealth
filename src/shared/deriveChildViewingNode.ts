import { HDKey } from 'viem/accounts';
import { hexToBytes, isHex } from 'viem';

/**
 * Derives a child viewing node from a private viewing key.
 * Credit: https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/main/src/extractViewingPrivateKeyNode.ts
 * @param p_view - The private viewing key to derive the child viewing node from.
 * @param node - The node to derive the child viewing node from (Default: 0).
 * @returns The child viewing node.
 */
export function deriveChildViewingNode(
  p_view: `0x${string}`,
  node: number = 0
): HDKey {
  if (!isHex(p_view) || p_view.length !== 66) {
    throw new Error('Private viewing key is not valid.');
  }
  const DERIVATION_PATH = `m/5564'/${node}'`;
  const masterNodeKey = HDKey.fromMasterSeed(hexToBytes(p_view));
  const childNodeKey = masterNodeKey.derive(DERIVATION_PATH);
  return childNodeKey;
}
