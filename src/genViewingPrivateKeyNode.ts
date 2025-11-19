import { HDKey } from 'viem/accounts';

export function deriveViewingPrivateKeyNode(
  privateViewingKey: `0x${string}`, // p_view
  node: number = 0
): HDKey {
  // m/5564'/0'
  // TODO: implement this
  return null as unknown as HDKey;
}
