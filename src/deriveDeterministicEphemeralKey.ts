import { type HDKey } from 'viem/accounts';

export function deriveDeterministicEphemeralKey({
  childViewingNode, // m/5564'/0'
  nonce,
  chainId,
  coinType,
}: {
  viewingPrivateKeyNode: HDKey;
  nonce: bigint;
  chainId?: number;
  coinType?: number;
}): { derivedPrivateKey: `0x${string}` } {
  // p_derived
  // TODO: implement this
  return null as unknown as { derivedPrivateKey: `0x${string}` };
}
