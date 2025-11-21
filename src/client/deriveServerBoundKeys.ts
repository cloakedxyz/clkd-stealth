import { PrivateKeyAccount } from 'viem';
import { HDKey } from 'viem/accounts';
import { genCloakedMessage } from './genCloakedMessage';
import { genKeysFromSignature } from './genKeysFromSignature';
import { deriveChildViewingNode } from '..';

// This is the node number we always use.
const VIEWING_PRIVATE_KEY_NODE_NUMBER = 0;

/**
 * Helper function for the Client to derive the keys the server needs to handle stealth
 * address generation and scanning.
 *
 * @param account - The private key account of the user.
 * @param pin - The pin of the user.
 * @returns P_view, P_spend, child_p_view.
 */
export async function deriveServerBoundKeys({
  account,
  pin,
}: {
  account: PrivateKeyAccount;
  pin: string;
  viewingPrivateKeyNodeNumber?: number;
}): Promise<{
  P_view: `0x${string}`;
  P_spend: `0x${string}`;
  child_p_view: HDKey;
}> {
  // Step 1: Generate the signature
  const { message } = genCloakedMessage({
    pin,
    address: account.address,
  });
  const signature = await account.signMessage({
    message: message,
  });

  // Step 2: Generate the private keys from the signature
  const { p_view, P_view, P_spend } = genKeysFromSignature(signature);

  // Step 3: Generate the child viewing node
  const child_p_view = deriveChildViewingNode(
    p_view,
    VIEWING_PRIVATE_KEY_NODE_NUMBER
  );

  return {
    P_view,
    P_spend,
    child_p_view,
  };
}
