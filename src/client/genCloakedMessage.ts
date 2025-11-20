import { keccak256, toHex, isAddress } from 'viem';

/**
 * Generate the Cloaked key generation message to be signed by the user.
 *
 * Credit: https://github.com/fluidkey/fluidkey-stealth-account-kit/blob/3bab3b158e4d9164dd96bd3d247c835328f1063c/src/utils/generateFluidkeyMessage.ts
 *
 * @param pin the user's PIN (string of exactly 4 digits)
 * @param address the address the user is connected to the application with (string)
 * @returns An object containing the message to be signed by the user
 */
export function genCloakedMessage({
  pin,
  address,
}: {
  pin: string;
  address: string;
}): { message: string } {
  if (!isAddress(address, { strict: false })) {
    throw new Error('Address is not valid.');
  }

  // Validate PIN: must be exactly 4 digits
  if (pin.length !== 4 || !/^\d{4}$/.test(pin)) {
    throw new Error('PIN must be exactly 4 digits.');
  }

  // Generate the secret based on the user's PIN and address
  const secret = keccak256(toHex(address + pin)).replace('0x', '');

  // Compose the message
  const message = `Sign this message to generate your Cloaked private payment keys.

WARNING: Only sign this message within a trusted website or platform to avoid loss of funds.

Secret: ${secret}`;

  // Return the message
  return { message };
}
