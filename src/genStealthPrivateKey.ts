export function generateStealthPrivateKey({
  spendingPrivateKey, // p_spend
  derivedPublicKey, // P_derived
}: {
  spendingPrivateKey: `0x${string}`; // p_spend
  derivedPublicKey: `0x${string}`; // P_derived
}): { stealthPrivateKey: `0x${string}` } {
  // p_stealth
  // TODO: implement this
  return null as unknown as { stealthPrivateKey: `0x${string}` };
}
