import { createClient, http, parseEther } from 'viem';
import { createPublicClient } from 'viem';
import { Account, Chains } from 'porto';
import { Key, RelayActions } from 'porto/viem';

const selfAddress = '0x35a7d3865f6e7807768f5d524b1e69310ce4193d';

const publicClient = createPublicClient({
  chain: Chains.base,
  transport: http(),
});

type Signatures = {
  auth?: `0x${string}`;
  exec?: `0x${string}`;
  payment: `0x${string}`;
};
type SignaturesAndRequests = {
  signatures: Signatures;
  upgradeRequest?: RelayActions.prepareUpgradeAccount.ReturnType;
  paymentRequest: RelayActions.prepareCalls.ReturnType;
};

const clientStep1 = async (): Promise<SignaturesAndRequests> => {
  const client = createClient({
    chain: Chains.base, // or Chains.base for mainnet
    transport: http('https://rpc.porto.sh'), // Use Porto Relay endpoint
  });

  // const key = Key.createSecp256k1();
  const key = Key.fromSecp256k1({
    privateKey:
      '0xe5b9cf1225c78dd19f0ff3dca2658bd37f69004e510db9548e86d572d600fac5',
  });
  if (!key.privateKey) {
    throw new Error('Failed to create private key');
  }
  const eoa = Account.fromPrivateKey(key.privateKey());
  console.log('EOA address:', eoa.address);

  // Check if EOA is already a contract
  const code = await publicClient.getCode({ address: eoa.address });
  const isContract = code !== undefined && code !== '0x';

  let upgradeSigs: { auth?: `0x${string}`; exec?: `0x${string}` } = {};
  let upgradeRequest:
    | RelayActions.prepareUpgradeAccount.ReturnType
    | undefined = undefined;
  if (!isContract) {
    // Prepare upgrade and sign auth + exec digests
    const adminKey = Key.fromSecp256k1({ address: eoa.address });
    upgradeRequest = await RelayActions.prepareUpgradeAccount(client, {
      address: eoa.address,
      authorizeKeys: [adminKey],
    });

    upgradeSigs = {
      auth: (await eoa.sign({
        hash: upgradeRequest.digests.auth,
      })) as `0x${string}`,
      exec: (await eoa.sign({
        hash: upgradeRequest.digests.exec,
      })) as `0x${string}`,
    };
  } else {
    console.log('EOA is already a contract, no need to upgrade.');
  }

  // Prepare payment call and sign payment digest
  const paymentRequest = await RelayActions.prepareCalls(client, {
    account: eoa,
    calls: [
      {
        to: selfAddress,
        value: parseEther('0.000001'),
        data: '0x',
      },
    ],
    // Before, we had 'keys' set to be the EOA but this caused an error. It was failing with:
    // key hash 0x93f9007dae459e600c1032c6f1ea42d82e80b8debfd83859c2f785f89f8c6a6a is unknown.
    // In relay.rs -> UnknownKeyHash(hash)
    // keccak256(abi.encode(uint8(2), keccak256(abi.encodePacked(uint256(0x00000000000000000000000035a7d3865f6e7807768f5d524b1e69310ce4193d)))))
    // To fix this, we removed the 'keys' parameter. Adding it makes the library think it's not the default key.
  });

  const paymentSignature = await eoa.sign({
    hash: paymentRequest.digest,
  });
  console.log('paymentSignature:', paymentSignature);

  const signatures: Signatures = {
    auth: upgradeSigs.auth,
    exec: upgradeSigs.exec,
    payment: paymentSignature,
  };
  return { signatures, upgradeRequest, paymentRequest };
};

const serverStep2 = async (
  clientStep1Response: SignaturesAndRequests
): Promise<boolean> => {
  const client = createClient({
    chain: Chains.base, // or Chains.base for mainnet
    transport: http('https://rpc.porto.sh'), // Use Porto Relay endpoint
  });

  // If we have upgrade signatures, we can upgrade the account
  if (
    clientStep1Response.signatures.auth &&
    clientStep1Response.signatures.exec &&
    clientStep1Response.upgradeRequest
  ) {
    const upgradedAccount = await RelayActions.upgradeAccount(client, {
      ...clientStep1Response.upgradeRequest,
      signatures: {
        auth: clientStep1Response.signatures.auth as `0x${string}`,
        exec: clientStep1Response.signatures.exec as `0x${string}`,
      },
    });

    console.log('upgradedAccount:', upgradedAccount);
  }

  // If we have payment signatures, we can pay the account
  const result = await RelayActions.sendPreparedCalls(client, {
    ...clientStep1Response.paymentRequest,
    signature: clientStep1Response.signatures.payment as `0x${string}`,
  });

  // Poll for status every 3 seconds until status is 200
  console.log(`Polling for status of call id: ${result.id}`);
  while (true) {
    const status = await RelayActions.getCallsStatus(client, {
      id: result.id,
    });

    const statusCode = status.status;
    console.log(`Current status: ${statusCode}`, status);

    // Handle different status codes
    if (statusCode === 200) {
      // Batch has been included onchain without reverts
      console.log('Status 200: Batch confirmed onchain successfully');
      break;
    } else if (statusCode === 100) {
      // Batch is pending, continue polling
      console.log('Status 100: Batch pending, waiting...');
    } else if (statusCode === 300) {
      // Batch has not been included onchain and wallet will not retry
      throw new Error(
        'Status 300: Offchain failure - batch will not be retried'
      );
    } else if (statusCode === 400) {
      // Batch reverted completely
      throw new Error(
        'Status 400: Chain rules failure - batch reverted completely'
      );
    } else if (statusCode === 500) {
      // Batch reverted partially
      throw new Error(
        'Status 500: Partial chain rules failure - batch reverted partially'
      );
    } else {
      // Unknown status code
      console.warn(`Unknown status code: ${statusCode}`);
    }

    // Wait 3 seconds before next check
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }

  return true;
};

const main = async () => {
  const clientStep1Response = await clientStep1();
  console.log('clientStep1Response:', clientStep1Response);
  const result = await serverStep2(clientStep1Response);
  console.log('result:', result);
};

main().catch((error) => {
  console.error('Error:', error);
  process.exit(1);
});
