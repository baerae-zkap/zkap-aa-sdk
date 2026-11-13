# @baerae/zkap-aa

[![npm version](https://img.shields.io/npm/v/@baerae/zkap-aa)](https://www.npmjs.com/package/@baerae/zkap-aa)
[![CI](https://github.com/baerae-zkap/zkap-aa-sdk/actions/workflows/dev-pr-ci.yml/badge.svg)](https://github.com/baerae-zkap/zkap-aa-sdk/actions)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](LICENSE)

TypeScript SDK for [ZKAP](https://zkap.app) smart wallets — ERC-4337 account abstraction with WebAuthn (Passkey) and ZK-OIDC (Google / Kakao) signing.

## Features

- **Passkey signing** — WebAuthn / FIDO2 credentials, no seed phrases
- **ZK-OIDC signing** — sign with Google or Kakao identity, privacy-preserving via ZK proofs
- **EOA signing** — standard private key / `ethers.Wallet` integration
- **Gas sponsorship** — verifying and ERC-20 paymaster support
- **Batch transactions** — multiple calls in a single UserOperation
- **Dual build** — CommonJS and ESM, works in Node.js and bundlers

## Installation

```bash
npm install @baerae/zkap-aa
```

`ethers` is a peer dependency — install it alongside:

```bash
npm install ethers
```

Requires Node.js >= 18.

## Quick Start

> **Prerequisites:** ZKAP wallets are ERC-4337 smart contract wallets, so before sending UserOps you need three things the SDK does not discover for you:
> - **Chain config** — an RPC URL, a bundler RPC URL, the EntryPoint address, and (only when deriving or deploying a wallet) the ZkapAccountFactory and key-logic addresses. Keep these in your own config table; see step 1.
> - **A wallet address** — an already-deployed wallet, or a counterfactual address derived with `ZkapCreator` (step 3).
> - **A signer** whose key type matches a key registered on that wallet.
>
> The first UserOp sent from a counterfactual address deploys the wallet on-chain via `initCode` — that is what `ZkapCreator` sets up.

### 1. Configure your chain

The SDK never fetches configuration — you pass addresses and endpoints in. Keep one entry per chain in your app; every sample below reads from this `CHAIN` object.

```typescript
const CHAIN = {
  chainId: 11155111,                     // Ethereum Sepolia
  rpcUrl: process.env.RPC_URL!,           // JSON-RPC node — gas estimation, nonce reads
  bundlerUrl: process.env.BUNDLER_URL!,   // ERC-4337 bundler RPC (Pimlico, Alchemy, alto, ...)
  entryPoint: '0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108', // EntryPoint v0.8

  // Only needed by the features that use them:
  zkapFactory: process.env.ZKAP_FACTORY!,               // deriving / deploying a wallet
  addressKeyLogic: process.env.ADDRESS_KEY_LOGIC!,      // building an EOA master key
  poseidonMerkleTreeDirectory: process.env.MERKLE_DIR!, // AccountKeyBuilder (zk key)
};
```

> `rpcUrl` and `bundlerUrl` are **different endpoints**. `Erc4337BundlerProvider` takes the bundler one.

This is the subset the samples below use. A production integration also needs a logic-contract address per key type it registers — `addressKeyLogic` for EOA keys, and the zkOAuth verifier or WebAuthn implementation address for those key types.

### 2. Send a transaction (EOA signer)

`ZkapBuilder` builds and signs the UserOperation; `BundlerClient` submits it and waits for the receipt.

```typescript
import {
  ZkapBuilder,
  BundlerClient,
  Erc4337BundlerProvider,
  AddressKeySigner,
} from '@baerae/zkap-aa';

const WALLET_ADDRESS = '0xYourZkapWalletAddress';
const signer = new AddressKeySigner([process.env.PRIVATE_KEY!]);

const builder = new ZkapBuilder({
  chainId: CHAIN.chainId,
  entryPoint: CHAIN.entryPoint,
  enUrl: CHAIN.rpcUrl,
});

builder
  .setSender(WALLET_ADDRESS)
  .setExecuteCallData(
    '0xRecipientAddress',
    '1000000000000000', // 0.001 ETH in wei
    '0x',               // calldata — '0x' for a plain transfer
    signer.keyTypes,    // which on-chain key verifies this op
  );

await builder.autoFillUserOp(); // nonce, gas limits and fee fields, from CHAIN.rpcUrl

// Trim preVerificationGas to what the bundler actually requires. Must run before
// getUserOpHash() — see "preVerificationGas calibration" below.
builder.applyBundlerPreVerificationGas();

const userOpHash = builder.getUserOpHash();
const signatures = await signer.signUserOpHash(userOpHash);
builder.setSignature(signer.keyTypes.map((_, i) => i), signatures);

const bundlerClient = new BundlerClient(
  new Erc4337BundlerProvider({
    rpcUrl: CHAIN.bundlerUrl,  // the BUNDLER endpoint, not CHAIN.rpcUrl
    usePimlicoFormat: true,    // Pimlico / alto want the unpacked factory+factoryData shape
  }),
);

const submittedHash = await bundlerClient.submitUserOp(
  builder.getPackedUserOp(),
  CHAIN.entryPoint,
);
console.log('Submitted:', submittedHash);

const receipt = await bundlerClient.waitForReceipt(submittedHash);
console.log('Confirmed in tx:', receipt.txHash, '— success:', receipt.success);
```

`waitForReceipt` returns a flat `UserOpReceipt` (`txHash`, `blockNumber`, `success`, `actualGasCost`, `actualGasUsed`, plus `revertReason` / `contractError` on an execution revert).

### 3. Derive a counterfactual wallet address

A ZKAP address is `CREATE2(salt, encodedMasterKey, encodedTxKey)` — it depends on the key material the wallet will be **deployed** with, not on the identity alone. Derive it from exactly the inputs you will deploy with, or you will fund an address the deploy never targets.

```typescript
import { computeSalt, ZkapCreator, AccountKeyBuilder, PrimitiveAccountKeyTypes } from '@baerae/zkap-aa';
import { ethers } from 'ethers';

// keccak256(abi.encode(aud, sub)). Pass a walletIndex of 1-255 to derive additional
// independent wallets for the same identity; 0 and omitted both mean the default wallet.
const salt = computeSalt(aud, sub);

// For a wallet controlled by an EOA:
const encodedMasterKey = new AccountKeyBuilder(1, [
  {
    keyType: PrimitiveAccountKeyTypes.keyAddress,
    logicContract: CHAIN.addressKeyLogic, // on-chain verifier for keyAddress
    weight: 1,
    keyData: { signerAddress: new ethers.Wallet(process.env.PRIVATE_KEY!).address },
  },
]).getEncodedKey();

const creator = new ZkapCreator({
  chainId: CHAIN.chainId,
  entryPoint: CHAIN.entryPoint,
  zkapFactory: CHAIN.zkapFactory,
  enUrl: CHAIN.rpcUrl,
  salt,
  encodedMasterKey,
  encodedTxKey: '0x', // '0x' when the wallet has no separate transaction key at deploy
});

const address = await creator.deriveZkapAddress(); // factory.calcAccountAddress eth_call
```

`ZkapCreator` extends `ZkapBuilder`, and `deriveZkapAddress()` has already set both `initCode` and `sender` — so the same instance sends the wallet's first UserOp, and that op deploys it. Use `ZkapCreator` for the first op and plain `ZkapBuilder` after that.

A ZKAP wallet with a zk key is deployed with the **initial cosigned master key** instead — build it with `buildInitialMasterKey` and pass that as `encodedMasterKey`. See [Cosigned master key](#cosigned-master-key).

## Signers

### AddressKeySigner

Signs with one or more EOA private keys. Useful for testing or server-side flows.

```typescript
import { AddressKeySigner } from '@baerae/zkap-aa';

const signer = new AddressKeySigner([privateKey]);
```

### PasskeySigner

Signs with a WebAuthn credential. Provide a `verifyWithPasskey` callback that calls
`navigator.credentials.get` and returns the assertion response. The txKey slot the
signature goes into is not always 0 — read it with
`(await reader.getPasskeys(address, { credentialId })).mine?.index`
(see [Reading account state](#reading-account-state)).

```typescript
import { PasskeySigner } from '@baerae/zkap-aa';

const signer = new PasskeySigner(
  credentialId,
  async (credentialId, challenge) => {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: Buffer.from(challenge, 'base64url'),
        allowCredentials: [{ type: 'public-key', id: Buffer.from(credentialId, 'base64url') }],
        userVerification: 'required',
      },
    }) as PublicKeyCredential;

    const response = assertion.response as AuthenticatorAssertionResponse;
    return {
      response: {
        signature: Buffer.from(response.signature).toString('base64url'),
        authenticatorData: Buffer.from(response.authenticatorData).toString('base64url'),
        clientDataJSON: Buffer.from(response.clientDataJSON).toString('base64url'),
      },
    };
  }
);
```

### ZkOidcSigner

Signs with a ZK proof of an OIDC id_token. The user's identity is never revealed
on-chain — the proof shows they hold a valid token without exposing it.

This signer performs **no network calls and never touches an id_token**. It takes
a finished proof and encodes it into the UserOperation signature. Producing that
proof — collecting the logins, fetching JWKS, running the circuit — is the job of
whatever backend you operate; the raw id_token must never reach the client.

```typescript
import { ZkOidcSigner } from '@baerae/zkap-aa';

const signer = new ZkOidcSigner();

signer.setProofData({
  // uint256[6]: hanchor, h_ctx, root, h_sign_userop, lhs, h_aud_list
  sharedInputs,
  // K entries each, one per proof
  jwtExpList,
  partialRhsList,
  // K x 8 Groth16 proofs
  proofs,
});

// signUserOpHash re-checks the binding itself:
//   sharedInputs[3] === userOpHash mod SNARK_SCALAR_FIELD
// so a proof cannot be replayed against a different UserOperation.
const signature = await signer.signUserOpHash(userOpHash);

// Drop the proof once used — it is single-use material.
signer.destroy();
```

All values are decimal strings and are range-checked against the BN254 scalar
field; a malformed proof throws `AaOperationError` with
`SIGNER_PROOF_INVALID` rather than producing an unusable signature.

## Batch transactions

`setExecuteBatchCallData` puts several calls into one UserOperation. Everything else — `autoFillUserOp`, PVG calibration, signing, submission — is identical to Quick Start step 2.

```typescript
builder
  .setSender(WALLET_ADDRESS)
  .setExecuteBatchCallData(
    [tokenAddress, recipient],  // to
    ['0', '1000000000000000'],  // value, in wei
    [approveCallData, '0x'],    // data
    signer.keyTypes,
  );
```

All three arrays must be the same length and in the same order — the calls execute sequentially, and a revert in any one reverts the whole UserOperation.

## preVerificationGas calibration

`autoFillUserOp()` leaves a conservative `preVerificationGas`. EntryPoint charges PVG in FULL — anything declared above the bundler's floor is paid and never refunded, and anything below it is rejected at submission — so `applyBundlerPreVerificationGas()` sets what the bundler actually requires plus a margin (default `x1.10 + 15,000`).

```typescript
await builder.autoFillUserOp();

// ORDER MATTERS:
//  1. after autoFillUserOp() — nonce / initCode / callData / signature must be final;
//  2. after the final callGasLimit — the EIP-7623 branch reads it;
//  3. BEFORE getUserOpHash() — preVerificationGas is part of the hash.
builder.applyBundlerPreVerificationGas();

const userOpHash = builder.getUserOpHash(); // safe to sign now
```

The signature present when you call it must already have the byte length of the REAL signature — that is what the dummy signature `autoFillUserOp()` installs is for. The bundler recomputes its floor from the bytes you submit, so a length that changes between calibration and submission invalidates the result.

> **Not compatible with a builder-configured paymaster.** When `paymaster` is set on `ZkapBuilder`, `autoFillUserOp()` performs the paymaster handoff itself and the paymaster signs a digest that includes `preVerificationGas`. Changing PVG afterwards invalidates that signature. Use a conservative multiplier on paymaster-sponsored ops instead.

Calibrated against Pimlico alto's **execution** component only. On chains where alto adds an L2 data-availability component (`op-stack`, `arbitrum`, `mantle`, `etherlink`, `citrea`, `monad`) supply it explicitly, or keep a conservative multiplier:

```typescript
builder.applyBundlerPreVerificationGas({ extraComponent: 40_000n });
```

Other options: `marginPercent` (default `110n`) and `marginAbsolute` (default `15000n`). The underlying functions are exported for direct use — `calcAltoRequiredPvg(userOp, opts)` and `calibrateBundlerPvg(userOp, opts)`.

## Gas Sponsorship (Paymaster)

Pass a `paymaster` config to `ZkapBuilder` to sponsor gas or accept ERC-20 payment:

```typescript
import { ZkapBuilder, PaymasterMode } from '@baerae/zkap-aa';

const builder = new ZkapBuilder({
  chainId: CHAIN.chainId,
  entryPoint: CHAIN.entryPoint,
  enUrl: CHAIN.rpcUrl,
  paymaster: {
    serverUrl: 'https://paymaster.example.com',
    paymasterAddress: '0xPaymasterContractAddress',
    chainId: CHAIN.chainId,
    mode: PaymasterMode.VERIFYING, // or PaymasterMode.ERC20
    // tokenAddress: '0x...'       // required for ERC20 mode
  },
});
```

`autoFillUserOp()` fetches and installs the paymaster signature itself when this config is present — do not call `applyBundlerPreVerificationGas()` on a sponsored op (see above).

## Reading account state

`AccountReader` reads a deployed ZkapAccount over plain JSON-RPC — no bundler, no server. Give it exactly one transport:

```typescript
import { AccountReader } from '@baerae/zkap-aa';

// 1. Let the reader build an ethers JsonRpcProvider.
//    chainId is optional but worth it — it sets staticNetwork and skips the eth_chainId probe.
const reader = new AccountReader({ rpcUrl: CHAIN.rpcUrl, chainId: CHAIN.chainId });

// 2. Reuse an ethers Provider you already have (BrowserProvider, a shared JsonRpcProvider, …).
const reader = new AccountReader({ provider });

// 3. Bring your own eth_call — a proxy, a relay, a rate-limited gateway.
const reader = new AccountReader({
  call: ({ to, data }) => proxy.ethCall({ to, data }), // must throw on any error — see below
});

await reader.isDeployed(WALLET_ADDRESS);   // false for a counterfactual address (forms 1 and 2 only)
await reader.getBalance(WALLET_ADDRESS);   // native balance in wei, as a string (forms 1 and 2 only)
```

`isDeployed()` and `getBalance()` need `eth_getCode` / `eth_getBalance`, so they work only with the first two forms; in `call` mode read `deployed` from `readTxKeySlots()` or `getPasskeys()` instead.

A `call` implementation **must throw** on a transport failure, HTTP error or JSON-RPC `error` — never resolve to `"0x"`. The reader treats `"0x"` as "a successful call to an address without code", which is how it detects an undeployed wallet and a chain without Multicall3; a transport that swallows errors into `"0x"` would make a dead node look like a missing wallet. `ethers.Provider.call` and any proxy that throws on a JSON-RPC `error` satisfy this.

### Passkeys registered as txKeys

```typescript
const result = await reader.getPasskeys(WALLET_ADDRESS, {
  service: {
    rpId: 'zkap.app',
    // The same app registers under a different origin per platform — list every one it signs from.
    origins: ['https://zkap.app', 'android:apk-key-hash:<base64url-sha256-of-signing-cert>'],
  },
  credentialId: localPasskeyId,  // base64url — the value you hand to PasskeySigner
  knownRpIds: ['pay.ifez.app'],  // optional: label other services' keys with their rpId
});

if (!result.deployed) { /* no wallet yet — not "no keys" */ }

result.mine?.index           // slot to pass to ZkapBuilder.setSignature([index], …)
result.myService             // rpId AND origin match
result.sameRpIdOtherOrigin   // same rpId, an origin you did not list (e.g. another platform of your app)
result.otherServices         // another service's passkeys
result.passkeys[0].publicKey // { x, y, cose, jwk } — hex coordinates, COSE (ES256) bytes, JWK
result.unreadable            // WebAuthn slots whose key data failed to decode — non-empty ⇒ don't conclude "not registered"
result.truncated             // more slots than the read window ⇒ don't conclude "no other keys"
result.readVia               // "multicall" | "direct" — "direct" on a chain that has Multicall3 means the transport misbehaved
```

- "My service" is strict: a key counts only when its `allowedRpIdHash` equals `sha256(rpId)` **and** its `allowedOriginHash` equals `keccak256(origin)` for one of `origins`. `origins` takes a string or an array.
- Any number of keys costs two `eth_call`s via Multicall3. On a chain without Multicall3 the reader confirms its absence with `eth_getCode` (provider modes) and falls back to one call per slot, in parallel; `readVia` tells you which path served the read.
- To rebuild the txKey list with `TxKeyHelper.buildReplaceTxKeyByRpId`, pass `result.txKeys` straight in and resolve origins from the classified keys — `(hash) => result.passkeys.find((k) => k.originHash === hash)?.origin`. The helper needs the plaintext origin of **every** WebAuthn key; a foreign key whose origin you do not know (neither in `service.origins` nor `knownOrigins`) cannot be re-encoded.

### Raw txKey slots

```typescript
import { rpIdHashOf } from '@baerae/zkap-aa';

await reader.readTxKeySlots(WALLET_ADDRESS);   // { deployed, keys, truncated, readVia }
await reader.getTxKeyList(WALLET_ADDRESS);     // keys only — [] for an undeployed account
await reader.getMasterKeyInfo(WALLET_ADDRESS); // { account, deployed, threshold, keys, truncated, readVia }
await reader.readKeyState(WALLET_ADDRESS);     // master and tx lists from one consistent state

// WebAuthn keys registered for one relying party
await reader.findTxKeysByRpId(WALLET_ADDRESS, rpIdHashOf('zkap.app'));
```

A key list ends at the first index whose getter **reverts without data** — what the account's public array getters answer past the end of the list — or reverts with `Panic(0x32)` (array index out of bounds). The two paths differ at a slot that holds the zero address: `readTxKeySlots` (and `getTxKeyList`, `getPasskeys`, `findTxKeysByRpId`) ends its list there, while `readKeyState` (and `getMasterKeyInfo`, `classifyMasterKey`) throws, because it reads every listed key's logic contract. Any other failed slot throws instead of ending the list: `AaFetchError` — `TRANSPORT` when the node cannot be reached, `RESPONSE_SHAPE` when it answers with undecodable data, with other revert data (`Error(string)`, another `Panic`), or with a failure that carries no revert data at all (a node error, such as a rate limit, on the per-call path). An empty array means the account has no keys, never that the RPC failed.

On a chain without Multicall3 the reader calls each getter on its own, and tells a revert from a node error through the error ethers throws: a revert carries its revert data in `err.data` (`"0x"` when there is none), a node error has `err.data === null`. That holds for a node that answers a data-less revert with `data: "0x"` (checked against a local anvil node); a node that omits the `data` field for such a revert looks like a node error here, and every key list read on this path then throws rather than returning a short list. Chains with Multicall3 are not affected. A custom `isRevertError` must keep that distinction — return `true` only for a contract revert and pass the revert data through as the error's `data` — or every list end reads as a failure (data dropped) or a node error reads as a list end (`data: "0x"` invented). Reverts are routine on this path: `readKeyState` asks each key's logic contract for the getters of every key type, and the ones that do not match its type revert.

On an **undeployed** account `getTxKeyList` returns `[]`, and `getMasterKeyInfo` resolves with `deployed: false`, `threshold: 0` and no keys. Check `deployed` (on `readTxKeySlots()`, `getMasterKeyInfo()` or `readKeyState()`) to tell "no keys" apart from "no wallet".

`getMasterKeyInfo` returns the same data as `readKeyState().master`: every master key as an `OnchainKeyEntry` — `logicContract`, `keyId`, `weight`, `keyType`, and the data its logic contract holds (`zk`, `signer` or `webauthn`, matching `keyType`). `zk.anchorWithHash` is the verifier's `getAnchor()` return: the registered anchor followed by one on-chain hash. Master keys are read over a window of 5, txKeys over `maxTxKeys`; `truncated: true` means the list continues past it.

### Public key formats

```typescript
import { toCosePublicKey, toJwkPublicKey, rpIdHashOf, originHashOf } from '@baerae/zkap-aa';

toCosePublicKey({ x, y });        // COSE_Key (ES256) hex — what a WebAuthn registration returns as credentialPublicKey
toJwkPublicKey({ x, y });         // { kty: 'EC', crv: 'P-256', x, y } with base64url coordinates
rpIdHashOf('zkap.app');           // sha256(rpId)      — what the chain stores as allowedRpIdHash
originHashOf('https://zkap.app'); // keccak256(origin) — what the chain stores as allowedOriginHash (keccak, not SHA-256)
```

## Cosigned master key

A ZKAP wallet's master key pairs the zk key with the service's cosigner key — an address key — so every master key operation (`updateKeys`, `updateMasterKey`, `updateTxKey`) carries two signatures. The SDK builds, parses and reads two fixed layouts:

| Layout | `[0]` zk key | `[1]` cosigner (address key) | `[2]` passkey | Threshold |
|---|---|---|---|---|
| Initial — installed at deployment (`INITIAL_MASTER_KEY`) | 1-of-1, weight 1 | weight 1 | — | 2 |
| Operational — installed by onboarding (`OPERATIONAL_MASTER_KEY`) | 3-of-6, weight 2 | weight 1 | weight 1, `requireUV = false` | 3 |

The initial key needs both signatures. The operational key is satisfied by zk + cosigner or zk + passkey. The positions are exported as `MASTER_KEY_INDEX` (`{ zk: 0, cosigner: 1, passkey: 2 }`).

### Building the keys

```typescript
import {
  buildInitialMasterKey,
  buildOperationalMasterKey,
  buildPasskeyTxKey,
  rpIdHashOf,
  type PasskeyKeyInput,
} from '@baerae/zkap-aa';

const contracts = {
  zkVerifier1of1: '0x…',      // zk verifier deployed for the 1-of-1 parameters
  zkVerifier3of6: '0x…',      // zk verifier deployed for the 3-of-6 parameters
  addressKeyLogic: '0x…',
  webAuthnLogic: '0x…',
  merkleTreeDirectory: '0x…',
};
const COSIGNER = '0x…';       // the service's cosigner address

// Computed by your backend — this package does not compute hAudList or the anchor.
const initialZk = { hAudList: '0x…', anchor: ['0x…'] };                       // 1 anchor element
const operationalZk = { hAudList: '0x…', anchor: ['0x…', '0x…', '0x…', '0x…'] }; // 4 anchor elements

// A passkey, in either form. Both encode to the same bytes.
const passkey: PasskeyKeyInput = {
  credentialPubkey: '0x…',              // COSE_Key bytes from the WebAuthn registration
  credentialId,                         // base64url, as the authenticator returned it
  origin: 'https://wallet.example.com',
  rpId: 'wallet.example.com',           // hashed here with SHA-256
};
const samePasskey: PasskeyKeyInput = {
  x: '0x…', y: '0x…',                   // 32-byte P-256 coordinates
  credentialId,
  origin: 'https://wallet.example.com',
  rpIdHash: rpIdHashOf('wallet.example.com'),
};

const initialMasterKey = buildInitialMasterKey({ contracts, zk: initialZk, cosigner: COSIGNER });
const operationalMasterKey = buildOperationalMasterKey({ contracts, zk: operationalZk, cosigner: COSIGNER, passkey });
const passkeyTxKey = buildPasskeyTxKey({ contracts, passkey });
```

Each builder takes only the contract addresses its layout uses; extra fields in `contracts` are ignored. Input rules — a violation throws `AaOperationError` instead of encoding a key that cannot sign:

- Addresses must be well-formed and non-zero.
- Numbers (`hAudList`, anchor elements) are a `bigint`, a `0x`-prefixed hex string or a decimal string of digits only. JS numbers and hex without `0x` are rejected. Each must be below the BN254 scalar field size, and `hAudList` must be non-zero.
- The anchor has exactly 1 element for the initial key and 4 for the operational key.
- A passkey has exactly one public key form (`credentialPubkey`, or `x` and `y`) and `rpId`, `rpIdHash` or both — given both, `rpIdHash` must equal `sha256(rpId)`. `rpId` is a bare host name (`wallet.example.com`); a value with `/` or `:` — an origin — is rejected. `credentialId` and `origin` are non-empty. User verification is never required: `requireUV` is always encoded as `false`, and may be passed only as `false`.

`encodePasskeyKeyInitData(passkey)` returns the passkey's init data alone — the same bytes the operational key's `[2]` and the passkey tx key carry.

> **`TxKeyHelper` encodes passkeys differently.** It registers a new key with `requireUV = true` unless told otherwise, and always re-encodes existing keys with `requireUV = true` (the chain does not expose the flag). Its output therefore differs from `buildPasskeyTxKey` and from the passkey entry of the operational master key. Use `buildPasskeyTxKey` for the tx key that goes with the operational master key.

The strict parsers `parseInitialMasterKey`, `parseOperationalMasterKey` and `parsePasskeyTxKey` read a blob back and throw unless it has the layout's shape and the builder reproduces it byte for byte. They do not check which contracts or cosigner it names — compare the returned values yourself. `decodeKeySet` decodes any key set without a shape check.

### Deploying with the initial master key

The initial master key is part of the wallet address (`CREATE2(salt, encodedMasterKey, encodedTxKey)`), so derive the address from the builder's output and deploy with exactly the same bytes. The wallet's first op typically installs the operational master key and the passkey tx key with `updateKeys`, signed by the initial master key:

```typescript
import {
  ZkapCreator,
  MASTER_OP_KEY_INDEX_LIST,
  createDummyZkSignature,
  createDummyCosignSignature,
} from '@baerae/zkap-aa';

const creator = new ZkapCreator({
  chainId: CHAIN.chainId,
  entryPoint: CHAIN.entryPoint,
  zkapFactory: CHAIN.zkapFactory,
  enUrl: CHAIN.rpcUrl,
  salt,
  encodedMasterKey: initialMasterKey,
  encodedTxKey: '0x',
});
const address = await creator.deriveZkapAddress();

creator.setUpdateKeysCallData({ encodedMasterKey: operationalMasterKey, encodedTxKey: passkeyTxKey });

// Dummy with the real signature's shape: the initial key's zk signature carries 1 proof.
creator.setSignature([...MASTER_OP_KEY_INDEX_LIST], [createDummyZkSignature(1), createDummyCosignSignature()]);
await creator.autoFillUserOp();
creator.applyBundlerPreVerificationGas();

const userOpHash = creator.getUserOpHash();
const [zkSignature] = await zkSigner.signUserOpHash(userOpHash); // ZkOidcSigner, 1-proof data
const cosignerSignature = await requestCosignature(userOpHash);  // your service's cosigner, 65 bytes
creator.setSignature([...MASTER_OP_KEY_INDEX_LIST], [zkSignature, cosignerSignature]);
```

### Master op signatures

- Key indices are `MASTER_OP_KEY_INDEX_LIST` (`[0, 1]`): the zk signature first, then the cosigner's 65-byte ECDSA signature over `userOpHash` (the format `AddressKeySigner` produces). The full signature is 1120 bytes with one proof (initial key) and 1760 bytes with three (operational key) — `MASTER_OP_SIGNATURE_LENGTH`.
- Put in only the signatures of the keys needed to reach the threshold. A well-formed signature from the wrong signer only fails to count, but a **malformed** one — an ECDSA signature of the wrong length, an undecodable or invalid proof — makes verification revert, and the whole op fails even when the other signatures would reach the threshold.
- To sign the operational key with zk + passkey instead, use indices `[0, 2]` and pass `[PrimitiveAccountKeyTypes.keyZkOAuthRS256, PrimitiveAccountKeyTypes.keyWebAuthn]` as the setter's second argument. Keep the zk key first in both lists.
- `setSignature` throws when the two lists differ in length or `keyIndexList` repeats an index.

### Dummy signature and gas

- `setUpdateKeysCallData`, `setUpdateMasterKeyCallData` and `setUpdateTxKeyCallData` set the signer key types to `[keyZkOAuthRS256, keyAddress]` (`MASTER_OP_SIGNER_KEY_TYPES`) unless you pass a second argument. For a wallet whose master key is still a zk key alone, pass `[PrimitiveAccountKeyTypes.keyZkOAuthRS256]`. The key types decide the `verificationGasLimit` that `autoFillUserOp()` computes.
- Before `autoFillUserOp()`, install a dummy with the real signature's shape, as above. Its bytes equal `createDummyMasterOpSignature(n)` — `n` is 1 for the initial key, 3 for the operational key. The proof count in the dummy picks the zk verification budget, and its length is what `applyBundlerPreVerificationGas()` calibrates against.
- `updateKeys` callGasLimit: with initCode (wallet not deployed yet) `ZkapBuilder.UPDATE_KEYS_CALL_GAS + GAS_BUFFER` = 1,825,000; on a deployed wallet the node's estimate × 1.2 + 25,000. Under-declaring reverts the execution on-chain and the op is still charged.

### Classifying a wallet's master key

```typescript
const expected = { contracts, cosigner: COSIGNER };
const { kind, reasons, state } = await reader.classifyMasterKey(WALLET_ADDRESS, expected);
```

| `kind` | Meaning |
|---|---|
| `"undeployed"` | No code at the address yet. |
| `"initial"` | The initial master key with the expected contracts and cosigner, and no tx key — onboarding has not run. |
| `"operational"` | The operational master key with the expected contracts and cosigner. Tx keys are not looked at. |
| `"other"` | Anything else, including a truncated read. `reasons` lists every failed condition with its expected and actual value. |

A failed read throws `AaFetchError`; it is never reported as `"other"`. Addresses compare case-insensitively. `"operational"` checks the layout, not every value: such a state can still fail reconstruction when its on-chain anchor or `hAudList` is out of the builder's range. The pure function `classifyMasterKey(state, expected)` classifies a state you read with `readKeyState()`.

### Rebuilding the operational master key

`reconstructOperationalMasterKey` rebuilds a wallet's operational master key with a new passkey at `[2]` — to replace a lost passkey, for example. `hAudList` and the anchor exist only on chain, so it takes them from the read state; contract addresses and the cosigner come from your parameters.

```typescript
import {
  AccountReader,
  ZkapBuilder,
  buildPasskeyTxKey,
  MASTER_OP_KEY_INDEX_LIST,
  createDummyZkSignature,
  createDummyCosignSignature,
  type MasterKeyExpectation,
  type PasskeyKeyInput,
} from '@baerae/zkap-aa';

// CHAIN: see "Configure your chain".
const WALLET_ADDRESS = '0x…';  // the wallet whose passkey is replaced
const COSIGNER = '0x…';        // the service's cosigner address
const newCredentialId = '…';   // base64url credential id of the new passkey

const reader = new AccountReader({ rpcUrl: CHAIN.rpcUrl, chainId: CHAIN.chainId });
const contracts = {
  zkVerifier1of1: '0x…',
  zkVerifier3of6: '0x…',
  addressKeyLogic: '0x…',
  webAuthnLogic: '0x…',
  merkleTreeDirectory: '0x…',
};
const expected: MasterKeyExpectation = { contracts, cosigner: COSIGNER };
// The replacement passkey, from its WebAuthn registration.
const newPasskey: PasskeyKeyInput = {
  credentialPubkey: '0x…',
  credentialId: newCredentialId,
  origin: 'https://wallet.example.com',
  rpId: 'wallet.example.com',
};

const { encodedMasterKey, state } = await reader.reconstructOperationalMasterKey(WALLET_ADDRESS, {
  ...expected,
  passkey: newPasskey,
});

const builder = new ZkapBuilder({ chainId: CHAIN.chainId, entryPoint: CHAIN.entryPoint, enUrl: CHAIN.rpcUrl });
builder
  .setSender(state.account) // the result is valid for this wallet only
  .setUpdateKeysCallData({ encodedMasterKey, encodedTxKey: buildPasskeyTxKey({ contracts, passkey: newPasskey }) });
// The operational key's zk signature carries 3 proofs.
builder.setSignature([...MASTER_OP_KEY_INDEX_LIST], [createDummyZkSignature(3), createDummyCosignSignature()]);
```

**A wrong blob locks the wallet's master key for good** — it installs a master key no zk proof can satisfy. So:

- It throws `AaOperationError` (`INPUT_INVALID`) unless the state classifies as `"operational"` against your `contracts` and `cosigner`. There are no defaults and no partial matches.
- The result is valid only for the wallet at `state.account`. Submitted to any other wallet it locks that wallet's master key — check that the op's sender is `state.account`.
- The result is only as current as the read. Use it right after reading, and re-check the wallet's key state before submitting; that check is yours.

The pure function `reconstructOperationalMasterKey(state, params)` does the same for a state you read with `readKeyState()`.

### Checking your own encoder against the vectors

The package ships known-answer vectors that the account contracts accepted on a local test chain, produced by an encoder independent of this package. Use them to test an implementation of your own (another language, a backend):

CommonJS:

```javascript
const assert = require('node:assert');
const vectors = require('@baerae/zkap-aa/fixtures/master-key-cosign-vectors.json');

const { contracts, initialMaster, operationalMaster, cosigner, passkey } = vectors.inputs;
// passkey carries x, y, credentialId, origin, rpId, rpIdHash (= sha256(rpId)) and requireUV: false.

assert.equal(myEncodeInitialMasterKey(contracts, initialMaster.zk, cosigner), vectors.outputs.initialMaster);
assert.equal(
  myEncodeOperationalMasterKey(contracts, operationalMaster.zk, cosigner, passkey),
  vectors.outputs.operationalMaster,
);
```

ES modules:

```javascript
import assert from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const vectors = require('@baerae/zkap-aa/fixtures/master-key-cosign-vectors.json');
// Or, where your Node.js version supports import attributes:
// import vectors from '@baerae/zkap-aa/fixtures/master-key-cosign-vectors.json' with { type: 'json' };

const { contracts, operationalMaster, cosigner, passkey } = vectors.inputs;
assert.equal(
  myEncodeOperationalMasterKey(contracts, operationalMaster.zk, cosigner, passkey),
  vectors.outputs.operationalMaster,
);
```

The SDK's own builders take the vector's records as they are, e.g. `buildOperationalMasterKey({ contracts, zk: operationalMaster.zk, cosigner, passkey })` returns `outputs.operationalMaster`.

- `inputs` — integers are decimal strings, bytes `0x` hex. `contracts` are addresses of the local test deployment: inputs to the encoding, not addresses of any live network.
- `outputs.initialMaster`, `operationalMaster`, `txKey` — the encoded keys. `reconstructedMaster` and `newTxKey` are the operational key and tx key with `inputs.newPasskey`.
- `outputs.onchainGetAnchor` — the verifier's `getAnchor()` return for the operational zk key (the anchor, then its on-chain hash). `outputs.walletAddress` — `calcAccountAddress(salt, initialMaster, 0x)` on that deployment. `outputs.signatureLength` — 1120 and 1760.
- The cosigner and passkeys are fixed, publicly known test keys. Never use them outside tests.

## Bundler Providers

```typescript
import { Erc4337BundlerProvider, BundlerClient } from '@baerae/zkap-aa';

// Any ERC-4337 JSON-RPC bundler (Pimlico, Alchemy, Stackup, self-hosted alto).
const provider = new Erc4337BundlerProvider({ rpcUrl: CHAIN.bundlerUrl });

// Pimlico / alto expect the unpacked v0.7+ shape — factory + factoryData instead of
// initCode, and individual gas fields instead of packed bytes32 values.
const pimlico = new Erc4337BundlerProvider({
  rpcUrl: 'https://public.pimlico.io/v2/11155111/rpc',
  usePimlicoFormat: true,
});

const bundlerClient = new BundlerClient(provider);
```

`Erc4337BundlerProvider` additionally exposes `estimateUserOpGas(packedUserOp, entryPoint)` for bundlers that implement `eth_estimateUserOperationGas`. It is not part of the `BundlerProvider` interface, so call it on the provider directly.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[ISC](LICENSE) — © 2026 baerae-zkap
