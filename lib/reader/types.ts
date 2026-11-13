import { PrimitiveAccountKeyTypes } from "../types/AccountKey";

/**
 * Discriminated string union representing the cryptographic key scheme used
 * by a ZkapAccount transaction or master key slot.
 *
 * - `"webauthn"` — WebAuthn / FIDO2 passkey (secp256r1 via authenticator).
 * - `"zkOAuth"` — ZK-OAuth RS256 key with zero-knowledge proof of JWT possession.
 * - `"address"` — Plain EOA address key.
 * - `"secp256k1"` — Raw secp256k1 key (Ethereum-native curve).
 * - `"secp256r1"` — Raw secp256r1 / P-256 key.
 * - `"oauthRs256"` — Non-ZK OAuth RS256 key.
 * - `"unknown"` — Key type could not be determined from the on-chain contract.
 */
export type KeyType = "webauthn" | "zkOAuth" | "address" | "secp256k1" | "secp256r1" | "oauthRs256" | "unknown";

/**
 * Public key material and binding identifiers for a WebAuthn key slot, as
 * returned by `AccountKeyWebAuthn.getKeyData`.
 */
export interface WebAuthnKeyData {
  /** x-coordinate of the P-256 public key (hex, 32 bytes). */
  x: string;
  /** y-coordinate of the P-256 public key (hex, 32 bytes). */
  y: string;
  /** WebAuthn credential ID associated with this key (base64url, as registered). */
  credentialId: string;
  /**
   * keccak256 of the allowed origin bytes (e.g. `https://example.com`). The
   * contract computes this itself in `register()`; compare with
   * {@link originHashOf}.
   */
  allowedOriginHash: string;
  /**
   * rpIdHash the key was registered with — by WebAuthn convention SHA-256 of
   * the rpId (the first 32 bytes of `authenticatorData`). Compare with
   * {@link rpIdHashOf}.
   */
  allowedRpIdHash: string;
}

/**
 * Metadata for a single transaction key slot in a ZkapAccount.
 */
export interface TxKeyInfo {
  /** Zero-based position of this key in the `txKeyList`. */
  index: number;
  /** Address of the key logic singleton contract. */
  logicContract: string;
  /** On-chain key ID used to look up key-specific data within the logic contract. */
  keyId: number;
  /** Detected cryptographic scheme for this key slot. */
  keyType: KeyType;
  /** Present when `keyType` is `"webauthn"`; contains the raw WebAuthn key data. */
  webauthn?: WebAuthnKeyData;
}

/**
 * ZK-OAuth key data as stored by `AccountKeyZkOAuthRS256Verifier`
 * (`getData` + `getAnchor`).
 */
export interface OnchainZkKeyData {
  /** Merkle tree directory the verifier resolves JWKS roots from. */
  directory: string;
  /** Number of anchor (identity) slots. */
  n: bigint;
  /** Number of proofs required out of `n`. */
  k: bigint;
  /** Hash of the allowed audience list. */
  hAudList: bigint;
  /** Raw getAnchor() return: the registered anchor elements followed by their on-chain hash. */
  anchorWithHash: bigint[];
}

/**
 * One key of a ZkapAccount key list (master or tx), with the data its logic
 * contract holds for it. Exactly the field matching `keyType` is set:
 * `zk` for `"zkOAuth"`, `signer` for `"address"`, `webauthn` for `"webauthn"`;
 * none for any other type.
 */
export interface OnchainKeyEntry {
  /** Zero-based position in the account's key list. */
  index: number;
  /** Address of the key logic singleton contract. */
  logicContract: string;
  /** Key ID within the logic contract. */
  keyId: bigint;
  /** Weight of this key towards the list's threshold. */
  weight: number;
  /** Scheme reported by the logic contract's `keyType()`. */
  keyType: KeyType;
  zk?: OnchainZkKeyData;
  /** Signer address of an `"address"` key. */
  signer?: string;
  webauthn?: WebAuthnKeyData;
}

/** One key list of a ZkapAccount (master or tx). */
export interface OnchainKeySet {
  /** Sum of weights required. `0` for an undeployed account. */
  threshold: number;
  /** Keys in list order. */
  keys: OnchainKeyEntry[];
  /**
   * `true` when the list continues past the read window — `keys` is then not
   * the whole list and must not be treated as such.
   */
  truncated: boolean;
}

/**
 * Both key lists of a ZkapAccount, read from one consistent state.
 */
export interface OnchainKeyState {
  /**
   * The account that was read, checksummed. Anything derived from this state
   * (e.g. a rebuilt master key) applies to this account only.
   */
  account: string;
  /** `false` for an address without code (counterfactual account); both sets are then empty. */
  deployed: boolean;
  master: OnchainKeySet;
  tx: OnchainKeySet;
  /** Which transport path served the read. */
  readVia: ReadVia;
}

/**
 * The master key list of a ZkapAccount. Same data as `OnchainKeyState.master`,
 * flattened with `account`, `deployed` and `readVia`.
 */
export interface MasterKeyInfo {
  /** The account that was read, checksummed. */
  account: string;
  /** `false` for an address without code; `threshold` is then `0` and `keys` empty. */
  deployed: boolean;
  /** Sum of weights required to authorize a master-key operation. */
  threshold: number;
  keys: OnchainKeyEntry[];
  /** See {@link OnchainKeySet.truncated}. */
  truncated: boolean;
  readVia: ReadVia;
}

/**
 * How a txKey read reached the chain.
 *
 * - `"multicall"` — one `eth_call` per round through Multicall3.
 * - `"direct"` — one `eth_call` per slot/detail, in parallel. Used when the
 *   chain has no Multicall3 (or `multicallAddress: false`). On a chain that is
 *   known to have Multicall3 — every major L1/L2 — `"direct"` means the
 *   transport answered `0x` for a contract that exists, i.e. it is lying.
 */
export type ReadVia = "multicall" | "direct";

/**
 * Raw result of reading an account's txKey slots.
 */
export interface TxKeySlots {
  /**
   * `false` when `txKeyList(0)` answered with empty data, which is how a call
   * to an address without code comes back — the account is still
   * counterfactual. Note a deployed contract that is not a ZkapAccount can
   * read as `false` too, since it has no `txKeyList` either.
   */
  deployed: boolean;
  /** Occupied slots, in slot order. */
  keys: TxKeyInfo[];
  /**
   * `true` when every requested slot was occupied AND the slot just past the
   * window also held a key — there may be more keys than `maxTxKeys` allows
   * this reader to see. Do not conclude "no other keys" while this is set.
   */
  truncated: boolean;
  /** Which transport path served the read. */
  readVia: ReadVia;
}

/** Map an on-chain `keyType()` discriminant to the SDK's {@link KeyType} union. */
export function keyTypeFromPrimitive(keyType: number): KeyType {
  switch (keyType) {
    case PrimitiveAccountKeyTypes.keyAddress: return "address";
    case PrimitiveAccountKeyTypes.keySecp256k1: return "secp256k1";
    case PrimitiveAccountKeyTypes.keySecp256r1: return "secp256r1";
    case PrimitiveAccountKeyTypes.keyWebAuthn: return "webauthn";
    case PrimitiveAccountKeyTypes.keyOAuthRS256: return "oauthRs256";
    case PrimitiveAccountKeyTypes.keyZkOAuthRS256: return "zkOAuth";
    default: return "unknown";
  }
}
