import { ethers } from "ethers";
import { AccountKeyBuilder } from "../builders/AccountKeyBuilder";
import { AaOperationError, AaOperationErrorCode, type ZkapAaOperationErrorCode } from "../errors";
import { BN254_FR } from "../utils/crypto";
import { encodeWebAuthnKeyInitData, rpIdHashOf } from "../utils/webauthnKey";
import {
  INITIAL_MASTER_PROFILE,
  OPERATIONAL_MASTER_PROFILE,
  PASSKEY_TX_PROFILE,
  type KeySetProfile,
  type MasterKeyProfile,
} from "./profiles";

/**
 * An unsigned integer input: a `bigint`, a `0x`-prefixed hex string, or a decimal
 * string (digits only). JS numbers and hex without `0x` are rejected so a value such
 * as `"1234"` can never be read in two different bases.
 */
export type UintInput = bigint | string;

/** zk key values the caller computed (this package does not compute them). */
export interface ZkKeyInput {
  /** Hash of the allowed audience list. Non-zero, below the BN254 scalar field size. */
  hAudList: UintInput;
  /** Anchor elements, each below the BN254 scalar field size. Length is fixed per layout. */
  anchor: readonly UintInput[];
}

/**
 * A passkey (WebAuthn P-256 credential) to register.
 *
 * - Public key: either `credentialPubkey` (COSE_Key bytes from a registration) or the
 *   affine coordinates `x`, `y` (32-byte hex each). Both paths encode to the same bytes.
 * - Relying party: `rpId` (hashed here with SHA-256), `rpIdHash` (32-byte hex), or both —
 *   then `rpIdHash` must equal `sha256(rpId)`. `rpId` is a bare host name such as
 *   `"wallet.example.com"`; a value containing `/` or `:` (an origin) is rejected.
 *
 * User verification is never required (`requireUV = false`). `requireUV` may be given
 * only as `false`, so a record that carries it (like the known-answer vectors) can be
 * passed as is.
 */
export type PasskeyKeyInput = (
  | { credentialPubkey: string; x?: never; y?: never }
  | { x: string; y: string; credentialPubkey?: never }
) & {
  /** Credential id as returned by the authenticator (base64url). Non-empty. */
  credentialId: string;
  /** Origin the assertion is produced for. Non-empty. */
  origin: string;
  /** Only `false` is accepted; omit it. */
  requireUV?: false;
} & ({ rpId: string; rpIdHash?: string } | { rpIdHash: string; rpId?: string });

/** Contracts referenced by the initial master key. */
export interface InitialMasterKeyContracts {
  /** zk-OAuth verifier deployed for the 1-of-1 parameters. */
  zkVerifier1of1: string;
  addressKeyLogic: string;
  merkleTreeDirectory: string;
}

/** Contracts referenced by the operational master key. */
export interface OperationalMasterKeyContracts {
  /** zk-OAuth verifier deployed for the 3-of-6 parameters. */
  zkVerifier3of6: string;
  addressKeyLogic: string;
  webAuthnLogic: string;
  merkleTreeDirectory: string;
}

export interface InitialMasterKeyParams {
  contracts: InitialMasterKeyContracts;
  zk: ZkKeyInput;
  /** Cosigner address registered as the address key. */
  cosigner: string;
}

export interface OperationalMasterKeyParams {
  contracts: OperationalMasterKeyContracts;
  zk: ZkKeyInput;
  /** Cosigner address registered as the address key. */
  cosigner: string;
  passkey: PasskeyKeyInput;
}

export interface PasskeyTxKeyParams {
  contracts: { webAuthnLogic: string };
  passkey: PasskeyKeyInput;
}

const BYTES32_HEX = /^0x[0-9a-fA-F]{64}$/;
const HEX_BYTES = /^0x(?:[0-9a-fA-F]{2})+$/;

function fail(code: ZkapAaOperationErrorCode, operation: string, message: string, cause?: unknown): never {
  throw new AaOperationError({ code, operation, message, cause });
}

function requireAddress(value: unknown, field: string, operation: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value) || !ethers.isAddress(value)) {
    fail(AaOperationErrorCode.INPUT_INVALID_ADDRESS, operation, `${field}: invalid address "${String(value)}"`);
  }
  if (BigInt(value) === 0n) {
    fail(AaOperationErrorCode.INPUT_INVALID_ADDRESS, operation, `${field}: zero address is not allowed`);
  }
  return ethers.getAddress(value);
}

function toFieldElement(value: unknown, field: string, operation: string): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") {
    parsed = value;
  } else if (typeof value === "string" && (/^0x[0-9a-fA-F]+$/.test(value) || /^\d+$/.test(value))) {
    parsed = BigInt(value);
  } else {
    fail(
      AaOperationErrorCode.INPUT_INVALID_FORMAT,
      operation,
      `${field}: expected a bigint, a 0x-prefixed hex string or a decimal string, got ${typeof value} "${String(value)}"`
    );
  }
  if (parsed < 0n || parsed >= BN254_FR) {
    fail(AaOperationErrorCode.CRYPTO_FIELD_RANGE, operation, `${field}: must be below the BN254 scalar field size`);
  }
  return parsed;
}

function requireNonEmptyString(value: unknown, field: string, operation: string): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(AaOperationErrorCode.INPUT_INVALID, operation, `${field}: must be a non-empty string`);
  }
  return value;
}

function encodeKeySet(profile: KeySetProfile, logicList: string[], initDataList: string[]): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint8", "address[]", "bytes[]", "uint8[]"],
    [profile.threshold, logicList, initDataList, profile.slots.map((slot) => slot.weight)]
  );
}

/** `AccountKeyZkOAuthRS256Verifier.register` init data: `abi.encode(bytes abi.encode(n, k, hAudList, anchor), address directory)`. */
function encodeZkKeyInitData(
  profile: MasterKeyProfile,
  zk: ZkKeyInput,
  directory: string,
  operation: string
): string {
  if (zk === null || typeof zk !== "object") {
    fail(AaOperationErrorCode.INPUT_INVALID, operation, "zk: expected { hAudList, anchor }");
  }
  const hAudList = toFieldElement(zk.hAudList, "zk.hAudList", operation);
  if (hAudList === 0n) {
    fail(AaOperationErrorCode.INPUT_INVALID, operation, "zk.hAudList: must be non-zero");
  }
  if (!Array.isArray(zk.anchor)) {
    fail(AaOperationErrorCode.INPUT_INVALID_FORMAT, operation, "zk.anchor: expected an array");
  }
  if (zk.anchor.length !== profile.zk.anchorLength) {
    fail(
      AaOperationErrorCode.INPUT_OUT_OF_RANGE,
      operation,
      `zk.anchor: the ${profile.name} needs ${profile.zk.anchorLength} anchor element(s), got ${zk.anchor.length}`
    );
  }
  // Array.from visits every index; `.map` would skip the holes of a sparse array.
  const anchor = Array.from(zk.anchor, (element, i) => toFieldElement(element, `zk.anchor[${i}]`, operation));
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const keyData = abiCoder.encode(
    ["uint256", "uint256", "uint256", "uint256[]"],
    [profile.zk.n, profile.zk.k, hAudList, anchor]
  );
  return abiCoder.encode(["bytes", "address"], [keyData, directory]);
}

/** `AccountKeyAddress.register` init data: `abi.encode(address signer)`. */
function encodeCosignerKeyInitData(cosigner: string): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(["address"], [cosigner]);
}

function passkeyInitData(passkey: PasskeyKeyInput, operation: string): string {
  if (passkey === null || typeof passkey !== "object") {
    fail(AaOperationErrorCode.INPUT_INVALID, operation, "passkey: expected an object");
  }
  const input = passkey as Record<string, unknown>;
  const credentialId = requireNonEmptyString(input.credentialId, "passkey.credentialId", operation);
  const origin = requireNonEmptyString(input.origin, "passkey.origin", operation);
  if (input.requireUV !== undefined && input.requireUV !== false) {
    fail(
      AaOperationErrorCode.INPUT_UNSUPPORTED,
      operation,
      "passkey.requireUV: user verification is never required for this key; omit the field"
    );
  }

  const hasRpId = input.rpId !== undefined;
  const hasRpIdHash = input.rpIdHash !== undefined;
  if (!hasRpId && !hasRpIdHash) {
    fail(AaOperationErrorCode.INPUT_INVALID, operation, "passkey: pass rpId or rpIdHash");
  }
  let givenRpIdHash: string | undefined;
  if (hasRpIdHash) {
    if (typeof input.rpIdHash !== "string" || !BYTES32_HEX.test(input.rpIdHash)) {
      fail(AaOperationErrorCode.INPUT_INVALID_FORMAT, operation, "passkey.rpIdHash: expected 32 bytes of 0x-prefixed hex");
    }
    givenRpIdHash = input.rpIdHash.toLowerCase();
  }
  let rpIdHash: string;
  if (hasRpId) {
    const rpId = requireNonEmptyString(input.rpId, "passkey.rpId", operation);
    if (/[/:]/.test(rpId)) {
      fail(
        AaOperationErrorCode.INPUT_INVALID_FORMAT,
        operation,
        `passkey.rpId: expected a bare host name such as "wallet.example.com", got "${rpId}" (an origin goes in passkey.origin)`
      );
    }
    rpIdHash = rpIdHashOf(rpId).toLowerCase();
    if (givenRpIdHash !== undefined && givenRpIdHash !== rpIdHash) {
      fail(
        AaOperationErrorCode.INPUT_INVALID,
        operation,
        `passkey: rpIdHash ${givenRpIdHash} is not sha256(rpId) for rpId "${rpId}" (${rpIdHash})`
      );
    }
  } else {
    rpIdHash = givenRpIdHash as string;
  }

  const hasCose = input.credentialPubkey !== undefined;
  const hasCoordinates = input.x !== undefined || input.y !== undefined;
  if (hasCose === hasCoordinates) {
    fail(
      AaOperationErrorCode.INPUT_INVALID,
      operation,
      "passkey: pass exactly one public key form, credentialPubkey (COSE) or x and y"
    );
  }

  if (hasCose) {
    const cose = input.credentialPubkey;
    if (typeof cose !== "string" || !HEX_BYTES.test(cose)) {
      fail(AaOperationErrorCode.SIGNER_KEY_INVALID, operation, "passkey.credentialPubkey: expected 0x-prefixed hex bytes");
    }
    try {
      // Decodes the COSE key and hands its coordinates to the same encoder as the x/y path.
      return new AccountKeyBuilder().getEncodedWebAuthnKey(cose, credentialId, rpIdHash, origin, false);
    } catch (err) {
      if (err instanceof AaOperationError) throw err;
      fail(AaOperationErrorCode.SIGNER_KEY_INVALID, operation, "passkey.credentialPubkey: not a COSE public key", err);
    }
  }

  for (const axis of ["x", "y"] as const) {
    const coordinate = input[axis];
    if (typeof coordinate !== "string" || !BYTES32_HEX.test(coordinate)) {
      fail(AaOperationErrorCode.SIGNER_KEY_INVALID, operation, `passkey.${axis}: expected 32 bytes of 0x-prefixed hex`);
    }
  }
  return encodeWebAuthnKeyInitData({
    x: (input.x as string).toLowerCase(),
    y: (input.y as string).toLowerCase(),
    credentialId,
    rpIdHash,
    origin,
    requireUV: false,
  });
}

function requireParams(params: unknown, operation: string): Record<string, unknown> {
  if (params === null || typeof params !== "object") {
    fail(AaOperationErrorCode.INPUT_INVALID, operation, "expected a parameter object");
  }
  const contracts = (params as Record<string, unknown>).contracts;
  if (contracts === null || typeof contracts !== "object") {
    fail(AaOperationErrorCode.INPUT_INVALID, operation, "contracts: expected an object of contract addresses");
  }
  return contracts as Record<string, unknown>;
}

/**
 * Init data of a passkey key (`AccountKeyWebAuthn.register`), with `requireUV = false`.
 * The single passkey encoder shared by the operational master key (slot 2) and the
 * passkey tx key, so the same passkey always encodes to the same bytes in both.
 *
 * @throws `AaOperationError` on an invalid passkey (see {@link PasskeyKeyInput}).
 */
export function encodePasskeyKeyInitData(passkey: PasskeyKeyInput): string {
  return passkeyInitData(passkey, "encode_passkey_key_init_data");
}

/**
 * Encoded initial master key, installed when the wallet is deployed (it is part of the
 * wallet address derivation):
 * `[0]` 1-of-1 zk key (weight 1), `[1]` cosigner address key (weight 1), threshold 2.
 *
 * @throws `AaOperationError` on a zero or malformed address, a malformed or out-of-range
 *   number, `hAudList == 0`, or an anchor that is not exactly 1 element long.
 */
export function buildInitialMasterKey(params: InitialMasterKeyParams): string {
  const operation = "build_initial_master_key";
  const contracts = requireParams(params, operation);
  const zkVerifier = requireAddress(contracts.zkVerifier1of1, "contracts.zkVerifier1of1", operation);
  const addressKeyLogic = requireAddress(contracts.addressKeyLogic, "contracts.addressKeyLogic", operation);
  const directory = requireAddress(contracts.merkleTreeDirectory, "contracts.merkleTreeDirectory", operation);
  const cosigner = requireAddress(params.cosigner, "cosigner", operation);
  const profile = INITIAL_MASTER_PROFILE;
  return encodeKeySet(
    profile,
    [zkVerifier, addressKeyLogic],
    [encodeZkKeyInitData(profile, params.zk, directory, operation), encodeCosignerKeyInitData(cosigner)]
  );
}

/**
 * Encoded operational master key:
 * `[0]` 3-of-6 zk key (weight 2), `[1]` cosigner address key (weight 1),
 * `[2]` passkey (weight 1, `requireUV = false`), threshold 3.
 *
 * @throws `AaOperationError` on a zero or malformed address, a malformed or out-of-range
 *   number, `hAudList == 0`, an anchor that is not exactly 4 elements long, or an
 *   invalid passkey.
 */
export function buildOperationalMasterKey(params: OperationalMasterKeyParams): string {
  const operation = "build_operational_master_key";
  const contracts = requireParams(params, operation);
  const zkVerifier = requireAddress(contracts.zkVerifier3of6, "contracts.zkVerifier3of6", operation);
  const addressKeyLogic = requireAddress(contracts.addressKeyLogic, "contracts.addressKeyLogic", operation);
  const webAuthnLogic = requireAddress(contracts.webAuthnLogic, "contracts.webAuthnLogic", operation);
  const directory = requireAddress(contracts.merkleTreeDirectory, "contracts.merkleTreeDirectory", operation);
  const cosigner = requireAddress(params.cosigner, "cosigner", operation);
  const profile = OPERATIONAL_MASTER_PROFILE;
  return encodeKeySet(
    profile,
    [zkVerifier, addressKeyLogic, webAuthnLogic],
    [
      encodeZkKeyInitData(profile, params.zk, directory, operation),
      encodeCosignerKeyInitData(cosigner),
      passkeyInitData(params.passkey, operation),
    ]
  );
}

/**
 * Encoded tx key holding a single passkey (weight 1, threshold 1, `requireUV = false`).
 *
 * @throws `AaOperationError` on a zero or malformed address or an invalid passkey.
 */
export function buildPasskeyTxKey(params: PasskeyTxKeyParams): string {
  const operation = "build_passkey_tx_key";
  const contracts = requireParams(params, operation);
  const webAuthnLogic = requireAddress(contracts.webAuthnLogic, "contracts.webAuthnLogic", operation);
  return encodeKeySet(PASSKEY_TX_PROFILE, [webAuthnLogic], [passkeyInitData(params.passkey, operation)]);
}
