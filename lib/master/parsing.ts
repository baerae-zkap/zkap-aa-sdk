import { ethers } from "ethers";
import { AaOperationError, AaOperationErrorCode } from "../errors";
import { buildInitialMasterKey, buildOperationalMasterKey, buildPasskeyTxKey } from "./encoding";
import {
  INITIAL_MASTER_PROFILE,
  OPERATIONAL_MASTER_PROFILE,
  PASSKEY_TX_PROFILE,
  type KeySetProfile,
  type MasterKeyProfile,
} from "./profiles";

/** A key set as the account contract decodes it, without any shape check. */
export interface DecodedKeySet {
  threshold: number;
  logicList: string[];
  initDataList: string[];
  weightList: number[];
}

export interface ParsedZkKey {
  /** Verifier contract (`logicList` entry). */
  logic: string;
  /** Merkle tree directory registered with the key. */
  directory: string;
  n: number;
  k: number;
  hAudList: bigint;
  anchor: bigint[];
}

export interface ParsedCosignerKey {
  /** Address key logic contract. */
  logic: string;
  /** Cosigner address. */
  signer: string;
}

export interface ParsedPasskeyKey {
  /** WebAuthn key logic contract. */
  logic: string;
  /** 32-byte coordinates, lowercase `0x` hex. */
  x: string;
  y: string;
  credentialId: string;
  /** 32-byte `SHA-256(rpId)`, lowercase `0x` hex. */
  rpIdHash: string;
  origin: string;
  /** Always `false` for the layouts this package builds. */
  requireUV: boolean;
}

export interface ParsedInitialMasterKey {
  zk: ParsedZkKey;
  cosigner: ParsedCosignerKey;
}

export interface ParsedOperationalMasterKey {
  zk: ParsedZkKey;
  cosigner: ParsedCosignerKey;
  passkey: ParsedPasskeyKey;
}

export interface ParsedPasskeyTxKey {
  passkey: ParsedPasskeyKey;
}

function parseFailed(operation: string, message: string, cause?: unknown): never {
  throw new AaOperationError({ code: AaOperationErrorCode.ENCODE_PARSE_FAILED, operation, message, cause });
}

function shapeMismatch(operation: string, message: string): never {
  throw new AaOperationError({ code: AaOperationErrorCode.INPUT_INVALID, operation, message });
}

/**
 * Decode an encoded key set (`abi.encode(uint8 threshold, address[] logicList,
 * bytes[] initDataList, uint8[] weightList)`) without checking its shape.
 *
 * @throws `AaOperationError` (`ENCODE_PARSE_FAILED`) when the bytes do not decode,
 *   (`INPUT_INVALID_FORMAT`) when `encoded` is not a string.
 */
export function decodeKeySet(encoded: string): DecodedKeySet {
  return decodeKeySetFor(encoded, "decode_key_set");
}

function decodeKeySetFor(encoded: string, operation: string): DecodedKeySet {
  if (typeof encoded !== "string") {
    throw new AaOperationError({
      code: AaOperationErrorCode.INPUT_INVALID_FORMAT,
      operation,
      message: `expected the encoded key set as a 0x-prefixed hex string, got ${encoded === null ? "null" : typeof encoded}`,
    });
  }
  try {
    const [threshold, logicList, initDataList, weightList] = ethers.AbiCoder.defaultAbiCoder().decode(
      ["uint8", "address[]", "bytes[]", "uint8[]"],
      encoded
    );
    return {
      threshold: Number(threshold),
      logicList: Array.from(logicList as string[]),
      initDataList: Array.from(initDataList as string[]),
      weightList: Array.from(weightList as bigint[], (weight) => Number(weight)),
    };
  } catch (err) {
    parseFailed(operation, "not an encoded key set", err);
  }
}

function checkShape(decoded: DecodedKeySet, profile: KeySetProfile, operation: string): void {
  const { slots } = profile;
  if (decoded.logicList.length !== slots.length || decoded.initDataList.length !== slots.length || decoded.weightList.length !== slots.length) {
    shapeMismatch(
      operation,
      `the ${profile.name} has ${slots.length} key(s), got ${decoded.logicList.length} logic / ${decoded.initDataList.length} init data / ${decoded.weightList.length} weight entries`
    );
  }
  if (decoded.threshold !== profile.threshold) {
    shapeMismatch(operation, `the ${profile.name} has threshold ${profile.threshold}, got ${decoded.threshold}`);
  }
  slots.forEach((slot, i) => {
    if (decoded.weightList[i] !== slot.weight) {
      shapeMismatch(operation, `the ${profile.name} has weight ${slot.weight} at key ${i}, got ${decoded.weightList[i]}`);
    }
  });
}

function parseZkKey(logic: string, initData: string, profile: MasterKeyProfile, operation: string): ParsedZkKey {
  let decoded: { directory: string; n: bigint; k: bigint; hAudList: bigint; anchor: bigint[] };
  try {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const [keyData, directory] = abiCoder.decode(["bytes", "address"], initData);
    const [n, k, hAudList, anchor] = abiCoder.decode(["uint256", "uint256", "uint256", "uint256[]"], keyData);
    decoded = { directory, n, k, hAudList, anchor: Array.from(anchor as bigint[]) };
  } catch (err) {
    parseFailed(operation, "key 0 is not an encoded zk key", err);
  }
  if (decoded.n !== BigInt(profile.zk.n) || decoded.k !== BigInt(profile.zk.k)) {
    shapeMismatch(
      operation,
      `the ${profile.name} zk key has n=${profile.zk.n}, k=${profile.zk.k}, got n=${decoded.n}, k=${decoded.k}`
    );
  }
  if (decoded.anchor.length !== profile.zk.anchorLength) {
    shapeMismatch(
      operation,
      `the ${profile.name} zk key has ${profile.zk.anchorLength} anchor element(s), got ${decoded.anchor.length}`
    );
  }
  return {
    logic,
    directory: decoded.directory,
    n: profile.zk.n,
    k: profile.zk.k,
    hAudList: decoded.hAudList,
    anchor: decoded.anchor,
  };
}

function parseCosignerKey(logic: string, initData: string, operation: string): ParsedCosignerKey {
  try {
    const [signer] = ethers.AbiCoder.defaultAbiCoder().decode(["address"], initData);
    return { logic, signer };
  } catch (err) {
    parseFailed(operation, "key 1 is not an encoded address key", err);
  }
}

function parsePasskeyKey(logic: string, initData: string, index: number, operation: string): ParsedPasskeyKey {
  let parsed: ParsedPasskeyKey;
  try {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const [keyData, rpIdHash, originBytes, requireUV] = abiCoder.decode(["bytes", "bytes32", "bytes", "bool"], initData);
    const [[x, y, credentialId]] = abiCoder.decode(["tuple(bytes32,bytes32,string)"], keyData);
    parsed = {
      logic,
      x,
      y,
      credentialId,
      rpIdHash,
      origin: ethers.toUtf8String(originBytes),
      requireUV,
    };
  } catch (err) {
    parseFailed(operation, `key ${index} is not an encoded WebAuthn key`, err);
  }
  if (parsed.requireUV !== false) {
    shapeMismatch(operation, `key ${index}: requireUV must be false`);
  }
  return parsed;
}

/** Rejects input whose canonical re-encoding differs (non-canonical ABI, trailing bytes, masked values). */
function requireCanonical(encoded: string, rebuilt: string, profile: KeySetProfile, operation: string): void {
  if (encoded.toLowerCase() !== rebuilt.toLowerCase()) {
    parseFailed(operation, `the ${profile.name} is not in canonical encoding`);
  }
}

function passkeyInput(passkey: ParsedPasskeyKey) {
  return {
    x: passkey.x,
    y: passkey.y,
    credentialId: passkey.credentialId,
    rpIdHash: passkey.rpIdHash,
    origin: passkey.origin,
  };
}

/**
 * Parse an initial master key (see `buildInitialMasterKey`).
 *
 * Throws when the key count, threshold, weights, zk `n`/`k` or anchor length differ
 * from the initial layout, and when rebuilding the parsed values does not reproduce
 * the input byte for byte. It does not check which contracts or cosigner the key
 * names; compare the returned values against the expected ones.
 *
 * @throws `AaOperationError` (`ENCODE_PARSE_FAILED` for undecodable or non-canonical
 *   bytes, `INPUT_INVALID_FORMAT` when `encoded` is not a string, `INPUT_INVALID` for
 *   a shape mismatch, or a builder error for values the builder rejects).
 */
export function parseInitialMasterKey(encoded: string): ParsedInitialMasterKey {
  const operation = "parse_initial_master_key";
  const profile = INITIAL_MASTER_PROFILE;
  const decoded = decodeKeySetFor(encoded, operation);
  checkShape(decoded, profile, operation);
  const zk = parseZkKey(decoded.logicList[0], decoded.initDataList[0], profile, operation);
  const cosigner = parseCosignerKey(decoded.logicList[1], decoded.initDataList[1], operation);
  const rebuilt = buildInitialMasterKey({
    contracts: { zkVerifier1of1: zk.logic, addressKeyLogic: cosigner.logic, merkleTreeDirectory: zk.directory },
    zk: { hAudList: zk.hAudList, anchor: zk.anchor },
    cosigner: cosigner.signer,
  });
  requireCanonical(encoded, rebuilt, profile, operation);
  return { zk, cosigner };
}

/**
 * Parse an operational master key (see `buildOperationalMasterKey`). Same rules as
 * {@link parseInitialMasterKey}, for the operational layout; the passkey must have
 * `requireUV = false`.
 */
export function parseOperationalMasterKey(encoded: string): ParsedOperationalMasterKey {
  const operation = "parse_operational_master_key";
  const profile = OPERATIONAL_MASTER_PROFILE;
  const decoded = decodeKeySetFor(encoded, operation);
  checkShape(decoded, profile, operation);
  const zk = parseZkKey(decoded.logicList[0], decoded.initDataList[0], profile, operation);
  const cosigner = parseCosignerKey(decoded.logicList[1], decoded.initDataList[1], operation);
  const passkey = parsePasskeyKey(decoded.logicList[2], decoded.initDataList[2], 2, operation);
  const rebuilt = buildOperationalMasterKey({
    contracts: {
      zkVerifier3of6: zk.logic,
      addressKeyLogic: cosigner.logic,
      webAuthnLogic: passkey.logic,
      merkleTreeDirectory: zk.directory,
    },
    zk: { hAudList: zk.hAudList, anchor: zk.anchor },
    cosigner: cosigner.signer,
    passkey: passkeyInput(passkey),
  });
  requireCanonical(encoded, rebuilt, profile, operation);
  return { zk, cosigner, passkey };
}

/**
 * Parse a passkey tx key (see `buildPasskeyTxKey`). Same rules as
 * {@link parseInitialMasterKey}, for the single-passkey layout.
 */
export function parsePasskeyTxKey(encoded: string): ParsedPasskeyTxKey {
  const operation = "parse_passkey_tx_key";
  const profile = PASSKEY_TX_PROFILE;
  const decoded = decodeKeySetFor(encoded, operation);
  checkShape(decoded, profile, operation);
  const passkey = parsePasskeyKey(decoded.logicList[0], decoded.initDataList[0], 0, operation);
  const rebuilt = buildPasskeyTxKey({
    contracts: { webAuthnLogic: passkey.logic },
    passkey: passkeyInput(passkey),
  });
  requireCanonical(encoded, rebuilt, profile, operation);
  return { passkey };
}
