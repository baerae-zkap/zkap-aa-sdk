import { AaOperationError, AaOperationErrorCode } from "../errors";
import type { OnchainKeyEntry, OnchainKeyState, OnchainZkKeyData } from "../reader/types";
import { safeStringify } from "../utils/safeStringify";
import { buildOperationalMasterKey, type PasskeyKeyInput } from "./encoding";
import { INITIAL_MASTER_PROFILE, OPERATIONAL_MASTER_PROFILE, type MasterKeyProfile, type SlotKind } from "./profiles";

/**
 * Contract addresses and cosigner a wallet's master key is expected to use.
 * Addresses are compared case-insensitively.
 */
export interface MasterKeyExpectation {
  contracts: {
    /** zk verifier of the initial (1-of-1) master key. */
    zkVerifier1of1: string;
    /** zk verifier of the operational (3-of-6) master key. */
    zkVerifier3of6: string;
    addressKeyLogic: string;
    webAuthnLogic: string;
    merkleTreeDirectory: string;
  };
  /** Cosigner address registered as the master key's address key. */
  cosigner: string;
}

/**
 * - `"undeployed"` — the account has no code yet.
 * - `"initial"` — the master key installed at deployment, and no tx key yet.
 * - `"operational"` — the master key installed by onboarding (zk + cosigner + passkey).
 * - `"other"` — anything else; see `reasons`.
 */
export type MasterKeyKind = "undeployed" | "initial" | "operational" | "other";

export interface MasterKeyClassification {
  kind: MasterKeyKind;
  /** Why the state is neither initial nor operational. Empty unless `kind` is `"other"`. */
  reasons: string[];
}

export interface ReconstructOperationalMasterKeyParams extends MasterKeyExpectation {
  /** Passkey to place at master key index 2 (it replaces the one registered on chain). */
  passkey: PasskeyKeyInput;
}

const ADDRESS_HEX = /^0x[0-9a-fA-F]{40}$/;

function sameAddress(actual: unknown, expected: unknown): boolean {
  return (
    typeof actual === "string" &&
    typeof expected === "string" &&
    ADDRESS_HEX.test(actual) &&
    ADDRESS_HEX.test(expected) &&
    actual.toLowerCase() === expected.toLowerCase()
  );
}

const KEY_TYPE_OF_SLOT: Record<SlotKind, OnchainKeyEntry["keyType"]> = {
  zk: "zkOAuth",
  cosigner: "address",
  passkey: "webauthn",
};

function show(value: unknown): string {
  if (typeof value === "bigint") return `${value}`;
  if (typeof value === "string") return JSON.stringify(value);
  return safeStringify(value);
}

/**
 * Every way `state.master` differs from `profile` with the expected addresses.
 * Never throws, whatever the input.
 */
function masterKeyMismatches(
  state: OnchainKeyState,
  expected: MasterKeyExpectation,
  profile: MasterKeyProfile,
  zkVerifier: unknown
): string[] {
  const reasons: string[] = [];
  const mismatch = (what: string, want: unknown, got: unknown) =>
    reasons.push(`${what}: expected ${show(want)}, got ${show(got)}`);

  const master = state?.master;
  if (master?.truncated !== false) mismatch("master key read truncated", false, master?.truncated);
  if (master?.threshold !== profile.threshold) mismatch("master threshold", profile.threshold, master?.threshold);
  const keys: unknown = master?.keys;
  if (!Array.isArray(keys)) {
    reasons.push("master keys: not a list");
    return reasons;
  }
  if (keys.length !== profile.slots.length) {
    mismatch("master key count", profile.slots.length, keys.length);
    return reasons;
  }

  const contracts = expected?.contracts;
  const logicOf: Record<SlotKind, unknown> = {
    zk: zkVerifier,
    cosigner: contracts?.addressKeyLogic,
    passkey: contracts?.webAuthnLogic,
  };

  profile.slots.forEach((slot, i) => {
    const key = keys[i] as Partial<OnchainKeyEntry> | undefined;
    if (key?.weight !== slot.weight) mismatch(`master[${i}] weight`, slot.weight, key?.weight);
    const keyType = KEY_TYPE_OF_SLOT[slot.kind];
    if (key?.keyType !== keyType) mismatch(`master[${i}] keyType`, keyType, key?.keyType);
    if (!sameAddress(key?.logicContract, logicOf[slot.kind])) {
      mismatch(`master[${i}] logic contract`, logicOf[slot.kind], key?.logicContract);
    }

    if (slot.kind === "zk") {
      const zk = key?.zk;
      if (zk == null || typeof zk !== "object") {
        reasons.push(`master[${i}]: no zk key data`);
        return;
      }
      if (!sameAddress(zk.directory, contracts?.merkleTreeDirectory)) {
        mismatch(`master[${i}] merkle tree directory`, contracts?.merkleTreeDirectory, zk.directory);
      }
      if (zk.n !== BigInt(profile.zk.n)) mismatch(`master[${i}] zk n`, BigInt(profile.zk.n), zk.n);
      if (zk.k !== BigInt(profile.zk.k)) mismatch(`master[${i}] zk k`, BigInt(profile.zk.k), zk.k);
      // getAnchor returns the registered anchor followed by one on-chain hash.
      const anchorWithHashLength = profile.zk.anchorLength + 1;
      const got = Array.isArray(zk.anchorWithHash) ? zk.anchorWithHash.length : zk.anchorWithHash;
      if (got !== anchorWithHashLength) mismatch(`master[${i}] getAnchor length`, anchorWithHashLength, got);
    } else if (slot.kind === "cosigner") {
      if (!sameAddress(key?.signer, expected?.cosigner)) mismatch(`master[${i}] cosigner`, expected?.cosigner, key?.signer);
    } else if (key?.webauthn == null || typeof key.webauthn !== "object") {
      reasons.push(`master[${i}]: no webauthn key data`);
    }
  });
  return reasons;
}

/**
 * Classify the master key of an account read with `AccountReader.readKeyState`.
 *
 * - `undeployed`: `state.deployed === false`.
 * - `initial`: the master key installed at deployment — threshold 2, weights `[1, 1]`,
 *   `[0]` zk key on `zkVerifier1of1` (`n = 1`, `k = 1`, one anchor element) with the
 *   expected directory, `[1]` address key on `addressKeyLogic` whose signer is the
 *   cosigner — and no tx key.
 * - `operational`: threshold 3, weights `[2, 1, 1]`, `[0]` zk key on `zkVerifier3of6`
 *   (`n = 6`, `k = 3`, four anchor elements) with the expected directory, `[1]` the
 *   cosigner as above, `[2]` a passkey on `webAuthnLogic`. Tx keys are not looked at.
 * - `other`: anything else, including a truncated master key read; `reasons` lists
 *   each condition that failed with its expected and actual value.
 *
 * `operational` checks the layout, not every value: a state classified as
 * `operational` can still fail {@link reconstructOperationalMasterKey} when its
 * on-chain anchor or `hAudList` fails the builder's range checks (each value
 * below the BN254 scalar field size, `hAudList ≠ 0`).
 *
 * Pure: never throws and never modifies `state`.
 */
export function classifyMasterKey(state: OnchainKeyState, expected: MasterKeyExpectation): MasterKeyClassification {
  if (state?.deployed === false) return { kind: "undeployed", reasons: [] };
  if (state?.deployed !== true) {
    return { kind: "other", reasons: [`deployed: expected true or false, got ${show(state?.deployed)}`] };
  }

  const operational = masterKeyMismatches(state, expected, OPERATIONAL_MASTER_PROFILE, expected?.contracts?.zkVerifier3of6);
  if (operational.length === 0) return { kind: "operational", reasons: [] };

  const initial = masterKeyMismatches(state, expected, INITIAL_MASTER_PROFILE, expected?.contracts?.zkVerifier1of1);
  const tx = state.tx;
  if (tx?.truncated !== false) initial.push(`tx key read truncated: expected false, got ${show(tx?.truncated)}`);
  const txKeyCount: unknown = Array.isArray(tx?.keys) ? tx.keys.length : tx?.keys;
  if (txKeyCount !== 0) initial.push(`tx key count: expected 0, got ${show(txKeyCount)}`);
  if (initial.length === 0) return { kind: "initial", reasons: [] };

  return {
    kind: "other",
    reasons: [
      ...initial.map((reason) => `not ${INITIAL_MASTER_PROFILE.name}: ${reason}`),
      ...operational.map((reason) => `not ${OPERATIONAL_MASTER_PROFILE.name}: ${reason}`),
    ],
  };
}

/**
 * Rebuild the encoded operational master key of a wallet with a new passkey at
 * index 2, keeping its zk key and cosigner — e.g. to replace a lost passkey.
 *
 * The zk key's `hAudList` and anchor exist only on chain: `hAudList` is taken from
 * `state` and the anchor is `getAnchor()` without its last element (the on-chain
 * hash), in on-chain order. Contract addresses and the cosigner come from `params`,
 * after {@link classifyMasterKey} has confirmed they match the chain; `n` and `k`
 * are the operational layout's constants, which the same check confirms.
 *
 * A wrong blob installs a master key no zk proof can satisfy, which locks the
 * wallet's master key for good. So nothing is rebuilt unless the state classifies
 * as `operational`; there are no defaults and no partial matches. The result is
 * only as current as `state`: use it right after the read, and re-check the
 * wallet's key state before submitting — that check is the caller's.
 *
 * The result is valid only for the wallet at `state.account`. Submitted to any
 * other wallet it locks that wallet's master key, so the caller must check that
 * the sender of the op it submits is `state.account`.
 *
 * @throws `AaOperationError` (`INPUT_INVALID`) when the state is not `operational`;
 *   the message carries the classification and its reasons.
 * @throws `AaOperationError` from {@link buildOperationalMasterKey} for an invalid
 *   passkey or an out-of-range value.
 */
export function reconstructOperationalMasterKey(state: OnchainKeyState, params: ReconstructOperationalMasterKeyParams): string {
  const classification = classifyMasterKey(state, params);
  if (classification.kind !== "operational") {
    const reasons = classification.reasons.length > 0 ? `: ${classification.reasons.join("; ")}` : "";
    throw new AaOperationError({
      code: AaOperationErrorCode.INPUT_INVALID,
      operation: "reconstruct_operational_master_key",
      message: `refusing to reconstruct the operational master key: the master key classifies as "${classification.kind}"${reasons}`,
    });
  }
  // `operational` guarantees key 0 carries zk data of the expected shape.
  const zk = state.master.keys[0].zk as OnchainZkKeyData;
  const { zkVerifier3of6, addressKeyLogic, webAuthnLogic, merkleTreeDirectory } = params.contracts;
  return buildOperationalMasterKey({
    contracts: { zkVerifier3of6, addressKeyLogic, webAuthnLogic, merkleTreeDirectory },
    zk: { hAudList: zk.hAudList, anchor: zk.anchorWithHash.slice(0, -1) },
    cosigner: params.cosigner,
    passkey: params.passkey,
  });
}
