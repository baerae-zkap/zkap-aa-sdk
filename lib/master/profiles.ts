/**
 * Shapes of the fixed key sets this package builds and parses, written as data.
 *
 * Internal: the public constants (`./constants`), the builders (`./encoding`) and
 * the strict parsers (`./parsing`) all read their numbers from here, so a layout
 * is defined in exactly one place.
 */

export type SlotKind = "zk" | "cosigner" | "passkey";

export interface SlotProfile {
  readonly kind: SlotKind;
  readonly weight: number;
}

export interface ZkSlotProfile extends SlotProfile {
  readonly kind: "zk";
  /** Verifier parameters registered with the key. */
  readonly n: number;
  readonly k: number;
  /** Number of anchor elements the verifier expects. */
  readonly anchorLength: number;
}

export interface KeySetProfile {
  /** Human-readable name used in error messages. */
  readonly name: string;
  readonly threshold: number;
  readonly slots: readonly SlotProfile[];
}

/** A master key profile: slot 0 is always the zk key, also reachable as `zk`. */
export interface MasterKeyProfile extends KeySetProfile {
  readonly zk: ZkSlotProfile;
}

const INITIAL_ZK: ZkSlotProfile = { kind: "zk", weight: 1, n: 1, k: 1, anchorLength: 1 };
const OPERATIONAL_ZK: ZkSlotProfile = { kind: "zk", weight: 2, n: 6, k: 3, anchorLength: 4 };

/** Master key installed at deployment: 1-of-1 zk key + cosigner address key, both required. */
export const INITIAL_MASTER_PROFILE: MasterKeyProfile = {
  name: "initial master key",
  threshold: 2,
  zk: INITIAL_ZK,
  slots: [INITIAL_ZK, { kind: "cosigner", weight: 1 }],
};

/** Master key after onboarding: 3-of-6 zk key (weight 2) + cosigner + passkey, threshold 3. */
export const OPERATIONAL_MASTER_PROFILE: MasterKeyProfile = {
  name: "operational master key",
  threshold: 3,
  zk: OPERATIONAL_ZK,
  slots: [OPERATIONAL_ZK, { kind: "cosigner", weight: 1 }, { kind: "passkey", weight: 1 }],
};

/** Transaction key: a single passkey. */
export const PASSKEY_TX_PROFILE: KeySetProfile = {
  name: "passkey tx key",
  threshold: 1,
  slots: [{ kind: "passkey", weight: 1 }],
};
