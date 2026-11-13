import { PrimitiveAccountKeyTypes } from "../types/AccountKey";
import {
  INITIAL_MASTER_PROFILE,
  OPERATIONAL_MASTER_PROFILE,
  PASSKEY_TX_PROFILE,
  type KeySetProfile,
  type MasterKeyProfile,
  type SlotKind,
} from "./profiles";

/** Shape of a fixed master key layout. */
export interface MasterKeyShape {
  readonly threshold: number;
  readonly weights: readonly number[];
  readonly zk: { readonly n: number; readonly k: number; readonly anchorLength: number };
}

/** Shape of a fixed tx key layout. */
export interface TxKeyShape {
  readonly threshold: number;
  readonly weights: readonly number[];
}

function weightsOf(profile: KeySetProfile): readonly number[] {
  return Object.freeze(profile.slots.map((slot) => slot.weight));
}

function masterShapeOf(profile: MasterKeyProfile): MasterKeyShape {
  const { n, k, anchorLength } = profile.zk;
  return Object.freeze({
    threshold: profile.threshold,
    weights: weightsOf(profile),
    zk: Object.freeze({ n, k, anchorLength }),
  });
}

function indexOf(kind: SlotKind): number {
  return OPERATIONAL_MASTER_PROFILE.slots.findIndex((slot) => slot.kind === kind);
}

/**
 * Position of each key in a cosigned master key. The same positions are used by the
 * initial layout (which has no passkey) and the operational layout, and they are the
 * key indices a master op signature refers to.
 */
export const MASTER_KEY_INDEX: { readonly zk: number; readonly cosigner: number; readonly passkey: number } =
  Object.freeze({ zk: indexOf("zk"), cosigner: indexOf("cosigner"), passkey: indexOf("passkey") });

/**
 * Master key installed when the wallet is deployed: a 1-of-1 zk key and the cosigner
 * address key, weights `[1, 1]`, threshold 2 (both must sign).
 */
export const INITIAL_MASTER_KEY: MasterKeyShape = masterShapeOf(INITIAL_MASTER_PROFILE);

/**
 * Master key after onboarding: a 3-of-6 zk key (weight 2), the cosigner address key and a
 * passkey (weight 1 each), threshold 3. Either zk + cosigner or zk + passkey can sign.
 */
export const OPERATIONAL_MASTER_KEY: MasterKeyShape = masterShapeOf(OPERATIONAL_MASTER_PROFILE);

/** Tx key holding a single passkey, weight 1, threshold 1. */
export const PASSKEY_TX_KEY: TxKeyShape = Object.freeze({
  threshold: PASSKEY_TX_PROFILE.threshold,
  weights: weightsOf(PASSKEY_TX_PROFILE),
});

/** Key indices a cosigned master op signature carries: the zk key, then the cosigner. */
export const MASTER_OP_KEY_INDEX_LIST: readonly number[] = Object.freeze([
  MASTER_KEY_INDEX.zk,
  MASTER_KEY_INDEX.cosigner,
]);

/** Signer key types of a cosigned master op, in `MASTER_OP_KEY_INDEX_LIST` order. */
export const MASTER_OP_SIGNER_KEY_TYPES: readonly number[] = Object.freeze([
  PrimitiveAccountKeyTypes.keyZkOAuthRS256,
  PrimitiveAccountKeyTypes.keyAddress,
]);

/**
 * Byte length of a full cosigned master op signature
 * (`abi.encode(uint8[] [0, 1], bytes[] [zkSignature, cosignerSignature])`):
 * one zk proof (initial master key) or three proofs (operational master key).
 */
export const MASTER_OP_SIGNATURE_LENGTH: { readonly singleProof: number; readonly threeProofs: number } =
  Object.freeze({ singleProof: 1120, threeProofs: 1760 });
