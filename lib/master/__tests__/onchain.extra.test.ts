/**
 * classifyMasterKey / reconstructOperationalMasterKey on malformed input: the
 * classifier must answer `other` (never throw), reconstruction must refuse, and
 * builder errors must reach the caller unchanged.
 */
import { ethers } from "ethers";
import { AaOperationError, AaOperationErrorCode } from "../../errors";
import { classifyMasterKey, reconstructOperationalMasterKey, type MasterKeyExpectation } from "../onchain";
import type { OnchainKeyState } from "../../reader/types";
import { loadVectors } from "./fixtures/vectors";

const { inputs, outputs } = loadVectors();

/** BN254 scalar field size (independent literal, not the package constant). */
const BN254_FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const EXPECTED: MasterKeyExpectation = {
  contracts: {
    zkVerifier1of1: inputs.contracts.zkVerifier1of1,
    zkVerifier3of6: inputs.contracts.zkVerifier3of6,
    addressKeyLogic: inputs.contracts.addressKeyLogic,
    webAuthnLogic: inputs.contracts.webAuthnLogic,
    merkleTreeDirectory: inputs.contracts.merkleTreeDirectory,
  },
  cosigner: inputs.cosigner,
};

const NEW_PASSKEY = {
  x: inputs.newPasskey.x,
  y: inputs.newPasskey.y,
  credentialId: inputs.newPasskey.credentialId,
  origin: inputs.newPasskey.origin,
  rpIdHash: inputs.newPasskey.rpIdHash,
};

function operationalState(): OnchainKeyState {
  const zk = inputs.operationalMaster.zk;
  return {
    account: "0x" + "11".repeat(20),
    deployed: true,
    readVia: "multicall",
    master: {
      threshold: 3,
      truncated: false,
      keys: [
        {
          index: 0,
          logicContract: inputs.contracts.zkVerifier3of6,
          keyId: 0n,
          weight: 2,
          keyType: "zkOAuth",
          zk: {
            directory: inputs.contracts.merkleTreeDirectory,
            n: 6n,
            k: 3n,
            hAudList: BigInt(zk.hAudList),
            anchorWithHash: outputs.onchainGetAnchor.map((a) => BigInt(a)),
          },
        },
        { index: 1, logicContract: inputs.contracts.addressKeyLogic, keyId: 1n, weight: 1, keyType: "address", signer: inputs.cosigner },
        {
          index: 2,
          logicContract: inputs.contracts.webAuthnLogic,
          keyId: 2n,
          weight: 1,
          keyType: "webauthn",
          webauthn: {
            x: inputs.passkey.x,
            y: inputs.passkey.y,
            credentialId: inputs.passkey.credentialId,
            allowedOriginHash: ethers.keccak256(ethers.toUtf8Bytes(inputs.passkey.origin)),
            allowedRpIdHash: inputs.passkey.rpIdHash,
          },
        },
      ],
    },
    tx: { threshold: 0, keys: [], truncated: false },
  };
}

/** Bypass the static types to feed shapes a caller could still pass at runtime. */
const loose = (value: unknown) => value as OnchainKeyState;

function refusal(state: OnchainKeyState, expected: MasterKeyExpectation = EXPECTED): AaOperationError {
  try {
    reconstructOperationalMasterKey(state, { ...expected, passkey: NEW_PASSKEY });
  } catch (err) {
    expect(err).toBeInstanceOf(AaOperationError);
    return err as AaOperationError;
  }
  throw new Error("reconstruction did not refuse");
}

describe("classifyMasterKey on malformed input", () => {
  it.each([
    ["null state", null],
    ["deployed missing", { ...operationalState(), deployed: undefined }],
    ["deployed is a string", { ...operationalState(), deployed: "true" }],
  ])("classifies %s as other without throwing", (_label, state) => {
    const c = classifyMasterKey(loose(state), EXPECTED);
    expect(c.kind).toBe("other");
    expect(c.reasons.length).toBeGreaterThan(0);
  });

  it.each([
    ["master missing", (s: Record<string, unknown>) => void delete s.master],
    ["master keys not a list", (s: Record<string, unknown>) => void ((s.master as Record<string, unknown>).keys = "0x")],
    ["a master key is null", (s: Record<string, unknown>) => void ((s.master as { keys: unknown[] }).keys[1] = null)],
    ["zk data is null", (s: Record<string, unknown>) => void ((s.master as { keys: Record<string, unknown>[] }).keys[0].zk = null)],
    [
      "getAnchor is not a list",
      (s: Record<string, unknown>) =>
        void (((s.master as { keys: Record<string, Record<string, unknown>>[] }).keys[0].zk).anchorWithHash = { length: 5, 0: 1n }),
    ],
    ["webauthn data is a string", (s: Record<string, unknown>) => void ((s.master as { keys: Record<string, unknown>[] }).keys[2].webauthn = "x")],
    ["a logic contract is not hex", (s: Record<string, unknown>) => void ((s.master as { keys: Record<string, unknown>[] }).keys[1].logicContract = "0xZZ")],
  ])("classifies a state with %s as other and refuses to rebuild", (_label, mutate) => {
    const state = operationalState() as unknown as Record<string, unknown>;
    mutate(state);
    const c = classifyMasterKey(loose(state), EXPECTED);
    expect(c.kind).toBe("other");
    expect(c.reasons.length).toBeGreaterThan(0);
    expect(refusal(loose(state)).code).toBe(AaOperationErrorCode.INPUT_INVALID);
  });

  it.each([
    ["tx missing", (s: Record<string, unknown>) => void delete s.tx],
    ["tx keys not a list", (s: Record<string, unknown>) => void ((s.tx as Record<string, unknown>).keys = 0)],
  ])("does not read the tx list for an operational state (%s)", (_label, mutate) => {
    const state = operationalState() as unknown as Record<string, unknown>;
    mutate(state);
    expect(classifyMasterKey(loose(state), EXPECTED)).toEqual({ kind: "operational", reasons: [] });
  });

  it.each([
    ["expectation missing", undefined],
    ["contracts missing", { cosigner: inputs.cosigner }],
    ["an expected address that is not hex", { ...EXPECTED, cosigner: "cosigner" }],
  ])("classifies the operational state as other with %s", (_label, expected) => {
    const c = classifyMasterKey(operationalState(), expected as MasterKeyExpectation);
    expect(c.kind).toBe("other");
    expect(c.reasons.length).toBeGreaterThan(0);
  });

  it("names the failed condition with its expected and actual value", () => {
    const state = operationalState();
    state.master.threshold = 4;
    const { reasons } = classifyMasterKey(state, EXPECTED);
    expect(reasons).toContain("not operational master key: master threshold: expected 3, got 4");
    expect(reasons).toContain("not initial master key: master threshold: expected 2, got 4");
  });

  it("reports an unclassifiable deployed flag", () => {
    expect(classifyMasterKey(loose({ ...operationalState(), deployed: undefined }), EXPECTED).reasons).toEqual([
      "deployed: expected true or false, got undefined",
    ]);
  });
});

describe("reconstructOperationalMasterKey errors", () => {
  it("names the classification and its reasons in the refusal", () => {
    const state = operationalState();
    state.master.keys[1].signer = "0x" + "5e".repeat(20);
    const err = refusal(state);
    expect(err.code).toBe(AaOperationErrorCode.INPUT_INVALID);
    expect(err.operation).toBe("reconstruct_operational_master_key");
    expect(err.message).toContain('classifies as "other"');
    expect(err.message).toContain("master[1] cosigner");
  });

  it("refuses an undeployed account and says so", () => {
    const err = refusal({ ...operationalState(), deployed: false });
    expect(err.message).toContain('classifies as "undeployed"');
  });

  it("passes an invalid passkey's builder error through unchanged", () => {
    let thrown: unknown;
    try {
      reconstructOperationalMasterKey(operationalState(), { ...EXPECTED, passkey: { ...NEW_PASSKEY, x: "0x1234" } });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(AaOperationError);
    expect((thrown as AaOperationError).code).toBe(AaOperationErrorCode.SIGNER_KEY_INVALID);
    expect((thrown as AaOperationError).operation).toBe("build_operational_master_key");
  });

  it("passes an out-of-range on-chain anchor element through as the builder's error", () => {
    const state = operationalState();
    state.master.keys[0].zk!.anchorWithHash[0] = (1n << 256n) - 1n;
    let thrown: unknown;
    try {
      reconstructOperationalMasterKey(state, { ...EXPECTED, passkey: NEW_PASSKEY });
    } catch (err) {
      thrown = err;
    }
    expect((thrown as AaOperationError).code).toBe(AaOperationErrorCode.CRYPTO_FIELD_RANGE);
  });

  it("passes a zero on-chain hAudList through as the builder's error", () => {
    const state = operationalState();
    state.master.keys[0].zk!.hAudList = 0n;
    expect(() => reconstructOperationalMasterKey(state, { ...EXPECTED, passkey: NEW_PASSKEY })).toThrow(/hAudList/);
  });

  it.each([
    ["an anchor element at the field size", (s: OnchainKeyState) => void (s.master.keys[0].zk!.anchorWithHash[1] = BN254_FIELD_SIZE)],
    ["a zero hAudList", (s: OnchainKeyState) => void (s.master.keys[0].zk!.hAudList = 0n)],
  ])("classifies %s as operational, yet reconstruction fails in the builder", (_label, mutate) => {
    const state = operationalState();
    mutate(state);
    expect(classifyMasterKey(state, EXPECTED)).toEqual({ kind: "operational", reasons: [] });
    let thrown: unknown;
    try {
      reconstructOperationalMasterKey(state, { ...EXPECTED, passkey: NEW_PASSKEY });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(AaOperationError);
    expect((thrown as AaOperationError).operation).toBe("build_operational_master_key");
  });
});
