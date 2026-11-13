import { ethers } from "ethers";
import {
  decodeKeySet,
  parseInitialMasterKey,
  parseOperationalMasterKey,
  parsePasskeyTxKey,
} from "../parsing";
import { AaOperationError, AaOperationErrorCode, type ZkapAaOperationErrorCode } from "../../errors";
import { loadVectors, type VectorPasskey } from "./fixtures/vectors";

const { inputs, outputs } = loadVectors();
const { contracts } = inputs;
const abi = ethers.AbiCoder.defaultAbiCoder();

// Independent encoders (straight AbiCoder, not the package builders) for crafting blobs.
function keySet(threshold: number, logicList: string[], initDataList: string[], weightList: number[]): string {
  return abi.encode(["uint8", "address[]", "bytes[]", "uint8[]"], [threshold, logicList, initDataList, weightList]);
}
function zkInitData(n: bigint, k: bigint, hAudList: bigint, anchor: bigint[], directory = contracts.merkleTreeDirectory): string {
  return abi.encode(
    ["bytes", "address"],
    [abi.encode(["uint256", "uint256", "uint256", "uint256[]"], [n, k, hAudList, anchor]), directory]
  );
}
function cosignerInitData(signer = inputs.cosigner): string {
  return abi.encode(["address"], [signer]);
}
function passkeyInitData(p: VectorPasskey, requireUV = false): string {
  const keyData = abi.encode(["tuple(bytes32,bytes32,string)"], [[p.x, p.y, p.credentialId]]);
  return abi.encode(["bytes", "bytes32", "bytes", "bool"], [keyData, p.rpIdHash, ethers.toUtf8Bytes(p.origin), requireUV]);
}

const opZk = inputs.operationalMaster.zk;
const opAnchor = opZk.anchor.map(BigInt);
const initZk = inputs.initialMaster.zk;
const initAnchor = initZk.anchor.map(BigInt);

function operationalBlob(overrides: {
  threshold?: number;
  weights?: number[];
  zk?: string;
  cosigner?: string;
  passkey?: string;
  logicList?: string[];
} = {}): string {
  return keySet(
    overrides.threshold ?? 3,
    overrides.logicList ?? [contracts.zkVerifier3of6, contracts.addressKeyLogic, contracts.webAuthnLogic],
    [
      overrides.zk ?? zkInitData(6n, 3n, BigInt(opZk.hAudList), opAnchor),
      overrides.cosigner ?? cosignerInitData(),
      overrides.passkey ?? passkeyInitData(inputs.passkey),
    ],
    overrides.weights ?? [2, 1, 1]
  );
}

function initialBlob(overrides: { threshold?: number; weights?: number[]; zk?: string; cosigner?: string } = {}): string {
  return keySet(
    overrides.threshold ?? 2,
    [contracts.zkVerifier1of1, contracts.addressKeyLogic],
    [overrides.zk ?? zkInitData(1n, 1n, BigInt(initZk.hAudList), initAnchor), overrides.cosigner ?? cosignerInitData()],
    overrides.weights ?? [1, 1]
  );
}

function txBlob(overrides: { threshold?: number; weights?: number[]; passkey?: string } = {}): string {
  return keySet(
    overrides.threshold ?? 1,
    [contracts.webAuthnLogic],
    [overrides.passkey ?? passkeyInitData(inputs.passkey)],
    overrides.weights ?? [1]
  );
}

function expectCode(fn: () => unknown, code: ZkapAaOperationErrorCode, message?: RegExp): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(AaOperationError);
  expect((thrown as AaOperationError).code).toBe(code);
  if (message) expect((thrown as AaOperationError).message).toMatch(message);
}

function expectedPasskey(p: VectorPasskey) {
  return {
    logic: contracts.webAuthnLogic,
    x: p.x,
    y: p.y,
    credentialId: p.credentialId,
    rpIdHash: p.rpIdHash,
    origin: p.origin,
    requireUV: false,
  };
}

describe("master key parsers", () => {
  it("crafted blobs equal the vector blobs (sanity check of the test encoders)", () => {
    expect(initialBlob()).toBe(outputs.initialMaster);
    expect(operationalBlob()).toBe(outputs.operationalMaster);
    expect(txBlob()).toBe(outputs.txKey);
  });

  describe("decodeKeySet", () => {
    it("decodes any key set without a shape check", () => {
      expect(decodeKeySet(outputs.operationalMaster)).toEqual({
        threshold: 3,
        logicList: [contracts.zkVerifier3of6, contracts.addressKeyLogic, contracts.webAuthnLogic],
        initDataList: [
          zkInitData(6n, 3n, BigInt(opZk.hAudList), opAnchor),
          cosignerInitData(),
          passkeyInitData(inputs.passkey),
        ],
        weightList: [2, 1, 1],
      });
      const odd = keySet(9, [contracts.addressKeyLogic], ["0x"], [4]);
      expect(decodeKeySet(odd)).toMatchObject({ threshold: 9, weightList: [4], initDataList: ["0x"] });
    });

    it.each([["0x1234"], ["not hex"], ["0x"]])("rejects %p", (encoded) => {
      expectCode(() => decodeKeySet(encoded), AaOperationErrorCode.ENCODE_PARSE_FAILED, /not an encoded key set/);
    });

    it.each([
      ["Uint8Array of a valid blob", () => ethers.getBytes(outputs.operationalMaster)],
      ["number", () => 1234],
      ["null", () => null],
      ["undefined", () => undefined],
    ])("rejects a non-string (%s) with AaOperationError in every parser", (_label, make) => {
      const parsers = [decodeKeySet, parseInitialMasterKey, parseOperationalMasterKey, parsePasskeyTxKey];
      for (const parse of parsers) {
        expectCode(() => parse(make() as unknown as string), AaOperationErrorCode.INPUT_INVALID_FORMAT, /hex string/);
      }
    });
  });

  describe("vector blobs round-trip", () => {
    it("initialMaster", () => {
      expect(parseInitialMasterKey(outputs.initialMaster)).toEqual({
        zk: {
          logic: contracts.zkVerifier1of1,
          directory: contracts.merkleTreeDirectory,
          n: 1,
          k: 1,
          hAudList: BigInt(initZk.hAudList),
          anchor: initAnchor,
        },
        cosigner: { logic: contracts.addressKeyLogic, signer: inputs.cosigner },
      });
    });

    it("operationalMaster and reconstructedMaster", () => {
      const zk = {
        logic: contracts.zkVerifier3of6,
        directory: contracts.merkleTreeDirectory,
        n: 6,
        k: 3,
        hAudList: BigInt(opZk.hAudList),
        anchor: opAnchor,
      };
      const cosigner = { logic: contracts.addressKeyLogic, signer: inputs.cosigner };
      expect(parseOperationalMasterKey(outputs.operationalMaster)).toEqual({
        zk,
        cosigner,
        passkey: expectedPasskey(inputs.passkey),
      });
      expect(parseOperationalMasterKey(outputs.reconstructedMaster)).toEqual({
        zk,
        cosigner,
        passkey: expectedPasskey(inputs.newPasskey),
      });
    });

    it("txKey and newTxKey", () => {
      expect(parsePasskeyTxKey(outputs.txKey)).toEqual({ passkey: expectedPasskey(inputs.passkey) });
      expect(parsePasskeyTxKey(outputs.newTxKey)).toEqual({ passkey: expectedPasskey(inputs.newPasskey) });
    });

    it("accepts uppercase hex input", () => {
      expect(() => parsePasskeyTxKey("0x" + outputs.txKey.slice(2).toUpperCase())).not.toThrow();
    });
  });

  describe("shape violations", () => {
    it.each([
      ["the operational blob", outputs.operationalMaster, /has 2 key/],
      ["the tx key blob", outputs.txKey, /has 2 key/],
      ["threshold 1", initialBlob({ threshold: 1 }), /threshold 2, got 1/],
      ["weights [2, 1]", initialBlob({ weights: [2, 1] }), /weight 1 at key 0, got 2/],
      ["n = 6", initialBlob({ zk: zkInitData(6n, 1n, BigInt(initZk.hAudList), initAnchor) }), /n=1, k=1, got n=6, k=1/],
      ["k = 3", initialBlob({ zk: zkInitData(1n, 3n, BigInt(initZk.hAudList), initAnchor) }), /got n=1, k=3/],
      ["2 anchor elements", initialBlob({ zk: zkInitData(1n, 1n, BigInt(initZk.hAudList), [1n, 2n]) }), /1 anchor element\(s\), got 2/],
      ["mismatched list lengths", keySet(2, [contracts.zkVerifier1of1, contracts.addressKeyLogic], ["0x", "0x"], [1]), /has 2 key/],
    ])("initial parser rejects %s", (_label, blob, message) => {
      expectCode(() => parseInitialMasterKey(blob), AaOperationErrorCode.INPUT_INVALID, message);
    });

    it.each([
      ["the initial blob", outputs.initialMaster, /has 3 key/],
      ["4 keys", keySet(3, [contracts.zkVerifier3of6, contracts.addressKeyLogic, contracts.webAuthnLogic, contracts.webAuthnLogic], [zkInitData(6n, 3n, 1n, opAnchor), cosignerInitData(), passkeyInitData(inputs.passkey), passkeyInitData(inputs.passkey)], [2, 1, 1, 1]), /has 3 key/],
      ["threshold 2", operationalBlob({ threshold: 2 }), /threshold 3, got 2/],
      ["weights [1, 2, 1]", operationalBlob({ weights: [1, 2, 1] }), /weight 2 at key 0, got 1/],
      ["weights [2, 1, 2]", operationalBlob({ weights: [2, 1, 2] }), /weight 1 at key 2, got 2/],
      ["n = 1", operationalBlob({ zk: zkInitData(1n, 3n, BigInt(opZk.hAudList), opAnchor) }), /got n=1, k=3/],
      ["k = 1", operationalBlob({ zk: zkInitData(6n, 1n, BigInt(opZk.hAudList), opAnchor) }), /got n=6, k=1/],
      ["5 anchor elements (getAnchor shape)", operationalBlob({ zk: zkInitData(6n, 3n, BigInt(opZk.hAudList), outputs.onchainGetAnchor.map(BigInt)) }), /4 anchor element\(s\), got 5/],
      ["3 anchor elements", operationalBlob({ zk: zkInitData(6n, 3n, BigInt(opZk.hAudList), opAnchor.slice(0, 3)) }), /got 3/],
      ["requireUV = true", operationalBlob({ passkey: passkeyInitData(inputs.passkey, true) }), /requireUV must be false/],
    ])("operational parser rejects %s", (_label, blob, message) => {
      expectCode(() => parseOperationalMasterKey(blob), AaOperationErrorCode.INPUT_INVALID, message);
    });

    it.each([
      ["the initial blob", outputs.initialMaster, /has 1 key/],
      ["threshold 2", txBlob({ threshold: 2 }), /threshold 1, got 2/],
      ["weight 2", txBlob({ weights: [2] }), /weight 1 at key 0, got 2/],
      ["requireUV = true", txBlob({ passkey: passkeyInitData(inputs.passkey, true) }), /key 0: requireUV must be false/],
    ])("tx key parser rejects %s", (_label, blob, message) => {
      expectCode(() => parsePasskeyTxKey(blob), AaOperationErrorCode.INPUT_INVALID, message);
    });
  });

  describe("undecodable key data", () => {
    it("rejects a zk slot that does not decode", () => {
      expectCode(() => parseInitialMasterKey(initialBlob({ zk: "0x" })), AaOperationErrorCode.ENCODE_PARSE_FAILED, /key 0 is not an encoded zk key/);
    });

    it("rejects a cosigner slot that does not decode", () => {
      expectCode(() => parseInitialMasterKey(initialBlob({ cosigner: "0x" })), AaOperationErrorCode.ENCODE_PARSE_FAILED, /key 1 is not an encoded address key/);
    });

    it("rejects a passkey slot that does not decode", () => {
      expectCode(() => parseOperationalMasterKey(operationalBlob({ passkey: "0x1234" })), AaOperationErrorCode.ENCODE_PARSE_FAILED, /key 2 is not an encoded WebAuthn key/);
      expectCode(() => parsePasskeyTxKey(txBlob({ passkey: "0x" })), AaOperationErrorCode.ENCODE_PARSE_FAILED, /key 0 is not an encoded WebAuthn key/);
    });

    it("rejects an origin that is not UTF-8", () => {
      const p = inputs.passkey;
      const keyData = abi.encode(["tuple(bytes32,bytes32,string)"], [[p.x, p.y, p.credentialId]]);
      const bad = abi.encode(["bytes", "bytes32", "bytes", "bool"], [keyData, p.rpIdHash, "0xff", false]);
      expectCode(() => parsePasskeyTxKey(txBlob({ passkey: bad })), AaOperationErrorCode.ENCODE_PARSE_FAILED);
    });

    it.each([
      ["initial", parseInitialMasterKey],
      ["operational", parseOperationalMasterKey],
      ["tx key", parsePasskeyTxKey],
    ])("%s parser rejects a non key set", (_label, parse) => {
      expectCode(() => parse("0xdeadbeef"), AaOperationErrorCode.ENCODE_PARSE_FAILED, /not an encoded key set/);
    });
  });

  describe("canonical encoding", () => {
    const word = (n: number) => n.toString(16).padStart(64, "0");

    it.each([
      ["initial", parseInitialMasterKey, outputs.initialMaster],
      ["operational", parseOperationalMasterKey, outputs.operationalMaster],
      ["tx key", parsePasskeyTxKey, outputs.txKey],
    ])("%s parser rejects trailing bytes", (_label, parse, blob) => {
      expectCode(() => parse(blob + "00".repeat(32)), AaOperationErrorCode.ENCODE_PARSE_FAILED, /not in canonical encoding/);
    });

    it("rejects a uint8 threshold with high bits set (decoders mask it)", () => {
      // 0x0102 masks to 2 as a uint8.
      const blob = "0x" + word(0x0102) + outputs.initialMaster.slice(2 + 64);
      expect(decodeKeySet(blob).threshold).toBe(2);
      expectCode(() => parseInitialMasterKey(blob), AaOperationErrorCode.ENCODE_PARSE_FAILED, /not in canonical encoding/);
    });

    it("rejects a dirty address word (upper 12 bytes set)", () => {
      // Cosigner init data is the last 32 bytes of the cosigner slot; dirty its upper bytes.
      const dirtyCosigner = "0x" + "ff".repeat(12) + inputs.cosigner.slice(2).toLowerCase();
      expectCode(
        () => parseInitialMasterKey(initialBlob({ cosigner: dirtyCosigner })),
        AaOperationErrorCode.ENCODE_PARSE_FAILED
      );
    });

    it("rejects a requireUV bool word that is neither 0 nor 1", () => {
      const p = inputs.passkey;
      const canonical = passkeyInitData(p);
      // Head word 3 is the bool; 2 decodes as true in lenient decoders but is not canonical.
      const dirty = canonical.slice(0, 2 + 3 * 64) + word(2) + canonical.slice(2 + 4 * 64);
      expect(() => parsePasskeyTxKey(txBlob({ passkey: dirty }))).toThrow(AaOperationError);
    });

    it("rejects a non-standard head offset", () => {
      // Point the logicList offset past an extra padding word that a canonical encoder would not emit.
      const blob = outputs.txKey;
      const head = blob.slice(2, 2 + 4 * 64);
      const tail = blob.slice(2 + 4 * 64);
      const words = head.match(/.{64}/g)!;
      const shift = (hex: string) => word(parseInt(hex, 16) + 32);
      const shiftedHead = words[0] + shift(words[1]) + shift(words[2]) + shift(words[3]);
      const shifted = "0x" + shiftedHead + word(0) + tail;
      expect(decodeKeySet(shifted).logicList).toEqual([contracts.webAuthnLogic]);
      expectCode(() => parsePasskeyTxKey(shifted), AaOperationErrorCode.ENCODE_PARSE_FAILED, /not in canonical encoding/);
    });
  });

  describe("values the builder rejects", () => {
    it("propagates the builder error for hAudList = 0", () => {
      const blob = initialBlob({ zk: zkInitData(1n, 1n, 0n, initAnchor) });
      expectCode(() => parseInitialMasterKey(blob), AaOperationErrorCode.INPUT_INVALID, /non-zero/);
    });

    it("propagates the builder error for a zero cosigner", () => {
      const blob = initialBlob({ cosigner: cosignerInitData(ethers.ZeroAddress) });
      expectCode(() => parseInitialMasterKey(blob), AaOperationErrorCode.INPUT_INVALID_ADDRESS);
    });

    it("propagates the builder error for an anchor element at the field size", () => {
      const fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
      const blob = operationalBlob({ zk: zkInitData(6n, 3n, 1n, [fr, 1n, 1n, 1n]) });
      expectCode(() => parseOperationalMasterKey(blob), AaOperationErrorCode.CRYPTO_FIELD_RANGE);
    });
  });
});
