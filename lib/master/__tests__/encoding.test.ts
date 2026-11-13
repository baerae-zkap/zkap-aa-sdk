import { ethers } from "ethers";
import {
  buildInitialMasterKey,
  buildOperationalMasterKey,
  buildPasskeyTxKey,
  encodePasskeyKeyInitData,
  type InitialMasterKeyParams,
  type OperationalMasterKeyParams,
  type PasskeyKeyInput,
} from "../encoding";
import { decodeKeySet } from "../parsing";
import { AccountKeyBuilder } from "../../builders/AccountKeyBuilder";
import { AaOperationError, AaOperationErrorCode, type ZkapAaOperationErrorCode } from "../../errors";
import { BN254_FR } from "../../utils/crypto";
import { toCosePublicKey } from "../../utils/webauthnKey";
import { loadVectors } from "./fixtures/vectors";

const { inputs, outputs } = loadVectors();
const { contracts } = inputs;

const passkey: PasskeyKeyInput = {
  x: inputs.passkey.x,
  y: inputs.passkey.y,
  credentialId: inputs.passkey.credentialId,
  origin: inputs.passkey.origin,
  rpId: inputs.passkey.rpId,
};

function initialParams(): InitialMasterKeyParams {
  return {
    contracts: {
      zkVerifier1of1: contracts.zkVerifier1of1,
      addressKeyLogic: contracts.addressKeyLogic,
      merkleTreeDirectory: contracts.merkleTreeDirectory,
    },
    zk: { hAudList: inputs.initialMaster.zk.hAudList, anchor: [...inputs.initialMaster.zk.anchor] },
    cosigner: inputs.cosigner,
  };
}

function operationalParams(): OperationalMasterKeyParams {
  return {
    contracts: {
      zkVerifier3of6: contracts.zkVerifier3of6,
      addressKeyLogic: contracts.addressKeyLogic,
      webAuthnLogic: contracts.webAuthnLogic,
      merkleTreeDirectory: contracts.merkleTreeDirectory,
    },
    zk: { hAudList: inputs.operationalMaster.zk.hAudList, anchor: [...inputs.operationalMaster.zk.anchor] },
    cosigner: inputs.cosigner,
    passkey: { ...passkey },
  };
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

describe("master key builders — input validation", () => {
  describe("numbers", () => {
    it("reads decimal strings as decimal, never as hex", () => {
      const asDecimal = buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "1234", anchor: ["1234"] } });
      const asBigint = buildInitialMasterKey({ ...initialParams(), zk: { hAudList: 1234n, anchor: [1234n] } });
      const asHex = buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "0x4d2", anchor: ["0x4D2"] } });
      expect(asDecimal).toBe(asBigint);
      expect(asHex).toBe(asBigint);
    });

    it.each([
      ["a JS number", 1234],
      ["hex without 0x", "4d2"],
      ["an empty 0x", "0x"],
      ["an empty string", ""],
      ["a negative decimal", "-1"],
      ["a decimal with a fraction", "1.5"],
      ["a decimal with spaces", " 12"],
      ["undefined", undefined],
    ])("rejects %s for hAudList", (_label, value) => {
      const params = initialParams();
      (params.zk as { hAudList: unknown }).hAudList = value;
      expectCode(() => buildInitialMasterKey(params), AaOperationErrorCode.INPUT_INVALID_FORMAT, /zk\.hAudList/);
    });

    it("rejects a JS number inside the anchor", () => {
      const params = initialParams();
      (params.zk.anchor as unknown[])[0] = 7;
      expectCode(() => buildInitialMasterKey(params), AaOperationErrorCode.INPUT_INVALID_FORMAT, /zk\.anchor\[0\]/);
    });

    it.each([0n, "0", "0x0", "0x00"])("rejects hAudList = %p", (value) => {
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: value, anchor: ["1"] } }),
        AaOperationErrorCode.INPUT_INVALID,
        /non-zero/
      );
    });

    it("accepts values up to field size - 1 and rejects the field size and above", () => {
      const max = BN254_FR - 1n;
      expect(() => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: max, anchor: [max] } })).not.toThrow();
      expect(() => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "1", anchor: [0n] } })).not.toThrow();
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: BN254_FR, anchor: ["1"] } }),
        AaOperationErrorCode.CRYPTO_FIELD_RANGE,
        /zk\.hAudList/
      );
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "1", anchor: [BN254_FR.toString()] } }),
        AaOperationErrorCode.CRYPTO_FIELD_RANGE,
        /zk\.anchor\[0\]/
      );
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "1", anchor: [`0x${"f".repeat(64)}`] } }),
        AaOperationErrorCode.CRYPTO_FIELD_RANGE
      );
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: -1n, anchor: ["1"] } }),
        AaOperationErrorCode.CRYPTO_FIELD_RANGE
      );
    });
  });

  describe("anchor length", () => {
    it.each([0, 2])("initial master key rejects %i anchor elements", (length) => {
      const anchor = Array.from({ length }, () => "1");
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "1", anchor } }),
        AaOperationErrorCode.INPUT_OUT_OF_RANGE,
        /needs 1 anchor element/
      );
    });

    it.each([1, 3, 5, 6])("operational master key rejects %i anchor elements", (length) => {
      const anchor = Array.from({ length }, () => "1");
      expectCode(
        () => buildOperationalMasterKey({ ...operationalParams(), zk: { hAudList: "1", anchor } }),
        AaOperationErrorCode.INPUT_OUT_OF_RANGE,
        /needs 4 anchor element/
      );
    });

    it("rejects a non-array anchor and a missing zk object", () => {
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "1", anchor: "1" as unknown as string[] } }),
        AaOperationErrorCode.INPUT_INVALID_FORMAT
      );
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: undefined as unknown as InitialMasterKeyParams["zk"] }),
        AaOperationErrorCode.INPUT_INVALID
      );
    });

    it("rejects a sparse anchor with AaOperationError naming the hole", () => {
      const anchor = ["1", , "3", "4"] as unknown as string[];
      expect(anchor).toHaveLength(4);
      expectCode(
        () => buildOperationalMasterKey({ ...operationalParams(), zk: { hAudList: "1", anchor } }),
        AaOperationErrorCode.INPUT_INVALID_FORMAT,
        /zk\.anchor\[1\]/
      );
      const initialAnchor = new Array<string>(1);
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), zk: { hAudList: "1", anchor: initialAnchor } }),
        AaOperationErrorCode.INPUT_INVALID_FORMAT,
        /zk\.anchor\[0\]/
      );
    });
  });

  describe("addresses", () => {
    const ZERO = ethers.ZeroAddress;

    it.each(["zkVerifier1of1", "addressKeyLogic", "merkleTreeDirectory"] as const)(
      "initial master key rejects a zero %s",
      (field) => {
        const params = initialParams();
        params.contracts[field] = ZERO;
        expectCode(() => buildInitialMasterKey(params), AaOperationErrorCode.INPUT_INVALID_ADDRESS, /zero address/);
      }
    );

    it.each(["zkVerifier3of6", "addressKeyLogic", "webAuthnLogic", "merkleTreeDirectory"] as const)(
      "operational master key rejects a zero %s",
      (field) => {
        const params = operationalParams();
        params.contracts[field] = ZERO;
        expectCode(() => buildOperationalMasterKey(params), AaOperationErrorCode.INPUT_INVALID_ADDRESS, /zero address/);
      }
    );

    it("rejects a zero cosigner and a zero tx key logic", () => {
      expectCode(
        () => buildInitialMasterKey({ ...initialParams(), cosigner: ZERO }),
        AaOperationErrorCode.INPUT_INVALID_ADDRESS
      );
      expectCode(
        () => buildOperationalMasterKey({ ...operationalParams(), cosigner: ZERO }),
        AaOperationErrorCode.INPUT_INVALID_ADDRESS
      );
      expectCode(
        () => buildPasskeyTxKey({ contracts: { webAuthnLogic: ZERO }, passkey }),
        AaOperationErrorCode.INPUT_INVALID_ADDRESS
      );
    });

    it.each([
      ["too short", "0x1234"],
      ["no 0x prefix", contracts.addressKeyLogic.slice(2)],
      ["a broken checksum", contracts.addressKeyLogic.slice(0, -1) + (contracts.addressKeyLogic.endsWith("A") ? "a" : "A")],
      ["not a string", 42],
    ])("rejects an address that is %s", (_label, value) => {
      const params = initialParams();
      (params as { cosigner: unknown }).cosigner = value;
      expectCode(() => buildInitialMasterKey(params), AaOperationErrorCode.INPUT_INVALID_ADDRESS, /cosigner/);
    });

    it("rejects a missing parameter or contracts object", () => {
      expectCode(
        () => buildInitialMasterKey(undefined as unknown as InitialMasterKeyParams),
        AaOperationErrorCode.INPUT_INVALID
      );
      expectCode(
        () => buildOperationalMasterKey({ ...operationalParams(), contracts: undefined as unknown as OperationalMasterKeyParams["contracts"] }),
        AaOperationErrorCode.INPUT_INVALID,
        /contracts/
      );
    });
  });

  describe("passkey", () => {
    const build = (p: unknown) =>
      buildPasskeyTxKey({ contracts: { webAuthnLogic: contracts.webAuthnLogic }, passkey: p as PasskeyKeyInput });

    it("matches the COSE path, rpIdHash path and uppercase coordinates byte for byte", () => {
      const reference = build(passkey);
      expect(reference).toBe(outputs.txKey);
      expect(build({ ...passkey, x: passkey.x!.toUpperCase().replace("0X", "0x"), y: passkey.y!.toUpperCase().replace("0X", "0x") })).toBe(reference);
      expect(
        build({
          credentialPubkey: toCosePublicKey({ x: inputs.passkey.x, y: inputs.passkey.y }),
          credentialId: passkey.credentialId,
          origin: passkey.origin,
          rpIdHash: inputs.passkey.rpIdHash.toUpperCase().replace("0X", "0x"),
        })
      ).toBe(reference);
    });

    it("accepts an explicit requireUV: false and rejects requireUV: true", () => {
      expect(build({ ...passkey, requireUV: false })).toBe(outputs.txKey);
      expectCode(() => build({ ...passkey, requireUV: true }), AaOperationErrorCode.INPUT_UNSUPPORTED, /requireUV/);
    });

    it.each([
      ["both public key forms", { ...passkey, credentialPubkey: toCosePublicKey({ x: inputs.passkey.x, y: inputs.passkey.y }) }],
      ["no public key", { credentialId: passkey.credentialId, origin: passkey.origin, rpId: inputs.passkey.rpId }],
      ["an rpIdHash that is not sha256(rpId)", { ...passkey, rpIdHash: "0x" + "ab".repeat(32) }],
      ["neither rpId nor rpIdHash", { x: passkey.x, y: passkey.y, credentialId: passkey.credentialId, origin: passkey.origin }],
      ["an empty rpId", { ...passkey, rpId: "" }],
      ["an empty credentialId", { ...passkey, credentialId: "" }],
      ["an empty origin", { ...passkey, origin: "" }],
      ["a missing origin", { ...passkey, origin: undefined }],
    ])("rejects %s", (_label, p) => {
      expectCode(() => build(p), AaOperationErrorCode.INPUT_INVALID);
    });

    it("accepts rpId together with the matching rpIdHash, in any hex case", () => {
      expect(build({ ...passkey, rpIdHash: inputs.passkey.rpIdHash })).toBe(outputs.txKey);
      expect(build({ ...passkey, rpIdHash: inputs.passkey.rpIdHash.toUpperCase().replace("0X", "0x") })).toBe(
        outputs.txKey
      );
    });

    it("checks a malformed rpIdHash even when rpId is given", () => {
      expectCode(() => build({ ...passkey, rpIdHash: "0x1234" }), AaOperationErrorCode.INPUT_INVALID_FORMAT, /rpIdHash/);
    });

    it.each([
      ["an https origin", "https://wallet.example.com"],
      ["an android origin", "android:apk-key-hash:abc"],
      ["a host with a port", "wallet.example.com:443"],
      ["a host with a path", "wallet.example.com/login"],
    ])("rejects %s as rpId", (_label, rpId) => {
      expectCode(() => build({ ...passkey, rpId }), AaOperationErrorCode.INPUT_INVALID_FORMAT, /passkey\.rpId/);
    });

    it("rejects a passkey that is not an object", () => {
      expectCode(() => build(null), AaOperationErrorCode.INPUT_INVALID);
      expectCode(
        () => buildOperationalMasterKey({ ...operationalParams(), passkey: "key" as unknown as PasskeyKeyInput }),
        AaOperationErrorCode.INPUT_INVALID
      );
    });

    it.each([
      ["a 31-byte rpIdHash", "0x" + "ab".repeat(31)],
      ["an rpIdHash without 0x", "ab".repeat(32)],
    ])("rejects %s", (_label, rpIdHash) => {
      expectCode(() => build({ ...passkey, rpId: undefined, rpIdHash }),AaOperationErrorCode.INPUT_INVALID_FORMAT, /rpIdHash/);
    });

    it.each([
      ["a short x", { x: "0x" + "11".repeat(31) }, /passkey\.x/],
      ["an x without 0x", { x: "11".repeat(32) }, /passkey\.x/],
      ["a missing y", { y: undefined }, /passkey\.y/],
      ["a long y", { y: "0x" + "11".repeat(33) }, /passkey\.y/],
    ])("rejects %s", (_label, patch, message) => {
      expectCode(() => build({ ...passkey, ...patch }), AaOperationErrorCode.SIGNER_KEY_INVALID, message);
    });

    it("rejects COSE bytes that are not hex", () => {
      const p = { credentialPubkey: "0xzz", credentialId: "id", origin: "o", rpId: "r" };
      expectCode(() => build(p), AaOperationErrorCode.SIGNER_KEY_INVALID, /credentialPubkey/);
    });

    it("wraps a COSE decoding failure as SIGNER_KEY_INVALID", () => {
      // CBOR unsigned integer 1 — not a map.
      const p = { credentialPubkey: "0x01", credentialId: "id", origin: "o", rpId: "r" };
      expectCode(() => build(p), AaOperationErrorCode.SIGNER_KEY_INVALID, /not a COSE public key/);
    });

    it("passes through the COSE key-type error of the shared decoder", () => {
      // CBOR map { 1: 1 } — kty = OKP, not EC2.
      const p = { credentialPubkey: "0xa10101", credentialId: "id", origin: "o", rpId: "r" };
      expectCode(() => build(p), AaOperationErrorCode.SIGNER_KEY_INVALID, /Not EC2/);
    });
  });
});

describe("encodePasskeyKeyInitData", () => {
  it("is the passkey slot of both the operational master key and the tx key", () => {
    const initData = encodePasskeyKeyInitData(passkey);
    expect(decodeKeySet(outputs.operationalMaster).initDataList[2]).toBe(initData);
    expect(decodeKeySet(outputs.txKey).initDataList[0]).toBe(initData);
  });

  it("encodes requireUV = false", () => {
    const [, , , requireUV] = ethers.AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32", "bytes", "bool"],
      encodePasskeyKeyInitData(passkey)
    );
    expect(requireUV).toBe(false);
  });

  it("validates its input", () => {
    expectCode(
      () => encodePasskeyKeyInitData({ ...passkey, credentialId: "" }),
      AaOperationErrorCode.INPUT_INVALID,
      /credentialId/
    );
  });

  it("is what AccountKeyBuilder.getEncodedWebAuthnKey produces for the same COSE key", () => {
    const cose = toCosePublicKey({ x: inputs.passkey.x, y: inputs.passkey.y });
    const builder = new AccountKeyBuilder();
    const viaBuilder = builder.getEncodedWebAuthnKey(
      cose,
      inputs.passkey.credentialId,
      inputs.passkey.rpIdHash,
      inputs.passkey.origin
    );
    expect(viaBuilder).toBe(encodePasskeyKeyInitData(passkey));

    // requireUV = true differs only in the bool word (4th head word).
    const withUV = builder.getEncodedWebAuthnKey(
      cose,
      inputs.passkey.credentialId,
      inputs.passkey.rpIdHash,
      inputs.passkey.origin,
      true
    );
    const boolWord = (hex: string) => hex.slice(2 + 3 * 64, 2 + 4 * 64);
    const withoutBoolWord = (hex: string) => hex.slice(0, 2 + 3 * 64) + hex.slice(2 + 4 * 64);
    expect(withoutBoolWord(withUV)).toBe(withoutBoolWord(viaBuilder));
    expect(boolWord(viaBuilder)).toBe("0".repeat(64));
    expect(boolWord(withUV)).toBe("0".repeat(63) + "1");
  });
});
