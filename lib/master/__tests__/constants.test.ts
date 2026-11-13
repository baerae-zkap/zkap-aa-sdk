import { ethers } from "ethers";
import {
  INITIAL_MASTER_KEY,
  MASTER_KEY_INDEX,
  MASTER_OP_KEY_INDEX_LIST,
  MASTER_OP_SIGNATURE_LENGTH,
  MASTER_OP_SIGNER_KEY_TYPES,
  OPERATIONAL_MASTER_KEY,
  PASSKEY_TX_KEY,
} from "../constants";
import { PrimitiveAccountKeyTypes } from "../../types/AccountKey";
import { AaOperationError, AaOperationErrorCode } from "../../errors";
import {
  createDummyCosignSignature,
  createDummyMasterOpSignature,
  createDummyZkSignature,
} from "../../utils/userOpUtils";

describe("master key constants", () => {
  it("describe the fixed layouts", () => {
    expect(MASTER_KEY_INDEX).toEqual({ zk: 0, cosigner: 1, passkey: 2 });
    expect(INITIAL_MASTER_KEY).toEqual({ threshold: 2, weights: [1, 1], zk: { n: 1, k: 1, anchorLength: 1 } });
    expect(OPERATIONAL_MASTER_KEY).toEqual({ threshold: 3, weights: [2, 1, 1], zk: { n: 6, k: 3, anchorLength: 4 } });
    expect(PASSKEY_TX_KEY).toEqual({ threshold: 1, weights: [1] });
    expect(MASTER_OP_KEY_INDEX_LIST).toEqual([0, 1]);
    expect(MASTER_OP_SIGNER_KEY_TYPES).toEqual([
      PrimitiveAccountKeyTypes.keyZkOAuthRS256,
      PrimitiveAccountKeyTypes.keyAddress,
    ]);
    expect(MASTER_OP_SIGNATURE_LENGTH).toEqual({ singleProof: 1120, threeProofs: 1760 });
  });

  it("are frozen", () => {
    for (const value of [
      MASTER_KEY_INDEX,
      INITIAL_MASTER_KEY,
      INITIAL_MASTER_KEY.weights,
      INITIAL_MASTER_KEY.zk,
      OPERATIONAL_MASTER_KEY,
      OPERATIONAL_MASTER_KEY.weights,
      PASSKEY_TX_KEY,
      PASSKEY_TX_KEY.weights,
      MASTER_OP_KEY_INDEX_LIST,
      MASTER_OP_SIGNER_KEY_TYPES,
      MASTER_OP_SIGNATURE_LENGTH,
    ]) {
      expect(Object.isFrozen(value)).toBe(true);
    }
  });
});

describe("master op dummy signatures", () => {
  const abi = ethers.AbiCoder.defaultAbiCoder();

  it("createDummyCosignSignature is a 65-byte signature that ECDSA recovery accepts", () => {
    const signature = createDummyCosignSignature();
    expect(ethers.getBytes(signature)).toHaveLength(65);
    expect(ethers.recoverAddress(ethers.ZeroHash, signature)).toBe(
      new ethers.Wallet(ethers.toBeHex(1n, 32)).address
    );
  });

  it.each([1, 3] as const)("createDummyMasterOpSignature(%i) is [0, 1] + zk dummy + cosign dummy", (proofCount) => {
    const signature = createDummyMasterOpSignature(proofCount);
    const [indices, signatures] = abi.decode(["uint8[]", "bytes[]"], signature);
    expect(Array.from(indices as bigint[], Number)).toEqual([0, 1]);
    expect(signatures[0]).toBe(createDummyZkSignature(proofCount));
    expect(signatures[1]).toBe(createDummyCosignSignature());
    const [, , , proofs] = abi.decode(["uint256[6]", "uint256[]", "uint256[]", "uint256[8][]"], signatures[0]);
    expect(proofs).toHaveLength(proofCount);
    expect(ethers.getBytes(signature)).toHaveLength(
      proofCount === 1 ? MASTER_OP_SIGNATURE_LENGTH.singleProof : MASTER_OP_SIGNATURE_LENGTH.threeProofs
    );
  });

  it.each([0, 2, 6])("createDummyMasterOpSignature(%i) throws", (proofCount) => {
    let thrown: unknown;
    try {
      createDummyMasterOpSignature(proofCount as 1 | 3);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(AaOperationError);
    expect((thrown as AaOperationError).code).toBe(AaOperationErrorCode.INPUT_OUT_OF_RANGE);
  });
});
