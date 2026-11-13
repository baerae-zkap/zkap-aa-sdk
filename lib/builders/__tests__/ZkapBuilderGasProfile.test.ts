/**
 * Gas-profile behaviour of `autoFillUserOp` + `applyBundlerPreVerificationGas`,
 * exercised against REAL ethers ABI coding (the sibling ZkapBuilder.test.ts mocks
 * `AbiCoder`, so it cannot produce a decodable zk signature).
 *
 * Only the RPC surface is stubbed, on the JsonRpcProvider prototype.
 */
import { ethers } from "ethers";
import { ZkapBuilder, ZkapAccountInfo } from "../ZkapBuilder";
import { calcAltoRequiredPvg, calibrateBundlerPvg } from "../../utils/bundlerPvg";
import {
  createDummyCosignSignature,
  createDummyMasterOpSignature,
  createDummyPasskeySignature,
  createDummyZkSignature,
} from "../../utils/userOpUtils";
import { ZkapAccountABI } from "../../types/abi";
import { PrimitiveAccountKeyTypes } from "../../types/AccountKey";
import { MASTER_OP_SIGNATURE_LENGTH } from "../../master/constants";
import { loadVectors } from "../../master/__tests__/fixtures/vectors";

const ENTRY_POINT = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";
const SENDER = "0x" + "11".repeat(20);

const accountInfo: ZkapAccountInfo = {
  chainId: 11155111,
  entryPoint: ENTRY_POINT,
  enUrl: "http://127.0.0.1:8545",
};

/** updateTxKey(bytes) with a 512-byte payload — shape of a real passkey-management op. */
const CALL_DATA = "0x25d90741" + "ab".repeat(512);

const ACCOUNT_IFACE = new ethers.Interface(ZkapAccountABI);
const FACTORY = "0x" + "44".repeat(20);
const ENCODED_MASTER_KEY = "0x" + "aa".repeat(640);
const ENCODED_TX_KEY = "0x" + "bb".repeat(320);
const UPDATE_KEYS_CALL_DATA = ACCOUNT_IFACE.encodeFunctionData("updateKeys", [
  ENCODED_MASTER_KEY,
  ENCODED_TX_KEY,
]);

const { keyZkOAuthRS256, keyAddress, keyWebAuthn } = PrimitiveAccountKeyTypes;

/** `[zk, cosigner]` signature as a cosigned master op carries it. */
const cosignedSignature = (proofCount: 1 | 3): [number[], string[]] => [
  [0, 1],
  [createDummyZkSignature(proofCount), createDummyCosignSignature()],
];

type MasterOpSetter = "setUpdateKeysCallData" | "setUpdateMasterKeyCallData" | "setUpdateTxKeyCallData";

const applyMasterOpSetter = (
  builder: ZkapBuilder,
  setter: MasterOpSetter,
  signerKeyTypes?: number[]
): void => {
  if (setter === "setUpdateKeysCallData") {
    builder.setUpdateKeysCallData(
      { encodedMasterKey: ENCODED_MASTER_KEY, encodedTxKey: ENCODED_TX_KEY },
      signerKeyTypes
    );
  } else {
    builder[setter](ENCODED_MASTER_KEY, signerKeyTypes);
  }
};

describe("ZkapBuilder gas profile (real ABI coding)", () => {
  beforeEach(() => {
    jest
      .spyOn(ethers.JsonRpcProvider.prototype, "getCode")
      .mockResolvedValue("0x60006000f3"); // wallet already deployed
    jest
      .spyOn(ethers.JsonRpcProvider.prototype, "estimateGas")
      .mockResolvedValue(BigInt(21000));
    jest.spyOn(ethers.JsonRpcProvider.prototype, "getFeeData").mockResolvedValue({
      maxFeePerGas: BigInt(2_000_000_000),
      maxPriorityFeePerGas: BigInt(1_000_000),
      gasPrice: BigInt(2_000_000_000),
    } as ethers.FeeData);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const build = async (signature?: string): Promise<ZkapBuilder> => {
    const builder = new ZkapBuilder(accountInfo);
    builder.setSender(SENDER);
    builder.setNonce("0x1"); // pre-set so no EntryPoint.getNonce call is needed
    builder.setSignerKeyTypes([6]); // keyZkOAuthRS256
    builder.setCallData(CALL_DATA);
    if (signature) {
      builder.setSignature([0], [signature]);
    }
    await builder.autoFillUserOp();
    return builder;
  };

  describe("verificationGasLimit follows the zk proof count", () => {
    it("uses the 1-of-1 budget for a single-proof signature (wallet deploy)", async () => {
      const builder = await build(createDummyZkSignature(1));

      // (25,000 base + 400,000 single-proof) * 1.2
      expect(BigInt(builder.getUserOp().verificationGasLimit)).toBe(510_000n);
    });

    it("uses the 3-of-6 budget for a three-proof signature (key updates)", async () => {
      const builder = await build(createDummyZkSignature(3));

      // (25,000 base + 900,000 three-of-six) * 1.2
      expect(BigInt(builder.getUserOp().verificationGasLimit)).toBe(1_110_000n);
    });

    it("falls back to the 3-of-6 budget when the signature is not a zk proof", async () => {
      // autoFillUserOp installs its own opaque dummy when no signature is set.
      const builder = await build();

      expect(BigInt(builder.getUserOp().verificationGasLimit)).toBe(1_110_000n);
    });
  });

  describe("master op signature byte length (preVerificationGas depends on it)", () => {
    // The bundler recomputes its PVG floor from the SUBMITTED signature length, while the
    // caller freezes PVG against the dummy. A cosigned master op signature is
    // abi.encode(uint8[] [0, 1], bytes[] [zkSignature, 65-byte cosigner signature]):
    // 1120B with one proof (initial master key), 1760B with three (operational master key).
    // If the proof or signature shape ever changes, this must fail before a flow silently
    // under-declares.
    const vectors = loadVectors();

    it.each([
      [1 as const, 1120, MASTER_OP_SIGNATURE_LENGTH.singleProof, vectors.outputs.signatureLength.initialMasterOp],
      [3 as const, 1760, MASTER_OP_SIGNATURE_LENGTH.threeProofs, vectors.outputs.signatureLength.operationalMasterOp],
    ])("proofCount %i encodes to %iB", (proofCount, expectedBytes, constantBytes, fixtureBytes) => {
      const signature = createDummyMasterOpSignature(proofCount);

      expect(ethers.dataLength(signature)).toBe(expectedBytes);
      expect(constantBytes).toBe(expectedBytes);
      expect(fixtureBytes).toBe(expectedBytes);
    });

    it.each([1 as const, 3 as const])(
      "setSignature([0, 1], [zk, cosign]) with %i proof(s) yields the same bytes as the dummy",
      (proofCount) => {
        const builder = new ZkapBuilder(accountInfo);
        builder.setSender(SENDER);
        builder.setSignature(...cosignedSignature(proofCount));

        expect(builder.getUserOp().signature).toBe(createDummyMasterOpSignature(proofCount));
      }
    );
  });

  describe("applyBundlerPreVerificationGas", () => {
    it("replaces the SDK estimate with the calibrated bundler floor", async () => {
      const builder = await build(createDummyZkSignature(3));
      const sdkEstimate = BigInt(builder.getUserOp().preVerificationGas);

      builder.applyBundlerPreVerificationGas();

      const applied = BigInt(builder.getUserOp().preVerificationGas);
      const required = calcAltoRequiredPvg(builder.getUserOp());

      expect(applied).toBe(calibrateBundlerPvg(builder.getUserOp()));
      expect(applied).toBeGreaterThan(required);
      expect(applied).not.toBe(sdkEstimate);
    });

    it("emits even-length hex (odd-length hex is rejected by gas setters downstream)", async () => {
      const builder = await build(createDummyZkSignature(3));

      builder.applyBundlerPreVerificationGas();

      const hex = builder.getUserOp().preVerificationGas;
      expect((hex.length - 2) % 2).toBe(0);
    });

    it("never lowers a preVerificationGas that is already higher", async () => {
      const builder = await build(createDummyZkSignature(3));
      builder.setPreVerificationGas(ethers.toBeHex(9_000_000));

      builder.applyBundlerPreVerificationGas();

      expect(BigInt(builder.getUserOp().preVerificationGas)).toBe(9_000_000n);
    });

    it("honours margin and L2 options", async () => {
      const builder = await build(createDummyZkSignature(3));
      const required = calcAltoRequiredPvg(builder.getUserOp(), {
        extraComponent: 50_000n,
      });

      builder.applyBundlerPreVerificationGas({
        marginPercent: 100n,
        marginAbsolute: 0n,
        extraComponent: 50_000n,
      });

      expect(BigInt(builder.getUserOp().preVerificationGas)).toBe(required);
    });
  });
  describe("verificationGasLimit of cosigned master ops", () => {
    const buildMasterOp = async (
      setter: MasterOpSetter,
      signature: [number[], string[]],
      signerKeyTypes?: number[]
    ): Promise<ZkapBuilder> => {
      const builder = new ZkapBuilder(accountInfo);
      builder.setSender(SENDER);
      builder.setNonce("0x1");
      applyMasterOpSetter(builder, setter, signerKeyTypes);
      builder.setSignature(...signature);
      await builder.autoFillUserOp();
      return builder;
    };

    const setters: MasterOpSetter[] = [
      "setUpdateKeysCallData",
      "setUpdateMasterKeyCallData",
      "setUpdateTxKeyCallData",
    ];

    describe.each(setters)("%s", (setter) => {
      it("default key types, one proof: (25,000 + 400,000 + 15,000) * 1.2", async () => {
        const builder = await buildMasterOp(setter, cosignedSignature(1));

        expect(BigInt(builder.getUserOp().verificationGasLimit)).toBe(528_000n);
      });

      it("default key types, three proofs: (25,000 + 900,000 + 15,000) * 1.2", async () => {
        const builder = await buildMasterOp(setter, cosignedSignature(3));

        expect(BigInt(builder.getUserOp().verificationGasLimit)).toBe(1_128_000n);
      });

      it("explicit [zk] keeps the zk-only budgets", async () => {
        const single = await buildMasterOp(setter, [[0], [createDummyZkSignature(1)]], [keyZkOAuthRS256]);
        const three = await buildMasterOp(setter, [[0], [createDummyZkSignature(3)]], [keyZkOAuthRS256]);

        expect(BigInt(single.getUserOp().verificationGasLimit)).toBe(510_000n);
        expect(BigInt(three.getUserOp().verificationGasLimit)).toBe(1_110_000n);
      });

      it("explicit [zk, webAuthn]: (25,000 + 900,000 + 150,000) * 1.2", async () => {
        const builder = await buildMasterOp(
          setter,
          [[0, 2], [createDummyZkSignature(3), createDummyPasskeySignature()]],
          [keyZkOAuthRS256, keyWebAuthn]
        );

        expect(BigInt(builder.getUserOp().verificationGasLimit)).toBe(
          ((25_000n + 900_000n + 150_000n) * 120n) / 100n
        );
      });
    });

    it("reads the proof count from the FIRST signature of a [zk, cosign] list", async () => {
      // keySignatureList[0] is the single-proof zk signature → 1-of-1 budget.
      const zkFirst = await buildMasterOp("setUpdateKeysCallData", cosignedSignature(1));
      // Cosigner first: [0] is not a zk proof → conservative 3-of-6 budget.
      const cosignFirst = await buildMasterOp("setUpdateKeysCallData", [
        [1, 0],
        [createDummyCosignSignature(), createDummyZkSignature(1)],
      ]);

      expect(BigInt(zkFirst.getUserOp().verificationGasLimit)).toBe(528_000n);
      expect(BigInt(cosignFirst.getUserOp().verificationGasLimit)).toBe(1_128_000n);
    });

    it("default key types are [keyZkOAuthRS256, keyAddress]", async () => {
      const builder = await buildMasterOp("setUpdateKeysCallData", cosignedSignature(1));
      const explicit = await buildMasterOp("setUpdateKeysCallData", cosignedSignature(1), [
        keyZkOAuthRS256,
        keyAddress,
      ]);

      expect(builder.getUserOp().verificationGasLimit).toBe(explicit.getUserOp().verificationGasLimit);
    });
  });

  describe("callGasLimit", () => {
    const buildDeployed = async (callData: string, estimate: bigint): Promise<ZkapBuilder> => {
      jest.spyOn(ethers.JsonRpcProvider.prototype, "estimateGas").mockResolvedValue(estimate);
      const builder = new ZkapBuilder(accountInfo);
      builder.setSender(SENDER);
      builder.setNonce("0x1");
      builder.setSignerKeyTypes([keyZkOAuthRS256, keyAddress]);
      builder.setCallData(callData);
      builder.setSignature(...cosignedSignature(3));
      await builder.autoFillUserOp();
      return builder;
    };

    describe("deployed wallet + updateKeys: estimate * 120 / 100 + 25,000", () => {
      it.each([
        [1_265_437n, 1_543_524n], // 1,518,524.4 → 1,518,524
        [663_641n, 821_369n], // 796,369.2 → 796,369
        [100_004n, 145_004n], // 120,004.8 → 120,004 (integer division floors)
      ])("estimate %s → %s", async (estimate, expected) => {
        const builder = await buildDeployed(UPDATE_KEYS_CALL_DATA, estimate);

        expect(BigInt(builder.getUserOp().callGasLimit)).toBe(expected);
      });

      it("matches the updateKeys selector case-insensitively", async () => {
        const upper = "0x" + UPDATE_KEYS_CALL_DATA.slice(2).toUpperCase();
        const builder = await buildDeployed(upper, 1_265_437n);

        expect(BigInt(builder.getUserOp().callGasLimit)).toBe(1_543_524n);
      });
    });

    describe("deployed wallet + any other selector: estimate + 25,000 (unchanged)", () => {
      const otherCallData: Array<[string, string]> = [
        ["updateMasterKey", ACCOUNT_IFACE.encodeFunctionData("updateMasterKey", [ENCODED_MASTER_KEY])],
        ["updateTxKey", ACCOUNT_IFACE.encodeFunctionData("updateTxKey", [ENCODED_TX_KEY])],
        ["execute", ACCOUNT_IFACE.encodeFunctionData("execute", [SENDER, 0n, "0x"])],
      ];

      it.each(otherCallData)("%s", async (_name, callData) => {
        const builder = await buildDeployed(callData, 1_265_437n);

        expect(BigInt(builder.getUserOp().callGasLimit)).toBe(1_290_437n);
      });

      it("callData shorter than a selector", async () => {
        const builder = await buildDeployed("0x1234", 1_265_437n);

        expect(BigInt(builder.getUserOp().callGasLimit)).toBe(1_290_437n);
      });
    });

    it("undeployed wallet + initCode + updateKeys: UPDATE_KEYS_CALL_GAS + 25,000 = 1,825,000", async () => {
      jest.spyOn(ethers.JsonRpcProvider.prototype, "getCode").mockResolvedValue("0x");
      const builder = new ZkapBuilder(accountInfo);
      builder.setSender(SENDER);
      builder.setNonce("0x0");
      builder.setInitCode(FACTORY, 1n, {
        encodedMasterKey: ENCODED_MASTER_KEY,
        encodedTxKey: ENCODED_TX_KEY,
      });
      builder.setUpdateKeysCallData({ encodedMasterKey: ENCODED_MASTER_KEY, encodedTxKey: ENCODED_TX_KEY });
      builder.setSignature(...cosignedSignature(1));

      await builder.autoFillUserOp();

      expect(ZkapBuilder.UPDATE_KEYS_CALL_GAS).toBe(1_800_000n);
      expect(BigInt(builder.getUserOp().callGasLimit)).toBe(1_825_000n);
    });
  });

  describe("updateKeys on a deployed wallet without initCode", () => {
    const NONCE = 7n;
    const getNonceIface = new ethers.Interface([
      "function getNonce(address,uint192) view returns (uint256)",
    ]);

    const stubNonce = (): jest.SpyInstance =>
      jest
        .spyOn(ethers.JsonRpcProvider.prototype, "call")
        .mockResolvedValue(getNonceIface.encodeFunctionResult("getNonce", [NONCE]));

    const newBuilder = (): ZkapBuilder => {
      const builder = new ZkapBuilder(accountInfo);
      builder.setSender(SENDER);
      builder.setUpdateKeysCallData({ encodedMasterKey: ENCODED_MASTER_KEY, encodedTxKey: ENCODED_TX_KEY });
      builder.setSignature(...cosignedSignature(3));
      return builder;
    };

    it("estimates from the EntryPoint against the wallet, skips the factory, reads the nonce from the EntryPoint", async () => {
      const callSpy = stubNonce();
      const estimateSpy = jest
        .spyOn(ethers.JsonRpcProvider.prototype, "estimateGas")
        .mockResolvedValue(663_641n);
      const builder = newBuilder();

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      // Only the execution estimate: no factory (initCode) estimate.
      expect(estimateSpy).toHaveBeenCalledTimes(1);
      expect(estimateSpy).toHaveBeenCalledWith(
        expect.objectContaining({ from: ENTRY_POINT, to: SENDER, data: UPDATE_KEYS_CALL_DATA })
      );
      expect(userOp.initCode).toBe("0x");
      expect(BigInt(userOp.callGasLimit)).toBe(821_369n);

      expect(callSpy).toHaveBeenCalledTimes(1);
      const nonceCall = callSpy.mock.calls[0][0] as ethers.TransactionRequest;
      expect(String(nonceCall.to).toLowerCase()).toBe(ENTRY_POINT.toLowerCase());
      expect(getNonceIface.decodeFunctionData("getNonce", nonceCall.data as string)[0].toLowerCase()).toBe(
        SENDER.toLowerCase()
      );
      expect(BigInt(userOp.nonce)).toBe(NONCE);
    });

    it("throws when the wallet is not deployed and there is no initCode", async () => {
      stubNonce();
      jest.spyOn(ethers.JsonRpcProvider.prototype, "getCode").mockResolvedValue("0x");
      const builder = newBuilder();

      await expect(builder.autoFillUserOp()).rejects.toThrow("Wallet not deployed and no initCode provided");
    });
  });
});
