/**
 * Known-answer tests against `fixtures/master-key-cosign-vectors.json`: byte strings
 * the account contracts accepted on a local test chain. The vectors are canonical;
 * these tests check this package against them, never the other way round.
 */
import { ethers } from "ethers";
import {
  buildInitialMasterKey,
  buildOperationalMasterKey,
  buildPasskeyTxKey,
  type PasskeyKeyInput,
  type UintInput,
  type ZkKeyInput,
} from "../encoding";
import {
  INITIAL_MASTER_KEY,
  MASTER_OP_SIGNATURE_LENGTH,
  OPERATIONAL_MASTER_KEY,
  PASSKEY_TX_KEY,
} from "../constants";
import { createDummyMasterOpSignature } from "../../utils/userOpUtils";
import { toCosePublicKey } from "../../utils/webauthnKey";
import { ZkapFactoryBuilder } from "../../builders/ZkapFactoryBuilder";
import { ZkapCreator } from "../../builders/ZkapCreator";
import { ZkapAccountABI, ZkapAccountFactoryABI } from "../../types/abi";
import { ERC1967_PROXY_CREATION_CODE } from "./fixtures/erc1967ProxyCreationCode";
import { loadVectors, readVectorsFile, type VectorPasskey, type VectorZk } from "./fixtures/vectors";

const vectors = loadVectors();
const { inputs, outputs } = vectors;
const { contracts } = inputs;

type Radix = "decimal" | "hex" | "bigint";
const RADIXES: Radix[] = ["decimal", "hex", "bigint"];

function asRadix(value: string, radix: Radix): UintInput {
  const n = BigInt(value);
  if (radix === "bigint") return n;
  if (radix === "hex") return `0x${n.toString(16)}`;
  return n.toString(10);
}

function zkInput(zk: VectorZk, radix: Radix): ZkKeyInput {
  return { hAudList: asRadix(zk.hAudList, radix), anchor: zk.anchor.map((a) => asRadix(a, radix)) };
}

type PasskeyForm = "xy+rpId" | "xy+rpIdHash" | "cose+rpId" | "cose+rpIdHash";
const PASSKEY_FORMS: PasskeyForm[] = ["xy+rpId", "xy+rpIdHash", "cose+rpId", "cose+rpIdHash"];

function passkeyInput(p: VectorPasskey, form: PasskeyForm): PasskeyKeyInput {
  const common = { credentialId: p.credentialId, origin: p.origin };
  const rp = form.endsWith("rpId") ? { rpId: p.rpId } : { rpIdHash: p.rpIdHash };
  const key = form.startsWith("xy") ? { x: p.x, y: p.y } : { credentialPubkey: toCosePublicKey({ x: p.x, y: p.y }) };
  return { ...common, ...rp, ...key } as PasskeyKeyInput;
}

const initialContracts = {
  zkVerifier1of1: contracts.zkVerifier1of1,
  addressKeyLogic: contracts.addressKeyLogic,
  merkleTreeDirectory: contracts.merkleTreeDirectory,
};
const operationalContracts = {
  zkVerifier3of6: contracts.zkVerifier3of6,
  addressKeyLogic: contracts.addressKeyLogic,
  webAuthnLogic: contracts.webAuthnLogic,
  merkleTreeDirectory: contracts.merkleTreeDirectory,
};

describe("master key vectors", () => {
  describe("vector layout matches the package constants", () => {
    it("initial master key", () => {
      expect(inputs.initialMaster.threshold).toBe(INITIAL_MASTER_KEY.threshold);
      expect(inputs.initialMaster.weights).toEqual(INITIAL_MASTER_KEY.weights);
      expect(BigInt(inputs.initialMaster.zk.n)).toBe(BigInt(INITIAL_MASTER_KEY.zk.n));
      expect(BigInt(inputs.initialMaster.zk.k)).toBe(BigInt(INITIAL_MASTER_KEY.zk.k));
      expect(inputs.initialMaster.zk.anchor).toHaveLength(INITIAL_MASTER_KEY.zk.anchorLength);
    });

    it("operational master key", () => {
      expect(inputs.operationalMaster.threshold).toBe(OPERATIONAL_MASTER_KEY.threshold);
      expect(inputs.operationalMaster.weights).toEqual(OPERATIONAL_MASTER_KEY.weights);
      expect(BigInt(inputs.operationalMaster.zk.n)).toBe(BigInt(OPERATIONAL_MASTER_KEY.zk.n));
      expect(BigInt(inputs.operationalMaster.zk.k)).toBe(BigInt(OPERATIONAL_MASTER_KEY.zk.k));
      expect(inputs.operationalMaster.zk.anchor).toHaveLength(OPERATIONAL_MASTER_KEY.zk.anchorLength);
    });

    it("tx key and passkeys", () => {
      expect(inputs.txKey.threshold).toBe(PASSKEY_TX_KEY.threshold);
      expect(inputs.txKey.weights).toEqual(PASSKEY_TX_KEY.weights);
      expect(inputs.passkey.requireUV).toBe(false);
      expect(inputs.newPasskey.requireUV).toBe(false);
    });
  });

  // Test 1 — builders reproduce the five accepted blobs byte for byte.
  describe("builders reproduce the vector blobs", () => {
    describe.each(RADIXES)("numbers as %s", (radix) => {
      it("initialMaster", () => {
        expect(
          buildInitialMasterKey({
            contracts: initialContracts,
            zk: zkInput(inputs.initialMaster.zk, radix),
            cosigner: inputs.cosigner,
          })
        ).toBe(outputs.initialMaster);
      });

      it.each(PASSKEY_FORMS)("operationalMaster (passkey %s)", (form) => {
        expect(
          buildOperationalMasterKey({
            contracts: operationalContracts,
            zk: zkInput(inputs.operationalMaster.zk, radix),
            cosigner: inputs.cosigner,
            passkey: passkeyInput(inputs.passkey, form),
          })
        ).toBe(outputs.operationalMaster);
      });

      it.each(PASSKEY_FORMS)("reconstructedMaster (new passkey %s)", (form) => {
        expect(
          buildOperationalMasterKey({
            contracts: operationalContracts,
            zk: zkInput(inputs.operationalMaster.zk, radix),
            cosigner: inputs.cosigner,
            passkey: passkeyInput(inputs.newPasskey, form),
          })
        ).toBe(outputs.reconstructedMaster);
      });
    });

    it.each(PASSKEY_FORMS)("txKey (passkey %s)", (form) => {
      expect(
        buildPasskeyTxKey({
          contracts: { webAuthnLogic: contracts.webAuthnLogic },
          passkey: passkeyInput(inputs.passkey, form),
        })
      ).toBe(outputs.txKey);
    });

    it.each(PASSKEY_FORMS)("newTxKey (new passkey %s)", (form) => {
      expect(
        buildPasskeyTxKey({
          contracts: { webAuthnLogic: contracts.webAuthnLogic },
          passkey: passkeyInput(inputs.newPasskey, form),
        })
      ).toBe(outputs.newTxKey);
    });

    it("takes the fixture's passkey objects as they are (rpId + rpIdHash + requireUV: false)", () => {
      // No picking or reshaping: the records go in exactly as the fixture holds them.
      const raw = JSON.parse(readVectorsFile().toString("utf8")) as {
        inputs: { passkey: PasskeyKeyInput; newPasskey: PasskeyKeyInput };
      };
      expect(raw.inputs.passkey.requireUV).toBe(false);
      expect(raw.inputs.passkey.rpId).toBeDefined();
      expect(raw.inputs.passkey.rpIdHash).toBeDefined();
      const zk = zkInput(inputs.operationalMaster.zk, "decimal");
      expect(
        buildOperationalMasterKey({ contracts: operationalContracts, zk, cosigner: inputs.cosigner, passkey: raw.inputs.passkey })
      ).toBe(outputs.operationalMaster);
      expect(
        buildOperationalMasterKey({ contracts: operationalContracts, zk, cosigner: inputs.cosigner, passkey: raw.inputs.newPasskey })
      ).toBe(outputs.reconstructedMaster);
      expect(buildPasskeyTxKey({ contracts: { webAuthnLogic: contracts.webAuthnLogic }, passkey: raw.inputs.passkey })).toBe(
        outputs.txKey
      );
      expect(
        buildPasskeyTxKey({ contracts: { webAuthnLogic: contracts.webAuthnLogic }, passkey: raw.inputs.newPasskey })
      ).toBe(outputs.newTxKey);
    });

    it("accepts the vector's lowercase-address and checksummed-address spellings alike", () => {
      const lower = Object.fromEntries(
        Object.entries(initialContracts).map(([k, v]) => [k, v.toLowerCase()])
      ) as typeof initialContracts;
      expect(
        buildInitialMasterKey({
          contracts: lower,
          zk: zkInput(inputs.initialMaster.zk, "decimal"),
          cosigner: inputs.cosigner.toLowerCase(),
        })
      ).toBe(outputs.initialMaster);
    });
  });

  // Test 3 — dummy master op signature lengths.
  describe("master op signature length", () => {
    const byteLength = (hex: string): number => ethers.getBytes(hex).length;

    it("one proof: dummy = vector = constant", () => {
      expect(byteLength(createDummyMasterOpSignature(1))).toBe(outputs.signatureLength.initialMasterOp);
      expect(MASTER_OP_SIGNATURE_LENGTH.singleProof).toBe(outputs.signatureLength.initialMasterOp);
    });

    it("three proofs: dummy = vector = constant", () => {
      expect(byteLength(createDummyMasterOpSignature(3))).toBe(outputs.signatureLength.operationalMasterOp);
      expect(MASTER_OP_SIGNATURE_LENGTH.threeProofs).toBe(outputs.signatureLength.operationalMasterOp);
    });
  });

  // Test 4 — wallet address.
  describe("wallet address", () => {
    const factoryInterface = new ethers.Interface(ZkapAccountFactoryABI);
    const expectedCallData = factoryInterface.encodeFunctionData("calcAccountAddress", [
      inputs.salt,
      outputs.initialMaster,
      "0x",
    ]);

    describe("① calcAccountAddress is asked for exactly (factory, salt, initialMaster, 0x)", () => {
      let calls: ethers.TransactionRequest[];

      beforeEach(() => {
        calls = [];
        jest
          .spyOn(ethers.JsonRpcProvider.prototype, "call")
          .mockImplementation(async (tx: ethers.TransactionRequest) => {
            calls.push(tx);
            return factoryInterface.encodeFunctionResult("calcAccountAddress", [outputs.walletAddress]);
          });
      });

      afterEach(() => {
        jest.restoreAllMocks();
      });

      it("ZkapFactoryBuilder.calcAccountAddress", async () => {
        const factory = new ZkapFactoryBuilder(contracts.factory, "http://127.0.0.1:8545");
        const address = await factory.calcAccountAddress(inputs.salt, outputs.initialMaster, "0x");

        expect(address).toBe(outputs.walletAddress);
        expect(calls).toHaveLength(1);
        expect(String(calls[0].to).toLowerCase()).toBe(contracts.factory.toLowerCase());
        expect(calls[0].data).toBe(expectedCallData);
      });

      it("ZkapCreator.deriveZkapAddress", async () => {
        const creator = new ZkapCreator({
          chainId: 31337,
          entryPoint: "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108",
          zkapFactory: contracts.factory,
          enUrl: "http://127.0.0.1:8545",
          salt: inputs.salt,
          encodedMasterKey: outputs.initialMaster,
          encodedTxKey: "0x",
        });
        const address = await creator.deriveZkapAddress();

        expect(address).toBe(outputs.walletAddress);
        expect(calls).toHaveLength(1);
        expect(String(calls[0].to).toLowerCase()).toBe(contracts.factory.toLowerCase());
        expect(calls[0].data).toBe(expectedCallData);
      });
    });

    describe("② local CREATE2 recomputation (test-only proxy creation code)", () => {
      const accountInterface = new ethers.Interface(ZkapAccountABI);

      function create2Address(initialMaster: string): string {
        const initializeCalldata = accountInterface.encodeFunctionData("initialize", [initialMaster, "0x"]);
        const constructorArgs = ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "bytes"],
          [contracts.accountImplementation, initializeCalldata]
        );
        const initCodeHash = ethers.keccak256(ethers.concat([ERC1967_PROXY_CREATION_CODE, constructorArgs]));
        return ethers.getCreate2Address(contracts.factory, ethers.toBeHex(BigInt(inputs.salt), 32), initCodeHash);
      }

      it("matches outputs.walletAddress", () => {
        expect(create2Address(outputs.initialMaster)).toBe(outputs.walletAddress);
      });

      it("changes when one byte of initialMaster changes", () => {
        const bytes = ethers.getBytes(outputs.initialMaster);
        bytes[bytes.length - 1] ^= 0x01;
        expect(create2Address(ethers.hexlify(bytes))).not.toBe(outputs.walletAddress);
      });
    });
  });

  // Test 5 — the package fixture is the reviewed one.
  it("fixture file sha256 is pinned", () => {
    expect(ethers.sha256(readVectorsFile()).slice(2)).toBe(
      "13b89bea35384d5c8932297aef4396ffaa67741bcabb1fa38ec10b88bdb2304e"
    );
  });
});
