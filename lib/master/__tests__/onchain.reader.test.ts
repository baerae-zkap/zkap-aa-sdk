/**
 * AccountReader.classifyMasterKey / reconstructOperationalMasterKey — the
 * on-chain read (`readKeyState`) followed by the pure functions, against a
 * strict fake chain that answers only through the package's generated ABIs.
 */
import { AccountReader } from "../../reader/AccountReader";
import { AaFetchError, AaOperationError } from "../../errors";
import type { MasterKeyExpectation, ReconstructOperationalMasterKeyParams } from "../onchain";
import type { PasskeyKeyInput } from "../encoding";
import {
  strictChain,
  vectorKeyState,
  type FakeAccountState,
  type FakeChainOptions,
  type FakeZkData,
  type StrictChain,
} from "../../__tests__/helpers/fakeEthCall";
import { loadVectors, type VectorPasskey } from "./fixtures/vectors";

const { inputs, outputs } = loadVectors();

const ACCOUNT = "0x" + "11".repeat(20);
const OTHER_ADDRESS = "0x" + "5e".repeat(20);
const INITIAL_ANCHOR_HASH = 4242424242424242424242424242n;

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

const xyPasskey = (p: VectorPasskey): PasskeyKeyInput => ({
  x: p.x,
  y: p.y,
  credentialId: p.credentialId,
  origin: p.origin,
  rpId: p.rpId,
});

const params = (p: VectorPasskey): ReconstructOperationalMasterKeyParams => ({ ...EXPECTED, passkey: xyPasskey(p) });

/** The fixture wallet right after deployment: initial master key, no tx key. */
function initialState(): FakeAccountState {
  const state = vectorKeyState("initial", { initialAnchorHash: INITIAL_ANCHOR_HASH });
  return { ...state, tx: { threshold: 0, keys: [] } };
}

/** The fixture's operational wallet with the cosigner key's signer replaced. */
function otherState(): FakeAccountState {
  const state = vectorKeyState("operational");
  state.master.keys[1] = { ...state.master.keys[1], signer: OTHER_ADDRESS } as (typeof state.master.keys)[number];
  return state;
}

const readerOn = (chain: StrictChain) => new AccountReader({ call: chain.call });

/** What `readKeyState` reports for the same chain state. */
async function stateOf(state: FakeAccountState | undefined, opts: Omit<FakeChainOptions, "blockNumber"> = {}) {
  return readerOn(strictChain(ACCOUNT, state, opts)).readKeyState(ACCOUNT);
}

async function expectRejected(promise: Promise<unknown>, ctor: typeof AaOperationError | typeof AaFetchError) {
  let thrown: unknown;
  let resolved: unknown;
  try {
    resolved = await promise;
  } catch (err) {
    thrown = err;
  }
  expect(resolved).toBeUndefined();
  expect(thrown).toBeInstanceOf(ctor);
  expect(thrown).not.toBeInstanceOf(ctor === AaOperationError ? AaFetchError : AaOperationError);
}

describe("AccountReader master key classification and reconstruction", () => {
  describe("classifyMasterKey", () => {
    it.each([
      ["initial", () => initialState()],
      ["operational", () => vectorKeyState("operational")],
      ["undeployed", () => undefined],
    ] as const)("reads a %s wallet as %s, with empty reasons and the state it read", async (kind, make) => {
      const result = await readerOn(strictChain(ACCOUNT, make())).classifyMasterKey(ACCOUNT, EXPECTED);
      expect(result.kind).toBe(kind);
      expect(result.reasons).toEqual([]);
      expect(result.state).toEqual(await stateOf(make()));
    });

    it("reads an operational wallet with a foreign cosigner as other, with reasons", async () => {
      const result = await readerOn(strictChain(ACCOUNT, otherState())).classifyMasterKey(ACCOUNT, EXPECTED);
      expect(result.kind).toBe("other");
      expect(result.reasons.length).toBeGreaterThan(0);
      expect(result.state).toEqual(await stateOf(otherState()));
    });

    it("reads an initial-shaped wallet that already has a tx key as other", async () => {
      const state = vectorKeyState("initial", { initialAnchorHash: INITIAL_ANCHOR_HASH });
      const result = await readerOn(strictChain(ACCOUNT, state)).classifyMasterKey(ACCOUNT, EXPECTED);
      expect(result.kind).toBe("other");
      expect(result.reasons.length).toBeGreaterThan(0);
    });

    it("reads an operational wallet whose getAnchor has 4 elements as other", async () => {
      const state = vectorKeyState("operational");
      const zk = (state.master.keys[0] as { zk: FakeZkData }).zk;
      zk.anchorWithHash = zk.anchorWithHash.slice(0, 4);
      const result = await readerOn(strictChain(ACCOUNT, state)).classifyMasterKey(ACCOUNT, EXPECTED);
      expect(result.kind).toBe("other");
    });
  });

  describe("reconstructOperationalMasterKey", () => {
    it("rebuilds the fixture's reconstructedMaster from the chain and the new passkey", async () => {
      const chain = strictChain(ACCOUNT, vectorKeyState("operational"));
      const result = await readerOn(chain).reconstructOperationalMasterKey(ACCOUNT, params(inputs.newPasskey));
      expect(result.encodedMasterKey).toBe(outputs.reconstructedMaster);
      expect(result.state).toEqual(await stateOf(vectorKeyState("operational")));
    });

    it("rebuilds the installed operationalMaster from the chain and the same passkey", async () => {
      const chain = strictChain(ACCOUNT, vectorKeyState("operational"));
      const result = await readerOn(chain).reconstructOperationalMasterKey(ACCOUNT, params(inputs.passkey));
      expect(result.encodedMasterKey).toBe(outputs.operationalMaster);
    });

    it("gives the same bytes on the direct path (no Multicall3)", async () => {
      const chain = strictChain(ACCOUNT, vectorKeyState("operational"), { multicall: "absent" });
      const result = await readerOn(chain).reconstructOperationalMasterKey(ACCOUNT, params(inputs.newPasskey));
      expect(result.encodedMasterKey).toBe(outputs.reconstructedMaster);
      expect(result.state.readVia).toBe("direct");
    });

    it.each([
      ["initial", () => initialState()],
      ["undeployed", () => undefined],
      ["other", () => otherState()],
    ] as const)("rejects with AaOperationError for a %s wallet", async (_kind, make) => {
      const chain = strictChain(ACCOUNT, make());
      await expectRejected(readerOn(chain).reconstructOperationalMasterKey(ACCOUNT, params(inputs.newPasskey)), AaOperationError);
    });

    it("rejects with AaOperationError when the expectation does not match the chain", async () => {
      const chain = strictChain(ACCOUNT, vectorKeyState("operational"));
      const promise = readerOn(chain).reconstructOperationalMasterKey(ACCOUNT, {
        ...params(inputs.newPasskey),
        cosigner: OTHER_ADDRESS,
      });
      await expectRejected(promise, AaOperationError);
    });
  });

  describe("transport failures surface as AaFetchError, never as other or AaOperationError", () => {
    const failingAt = (index: number) =>
      strictChain(ACCOUNT, vectorKeyState("operational"), {
        beforeCall: (i) => {
          if (i === index) throw new Error("socket hang up");
        },
      });

    it.each([0, 1])("classifyMasterKey rejects when request %p fails", async (index) => {
      await expectRejected(readerOn(failingAt(index)).classifyMasterKey(ACCOUNT, EXPECTED), AaFetchError);
    });

    it.each([0, 1])("reconstructOperationalMasterKey rejects when request %p fails", async (index) => {
      await expectRejected(
        readerOn(failingAt(index)).reconstructOperationalMasterKey(ACCOUNT, params(inputs.newPasskey)),
        AaFetchError,
      );
    });

    it("classifyMasterKey rejects when the node cannot be reached at all", async () => {
      const reader = new AccountReader({
        call: async () => {
          throw new Error("ECONNRESET");
        },
      });
      await expectRejected(reader.classifyMasterKey(ACCOUNT, EXPECTED), AaFetchError);
      await expectRejected(reader.reconstructOperationalMasterKey(ACCOUNT, params(inputs.newPasskey)), AaFetchError);
    });
  });
});
