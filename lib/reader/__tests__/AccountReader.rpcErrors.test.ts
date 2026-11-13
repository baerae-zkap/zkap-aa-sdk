/**
 * AccountReader against real node error shapes.
 *
 * A real `ethers.JsonRpcProvider` is used; only its wire (`_send`) is stubbed.
 * ethers turns every JSON-RPC `error` answer to `eth_call` — a rate limit as
 * much as a revert — into a `CALL_EXCEPTION`; only a revert carries data
 * (`"0x"` for a revert without data), a node error has `data: null`.
 * These tests pin that a node error is never read as the end of a key list, as
 * an `"unknown"` key type or as a missing value: the read fails instead.
 */
import { ethers } from "ethers";
import { AccountReader } from "../AccountReader";
import { MULTICALL3_ADDRESS } from "../transport";
import { AaFetchError, AaFetchErrorCode } from "../../errors";
import {
  AccountKeyAddressABI,
  AccountKeyWebAuthnABI,
  AccountKeyZkOAuthRS256VerifierABI,
} from "../../types/abi";
import {
  accountIface,
  coder,
  decodeAggregate3Calls,
  fakeChain,
  PANIC_OOB,
  strictResolver,
  vectorKeyState,
} from "../../__tests__/helpers/fakeEthCall";
import type { Answer, FakeChain, FakeAccountState, MulticallMode } from "../../__tests__/helpers/fakeEthCall";
import type { MasterKeyExpectation } from "../../master/onchain";
import { loadVectors } from "../../master/__tests__/fixtures/vectors";

const { inputs } = loadVectors();
const { contracts } = inputs;

const ACCOUNT = "0x" + "11".repeat(20);
const RATE_LIMITED = { code: -32005, message: "rate limited" };

const EXPECTED: MasterKeyExpectation = {
  contracts: {
    zkVerifier1of1: contracts.zkVerifier1of1,
    zkVerifier3of6: contracts.zkVerifier3of6,
    addressKeyLogic: contracts.addressKeyLogic,
    webAuthnLogic: contracts.webAuthnLogic,
    merkleTreeDirectory: contracts.merkleTreeDirectory,
  },
  cosigner: inputs.cosigner,
};

const zkIface = new ethers.Interface(AccountKeyZkOAuthRS256VerifierABI);
const addressKeyIface = new ethers.Interface(AccountKeyAddressABI);
const webAuthnIface = new ethers.Interface(AccountKeyWebAuthnABI);

/** One `eth_call` (or one sub-call of an `aggregate3`). */
type Request = { to: string; data: string };
type Fault = (request: Request) => boolean;

const NO_FAULT: Fault = () => false;

/**
 * A real JsonRpcProvider whose wire answers from a fake chain, and answers
 * `error` for every `eth_call` that is — or, through Multicall3, contains — a
 * request matching `fault`. A contract revert goes over the wire the way anvil
 * sends it: `{ code: 3, message: "execution reverted", data }`, with
 * `data: "0x"` for a revert without data (see the captured responses).
 */
class WireStubbedProvider extends ethers.JsonRpcProvider {
  constructor(
    private readonly chain: FakeChain,
    private readonly fault: Fault,
    private readonly multicall: boolean,
  ) {
    super("http://127.0.0.1:1", 1, { staticNetwork: true });
  }

  override async _send(payload: ethers.JsonRpcPayload | ethers.JsonRpcPayload[]): Promise<ethers.JsonRpcResult[]> {
    const payloads = Array.isArray(payload) ? payload : [payload];
    return (await Promise.all(payloads.map((p) => this.answer(p)))) as ethers.JsonRpcResult[];
  }

  private async answer(p: ethers.JsonRpcPayload): Promise<ethers.JsonRpcResult | ethers.JsonRpcError> {
    const params = p.params as unknown[];
    if (p.method === "eth_chainId") return { id: p.id, result: "0x1" };
    if (p.method === "eth_getCode") return { id: p.id, result: await this.chain.getCode(params[0] as string) };
    if (p.method !== "eth_call") return { id: p.id, error: { code: -32601, message: "method not found" } };

    const { to, data } = params[0] as Request;
    const isMulticall = to.toLowerCase() === MULTICALL3_ADDRESS.toLowerCase();
    // Without Multicall3 the aggregate3 probe hits an address without code.
    const requests = isMulticall ? (this.multicall ? decodeAggregate3Calls(data) : []) : [{ target: to, callData: data }];
    if (requests.some((r) => this.fault({ to: r.target, data: r.callData }))) return { id: p.id, error: RATE_LIMITED };
    try {
      return { id: p.id, result: await this.chain.call({ to, data }) };
    } catch (err) {
      const revert = (err as { data?: string | null }).data;
      return typeof revert === "string"
        ? { id: p.id, error: { code: 3, message: "execution reverted", data: revert } }
        : { id: p.id, error: RATE_LIMITED };
    }
  }
}

const PATHS: [string, MulticallMode][] = [
  ["through Multicall3", "present"],
  ["through direct calls", "absent"],
];

function readerOn(state: FakeAccountState, mode: MulticallMode, fault: Fault = NO_FAULT) {
  const chain = fakeChain(strictResolver(ACCOUNT, () => state), { multicall: mode });
  const provider = new WireStubbedProvider(chain, fault, mode === "present");
  return { chain, reader: new AccountReader({ provider }) };
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const accountCall = (fn: string, index: number): Fault => (r) =>
  same(r.to, ACCOUNT) && same(r.data, accountIface.encodeFunctionData(fn, [index]));
const keyTypeOn = (logic: string): Fault => (r) =>
  same(r.to, logic) && same(r.data, webAuthnIface.encodeFunctionData("keyType"));
/** A typed getter of a master key (purpose 0). */
const masterGetter = (iface: ethers.Interface, fn: string, logic: string): Fault => (r) => {
  if (!same(r.to, logic) || !r.data.toLowerCase().startsWith(iface.getFunction(fn)!.selector)) return false;
  return Number(iface.decodeFunctionData(fn, r.data)[0]) === 0;
};

async function expectFetchError(promise: Promise<unknown>): Promise<AaFetchError> {
  let resolved: unknown;
  let thrown: unknown;
  try {
    resolved = await promise;
  } catch (err) {
    thrown = err;
  }
  expect(resolved).toBeUndefined();
  expect(thrown).toBeInstanceOf(AaFetchError);
  return thrown as AaFetchError;
}

describe("AccountReader on a real JsonRpcProvider with a stubbed wire", () => {
  describe.each(PATHS)("%s", (_label, mode) => {
    it("reads the operational wallet unchanged when the node answers everything", async () => {
      const { reader } = readerOn(vectorKeyState("operational"), mode);
      const result = await reader.classifyMasterKey(ACCOUNT, EXPECTED);
      expect(result.kind).toBe("operational");
      expect(result.state.readVia).toBe(mode === "present" ? "multicall" : "direct");
      expect(result.state.master.keys).toHaveLength(3);
      expect(result.state.tx.keys).toHaveLength(1);
    });

    // The operational wallet: master [zk, cosigner, passkey] (indices 0..2, the list ends at 3), tx [passkey].
    it.each<[string, Fault]>([
      ["masterKeyList(1), mid-list", accountCall("masterKeyList", 1)],
      ["masterKeyList(2), the last key", accountCall("masterKeyList", 2)],
      ["masterKeyList(3), where the list ends", accountCall("masterKeyList", 3)],
      ["masterKeyWeightList(1)", accountCall("masterKeyWeightList", 1)],
      ["masterKeyWeightList(3), where the weights end", accountCall("masterKeyWeightList", 3)],
      ["masterKeyThreshold()", (r) => same(r.to, ACCOUNT) && r.data.startsWith(accountIface.getFunction("masterKeyThreshold")!.selector)],
      ["txKeyList(1), where the tx list ends", accountCall("txKeyList", 1)],
      ["keyType() of the zk verifier", keyTypeOn(contracts.zkVerifier3of6)],
      ["keyType() of the address key logic", keyTypeOn(contracts.addressKeyLogic)],
      ["keyType() of the WebAuthn logic", keyTypeOn(contracts.webAuthnLogic)],
      ["getData of the zk key", masterGetter(zkIface, "getData", contracts.zkVerifier3of6)],
      ["getAnchor of the zk key", masterGetter(zkIface, "getAnchor", contracts.zkVerifier3of6)],
      ["getSigner of the cosigner", masterGetter(addressKeyIface, "getSigner", contracts.addressKeyLogic)],
      ["getKeyData of the master passkey", masterGetter(webAuthnIface, "getKeyData", contracts.webAuthnLogic)],
    ])("a rate-limited %s fails every read with AaFetchError", async (_what, fault) => {
      const { reader } = readerOn(vectorKeyState("operational"), mode, fault);
      const err = await expectFetchError(reader.readKeyState(ACCOUNT));
      // Through Multicall3 the whole eth_call fails; per call, ethers hands back a data-less CALL_EXCEPTION.
      expect(err.code).toBe(mode === "present" ? AaFetchErrorCode.TRANSPORT : AaFetchErrorCode.RESPONSE_SHAPE);
      await expectFetchError(reader.getMasterKeyInfo(ACCOUNT));
      await expectFetchError(reader.classifyMasterKey(ACCOUNT, EXPECTED));
    });

    it("readTxKeySlots fails when the slot that ends the list is rate-limited", async () => {
      const { reader } = readerOn(vectorKeyState("operational"), mode, accountCall("txKeyList", 1));
      await expectFetchError(reader.readTxKeySlots(ACCOUNT));
      await expectFetchError(reader.getPasskeys(ACCOUNT));
    });

    it.each<[string, Fault]>([
      ["keyType() of the WebAuthn logic", keyTypeOn(contracts.webAuthnLogic)],
      [
        "getKeyData of the tx passkey",
        (r) => same(r.to, contracts.webAuthnLogic) && r.data.toLowerCase().startsWith(webAuthnIface.getFunction("getKeyData")!.selector),
      ],
    ])("readTxKeySlots fails, instead of reporting an unknown or bare key, when %s is rate-limited", async (_what, fault) => {
      const { reader } = readerOn(vectorKeyState("operational"), mode, fault);
      await expectFetchError(reader.readTxKeySlots(ACCOUNT));
      await expectFetchError(reader.getPasskeys(ACCOUNT));
    });

    it("a getter of another key type failing does not matter: only the matching one is used", async () => {
      // getSigner on the zk verifier is not in its ABI; rate-limit it anyway.
      const fault: Fault = (r) =>
        same(r.to, contracts.zkVerifier3of6) && r.data.startsWith(addressKeyIface.getFunction("getSigner")!.selector);
      const { reader } = readerOn(vectorKeyState("operational"), mode, fault);
      if (mode === "present") {
        // Through Multicall3 it shares the eth_call with everything else.
        await expectFetchError(reader.readKeyState(ACCOUNT));
      } else {
        expect((await reader.classifyMasterKey(ACCOUNT, EXPECTED)).kind).toBe("operational");
      }
    });
  });
});

describe("a list ends on a revert without data or with Panic(0x32), and on nothing else", () => {
  const ERROR_STRING = "0x08c379a0" + coder.encode(["string"], ["out of range"]).slice(2);
  const PANIC_OVERFLOW = "0x4e487b71" + coder.encode(["uint256"], [0x11]).slice(2);
  const PANIC_END: Answer = { revert: true, data: PANIC_OOB };

  /** The operational wallet with some account getters answering otherwise. */
  function chainWith(
    overrides: [fn: string, index: number, answer: Answer][],
    mode: MulticallMode,
    state: FakeAccountState = vectorKeyState("operational"),
  ) {
    const resolve = strictResolver(ACCOUNT, () => state);
    const answers = new Map(
      overrides.map(([fn, index, answer]) => [accountIface.encodeFunctionData(fn, [index]).toLowerCase(), answer]),
    );
    return fakeChain(
      (address) => {
        const strict = resolve(address);
        if (!same(address, ACCOUNT) || !strict) return strict;
        return (data) => answers.get(data.toLowerCase()) ?? strict(data);
      },
      { multicall: mode },
    );
  }

  describe.each(PATHS)("%s", (_label, mode) => {
    // Through Multicall3 a node error fails the whole eth_call; per call it comes back without revert data.
    const nodeErrorCode = mode === "present" ? AaFetchErrorCode.TRANSPORT : AaFetchErrorCode.RESPONSE_SHAPE;

    it("reads the lists to their end when the getters revert without data (what the real getters do)", async () => {
      const state = await new AccountReader({ call: chainWith([], mode).call }).readKeyState(ACCOUNT);
      expect(state.master.keys).toHaveLength(3);
      expect(state.tx.keys).toHaveLength(1);
      expect([state.master.truncated, state.tx.truncated]).toEqual([false, false]);
    });

    it.each<[string, [string, number, Answer][]]>([
      ["both master lists end with Panic(0x32)", [["masterKeyList", 3, PANIC_END], ["masterKeyWeightList", 3, PANIC_END]]],
      ["masterKeyList ends with Panic(0x32), its weights without data", [["masterKeyList", 3, PANIC_END]]],
      ["the tx lists end with Panic(0x32)", [["txKeyList", 1, PANIC_END], ["txKeyWeightList", 1, PANIC_END]]],
    ])("also accepts Panic(0x32) as the end: %s", async (_what, overrides) => {
      const reader = new AccountReader({ call: chainWith(overrides, mode).call });
      expect((await reader.classifyMasterKey(ACCOUNT, EXPECTED)).kind).toBe("operational");
    });

    it.each<[string, string, number, Answer, string]>([
      ["masterKeyList(1) reverts with Error(string)", "masterKeyList", 1, { revert: true, data: ERROR_STRING }, AaFetchErrorCode.RESPONSE_SHAPE],
      ["masterKeyList(3) reverts with Panic(0x11)", "masterKeyList", 3, { revert: true, data: PANIC_OVERFLOW }, AaFetchErrorCode.RESPONSE_SHAPE],
      ["masterKeyList(3) answers empty data", "masterKeyList", 3, "0x", AaFetchErrorCode.RESPONSE_SHAPE],
      ["masterKeyList(1) ends early: its weight list goes on", "masterKeyList", 1, { revert: true }, AaFetchErrorCode.RESPONSE_SHAPE],
      ["masterKeyWeightList(3) still answers a weight", "masterKeyWeightList", 3, accountIface.encodeFunctionResult("masterKeyWeightList", [1]), AaFetchErrorCode.RESPONSE_SHAPE],
      ["masterKeyWeightList(3) reverts with Error(string)", "masterKeyWeightList", 3, { revert: true, data: ERROR_STRING }, AaFetchErrorCode.RESPONSE_SHAPE],
      ["txKeyList(1) reverts with Error(string)", "txKeyList", 1, { revert: true, data: ERROR_STRING }, AaFetchErrorCode.RESPONSE_SHAPE],
      ["masterKeyList(3) hits a node error", "masterKeyList", 3, "nodeerror", ""],
      ["masterKeyWeightList(3) hits a node error", "masterKeyWeightList", 3, "nodeerror", ""],
      ["txKeyList(1) hits a node error", "txKeyList", 1, "nodeerror", ""],
    ])("readKeyState throws when %s", async (_what, fn, index, answer, code) => {
      const reader = new AccountReader({ call: chainWith([[fn, index, answer]], mode).call });
      const err = await expectFetchError(reader.readKeyState(ACCOUNT));
      expect(err.code).toBe(code || nodeErrorCode);
      await expectFetchError(reader.classifyMasterKey(ACCOUNT, EXPECTED));
    });

    it("readKeyState throws on a zero-address slot instead of ending the list there", async () => {
      const zeroSlot: [string, number, Answer][] = [
        ["txKeyList", 0, accountIface.encodeFunctionResult("txKeyList", [ethers.ZeroAddress, 0])],
      ];
      const err = await expectFetchError(new AccountReader({ call: chainWith(zeroSlot, mode).call }).readKeyState(ACCOUNT));
      expect(err.code).toBe(AaFetchErrorCode.RESPONSE_SHAPE);
      // readTxKeySlots ends its list there instead.
      const slots = await new AccountReader({ call: chainWith(zeroSlot, mode).call }).readTxKeySlots(ACCOUNT);
      expect([slots.deployed, slots.keys, slots.truncated]).toEqual([true, [], false]);
    });

    it("readKeyState: the probe slot past a full window must end the list or hold a key", async () => {
      const state = vectorKeyState("operational");
      state.master.keys = Array.from({ length: 5 }, (_, i) => ({
        logic: contracts.addressKeyLogic,
        keyId: i,
        weight: 1,
        signer: inputs.cosigner,
      }));
      const full = await new AccountReader({ call: chainWith([], mode, state).call }).readKeyState(ACCOUNT);
      expect([full.master.keys.length, full.master.truncated]).toEqual([5, false]);

      for (const answer of ["nodeerror", { revert: true, data: ERROR_STRING }] as Answer[]) {
        const chain = chainWith([["masterKeyList", 5, answer]], mode, state);
        await expectFetchError(new AccountReader({ call: chain.call }).readKeyState(ACCOUNT));
      }
    });

    it("a getter past the list's end is not looked at", async () => {
      // The list ends at 3; index 4 answering an Error(string) changes nothing.
      const chain = chainWith([["masterKeyList", 4, { revert: true, data: ERROR_STRING }]], mode);
      const result = await new AccountReader({ call: chain.call }).classifyMasterKey(ACCOUNT, EXPECTED);
      expect(result.kind).toBe("operational");
    });

    it("readTxKeySlots: an empty list ends at txKeyList(0)", async () => {
      const state = vectorKeyState("operational");
      state.tx.keys = [];
      const slots = await new AccountReader({ call: chainWith([], mode, state).call }).readTxKeySlots(ACCOUNT);
      expect([slots.deployed, slots.keys, slots.truncated]).toEqual([true, [], false]);
    });

    it.each<[string, number, Answer, string]>([
      ["txKeyList(0) hits a node error", 0, "nodeerror", ""],
      ["txKeyList(1) hits a node error", 1, "nodeerror", ""],
      ["txKeyList(1) reverts with Error(string)", 1, { revert: true, data: ERROR_STRING }, AaFetchErrorCode.RESPONSE_SHAPE],
      ["txKeyList(1) reverts with Panic(0x11)", 1, { revert: true, data: PANIC_OVERFLOW }, AaFetchErrorCode.RESPONSE_SHAPE],
      ["txKeyList(1) answers empty data", 1, "0x", AaFetchErrorCode.RESPONSE_SHAPE],
    ])("readTxKeySlots throws when %s", async (_what, index, answer, code) => {
      const chain = chainWith([["txKeyList", index, answer]], mode);
      const err = await expectFetchError(new AccountReader({ call: chain.call }).readTxKeySlots(ACCOUNT));
      expect(err.code).toBe(code || nodeErrorCode);
    });

    it("readTxKeySlots: the probe slot past a full window must end the list or hold a key", async () => {
      const ends = await new AccountReader({ call: chainWith([], mode).call, maxTxKeys: 1 }).readTxKeySlots(ACCOUNT);
      expect([ends.keys.length, ends.truncated]).toEqual([1, false]);
      const chain = chainWith([["txKeyList", 1, "nodeerror"]], mode);
      await expectFetchError(new AccountReader({ call: chain.call, maxTxKeys: 1 }).readTxKeySlots(ACCOUNT));
    });

    it("readTxKeySlots still ends the list on Panic(0x32)", async () => {
      const chain = chainWith([["txKeyList", 1, PANIC_END]], mode);
      const slots = await new AccountReader({ call: chain.call }).readTxKeySlots(ACCOUNT);
      expect(slots.keys).toHaveLength(1);
      expect(slots.truncated).toBe(false);
    });
  });
});
