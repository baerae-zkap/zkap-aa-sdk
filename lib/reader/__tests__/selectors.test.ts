/**
 * Selector and response goldens for the reader's contract reads.
 *
 * The 4-byte selectors are pinned as literals (keccak256 of the Solidity
 * signature) and checked against both the generated ABI and the calldata the
 * reader actually sends, so neither can drift on its own. The fixture's
 * on-chain answers are replayed as raw bytes encoded without any ABI, so the
 * reader's decoding is checked against an independent encoding.
 */
import { ethers } from "ethers";
import { AccountReader } from "../AccountReader";
import {
  AccountKeyAddressABI,
  AccountKeyWebAuthnABI,
  AccountKeyZkOAuthRS256VerifierABI,
  Multicall3ABI,
  ZkapAccountABI,
} from "../../types/abi";
import {
  coder,
  decodeAggregate3Calls,
  fakeChain,
  strictChain,
  strictResolver,
  vectorKeyState,
} from "../../__tests__/helpers/fakeEthCall";
import type { FakeChainOptions, Handler } from "../../__tests__/helpers/fakeEthCall";
import { loadVectors } from "../../master/__tests__/fixtures/vectors";

const ACCOUNT = "0x" + "11".repeat(20);

/** [signature, selector literal, generated ABI that must carry it] */
const GOLDEN: [string, string, readonly unknown[]][] = [
  ["getData(uint8,address,uint256)", "0xa14fe394", AccountKeyZkOAuthRS256VerifierABI],
  ["getAnchor(uint8,address,uint256)", "0x04c713f4", AccountKeyZkOAuthRS256VerifierABI],
  ["getSigner(uint8,address,uint256)", "0x15c02b53", AccountKeyAddressABI],
  ["getKeyData(uint8,address,uint256)", "0xbe271ac5", AccountKeyWebAuthnABI],
  ["keyType()", "0x38592e5a", AccountKeyZkOAuthRS256VerifierABI],
  ["keyType()", "0x38592e5a", AccountKeyAddressABI],
  ["keyType()", "0x38592e5a", AccountKeyWebAuthnABI],
  ["masterKeyList(uint256)", "0x9036acff", ZkapAccountABI],
  ["masterKeyWeightList(uint256)", "0x6ff033f6", ZkapAccountABI],
  ["masterKeyThreshold()", "0x32632ad2", ZkapAccountABI],
  ["txKeyList(uint256)", "0xa93a3d92", ZkapAccountABI],
  ["txKeyWeightList(uint256)", "0x852533cb", ZkapAccountABI],
  ["txKeyThreshold()", "0x0ee96d17", ZkapAccountABI],
];
const AGGREGATE3 = "0x82ad56cb";

const ACCOUNT_SELECTORS = ["0x9036acff", "0x6ff033f6", "0x32632ad2", "0xa93a3d92", "0x852533cb", "0x0ee96d17"];
const LOGIC_SELECTORS = ["0xa14fe394", "0x04c713f4", "0x15c02b53", "0xbe271ac5", "0x38592e5a"];

describe("selector goldens", () => {
  it.each(GOLDEN)("generated ABI: %s is %s", (signature, selector, abi) => {
    const fn = new ethers.Interface(abi as ethers.InterfaceAbi).getFunction(signature);
    expect(fn?.selector).toBe(selector);
  });

  it("Multicall3 ABI: aggregate3 only", () => {
    const iface = new ethers.Interface(Multicall3ABI);
    expect(iface.getFunction("aggregate3((address,bool,bytes)[])")?.selector).toBe(AGGREGATE3);
    expect(iface.fragments.filter((f) => f.type === "function")).toHaveLength(1);
  });

  it.each<[string, FakeChainOptions]>([
    ["through Multicall3", {}],
    ["through direct calls", { multicall: "absent" }],
  ])("readKeyState sends exactly the pinned selectors %s", async (_label, opts) => {
    const chain = strictChain(ACCOUNT, vectorKeyState("operational"), opts);
    await new AccountReader({ call: chain.call }).readKeyState(ACCOUNT);

    // Direct mode still sends one aggregate3 probe first (answered `0x`); only
    // the calls that were actually answered count.
    const answered = opts.multicall === undefined ? chain.sent : chain.sent.slice(1);
    const subCalls = answered.flatMap(({ to, data }) =>
      data.startsWith(AGGREGATE3) ? decodeAggregate3Calls(data) : [{ target: to, callData: data }],
    );
    const selectorsTo = (pred: (target: string) => boolean) =>
      new Set(subCalls.filter((c) => pred(c.target.toLowerCase())).map((c) => c.callData.slice(0, 10)));

    const toAccount = selectorsTo((t) => t === ACCOUNT);
    const toMulticall = selectorsTo((t) => t === "0xca11bde05977b3631167028862be2a173976ca11");
    const toLogic = selectorsTo((t) => t !== ACCOUNT && t !== "0xca11bde05977b3631167028862be2a173976ca11");

    expect([...toAccount].sort()).toEqual([...ACCOUNT_SELECTORS].sort());
    expect([...toLogic].sort()).toEqual([...LOGIC_SELECTORS].sort());
    // Multicall3 is only ever the aggregate3 target, never a sub-call target.
    expect(toMulticall.size).toBe(0);
    if (opts.multicall === undefined) {
      expect(chain.sent.every((s) => s.data.startsWith(AGGREGATE3))).toBe(true);
    } else {
      expect(chain.sent[0].data.startsWith(AGGREGATE3)).toBe(true);
    }
  });
});

describe("fixture answers replayed as raw bytes", () => {
  const { inputs, outputs } = loadVectors();
  const { contracts } = inputs;
  const zk = inputs.operationalMaster.zk;
  const zkLogic = contracts.zkVerifier3of6.toLowerCase();

  // Encoded from Solidity output types only — no ABI involved.
  const rawGetData = coder.encode(
    ["address", "uint256", "uint256", "uint256"],
    [contracts.merkleTreeDirectory, zk.n, zk.k, zk.hAudList],
  );
  const rawGetAnchor = coder.encode(["uint256[]"], [outputs.onchainGetAnchor]);

  /** The zk verifier, answered by selector literal; only the master key (purpose 0, keyId 0) exists. */
  const rawVerifier: Handler = (data) => {
    if (data === "0x38592e5a") return coder.encode(["uint8"], [6]);
    const selector = data.slice(0, 10);
    if (selector !== "0xa14fe394" && selector !== "0x04c713f4") return { revert: true };
    const [purpose, account, keyId] = coder.decode(["uint8", "address", "uint256"], "0x" + data.slice(10));
    if (Number(purpose) !== 0 || account.toLowerCase() !== ACCOUNT || keyId !== BigInt(0)) return { revert: true };
    return selector === "0xa14fe394" ? rawGetData : rawGetAnchor;
  };

  it("the generated ABI encodes the same bytes as the raw replay", () => {
    const iface = new ethers.Interface(AccountKeyZkOAuthRS256VerifierABI);
    expect(
      iface.encodeFunctionResult("getData", [contracts.merkleTreeDirectory, zk.n, zk.k, zk.hAudList]),
    ).toBe(rawGetData);
    expect(iface.encodeFunctionResult("getAnchor", [outputs.onchainGetAnchor])).toBe(rawGetAnchor);
  });

  it.each<[string, FakeChainOptions]>([
    ["through Multicall3", {}],
    ["through direct calls", { multicall: "absent" }],
  ])("readKeyState and getMasterKeyInfo return the replayed values unchanged %s", async (_label, opts) => {
    const state = vectorKeyState("operational");
    const resolve = strictResolver(ACCOUNT, () => state);
    const chain = fakeChain((address) => (address.toLowerCase() === zkLogic ? rawVerifier : resolve(address)), opts);
    const reader = new AccountReader({ call: chain.call });

    const expectedZk = {
      directory: ethers.getAddress(contracts.merkleTreeDirectory),
      n: BigInt(zk.n),
      k: BigInt(zk.k),
      hAudList: BigInt(zk.hAudList),
      anchorWithHash: outputs.onchainGetAnchor.map((v) => BigInt(v)),
    };
    const keyState = await reader.readKeyState(ACCOUNT);
    expect(keyState.master.keys[0].zk).toEqual(expectedZk);
    const info = await reader.getMasterKeyInfo(ACCOUNT);
    expect(info.keys[0].keyType).toBe("zkOAuth");
    expect(info.keys[0].zk).toEqual(expectedZk);
  });
});
