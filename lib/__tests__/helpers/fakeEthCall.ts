/**
 * An in-memory chain for AccountReader tests.
 *
 * Encodes and decodes with the REAL ethers coder so the tests pin the ABI
 * signatures the reader depends on — a mocked `Contract` would pass even if a
 * fragment drifted. Handlers answer per target address; Multicall3 is
 * emulated by decoding `aggregate3` and answering each sub-call.
 */
import { ethers } from "ethers";
import {
  AccountKeyAddressABI,
  AccountKeyWebAuthnABI,
  AccountKeyZkOAuthRS256VerifierABI,
  Multicall3ABI,
  ZkapAccountABI,
} from "../../types/abi";
import { PrimitiveAccountKeyTypes } from "../../types/AccountKey";
import { MULTICALL3_ADDRESS } from "../../reader/transport";
import type { EthCall } from "../../reader/transport";
import { originHashOf, rpIdHashOf } from "../../utils/webauthnKey";
import { loadVectors, type VectorPasskey } from "../../master/__tests__/fixtures/vectors";

/**
 * What a handler returns for one call: hex data, a revert (`data` defaults to
 * `"0x"`, a revert without data), "this address has no code", or a node error
 * (`"nodeerror"`: the node answers the whole `eth_call` with a JSON-RPC error —
 * through Multicall3 the entire `aggregate3` fails; per call, the error has no
 * revert data, as ethers reports it).
 */
export type Answer = string | { revert: true; data?: string } | "nocode" | "nodeerror";
export type Handler = (callData: string) => Answer;

/**
 * - `present` — Multicall3 works.
 * - `absent`  — `aggregate3` answers `0x` and `getCode` says no code (a chain without Multicall3).
 * - `lying`   — `aggregate3` answers `0x` but `getCode` shows code (a transport returning bogus data).
 * - `garbage` — `aggregate3` answers undecodable bytes.
 */
export type MulticallMode = "present" | "absent" | "lying" | "garbage";

export const multicallIface = new ethers.Interface(Multicall3ABI);
export const accountIface = new ethers.Interface(ZkapAccountABI);
export const webAuthnIface = new ethers.Interface(AccountKeyWebAuthnABI);
export const coder = ethers.AbiCoder.defaultAbiCoder();

/** Some bytecode — anything but "0x". */
export const CODE = "0x6080604052";
/**
 * Solidity `Panic(0x32)` — array index out of bounds. NOT what the account's
 * list getters answer past the end (they revert without data; see the captured
 * responses in `lib/reader/__tests__/fixtures/`); the reader accepts it as a
 * list end too.
 */
export const PANIC_OOB = "0x4e487b71" + coder.encode(["uint256"], [0x32]).slice(2);

export function encodeAggregate3Results(results: { success: boolean; returnData: string }[]): string {
  return coder.encode(["(bool,bytes)[]"], [results.map((r) => [r.success, r.returnData])]);
}

export function decodeAggregate3Calls(data: string): { target: string; allowFailure: boolean; callData: string }[] {
  const [calls] = multicallIface.decodeFunctionData("aggregate3", data);
  return Array.from(calls as Iterable<unknown>).map((c) => {
    const [target, allowFailure, callData] = c as unknown as [string, boolean, string];
    return { target, allowFailure, callData };
  });
}

export interface FakeChain {
  call: EthCall;
  getCode: (address: string) => Promise<string>;
  /** Every request, in order. */
  sent: { to: string; data: string }[];
  /** How many of `sent` went to Multicall3. */
  multicallRequests: () => number;
}

export interface FakeChainOptions {
  multicall?: MulticallMode;
  multicallAddress?: string;
  /**
   * Runs before each top-level `eth_call` is answered; `index` is its position
   * in `sent`. Use it to change state between round trips.
   */
  beforeCall?: (index: number, request: { to: string; data: string }) => void;
}

/**
 * `handlers` maps an address to its contract, or is a resolver called on every
 * request (lets the contract set change while the test runs). An address with
 * no handler has no code.
 */
export function fakeChain(
  handlers: Record<string, Handler> | ((address: string) => Handler | undefined),
  opts: FakeChainOptions = {},
): FakeChain {
  const mode = opts.multicall ?? "present";
  const multicallAddress = (opts.multicallAddress ?? MULTICALL3_ADDRESS).toLowerCase();
  const byAddress =
    typeof handlers === "function"
      ? undefined
      : new Map(Object.entries(handlers).map(([address, handler]) => [address.toLowerCase(), handler]));
  const handlerAt = (address: string): Handler | undefined =>
    byAddress ? byAddress.get(address.toLowerCase()) : (handlers as (a: string) => Handler | undefined)(address);
  const sent: { to: string; data: string }[] = [];

  const answer = (to: string, data: string): Answer => handlerAt(to)?.(data) ?? "nocode";

  const call: EthCall = async ({ to, data }) => {
    sent.push({ to, data });
    opts.beforeCall?.(sent.length - 1, { to, data });

    if (to.toLowerCase() === multicallAddress) {
      if (mode === "absent" || mode === "lying") return "0x";
      if (mode === "garbage") return "0xdeadbeef";
      const answers = decodeAggregate3Calls(data).map(({ target, callData }) => answer(target, callData));
      if (answers.includes("nodeerror")) throw new Error("fake chain: node error");
      const results = answers.map((a) => {
        if (a === "nocode") return { success: true, returnData: "0x" };
        if (typeof a === "string") return { success: true, returnData: a };
        return { success: false, returnData: a.data ?? "0x" };
      });
      return encodeAggregate3Results(results);
    }

    const a = answer(to, data);
    if (a === "nocode") return "0x";
    // What ethers' provider.call throws for a node error: a CALL_EXCEPTION without revert data.
    if (a === "nodeerror") throw Object.assign(new Error("rate limited"), { code: "CALL_EXCEPTION", data: null });
    if (typeof a === "string") return a;
    // What ethers' provider.call throws for a revert: the revert data, "0x" when there is none.
    throw Object.assign(new Error("execution reverted"), { code: "CALL_EXCEPTION", data: a.data ?? "0x" });
  };

  const getCode = async (address: string): Promise<string> => {
    if (address.toLowerCase() === multicallAddress) return mode === "absent" ? "0x" : CODE;
    return handlerAt(address) ? CODE : "0x";
  };

  return {
    call,
    getCode,
    sent,
    multicallRequests: () => sent.filter((s) => s.to.toLowerCase() === multicallAddress).length,
  };
}

/** An `ethers.Provider` stand-in backed by a {@link FakeChain}. */
export function fakeProvider(chain: FakeChain, balance = BigInt(0)): ethers.Provider {
  return {
    call: (tx: { to?: unknown; data?: unknown }) => chain.call({ to: tx.to as string, data: tx.data as string }),
    getCode: chain.getCode,
    getBalance: async () => balance,
  } as unknown as ethers.Provider;
}

// ---------------------------------------------------------------------------
// ZkapAccount + key logic emulation
// ---------------------------------------------------------------------------

export interface KeyDataSpec {
  x: string;
  y: string;
  credentialId: string;
  originHash: string;
  rpIdHash: string;
}

export interface SlotSpec {
  logic: string;
  keyId: number;
  /** `PrimitiveAccountKeyTypes` value (default WebAuthn), or how `keyType()` misbehaves. */
  keyType?: number | "revert" | "garbage";
  /** `getKeyData` answer; omitted = revert (non-WebAuthn logic). */
  keyData?: KeyDataSpec | "revert" | "garbage";
}

export const X = "0x" + "12".repeat(32);
export const Y = "0x" + "34".repeat(32);

/** A WebAuthn slot whose hashes are derived from a plaintext rpId/origin. */
export function webauthnSlot(spec: {
  logic: string;
  keyId: number;
  credentialId: string;
  rpId: string;
  origin: string;
  x?: string;
  y?: string;
}): SlotSpec {
  return {
    logic: spec.logic,
    keyId: spec.keyId,
    keyType: PrimitiveAccountKeyTypes.keyWebAuthn,
    keyData: {
      x: spec.x ?? X,
      y: spec.y ?? Y,
      credentialId: spec.credentialId,
      originHash: originHashOf(spec.origin),
      rpIdHash: rpIdHashOf(spec.rpId),
    },
  };
}

const txKeyListSelector = accountIface.getFunction("txKeyList")!.selector;
const keyTypeSelector = webAuthnIface.getFunction("keyType")!.selector;
const getKeyDataSelector = webAuthnIface.getFunction("getKeyData")!.selector;

/**
 * Handlers for a deployed ZkapAccount with the given txKey slots, plus one
 * handler per distinct key logic contract. `txKeyList(i)` reverts without data
 * past the last slot, like the real array getter.
 */
export function zkapAccount(
  account: string,
  slots: SlotSpec[],
  opts: { zeroAt?: number; garbageAt?: number } = {},
): Record<string, Handler> {
  const handlers: Record<string, Handler> = {};

  handlers[account] = (data) => {
    if (!data.startsWith(txKeyListSelector)) return { revert: true };
    const [index] = accountIface.decodeFunctionData("txKeyList", data);
    const i = Number(index);
    if (opts.garbageAt === i) return "0x1234";
    if (opts.zeroAt === i) return accountIface.encodeFunctionResult("txKeyList", [ethers.ZeroAddress, 0]);
    if (i < slots.length) return accountIface.encodeFunctionResult("txKeyList", [slots[i].logic, slots[i].keyId]);
    return { revert: true };
  };

  const logics = [...new Set(slots.map((s) => s.logic.toLowerCase()))];
  for (const logic of logics) {
    const specs = slots.filter((s) => s.logic.toLowerCase() === logic);
    handlers[logic] = (data) => {
      if (data.startsWith(keyTypeSelector)) {
        const keyType = specs[0].keyType ?? PrimitiveAccountKeyTypes.keyWebAuthn;
        if (keyType === "revert") return { revert: true };
        if (keyType === "garbage") return "0x12";
        return coder.encode(["uint8"], [keyType]);
      }
      if (data.startsWith(getKeyDataSelector)) {
        const [, , keyId] = webAuthnIface.decodeFunctionData("getKeyData", data);
        const keyData = specs.find((s) => s.keyId === Number(keyId))?.keyData;
        if (keyData === undefined || keyData === "revert") return { revert: true };
        if (keyData === "garbage") return "0xabcdef";
        return webAuthnIface.encodeFunctionResult("getKeyData", [
          keyData.x,
          keyData.y,
          keyData.credentialId,
          keyData.originHash,
          keyData.rpIdHash,
        ]);
      }
      return { revert: true };
    };
  }

  return handlers;
}

// ---------------------------------------------------------------------------
// Strict emulation: contracts answer only through their generated ABI
// ---------------------------------------------------------------------------

/**
 * What an emulated function returns: its output values (encoded with the
 * contract's generated ABI), or a raw {@link Answer} (revert, garbage bytes).
 */
export type AbiImpl = Record<string, (args: ethers.Result) => unknown[] | Answer>;

/**
 * A contract that answers only through `abi` — the package's generated ABI,
 * never a test-local fragment. A selector the ABI does not have reverts, like
 * a real contract without a fallback. A selector the ABI has but `impl` does
 * not emulate throws, so a test notices instead of reading a silent revert.
 */
export function abiContract(abi: readonly unknown[], impl: AbiImpl): Handler {
  const iface = new ethers.Interface(abi as ethers.InterfaceAbi);
  return (data) => {
    const fn = data.length >= 10 ? iface.getFunction(data.slice(0, 10)) : null;
    if (!fn) return { revert: true };
    const run = impl[fn.name];
    if (!run) throw new Error(`fake chain: ${fn.format()} is in the ABI but not emulated`);
    const out = run(iface.decodeFunctionData(fn, data));
    return Array.isArray(out) ? iface.encodeFunctionResult(fn, out) : out;
  };
}

/** Make a getter misbehave: revert, or answer bytes that do not decode. */
export type Misbehave = "revert" | "garbage";

export interface FakeZkData {
  directory: string;
  n: ethers.BigNumberish;
  k: ethers.BigNumberish;
  hAudList: ethers.BigNumberish;
  /** Exactly what `getAnchor` returns: the anchor elements followed by their hash. */
  anchorWithHash: ethers.BigNumberish[];
}

interface FakeKeyBase {
  logic: string;
  keyId: ethers.BigNumberish;
  weight: number;
  /**
   * Overrides `keyType()` of this key's logic contract (the first key on that
   * logic decides). Default: the type matching the key's data.
   */
  keyType?: number | Misbehave;
  /** Make this key's getters misbehave. */
  fail?: Partial<Record<"getData" | "getAnchor" | "getSigner" | "getKeyData", Misbehave>>;
}

/** One key: ZK-OAuth (`zk`), address (`signer`) or WebAuthn (`webauthn`). */
export type FakeKey = FakeKeyBase & ({ zk: FakeZkData } | { signer: string } | { webauthn: KeyDataSpec });

export interface FakeKeySet {
  threshold: number;
  keys: FakeKey[];
}

/** On-chain key state of one account. `undefined` = the account has no code. */
export interface FakeAccountState {
  master: FakeKeySet;
  tx: FakeKeySet;
}

export interface StrictChain extends FakeChain {
  /** Mutable: replace or edit it (e.g. from `beforeCall`) to change the chain state. */
  state: FakeAccountState | undefined;
}

const PURPOSE = { master: 0, tx: 1 } as const;
/** What each typed getter answers for a key that is not registered: zero values, not a revert. */
const UNREGISTERED: Record<"getData" | "getAnchor" | "getSigner" | "getKeyData", unknown[]> = {
  getData: [ethers.ZeroAddress, 0, 0, 0],
  getAnchor: [[]],
  getSigner: [ethers.ZeroAddress],
  getKeyData: [ethers.ZeroHash, ethers.ZeroHash, "", ethers.ZeroHash, ethers.ZeroHash],
};
const GARBAGE = "0x1234";

type Kind = "zk" | "signer" | "webauthn";
const kindOf = (key: FakeKey): Kind => ("zk" in key ? "zk" : "signer" in key ? "signer" : "webauthn");
const KIND_ABI: Record<Kind, readonly unknown[]> = {
  zk: AccountKeyZkOAuthRS256VerifierABI,
  signer: AccountKeyAddressABI,
  webauthn: AccountKeyWebAuthnABI,
};
const KIND_TYPE: Record<Kind, number> = {
  zk: PrimitiveAccountKeyTypes.keyZkOAuthRS256,
  signer: PrimitiveAccountKeyTypes.keyAddress,
  webauthn: PrimitiveAccountKeyTypes.keyWebAuthn,
};

/**
 * A chain holding one ZkapAccount (at `account`) and its key logic contracts,
 * every one emulated strictly through the package's generated ABIs.
 *
 * - The account answers `masterKeyList` / `masterKeyWeightList` /
 *   `masterKeyThreshold` and the `txKey*` equivalents from `state`; past the
 *   end of a list the getters revert without data, like the real ones.
 * - Each logic contract answers `keyType()` and its own typed getter, keyed by
 *   `(purpose, account, keyId)`: master keys under purpose 0, tx keys under 1.
 *   An unregistered key answers zero values (zero address, zero numbers, empty
 *   string / array), like the real getters. The other types' getters are not in
 *   its ABI and revert without data.
 * - `state` is read on every request, so a test can change it between round
 *   trips. There is no block number: a change shows up only in the answers.
 *
 * @example
 * const chain = strictChain(ACCOUNT, {
 *   master: { threshold: 2, keys: [
 *     { logic: ZK, keyId: 0, weight: 1, zk: { directory, n: 1, k: 1, hAudList, anchorWithHash: [a0, h] } },
 *     { logic: ADDR, keyId: 0, weight: 1, signer: COSIGNER },
 *   ] },
 *   tx: { threshold: 1, keys: [{ logic: WA, keyId: 0, weight: 1, webauthn: keyData }] },
 * }, { beforeCall: (i) => { if (i === 1) chain.state!.master.threshold += 1; } });
 * const reader = new AccountReader({ call: chain.call });
 */
export function strictChain(
  account: string,
  state: FakeAccountState | undefined,
  opts: FakeChainOptions = {},
): StrictChain {
  const resolve = strictResolver(account, () => chain.state);
  const chain = fakeChain(resolve, opts) as StrictChain;
  chain.state = state;
  return chain;
}

/**
 * The address → contract resolver behind {@link strictChain}, for composing a
 * chain by hand (e.g. to answer one contract with raw bytes and the rest
 * strictly): `fakeChain((a) => (a === X ? raw : resolve(a)))`.
 */
export function strictResolver(
  account: string,
  getState: () => FakeAccountState | undefined,
): (address: string) => Handler | undefined {
  const accountKey = account.toLowerCase();
  const sets = (s: FakeAccountState) => [
    { set: "master" as const, keys: s.master.keys },
    { set: "tx" as const, keys: s.tx.keys },
  ];

  const accountHandler = (s: FakeAccountState): Handler => {
    const listGetter = (keys: FakeKey[], pick: (k: FakeKey) => unknown[]) => (args: ethers.Result) => {
      const i = Number(args[0]);
      return i < keys.length ? pick(keys[i]) : { revert: true as const };
    };
    return abiContract(ZkapAccountABI, {
      masterKeyThreshold: () => [s.master.threshold],
      masterKeyList: listGetter(s.master.keys, (k) => [k.logic, k.keyId]),
      masterKeyWeightList: listGetter(s.master.keys, (k) => [k.weight]),
      txKeyThreshold: () => [s.tx.threshold],
      txKeyList: listGetter(s.tx.keys, (k) => [k.logic, k.keyId]),
      txKeyWeightList: listGetter(s.tx.keys, (k) => [k.weight]),
    });
  };

  const logicHandler = (s: FakeAccountState, logic: string): Handler | undefined => {
    const onLogic = sets(s).flatMap(({ set, keys }) =>
      keys.filter((k) => k.logic.toLowerCase() === logic).map((key) => ({ set, key })),
    );
    if (onLogic.length === 0) return undefined;
    const kind = kindOf(onLogic[0].key);
    if (onLogic.some(({ key }) => kindOf(key) !== kind)) {
      throw new Error(`fake chain: logic ${logic} holds keys of different types`);
    }

    // Look up the key a getter asks for; `undefined` = not registered.
    const find = (args: ethers.Result) =>
      onLogic.find(
        ({ set, key }) =>
          PURPOSE[set] === Number(args[0]) &&
          String(args[1]).toLowerCase() === accountKey &&
          BigInt(key.keyId) === BigInt(args[2]),
      )?.key;
    const getter =
      (name: keyof NonNullable<FakeKeyBase["fail"]>, values: (key: FakeKey) => unknown[]) =>
      (args: ethers.Result): unknown[] | Answer => {
        const key = find(args);
        if (!key) return UNREGISTERED[name];
        const fail = key.fail?.[name];
        if (fail === "revert") return { revert: true };
        if (fail === "garbage") return GARBAGE;
        return values(key);
      };

    const override = onLogic[0].key.keyType;
    const impl: AbiImpl = {
      keyType: () => {
        if (override === "revert") return { revert: true };
        if (override === "garbage") return GARBAGE;
        return [override ?? KIND_TYPE[kind]];
      },
    };
    if (kind === "zk") {
      const zk = (key: FakeKey) => (key as { zk: FakeZkData }).zk;
      impl.getData = getter("getData", (key) => [zk(key).directory, zk(key).n, zk(key).k, zk(key).hAudList]);
      impl.getAnchor = getter("getAnchor", (key) => [zk(key).anchorWithHash]);
    } else if (kind === "signer") {
      impl.getSigner = getter("getSigner", (key) => [(key as { signer: string }).signer]);
    } else {
      impl.getKeyData = getter("getKeyData", (key) => {
        const d = (key as { webauthn: KeyDataSpec }).webauthn;
        return [d.x, d.y, d.credentialId, d.originHash, d.rpIdHash];
      });
    }
    return abiContract(KIND_ABI[kind], impl);
  };

  return (address) => {
    const s = getState();
    if (!s) return undefined;
    const lower = address.toLowerCase();
    return lower === accountKey ? accountHandler(s) : logicHandler(s, lower);
  };
}

/** The fixture's passkey as `getKeyData` stores it. */
export function vectorKeyData(passkey: VectorPasskey): KeyDataSpec {
  return {
    x: passkey.x,
    y: passkey.y,
    credentialId: passkey.credentialId,
    originHash: originHashOf(passkey.origin),
    rpIdHash: passkey.rpIdHash,
  };
}

/**
 * Account state built from `fixtures/master-key-cosign-vectors.json`, with the
 * fixture's logic contract addresses:
 *
 * - `"operational"` — master `[zk 3-of-6 (w2), cosigner (w1), passkey (w1)]`,
 *   threshold 3; the zk key's `getAnchor` answers `outputs.onchainGetAnchor`.
 * - `"initial"` — master `[zk 1-of-1 (w1), cosigner (w1)]`, threshold 2. The
 *   fixture has no on-chain anchor hash for this shape, so the caller supplies
 *   `initialAnchorHash` (appended to `initialMaster.zk.anchor`).
 *
 * Both carry the fixture passkey as the single tx key (threshold 1). Key ids:
 * every master key 0, the tx key 1.
 */
export function vectorKeyState(
  shape: "initial" | "operational",
  opts: { initialAnchorHash?: ethers.BigNumberish } = {},
): FakeAccountState {
  const { inputs, outputs } = loadVectors();
  const { contracts } = inputs;
  const passkey = vectorKeyData(inputs.passkey);
  const cosigner: FakeKey = { logic: contracts.addressKeyLogic, keyId: 0, weight: 1, signer: inputs.cosigner };
  const tx: FakeKeySet = {
    threshold: inputs.txKey.threshold,
    keys: [{ logic: contracts.webAuthnLogic, keyId: 1, weight: inputs.txKey.weights[0], webauthn: passkey }],
  };

  if (shape === "operational") {
    const { zk, weights, threshold } = inputs.operationalMaster;
    return {
      master: {
        threshold,
        keys: [
          {
            logic: contracts.zkVerifier3of6,
            keyId: 0,
            weight: weights[0],
            zk: {
              directory: contracts.merkleTreeDirectory,
              n: zk.n,
              k: zk.k,
              hAudList: zk.hAudList,
              anchorWithHash: outputs.onchainGetAnchor,
            },
          },
          { ...cosigner, weight: weights[1] },
          { logic: contracts.webAuthnLogic, keyId: 0, weight: weights[2], webauthn: passkey },
        ],
      },
      tx,
    };
  }

  if (opts.initialAnchorHash === undefined) {
    throw new Error("vectorKeyState: the initial shape needs initialAnchorHash");
  }
  const { zk, weights, threshold } = inputs.initialMaster;
  return {
    master: {
      threshold,
      keys: [
        {
          logic: contracts.zkVerifier1of1,
          keyId: 0,
          weight: weights[0],
          zk: {
            directory: contracts.merkleTreeDirectory,
            n: zk.n,
            k: zk.k,
            hAudList: zk.hAudList,
            anchorWithHash: [...zk.anchor, opts.initialAnchorHash],
          },
        },
        { ...cosigner, weight: weights[1] },
      ],
    },
    tx,
  };
}
