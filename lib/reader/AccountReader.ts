import { ethers } from "ethers";
import {
  AccountKeyAddressABI,
  AccountKeyWebAuthnABI,
  AccountKeyZkOAuthRS256VerifierABI,
  ZkapAccountABI,
} from "../types/abi";
import { AaFetchError, AaFetchErrorCode, AaOperationError, AaOperationErrorCode } from "../errors";
import { BatchCaller, ethCallFromProvider, hasValue, isListEnd } from "./transport";
import type { Call3, EthCall, Result3 } from "./transport";
import { buildPasskeysResult, normalizeOptions } from "./passkeys";
import type { GetPasskeysOptions, PasskeysResult } from "./passkeys";
import { keyTypeFromPrimitive } from "./types";
import { classifyMasterKey, reconstructOperationalMasterKey } from "../master/onchain";
import type {
  MasterKeyClassification,
  MasterKeyExpectation,
  ReconstructOperationalMasterKeyParams,
} from "../master/onchain";
import type {
  KeyType,
  MasterKeyInfo,
  OnchainKeyEntry,
  OnchainKeySet,
  OnchainKeyState,
  TxKeyInfo,
  TxKeySlots,
  WebAuthnKeyData,
} from "./types";

// Re-exported so existing `import … from "./reader/AccountReader"` paths keep resolving.
export type {
  KeyType,
  WebAuthnKeyData,
  TxKeyInfo,
  MasterKeyInfo,
  TxKeySlots,
  ReadVia,
  OnchainKeyEntry,
  OnchainKeySet,
  OnchainKeyState,
  OnchainZkKeyData,
} from "./types";

/** Tuning knobs shared by every transport mode. */
export interface AccountReaderOptions {
  /** Multicall3 address; `false` disables batching. Default: the canonical address. */
  multicallAddress?: string | false;
  /**
   * How many txKey slots to read (default 5, the WebAuthn singleton's per-account
   * cap). The account contract has its own limit; this exists for forward
   * compatibility only. Integer ≥ 1. Also the tx-key window of
   * {@link AccountReader.readKeyState}; master keys always use a window of 5.
   */
  maxTxKeys?: number;
  /** See {@link BatchCallerOptions.isRevertError}. Only matters on chains without Multicall3. */
  isRevertError?: (err: unknown) => boolean;
}

/**
 * Exactly one transport:
 * - `{ rpcUrl, chainId? }` — the reader builds an ethers `JsonRpcProvider` (original behaviour).
 * - `{ provider }` — any ethers `Provider` (e.g. `BrowserProvider`, a shared `JsonRpcProvider`).
 * - `{ call }` — a bare `eth_call` function (proxy / relay). `isDeployed` and
 *   `getBalance` are unavailable in this mode; use `readTxKeySlots().deployed`.
 */
export type AccountReaderConfig = AccountReaderOptions &
  (
    | { rpcUrl: string; chainId?: number }
    | { provider: ethers.Provider }
    | { call: EthCall }
  );

const DEFAULT_MAX_TX_KEYS = 5;
/** How many master keys {@link AccountReader.readKeyState} reads before reporting `truncated`. */
const MASTER_KEY_WINDOW = 5;
/** `IAccountKey.KeyPurpose.Master` */
const KEY_PURPOSE_MASTER = 0;
/** `IAccountKey.KeyPurpose.Tx` */
const KEY_PURPOSE_TX = 1;
const READ_TX_KEYS = "read_tx_keys";
const READ_KEY_STATE = "read_key_state";

// Every ABI comes from the generated module (synced contract artifacts); never
// hand-write fragments here — a drifted fragment silently reads nothing.
const accountIface = new ethers.Interface(ZkapAccountABI);
// `keyType()` is common to every key logic contract; the WebAuthn ABI carries it too.
const webAuthnIface = new ethers.Interface(AccountKeyWebAuthnABI);
const zkIface = new ethers.Interface(AccountKeyZkOAuthRS256VerifierABI);
const addressKeyIface = new ethers.Interface(AccountKeyAddressABI);

const KEY_LISTS = {
  master: {
    list: "masterKeyList",
    weight: "masterKeyWeightList",
    threshold: "masterKeyThreshold",
    purpose: KEY_PURPOSE_MASTER,
  },
  tx: { list: "txKeyList", weight: "txKeyWeightList", threshold: "txKeyThreshold", purpose: KEY_PURPOSE_TX },
} as const;

/** Byte-for-byte equality of two rounds of answers. */
function sameResults(a: Result3[], b: Result3[]): boolean {
  return (
    a.length === b.length &&
    a.every(
      (r, i) =>
        r.success === b[i].success &&
        r.returnData.toLowerCase() === b[i].returnData.toLowerCase() &&
        !r.revertDataMissing === !b[i].revertDataMissing,
    )
  );
}

/** A key-list entry from round 1 of {@link AccountReader.readKeyState}. */
interface KeySlot {
  set: "master" | "tx";
  purpose: number;
  index: number;
  logic: string;
  keyId: bigint;
  weight: number;
}

/**
 * Read-only utility for inspecting on-chain state of a deployed ZkapAccount.
 *
 * txKey reads go through Multicall3 — two `eth_call`s for any number of keys —
 * and fall back to parallel individual calls on chains without it. A transport
 * failure throws `AaFetchError`; an empty result always means "no keys", never
 * "the node did not answer".
 *
 * @example
 * ```ts
 * const reader = new AccountReader({ rpcUrl: "https://arb1.arbitrum.io/rpc", chainId: 42161 });
 * const { deployed, mine, myService } = await reader.getPasskeys(account, {
 *   service: { rpId: "zkap.app", origins: ["https://zkap.app", "android:apk-key-hash:…"] },
 *   credentialId: localPasskeyId,
 * });
 * ```
 */
export class AccountReader {
  private readonly provider?: ethers.Provider;
  private readonly rpcUrl?: string;
  private readonly ethCall: EthCall;
  private readonly batch: BatchCaller;
  private readonly maxTxKeys: number;

  constructor(config: AccountReaderConfig) {
    const c = config as AccountReaderOptions & {
      rpcUrl?: string;
      chainId?: number;
      provider?: ethers.Provider;
      call?: EthCall;
    };

    const transports = [c.rpcUrl !== undefined, c.provider !== undefined, c.call !== undefined].filter(Boolean).length;
    if (transports === 0) {
      throw new AaOperationError({
        code: AaOperationErrorCode.CONFIG_REQUIRED_FIELD_MISSING,
        operation: "account_reader",
        message: "AccountReader: one of rpcUrl, provider or call is required",
      });
    }
    if (transports > 1) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID,
        operation: "account_reader",
        message: "AccountReader: rpcUrl, provider and call are mutually exclusive — pass exactly one",
      });
    }

    const maxTxKeys = c.maxTxKeys ?? DEFAULT_MAX_TX_KEYS;
    if (!Number.isInteger(maxTxKeys) || maxTxKeys < 1) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_OUT_OF_RANGE,
        operation: "account_reader",
        message: `AccountReader: maxTxKeys must be an integer >= 1 (got ${maxTxKeys})`,
      });
    }
    this.maxTxKeys = maxTxKeys;

    if (c.call !== undefined) {
      this.ethCall = c.call;
    } else {
      const provider =
        c.provider ??
        new ethers.JsonRpcProvider(c.rpcUrl, undefined, {
          staticNetwork: c.chainId ? ethers.Network.from(c.chainId) : true,
        });
      this.provider = provider;
      this.rpcUrl = c.rpcUrl;
      this.ethCall = ethCallFromProvider(provider);
    }

    const provider = this.provider;
    this.batch = new BatchCaller({
      call: this.ethCall,
      getCode: provider ? (address) => provider.getCode(address) : undefined,
      multicallAddress: c.multicallAddress,
      isRevertError: c.isRevertError,
      url: this.rpcUrl,
    });
  }

  /**
   * Check whether a ZkapAccount has been deployed on-chain.
   *
   * Needs `rpcUrl` or `provider` (`eth_getCode`). In `call` mode use
   * {@link readTxKeySlots} / {@link getPasskeys} — they report `deployed` for free.
   *
   * @param address - The counterfactual or deployed account address.
   * @returns `true` if the account has deployed bytecode; `false` if it is still counterfactual.
   */
  async isDeployed(address: string): Promise<boolean> {
    const code = await this.requireProvider("is_deployed", "isDeployed").getCode(address);
    return code !== "0x";
  }

  /**
   * Return the native token balance of the account. Needs `rpcUrl` or `provider`.
   *
   * @param address - The account address to query.
   * @returns The balance in wei as a decimal string.
   */
  async getBalance(address: string): Promise<string> {
    const balance = await this.requireProvider("get_balance", "getBalance").getBalance(address);
    return balance.toString();
  }

  /**
   * Read the account's txKey slots in at most two round trips, regardless of
   * how many keys are registered.
   *
   * Round 1 asks `txKeyList(0..maxTxKeys)`; round 2 asks each slot's logic
   * contract for `keyType()` and `getKeyData(Tx, account, keyId)`. An
   * undeployed account is detected from round 1 alone.
   *
   * The list ends at the first `txKeyList(i)` that reverts without data —
   * what the account's public array getter answers past the end of the array
   * — or with `Panic(0x32)` (see {@link isListEnd}). Unlike
   * {@link readKeyState}, it also ends at a slot holding the zero address,
   * without reading further. A slot that fails any other way — other revert
   * data, empty data, a node error on the per-call path (a failure without
   * revert data) — is not taken as the end of the list: the read throws.
   *
   * A slot whose `keyType()` reverts or does not decode comes back as
   * `"unknown"`, and a WebAuthn slot whose `getKeyData` does so comes back
   * without `webauthn`; on the per-call path a node error there throws
   * instead.
   *
   * @throws `AaOperationError` (`INPUT_INVALID_ADDRESS`) for a malformed address.
   * @throws `AaFetchError` (`TRANSPORT`) when the node cannot be reached, or
   *   (`RESPONSE_SHAPE`) when it answers with undecodable data, a slot fails
   *   in a way that does not end the list, or a needed answer came back
   *   without revert data.
   */
  async readTxKeySlots(address: string): Promise<TxKeySlots> {
    if (!ethers.isAddress(address)) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID_ADDRESS,
        operation: READ_TX_KEYS,
        message: `AccountReader: invalid account address "${address}"`,
      });
    }

    // One extra slot past the window tells us whether the list continues.
    const slotCalls: Call3[] = Array.from({ length: this.maxTxKeys + 1 }, (_, index) => ({
      target: address,
      allowFailure: true,
      callData: accountIface.encodeFunctionData("txKeyList", [index]),
    }));
    const round1 = await this.batch.batch(slotCalls, READ_TX_KEYS);

    // A call to an address without code succeeds with empty data.
    const first = round1.results[0];
    if (first.success && first.returnData === "0x") {
      return { deployed: false, keys: [], truncated: false, readVia: round1.via };
    }

    const slots: { index: number; logic: string; keyId: bigint }[] = [];
    for (let index = 0; index < this.maxTxKeys; index++) {
      const result = round1.results[index];
      // The list is filled from the front and ends where the getter reverts (see isListEnd).
      if (this.listEnded(result, `txKeyList(${index})`, READ_TX_KEYS)) break;
      const [logic, keyId] = this.decodeSlot(result.returnData);
      if (!logic || logic === ethers.ZeroAddress) break;
      slots.push({ index, logic, keyId });
    }
    const truncated =
      slots.length === this.maxTxKeys &&
      !this.listEnded(round1.results[this.maxTxKeys], `txKeyList(${this.maxTxKeys})`, READ_TX_KEYS);

    if (slots.length === 0) {
      return { deployed: true, keys: [], truncated, readVia: round1.via };
    }

    const detailCalls: Call3[] = slots.flatMap(({ logic, keyId }) => [
      { target: logic, allowFailure: true, callData: webAuthnIface.encodeFunctionData("keyType") },
      {
        target: logic,
        allowFailure: true,
        callData: webAuthnIface.encodeFunctionData("getKeyData", [KEY_PURPOSE_TX, address, keyId]),
      },
    ]);
    const round2 = await this.batch.batch(detailCalls, READ_TX_KEYS);

    const keys = slots.map((slot, position): TxKeyInfo => {
      const keyTypeResult = round2.results[position * 2];
      this.requireRevertData(keyTypeResult, `keyType() for tx key ${slot.index}`, READ_TX_KEYS);
      const keyType = this.decodeKeyType(keyTypeResult);
      const info: TxKeyInfo = {
        index: slot.index,
        logicContract: slot.logic,
        keyId: Number(slot.keyId),
        keyType,
      };
      if (keyType === "webauthn") {
        const keyDataResult = round2.results[position * 2 + 1];
        this.requireRevertData(keyDataResult, `getKeyData for tx key ${slot.index}`, READ_TX_KEYS);
        const webauthn = this.decodeKeyData(keyDataResult);
        if (webauthn) info.webauthn = webauthn;
      }
      return info;
    });

    return { deployed: true, keys, truncated, readVia: round1.via };
  }

  /**
   * Read all transaction key slots from a deployed ZkapAccount.
   *
   * Returns `[]` for an undeployed account (see {@link readTxKeySlots} to tell
   * that apart from "deployed with no keys"). Throws `AaFetchError` when the
   * node cannot be read — an empty array never means the RPC failed.
   *
   * @param address - Address of the ZkapAccount.
   * @returns One {@link TxKeyInfo} per occupied key slot.
   */
  async getTxKeyList(address: string): Promise<TxKeyInfo[]> {
    return (await this.readTxKeySlots(address)).keys;
  }

  /**
   * Read the WebAuthn (passkey) txKeys and classify them for the calling
   * service — see {@link GetPasskeysOptions} and {@link PasskeysResult}.
   *
   * Option validation happens before any RPC.
   */
  async getPasskeys(address: string, opts?: GetPasskeysOptions): Promise<PasskeysResult> {
    normalizeOptions(opts);
    const slots = await this.readTxKeySlots(address);
    return buildPasskeysResult(slots, opts);
  }

  /**
   * Find txKeys matching the given rpIdHash (SHA-256 of rpId).
   * Returns all WebAuthn keys whose allowedRpIdHash matches.
   *
   * @see getPasskeys — resolves rpId/origin for you and classifies every key.
   */
  async findTxKeysByRpId(address: string, rpIdHash: string): Promise<TxKeyInfo[]> {
    const keys = await this.getTxKeyList(address);
    return keys.filter(
      (k) =>
        k.keyType === "webauthn" &&
        k.webauthn?.allowedRpIdHash?.toLowerCase() === rpIdHash.toLowerCase(),
    );
  }

  /**
   * Read both key lists of a ZkapAccount — thresholds, every key's weight,
   * type and logic-contract data — from one consistent state.
   *
   * Two round trips: round 1 asks the account for both thresholds and
   * `masterKeyList` / `masterKeyWeightList` / `txKeyList` / `txKeyWeightList`
   * over the read window plus one probe slot; round 2 asks each key's logic
   * contract for `keyType()` and all three typed getters (`getData` +
   * `getAnchor`, `getSigner`, `getKeyData`), of which only the one matching
   * `keyType()` is used. A list ends at the first index whose getter reverts
   * without data — what the account's public array getters answer past the
   * end of the array — or with `Panic(0x32)` (see {@link isListEnd}), and its
   * weight list must end at the same index. A slot holding the zero address is
   * not an end: its `keyType()` cannot be read, so the read throws (where
   * {@link readTxKeySlots} ends its list there). Any other failure of a call
   * the read needs — other revert data, empty data, a node error on the
   * per-call path (a failure without revert data), a `keyType()` that does not
   * answer — throws; it is never taken as the end of a list or as an
   * `"unknown"` key.
   *
   * Consistency: through Multicall3, round 2 repeats round 1's calls inside the
   * same `aggregate3`, and their answers must equal round 1's byte for byte —
   * so the details were read from the state round 1 describes, whatever the
   * chain's block numbering. Without Multicall3, round 1 is read again after
   * round 2 and must come back identical. One mismatch triggers one full
   * re-read; a second mismatch throws.
   *
   * Windows: master keys {@link MASTER_KEY_WINDOW} (5), tx keys `maxTxKeys`.
   * A list longer than its window is returned cut short with `truncated: true`.
   *
   * @throws `AaOperationError` (`INPUT_INVALID_ADDRESS`) for a malformed address.
   * @throws `AaFetchError` (`TRANSPORT`) when the node cannot be reached;
   *   (`RESPONSE_SHAPE`) when an answer cannot be decoded, when a list getter
   *   fails in a way that does not end a list, when `keyType()` or the getter matching a
   *   key's type fails, or when the state keeps changing between rounds. Data
   *   that could not be read is never reported as absent.
   */
  async readKeyState(address: string): Promise<OnchainKeyState> {
    if (!ethers.isAddress(address)) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID_ADDRESS,
        operation: READ_KEY_STATE,
        message: `AccountReader: invalid account address "${address}"`,
      });
    }
    const first = await this.readKeyStateOnce(address);
    if ("state" in first) return first.state;
    const second = await this.readKeyStateOnce(address);
    if ("state" in second) return second.state;
    throw new AaFetchError({
      code: AaFetchErrorCode.RESPONSE_SHAPE,
      operation: READ_KEY_STATE,
      service: "rpc",
      url: this.rpcUrl,
      method: "POST",
      message: `AccountReader: key state of ${address} changed between reads twice in a row (${second.mismatch})`,
    });
  }

  /**
   * Read the master key list of a ZkapAccount — see {@link readKeyState}.
   *
   * An undeployed account resolves with `deployed: false`, `threshold: 0` and
   * no keys; it does not throw.
   */
  async getMasterKeyInfo(address: string): Promise<MasterKeyInfo> {
    const { account, deployed, master, readVia } = await this.readKeyState(address);
    return { account, deployed, threshold: master.threshold, keys: master.keys, truncated: master.truncated, readVia };
  }

  /**
   * Read the account's key state ({@link readKeyState}) and classify its master
   * key ({@link classifyMasterKey}). Resolves with the state that was classified.
   *
   * @throws `AaFetchError` when the read fails — a failed read is never reported
   *   as `"other"`.
   */
  async classifyMasterKey(
    address: string,
    expected: MasterKeyExpectation
  ): Promise<MasterKeyClassification & { state: OnchainKeyState }> {
    const state = await this.readKeyState(address);
    return { ...classifyMasterKey(state, expected), state };
  }

  /**
   * Read the account's key state ({@link readKeyState}) and rebuild its
   * operational master key with `params.passkey` ({@link reconstructOperationalMasterKey}).
   * Resolves with the encoded master key and the state it was rebuilt from.
   *
   * The result is only as current as this read: use it right away, and re-check
   * the wallet's key state before submitting it. It is valid only for
   * `address` (`state.account`): submitted to another wallet it locks that
   * wallet's master key.
   *
   * @throws `AaOperationError` when the master key is not operational, or from
   *   the builder for an invalid passkey.
   * @throws `AaFetchError` when the read fails.
   */
  async reconstructOperationalMasterKey(
    address: string,
    params: ReconstructOperationalMasterKeyParams
  ): Promise<{ encodedMasterKey: string; state: OnchainKeyState }> {
    const state = await this.readKeyState(address);
    return { encodedMasterKey: reconstructOperationalMasterKey(state, params), state };
  }

  private async readKeyStateOnce(address: string): Promise<{ state: OnchainKeyState } | { mismatch: string }> {
    const account = ethers.getAddress(address);
    const lists = [
      { set: "master" as const, window: MASTER_KEY_WINDOW },
      { set: "tx" as const, window: this.maxTxKeys },
    ];
    // Layout: [masterKeyThreshold, txKeyThreshold, then per list: list(0..window), weight(0..window)]
    const round1Calls: Call3[] = [
      this.accountCall(address, KEY_LISTS.master.threshold, []),
      this.accountCall(address, KEY_LISTS.tx.threshold, []),
    ];
    for (const { set, window } of lists) {
      for (const fn of [KEY_LISTS[set].list, KEY_LISTS[set].weight]) {
        for (let index = 0; index <= window; index++) round1Calls.push(this.accountCall(address, fn, [index]));
      }
    }
    const round1 = await this.batch.batch(round1Calls, READ_KEY_STATE);
    const via = round1.via;

    // A call to an address without code succeeds with empty data.
    const head = round1.results[0];
    if (head.success && head.returnData === "0x") {
      const empty = (): OnchainKeySet => ({ threshold: 0, keys: [], truncated: false });
      return { state: { account, deployed: false, master: empty(), tx: empty(), readVia: via } };
    }

    let offset = 2;
    const parsed = lists.map(({ set, window }, position) => {
      const parsedList = this.parseKeyList(round1.results, set, position, offset, window);
      offset += 2 * (window + 1);
      return parsedList;
    });
    const slots = parsed.flatMap((p) => p.slots);

    let details: Result3[] = [];
    if (slots.length > 0) {
      const detailCalls = slots.flatMap(({ logic, keyId, purpose }): Call3[] => {
        const args = [purpose, address, keyId];
        return [
          { target: logic, allowFailure: true, callData: webAuthnIface.encodeFunctionData("keyType") },
          { target: logic, allowFailure: true, callData: zkIface.encodeFunctionData("getData", args) },
          { target: logic, allowFailure: true, callData: zkIface.encodeFunctionData("getAnchor", args) },
          { target: logic, allowFailure: true, callData: addressKeyIface.encodeFunctionData("getSigner", args) },
          { target: logic, allowFailure: true, callData: webAuthnIface.encodeFunctionData("getKeyData", args) },
        ];
      });

      // Check consistency before decoding: after a concurrent key change the
      // round-2 getters may revert, and that must lead to a re-read, not an error.
      if (via === "multicall") {
        // Round 1's calls run again in the same eth_call as the details, so an
        // identical answer proves the details belong to the state round 1 read.
        const round2 = await this.batch.batch([...round1Calls, ...detailCalls], READ_KEY_STATE);
        if (round2.via !== via) return { mismatch: "Multicall3 answered round 1 but not round 2" };
        if (!sameResults(round2.results.slice(0, round1Calls.length), round1.results)) {
          return { mismatch: "the key lists differ between rounds" };
        }
        details = round2.results.slice(round1Calls.length);
      } else {
        details = (await this.batch.batch(detailCalls, READ_KEY_STATE)).results;
        const again = await this.batch.batch(round1Calls, READ_KEY_STATE);
        if (!sameResults(again.results, round1.results)) return { mismatch: "the key lists differ on re-read" };
      }
    }

    const keys = slots.map((slot, position) => this.decodeKeyEntry(slot, details, position * 5));
    const sets = parsed.map(
      (p): OnchainKeySet => ({
        threshold: p.threshold,
        keys: keys.filter((_, i) => slots[i].set === p.set),
        truncated: p.truncated,
      }),
    );
    return { state: { account, deployed: true, master: sets[0], tx: sets[1], readVia: via } };
  }

  private accountCall(address: string, fn: string, args: unknown[]): Call3 {
    return { target: address, allowFailure: true, callData: accountIface.encodeFunctionData(fn, args) };
  }

  /** Decode one key list from round 1. `thresholdAt` is the threshold's position in `results`. */
  private parseKeyList(
    results: Result3[],
    set: "master" | "tx",
    thresholdAt: number,
    offset: number,
    window: number,
  ): { set: "master" | "tx"; threshold: number; slots: KeySlot[]; truncated: boolean } {
    const fns = KEY_LISTS[set];
    const listAt = (index: number) => results[offset + index];
    const weightAt = (index: number) => results[offset + window + 1 + index];

    const [threshold] = this.decodeRequired(accountIface, fns.threshold, results[thresholdAt], fns.threshold);
    const slots: KeySlot[] = [];
    // Index `window` is only probed: a value there means the list continues past the window.
    for (let index = 0; index <= window; index++) {
      if (this.listEnded(listAt(index), `${fns.list}(${index})`, READ_KEY_STATE)) {
        if (!isListEnd(weightAt(index))) {
          throw this.shapeError(
            READ_KEY_STATE,
            weightAt(index).returnData,
            `AccountReader: ${fns.list} ends at ${index} but ${fns.weight}(${index}) does not end there`,
          );
        }
        return { set, threshold: Number(threshold), slots, truncated: false };
      }
      if (index === window) break;
      const [logic, keyId] = this.decodeRequired(accountIface, fns.list, listAt(index), `${fns.list}(${index})`);
      const [weight] = this.decodeRequired(accountIface, fns.weight, weightAt(index), `${fns.weight}(${index})`);
      slots.push({ set, purpose: fns.purpose, index, logic, keyId, weight: Number(weight) });
    }
    return { set, threshold: Number(threshold), slots, truncated: true };
  }

  /**
   * Whether a key-list getter answer marks the end of the list: `true` for a
   * revert without data or with `Panic(0x32)` ({@link isListEnd}), `false` for
   * a value. Anything else proves neither, so it throws.
   */
  private listEnded(result: Result3, what: string, operation: string): boolean {
    if (isListEnd(result)) return true;
    if (hasValue(result)) return false;
    const why = result.success
      ? "returned empty data"
      : result.revertDataMissing
        ? "failed without revert data (a node error, not a revert)"
        : `reverted with data that does not end a list (${result.returnData})`;
    throw this.shapeError(
      operation,
      result.returnData,
      `AccountReader: ${what} ${why} — neither a value nor the end of the list`,
    );
  }

  private decodeKeyEntry(slot: KeySlot, results: Result3[], base: number): OnchainKeyEntry {
    const what = (fn: string) => `${fn} for ${slot.set} key ${slot.index}`;
    // `"unknown"` only for a type number this SDK does not know — never for a failed read.
    const [rawKeyType] = this.decodeRequired(webAuthnIface, "keyType", results[base], what("keyType()"));
    const keyType = keyTypeFromPrimitive(Number(rawKeyType));
    const entry: OnchainKeyEntry = {
      index: slot.index,
      logicContract: slot.logic,
      keyId: slot.keyId,
      weight: slot.weight,
      keyType,
    };
    if (keyType === "zkOAuth") {
      const data = this.decodeRequired(zkIface, "getData", results[base + 1], what("getData"));
      const [anchor] = this.decodeRequired(zkIface, "getAnchor", results[base + 2], what("getAnchor"));
      entry.zk = {
        directory: data[0] as string,
        n: data[1] as bigint,
        k: data[2] as bigint,
        hAudList: data[3] as bigint,
        anchorWithHash: Array.from(anchor as Iterable<bigint>),
      };
    } else if (keyType === "address") {
      const [signer] = this.decodeRequired(addressKeyIface, "getSigner", results[base + 3], what("getSigner"));
      entry.signer = signer as string;
    } else if (keyType === "webauthn") {
      const d = this.decodeRequired(webAuthnIface, "getKeyData", results[base + 4], what("getKeyData"));
      entry.webauthn = {
        x: d[0] as string,
        y: d[1] as string,
        credentialId: d[2] as string,
        allowedOriginHash: d[3] as string,
        allowedRpIdHash: d[4] as string,
      };
    }
    return entry;
  }

  /** Decode a sub-result that must be there; a revert or bad data is RESPONSE_SHAPE, never "absent". */
  private decodeRequired(iface: ethers.Interface, fn: string, result: Result3, what: string): ethers.Result {
    try {
      if (!hasValue(result)) throw new Error(result.success ? "empty return data" : "call reverted");
      return iface.decodeFunctionResult(fn, result.returnData);
    } catch (err) {
      throw this.shapeError(READ_KEY_STATE, result.returnData, `AccountReader: ${what} returned no usable value`, err);
    }
  }

  /** A failure whose revert data never arrived is a node error: never read it as "no value". */
  private requireRevertData(result: Result3, what: string, operation: string): void {
    if (result.revertDataMissing) {
      throw this.shapeError(operation, result.returnData, `AccountReader: ${what} failed without revert data (a node error, not a revert)`);
    }
  }

  private shapeError(operation: string, rawResponse: string, message: string, cause?: unknown): AaFetchError {
    return new AaFetchError({
      code: AaFetchErrorCode.RESPONSE_SHAPE,
      operation,
      service: "rpc",
      url: this.rpcUrl,
      method: "POST",
      rawResponse,
      cause,
      message,
    });
  }

  private requireProvider(operation: string, method: string): ethers.Provider {
    if (!this.provider) {
      throw new AaOperationError({
        code: AaOperationErrorCode.CONFIG_REQUIRED_FIELD_MISSING,
        operation,
        message:
          `AccountReader: ${method} needs rpcUrl or provider — a call-only transport has no ` +
          "eth_getCode / eth_getBalance. Use readTxKeySlots().deployed instead.",
      });
    }
    return this.provider;
  }

  private decodeSlot(returnData: string): [string, bigint] {
    try {
      const decoded = accountIface.decodeFunctionResult("txKeyList", returnData);
      return [decoded[0] as string, decoded[1] as bigint];
    } catch (err) {
      throw new AaFetchError({
        code: AaFetchErrorCode.RESPONSE_SHAPE,
        operation: READ_TX_KEYS,
        service: "rpc",
        url: this.rpcUrl,
        method: "POST",
        rawResponse: returnData,
        cause: err,
        message: "AccountReader: txKeyList returned undecodable data",
      });
    }
  }

  private decodeKeyType(result: Result3): KeyType {
    if (!hasValue(result)) return "unknown";
    try {
      const [keyType] = webAuthnIface.decodeFunctionResult("keyType", result.returnData);
      return keyTypeFromPrimitive(Number(keyType));
    } catch {
      return "unknown";
    }
  }

  private decodeKeyData(result: Result3): WebAuthnKeyData | undefined {
    if (!hasValue(result)) return undefined;
    try {
      const d = webAuthnIface.decodeFunctionResult("getKeyData", result.returnData);
      return {
        x: d[0] as string,
        y: d[1] as string,
        credentialId: d[2] as string,
        allowedOriginHash: d[3] as string,
        allowedRpIdHash: d[4] as string,
      };
    } catch {
      return undefined;
    }
  }
}
