import { ethers } from "ethers";
import { Multicall3ABI } from "../types/abi";
import { AaFetchError, AaFetchErrorCode } from "../errors";
import type { ReadVia } from "./types";

/**
 * The one transport primitive the reader needs: an `eth_call` against `to`
 * with `data`, resolving to the returned hex.
 *
 * **Contract:** resolve only with what the node actually returned. A transport
 * failure, an HTTP error, or a JSON-RPC `error` object MUST throw — never
 * swallow them into `"0x"` or `""`. The reader interprets `"0x"` as "a
 * successful call to an address without code" (an undeployed account, or a
 * chain without Multicall3); a transport that returns `"0x"` on failure would
 * make a dead node look like a missing wallet. `ethers.Provider.call` and any
 * JSON-RPC proxy that throws on `error` satisfy this.
 */
export type EthCall = (params: { to: string; data: string }) => Promise<string>;

/** One sub-call of a Multicall3 `aggregate3` batch. */
export interface Call3 {
  target: string;
  allowFailure: boolean;
  callData: string;
}

/** One sub-result of a Multicall3 `aggregate3` batch. */
export interface Result3 {
  success: boolean;
  returnData: string;
  /**
   * Set (to `true`) only on the per-call path, for a call whose error
   * `isRevertError` accepted but that carried no revert data (`err.data` not a
   * string). `returnData` is then `"0x"`, but nobody saw the call revert with
   * empty data: ethers v6 reports a node error (rate limit, `header not
   * found`, …) to `eth_call` the same way, with `data: null`. Such a result is
   * neither a value nor the end of a key list; the reader fails instead.
   * Absent on every Multicall3 result: a sub-call of `aggregate3` that failed
   * did revert with exactly `returnData`.
   */
  revertDataMissing?: true;
}

/** Multicall3 — deployed at the same address on every major chain. */
export const MULTICALL3_ADDRESS = "0xcA11bde05977b3631167028862bE2a173976CA11";

const multicallIface = new ethers.Interface(Multicall3ABI);

/** Adapt an ethers `Provider` to {@link EthCall}. */
export function ethCallFromProvider(provider: ethers.Provider): EthCall {
  return async ({ to, data }) => await provider.call({ to, data });
}

/**
 * Did this sub-call succeed with actual data? Empty `returnData` on success is
 * how a call to an address without code comes back, so it does not count.
 */
export function hasValue(result: Result3): boolean {
  return result.success && result.returnData !== "0x" && result.returnData.length > 2;
}

/** Solidity `Panic(0x32)`: array index out of bounds. */
const PANIC_ARRAY_OUT_OF_BOUNDS = "0x4e487b71" + "32".padStart(64, "0");

/**
 * Did this sub-call revert with Solidity `Panic(0x32)` (array index out of
 * bounds)? Code that indexes an array (`arr[i]`) panics this way past its end.
 */
export function isArrayOutOfBounds(result: Result3): boolean {
  return !result.success && result.returnData.toLowerCase() === PANIC_ARRAY_OUT_OF_BOUNDS;
}

/**
 * Does this answer of a key-list getter (`masterKeyList(i)`, `txKeyList(i)`, their
 * weight lists) mark the end of the list?
 *
 * - A revert seen to carry **no data**. The compiler-generated getter of a public
 *   array reverts this way past the end of the array — that is what the
 *   ZkapAccount bytecode shipped in this package answers.
 * - A revert with `Panic(0x32)` ({@link isArrayOutOfBounds}), which the same
 *   getter would answer if compiled to index the array explicitly.
 *
 * Not the end: a value, empty data on success, any other revert data
 * (`Error(string)`, another `Panic`), and a failure whose revert data was never
 * received (`revertDataMissing` — a node error on the per-call path).
 */
export function isListEnd(result: Result3): boolean {
  if (result.success || result.revertDataMissing) return false;
  return result.returnData === "0x" || isArrayOutOfBounds(result);
}

export interface BatchCallerOptions {
  call: EthCall;
  /**
   * `eth_getCode`, when the transport can do it (provider modes). Used once,
   * only if `aggregate3` answers `0x`, to tell "no Multicall3 on this chain"
   * from "the transport returned bogus empty data".
   */
  getCode?: (address: string) => Promise<string>;
  /** Multicall3 address; `false` disables batching and always calls per slot. */
  multicallAddress?: string | false;
  /**
   * Classifies an error thrown by `call` on the per-call fallback path (chains
   * without Multicall3): `true` means "the contract call reverted", and the
   * error's `data` must then be the revert data as a hex string — `"0x"` for a
   * revert without data. Such an error becomes
   * `{ success: false, returnData: err.data }`. An accepted error whose `data`
   * is not a string becomes `{ success: false, returnData: "0x",
   * revertDataMissing: true }`: a failure whose revert data is unknown, which
   * the reader never takes as a value or as the end of a key list. Any error
   * classified `false` throws `AaFetchError` (`TRANSPORT`). Defaults to
   * `ethers.isCallException`.
   *
   * With ethers v6, a revert the node answers WITH a `data` field carries it
   * through, `"0x"` included, while every other JSON-RPC `error` answer to
   * `eth_call` (rate limit, `header not found`, …) is also a `CALL_EXCEPTION`,
   * but with `data: null` — so the default keeps the two apart through `data`.
   * This was observed against a local anvil node, which answers a revert
   * without data as `{ code: 3, data: "0x" }`. Nodes differ: one that answers
   * such a revert with no `data` field at all is indistinguishable from a node
   * error here, so on this per-call path every key list read fails (it never
   * reads as an empty list). Chains with Multicall3 are not affected.
   *
   * A custom classifier must keep the same distinction: return `true` only for
   * a revert, and pass its revert data through in `data`. The key-list getters
   * revert without data past the end of a list, so a classifier that drops
   * revert data turns every list end into a failed read; one that reports a
   * node error as a revert with `data: "0x"` makes a node error look like the
   * end of a list. Expect reverts in ordinary reads, too: `readKeyState` asks
   * each key's logic contract for the getters of every key type, and the ones
   * that do not match the key's type revert.
   */
  isRevertError?: (err: unknown) => boolean;
  /** Surfaced as `AaFetchError.url` for diagnostics (rpcUrl mode). */
  url?: string;
}

/**
 * Executes a round of `eth_call`s as one Multicall3 `aggregate3` when the chain
 * has Multicall3, and as parallel individual calls otherwise. Both paths yield
 * the same `Result3[]`, so callers decode identically.
 */
export class BatchCaller {
  private readonly call: EthCall;
  private readonly getCode?: (address: string) => Promise<string>;
  private readonly multicallAddress: string | false;
  private readonly isRevertError: (err: unknown) => boolean;
  private readonly url?: string;
  private _multicallAvailable: boolean | undefined;

  constructor(opts: BatchCallerOptions) {
    this.call = opts.call;
    this.getCode = opts.getCode;
    this.multicallAddress = opts.multicallAddress === undefined ? MULTICALL3_ADDRESS : opts.multicallAddress;
    this.isRevertError = opts.isRevertError ?? ethers.isCallException;
    this.url = opts.url;
    this._multicallAvailable = this.multicallAddress === false ? false : undefined;
  }

  /** `undefined` until the first round; `false` once Multicall3 is known to be absent. */
  get multicallAvailable(): boolean | undefined {
    return this._multicallAvailable;
  }

  /** Run one round of calls. */
  async batch(calls: Call3[], operation: string): Promise<{ results: Result3[]; via: ReadVia }> {
    const multicallAddress = this.multicallAddress;
    if (multicallAddress !== false && this._multicallAvailable !== false) {
      const raw = await this.send(
        {
          to: multicallAddress,
          data: multicallIface.encodeFunctionData("aggregate3", [
            calls.map((c) => [c.target, c.allowFailure, c.callData]),
          ]),
        },
        operation,
      );
      // Check for "no code here" BEFORE decoding: ethers throws the same
      // BAD_DATA for "0x" as for a corrupt payload, so a catch could not tell
      // an absent Multicall3 from a broken transport.
      if (raw !== "0x") {
        this._multicallAvailable = true;
        return { results: this.decodeAggregate3(raw, calls.length, operation), via: "multicall" };
      }
      await this.confirmMulticallAbsent(multicallAddress, raw, operation);
    }
    return { results: await this.direct(calls, operation), via: "direct" };
  }

  private async send(params: { to: string; data: string }, operation: string): Promise<string> {
    try {
      return await this.call(params);
    } catch (err) {
      throw this.transportError(operation, err, `AccountReader: eth_call to ${params.to} failed`);
    }
  }

  private async confirmMulticallAbsent(multicallAddress: string, raw: string, operation: string): Promise<void> {
    if (this.getCode) {
      let code: string;
      try {
        code = await this.getCode(multicallAddress);
      } catch (err) {
        throw this.transportError(operation, err, `AccountReader: eth_getCode for Multicall3 at ${multicallAddress} failed`);
      }
      if (code !== "0x") {
        throw new AaFetchError({
          code: AaFetchErrorCode.RESPONSE_SHAPE,
          operation,
          service: "rpc",
          url: this.url,
          method: "POST",
          rawResponse: raw,
          message:
            `AccountReader: Multicall3 at ${multicallAddress} has code but aggregate3 returned empty data — ` +
            "the transport returned a bogus result",
        });
      }
    }
    this._multicallAvailable = false;
  }

  private decodeAggregate3(raw: string, expected: number, operation: string): Result3[] {
    let entries: unknown[];
    try {
      const [decoded] = multicallIface.decodeFunctionResult("aggregate3", raw);
      entries = Array.from(decoded as Iterable<unknown>);
    } catch (err) {
      throw this.shapeError(operation, raw, err, "AccountReader: aggregate3 returned undecodable data");
    }
    if (entries.length !== expected) {
      throw this.shapeError(
        operation,
        raw,
        undefined,
        `AccountReader: aggregate3 returned ${entries.length} results for ${expected} calls`,
      );
    }
    return entries.map((entry) => {
      const [success, returnData] = entry as unknown as [boolean, string];
      return { success, returnData };
    });
  }

  private async direct(calls: Call3[], operation: string): Promise<Result3[]> {
    return await Promise.all(
      calls.map(async (c): Promise<Result3> => {
        try {
          return { success: true, returnData: await this.call({ to: c.target, data: c.callData }) };
        } catch (err) {
          if (this.isRevertError(err)) {
            const data = (err as { data?: unknown }).data;
            return typeof data === "string"
              ? { success: false, returnData: data }
              : { success: false, returnData: "0x", revertDataMissing: true };
          }
          throw this.transportError(operation, err, `AccountReader: eth_call to ${c.target} failed`);
        }
      }),
    );
  }

  private transportError(operation: string, cause: unknown, message: string): AaFetchError {
    return new AaFetchError({
      code: AaFetchErrorCode.TRANSPORT,
      operation,
      service: "rpc",
      url: this.url,
      method: "POST",
      cause,
      message,
    });
  }

  private shapeError(operation: string, raw: string, cause: unknown, message: string): AaFetchError {
    return new AaFetchError({
      code: AaFetchErrorCode.RESPONSE_SHAPE,
      operation,
      service: "rpc",
      url: this.url,
      method: "POST",
      rawResponse: raw,
      cause,
      message,
    });
  }
}
