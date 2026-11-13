import { ethers } from "ethers";
import { BatchCaller, ethCallFromProvider, hasValue, isArrayOutOfBounds, isListEnd, MULTICALL3_ADDRESS } from "../transport";
import type { Call3 } from "../transport";
import { AaFetchError, AaFetchErrorCode } from "../../errors";
import { coder, encodeAggregate3Results, PANIC_OOB } from "../../__tests__/helpers/fakeEthCall";

const TARGET = "0x" + "11".repeat(20);
const value = (n: number) => coder.encode(["uint256"], [n]);
const calls = (n: number): Call3[] =>
  Array.from({ length: n }, (_, i) => ({ target: TARGET, allowFailure: true, callData: value(i) }));

describe("ethCallFromProvider", () => {
  it("forwards to provider.call and returns its hex", async () => {
    const call = jest.fn().mockResolvedValue("0x01");
    const eth = ethCallFromProvider({ call } as unknown as ethers.Provider);
    await expect(eth({ to: TARGET, data: "0xabcd" })).resolves.toBe("0x01");
    expect(call).toHaveBeenCalledWith({ to: TARGET, data: "0xabcd" });
  });
});

describe("hasValue", () => {
  it.each([
    [{ success: true, returnData: "0x" }, false],
    [{ success: false, returnData: "0x1234" }, false],
    [{ success: true, returnData: "0x1234" }, true],
  ])("%p → %p", (result, expected) => {
    expect(hasValue(result)).toBe(expected);
  });
});

describe("isArrayOutOfBounds", () => {
  const panic = (code: number) => "0x4e487b71" + coder.encode(["uint256"], [code]).slice(2);

  it("pins Panic(0x32) independently of the fake chain's constant", () => {
    expect(panic(0x32)).toBe(PANIC_OOB);
  });

  it.each([
    ["Panic(0x32)", { success: false, returnData: panic(0x32) }, true],
    ["Panic(0x32), uppercase hex", { success: false, returnData: "0x" + panic(0x32).slice(2).toUpperCase() }, true],
    ["a revert without data", { success: false, returnData: "0x" }, false],
    ["Panic(0x11) (overflow)", { success: false, returnData: panic(0x11) }, false],
    ["Error(string)", { success: false, returnData: "0x08c379a0" + coder.encode(["string"], ["nope"]).slice(2) }, false],
    ["Panic(0x32) with trailing bytes", { success: false, returnData: panic(0x32) + "00" }, false],
    ["the Panic selector alone", { success: false, returnData: "0x4e487b71" }, false],
    ["a successful call returning the Panic bytes", { success: true, returnData: panic(0x32) }, false],
  ])("%s", (_label, result, expected) => {
    expect(isArrayOutOfBounds(result)).toBe(expected);
  });
});

describe("isListEnd", () => {
  const panic = (code: number) => "0x4e487b71" + coder.encode(["uint256"], [code]).slice(2);

  it.each([
    ["a revert without data (the public array getter past its end)", { success: false, returnData: "0x" }, true],
    ["Panic(0x32)", { success: false, returnData: panic(0x32) }, true],
    ["a failure whose revert data never arrived", { success: false, returnData: "0x", revertDataMissing: true as const }, false],
    ["Panic(0x11) (overflow)", { success: false, returnData: panic(0x11) }, false],
    ["Error(string)", { success: false, returnData: "0x08c379a0" + coder.encode(["string"], ["nope"]).slice(2) }, false],
    ["the Panic selector alone", { success: false, returnData: "0x4e487b71" }, false],
    ["a success with empty data", { success: true, returnData: "0x" }, false],
    ["a value", { success: true, returnData: value(1) }, false],
  ])("%s", (_label, result, expected) => {
    expect(isListEnd(result)).toBe(expected);
  });
});

describe("BatchCaller", () => {
  it("batches through Multicall3 and reports via=multicall", async () => {
    const call = jest.fn().mockResolvedValue(
      encodeAggregate3Results([
        { success: true, returnData: value(1) },
        { success: false, returnData: "0x" },
      ]),
    );
    const caller = new BatchCaller({ call });
    expect(caller.multicallAvailable).toBeUndefined();

    const { results, via } = await caller.batch(calls(2), "op");
    expect(via).toBe("multicall");
    expect(results).toEqual([
      { success: true, returnData: value(1) },
      { success: false, returnData: "0x" },
    ]);
    expect(caller.multicallAvailable).toBe(true);
    expect(call).toHaveBeenCalledTimes(1);
    expect(call.mock.calls[0][0].to).toBe(MULTICALL3_ADDRESS);
  });

  it("wraps a transport failure as TRANSPORT with the operation and url", async () => {
    const cause = new Error("boom");
    const caller = new BatchCaller({ call: jest.fn().mockRejectedValue(cause), url: "https://rpc" });
    const promise = caller.batch(calls(1), "my_op");
    await expect(promise).rejects.toBeInstanceOf(AaFetchError);
    await expect(promise).rejects.toMatchObject({
      code: AaFetchErrorCode.TRANSPORT,
      operation: "my_op",
      url: "https://rpc",
      service: "rpc",
      method: "POST",
      cause,
    });
  });

  it("rejects a result count that does not match the call count", async () => {
    const call = jest.fn().mockResolvedValue(encodeAggregate3Results([{ success: true, returnData: value(1) }]));
    const caller = new BatchCaller({ call });
    await expect(caller.batch(calls(3), "op")).rejects.toMatchObject({
      code: AaFetchErrorCode.RESPONSE_SHAPE,
      operation: "op",
    });
  });

  it("rejects undecodable aggregate3 output", async () => {
    const caller = new BatchCaller({ call: jest.fn().mockResolvedValue("0xdeadbeef") });
    const promise = caller.batch(calls(1), "op");
    await expect(promise).rejects.toMatchObject({ code: AaFetchErrorCode.RESPONSE_SHAPE, rawResponse: "0xdeadbeef" });
  });

  describe("when aggregate3 answers 0x", () => {
    it("without getCode: falls back to direct calls and remembers", async () => {
      const call = jest.fn().mockResolvedValueOnce("0x").mockResolvedValue(value(9));
      const caller = new BatchCaller({ call });
      const first = await caller.batch(calls(2), "op");
      expect(first.via).toBe("direct");
      expect(first.results).toEqual([
        { success: true, returnData: value(9) },
        { success: true, returnData: value(9) },
      ]);
      expect(caller.multicallAvailable).toBe(false);
      expect(call).toHaveBeenCalledTimes(3);

      await caller.batch(calls(1), "op");
      // no new aggregate3 attempt
      expect(call.mock.calls.filter(([p]) => p.to === MULTICALL3_ADDRESS)).toHaveLength(1);
    });

    it("with getCode reporting no code: falls back", async () => {
      const call = jest.fn().mockResolvedValueOnce("0x").mockResolvedValue(value(1));
      const getCode = jest.fn().mockResolvedValue("0x");
      const caller = new BatchCaller({ call, getCode });
      const { via } = await caller.batch(calls(1), "op");
      expect(via).toBe("direct");
      expect(getCode).toHaveBeenCalledWith(MULTICALL3_ADDRESS);
    });

    it("with getCode reporting code: the transport is lying → RESPONSE_SHAPE", async () => {
      const call = jest.fn().mockResolvedValue("0x");
      const getCode = jest.fn().mockResolvedValue("0x6080");
      const caller = new BatchCaller({ call, getCode });
      await expect(caller.batch(calls(1), "op")).rejects.toMatchObject({
        code: AaFetchErrorCode.RESPONSE_SHAPE,
        rawResponse: "0x",
      });
      expect(caller.multicallAvailable).toBeUndefined();
    });

    it("with getCode failing: TRANSPORT", async () => {
      const call = jest.fn().mockResolvedValue("0x");
      const getCode = jest.fn().mockRejectedValue(new Error("down"));
      const caller = new BatchCaller({ call, getCode });
      await expect(caller.batch(calls(1), "op")).rejects.toMatchObject({ code: AaFetchErrorCode.TRANSPORT });
    });
  });

  describe("direct path", () => {
    const revert = (data?: string) => Object.assign(new Error("execution reverted"), { code: "CALL_EXCEPTION", data });

    it("maps a revert with data to success:false carrying the data", async () => {
      const call = jest.fn().mockRejectedValue(revert("0x08c379a0"));
      const caller = new BatchCaller({ call, multicallAddress: false });
      const { results, via } = await caller.batch(calls(1), "op");
      expect(via).toBe("direct");
      expect(results).toEqual([{ success: false, returnData: "0x08c379a0" }]);
    });

    it("maps a revert with empty data (err.data === '0x') to success:false / 0x", async () => {
      const call = jest.fn().mockRejectedValue(revert("0x"));
      const caller = new BatchCaller({ call, multicallAddress: false });
      const { results } = await caller.batch(calls(1), "op");
      expect(results).toEqual([{ success: false, returnData: "0x" }]);
    });

    it.each([
      ["null (how ethers reports a node error)", null],
      ["missing", undefined],
    ])("marks a failure whose err.data is %s as revertDataMissing", async (_label, data) => {
      const call = jest.fn().mockRejectedValue(revert(data as string | undefined));
      const caller = new BatchCaller({ call, multicallAddress: false });
      const { results } = await caller.batch(calls(1), "op");
      expect(results).toEqual([{ success: false, returnData: "0x", revertDataMissing: true }]);
    });

    it("treats a non-revert error as TRANSPORT", async () => {
      const call = jest.fn().mockRejectedValue(new Error("ECONNREFUSED"));
      const caller = new BatchCaller({ call, multicallAddress: false });
      await expect(caller.batch(calls(1), "op")).rejects.toMatchObject({ code: AaFetchErrorCode.TRANSPORT });
    });

    it("honours a custom isRevertError", async () => {
      class ProxyRevert extends Error {}
      const call = jest.fn().mockRejectedValue(new ProxyRevert("rpc error"));
      const caller = new BatchCaller({
        call,
        multicallAddress: false,
        isRevertError: (e) => e instanceof ProxyRevert,
      });
      const { results } = await caller.batch(calls(1), "op");
      expect(results).toEqual([{ success: false, returnData: "0x", revertDataMissing: true }]);
    });

    it("multicallAddress:false starts with multicallAvailable=false", () => {
      expect(new BatchCaller({ call: jest.fn(), multicallAddress: false }).multicallAvailable).toBe(false);
    });
  });
});
