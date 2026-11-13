/**
 * AccountReader against answers captured from the REAL contract bytecode.
 *
 * `fixtures/reader-capture.json` holds the raw JSON-RPC answers that the
 * bytecode in `lib/types/abi/*.json` gave on a local anvil
 * (`node scripts/capture-reader-fixture.mjs`). A real `ethers.JsonRpcProvider`
 * replays them through a stubbed wire; a request the capture does not hold
 * fails the test. The fake chain the other reader tests use is checked against
 * the same answers, so it cannot drift from the contracts unnoticed.
 */
import { createHash } from "crypto";
import fs from "fs";
import path from "path";
import { ethers } from "ethers";
import { AccountReader } from "../AccountReader";
import type { OnchainKeyState, ReadVia } from "../AccountReader";
import { MULTICALL3_ADDRESS } from "../transport";
import { AccountKeyWebAuthnABI, Multicall3ABI, ZkapAccountABI } from "../../types/abi";
import { PrimitiveAccountKeyTypes } from "../../types/AccountKey";
import { originHashOf } from "../../utils/webauthnKey";
import { fakeChain, strictResolver } from "../../__tests__/helpers/fakeEthCall";
import type { FakeAccountState, FakeKey, Handler } from "../../__tests__/helpers/fakeEthCall";

interface RawAnswer {
  result?: string;
  error?: { code: number; message: string; data?: string };
}

interface Capture {
  chainId: string;
  deployedBytecodeSha256: Record<string, string>;
  addresses: Record<
    | "noCodeAccount"
    | "uninitializedAccount"
    | "initializedAccount"
    | "addressKeyLogic"
    | "webAuthnLogic"
    | "zkVerifier"
    | "cosigner"
    | "multicall3",
    string
  >;
  initializedAccount: {
    passkey: { x: string; y: string; credentialId: string; rpId: string; rpIdHash: string; origin: string };
  };
  multicall3Code: string;
  calls: { to: string; data: string; response: RawAnswer }[];
}

const capture = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "fixtures/reader-capture.json"), "utf8"),
) as Capture;
const A = capture.addresses;
const passkey = capture.initializedAccount.passkey;
const answers = new Map(capture.calls.map((c) => [`${c.to} ${c.data}`, c.response]));
const multicallIface = new ethers.Interface(Multicall3ABI);
const accountIface = new ethers.Interface(ZkapAccountABI);
const webAuthnIface = new ethers.Interface(AccountKeyWebAuthnABI);
const lower = (s: string) => s.toLowerCase();

/**
 * A real JsonRpcProvider whose wire answers from the capture. `multicall`:
 * whether the chain has Multicall3 — if so, `aggregate3` is answered by
 * assembling the captured sub-call answers the way Multicall3 does (a failed
 * sub-call carries its revert data); if not, by the captured answer of the
 * code-less Multicall3 address.
 */
class ReplayProvider extends ethers.JsonRpcProvider {
  readonly unexpected: string[] = [];

  constructor(private readonly multicall: boolean) {
    super("http://127.0.0.1:1", Number(capture.chainId), { staticNetwork: true });
  }

  override async _send(payload: ethers.JsonRpcPayload | ethers.JsonRpcPayload[]): Promise<ethers.JsonRpcResult[]> {
    const payloads = Array.isArray(payload) ? payload : [payload];
    return payloads.map((p) => ({ id: p.id, ...this.answer(p) })) as ethers.JsonRpcResult[];
  }

  private fail(what: string): never {
    this.unexpected.push(what);
    throw new Error(`replay: not in the capture: ${what}`);
  }

  private answer(p: ethers.JsonRpcPayload): RawAnswer {
    const params = p.params as unknown[];
    if (p.method === "eth_chainId") return { result: capture.chainId };
    if (p.method === "eth_getCode" && lower(params[0] as string) === lower(MULTICALL3_ADDRESS) && !this.multicall) {
      return { result: capture.multicall3Code };
    }
    if (p.method !== "eth_call") return this.fail(`${p.method} ${JSON.stringify(params)}`);

    const { to, data } = params[0] as { to: string; data: string };
    if (lower(to) === lower(MULTICALL3_ADDRESS)) {
      if (!this.multicall) return this.lookup(A.multicall3, multicallIface.encodeFunctionData("aggregate3", [[]]));
      const [calls] = multicallIface.decodeFunctionData("aggregate3", data);
      const results = Array.from(calls as Iterable<[string, boolean, string]>).map(([target, , callData]) => {
        const raw = this.lookup(target, callData);
        if (raw.result !== undefined) return [true, raw.result];
        if (raw.error?.code === 3 && typeof raw.error.data === "string") return [false, raw.error.data];
        return this.fail(`a sub-call answer Multicall3 cannot carry: ${JSON.stringify(raw)}`);
      });
      return { result: multicallIface.encodeFunctionResult("aggregate3", [results]) };
    }
    return this.lookup(to, data);
  }

  private lookup(to: string, data: string): RawAnswer {
    return answers.get(`${lower(to)} ${lower(data)}`) ?? this.fail(`eth_call ${to} ${data}`);
  }
}

const PATHS: [string, boolean, ReadVia][] = [
  ["through Multicall3", true, "multicall"],
  ["through direct calls", false, "direct"],
];

const PASSKEY_DATA = {
  x: passkey.x,
  y: passkey.y,
  credentialId: passkey.credentialId,
  allowedOriginHash: originHashOf(passkey.origin),
  allowedRpIdHash: passkey.rpIdHash,
};

function expectedState(account: string, readVia: ReadVia): OnchainKeyState {
  const empty = { threshold: 0, keys: [], truncated: false };
  if (account === A.noCodeAccount) {
    return { account: ethers.getAddress(account), deployed: false, master: empty, tx: empty, readVia };
  }
  if (account === A.uninitializedAccount) {
    return { account: ethers.getAddress(account), deployed: true, master: empty, tx: empty, readVia };
  }
  const webauthn = { logicContract: ethers.getAddress(A.webAuthnLogic), keyId: 0n, weight: 1, keyType: "webauthn" as const, webauthn: PASSKEY_DATA };
  return {
    account: ethers.getAddress(account),
    deployed: true,
    master: {
      threshold: 2,
      keys: [
        { index: 0, logicContract: ethers.getAddress(A.addressKeyLogic), keyId: 0n, weight: 1, keyType: "address", signer: ethers.getAddress(A.cosigner) },
        { index: 1, ...webauthn },
      ],
      truncated: false,
    },
    tx: { threshold: 1, keys: [{ index: 0, ...webauthn }], truncated: false },
    readVia,
  };
}

describe("captured answers of the real contract bytecode", () => {
  it("were captured from the bytecode in lib/types/abi (re-run scripts/capture-reader-fixture.mjs after updating it)", () => {
    for (const [name, hash] of Object.entries(capture.deployedBytecodeSha256)) {
      const artifact = JSON.parse(
        fs.readFileSync(path.resolve(__dirname, `../../types/abi/${name}.json`), "utf8"),
      ) as { deployedBytecode: string };
      expect([name, createHash("sha256").update(artifact.deployedBytecode).digest("hex")]).toEqual([name, hash]);
    }
  });

  it("show the list getters reverting without data past the end", () => {
    const listEnd = answers.get(`${A.uninitializedAccount} ${lower(accountIface.encodeFunctionData("txKeyList", [0]))}`);
    expect(listEnd).toEqual({ error: { code: 3, message: "execution reverted", data: "0x" } });
  });

  describe.each(PATHS)("replayed %s", (_label, multicall, readVia) => {
    let provider: ReplayProvider;
    let reader: AccountReader;
    beforeEach(() => {
      provider = new ReplayProvider(multicall);
      reader = new AccountReader({ provider });
    });
    afterEach(() => {
      expect(provider.unexpected).toEqual([]);
    });

    describe.each([
      ["(a) an address without code", A.noCodeAccount],
      ["(b) an uninitialized account", A.uninitializedAccount],
      ["(c) an account with an address key and a passkey", A.initializedAccount],
    ])("%s", (_scenario, account) => {
      it("readKeyState", async () => {
        expect(await reader.readKeyState(account)).toEqual(expectedState(account, readVia));
      });

      it("getMasterKeyInfo", async () => {
        const { master, deployed } = expectedState(account, readVia);
        expect(await reader.getMasterKeyInfo(account)).toEqual({
          account: ethers.getAddress(account),
          deployed,
          threshold: master.threshold,
          keys: master.keys,
          truncated: false,
          readVia,
        });
      });

      it("readTxKeySlots", async () => {
        const { tx, deployed } = expectedState(account, readVia);
        expect(await reader.readTxKeySlots(account)).toEqual({
          deployed,
          keys: tx.keys.map((k) => ({
            index: k.index,
            logicContract: k.logicContract,
            keyId: Number(k.keyId),
            keyType: k.keyType,
            webauthn: k.webauthn,
          })),
          truncated: false,
          readVia,
        });
      });

      it("getPasskeys", async () => {
        const result = await reader.getPasskeys(account, {
          service: { rpId: passkey.rpId, origins: [passkey.origin] },
          credentialId: passkey.credentialId,
        });
        const registered = account === A.initializedAccount;
        expect(result.deployed).toBe(account !== A.noCodeAccount);
        expect(result.unreadable).toEqual([]);
        expect(result.myService.map((k) => k.credentialId)).toEqual(registered ? [passkey.credentialId] : []);
        expect(result.mine?.credentialId).toBe(registered ? passkey.credentialId : undefined);
      });
    });
  });
});

describe("the fake chain answers like the captured bytecode", () => {
  const OTHER = "0x" + "77".repeat(20);
  const keyData = {
    x: passkey.x,
    y: passkey.y,
    credentialId: passkey.credentialId,
    originHash: originHashOf(passkey.origin),
    rpIdHash: passkey.rpIdHash,
  };
  const webauthnKey: FakeKey = { logic: A.webAuthnLogic, keyId: 0, weight: 1, webauthn: keyData };
  const states: Record<string, FakeAccountState | undefined> = {
    [A.noCodeAccount]: undefined,
    [A.uninitializedAccount]: { master: { threshold: 0, keys: [] }, tx: { threshold: 0, keys: [] } },
    [A.initializedAccount]: {
      master: { threshold: 2, keys: [{ logic: A.addressKeyLogic, keyId: 0, weight: 1, signer: A.cosigner }, webauthnKey] },
      tx: { threshold: 1, keys: [webauthnKey] },
    },
  };
  // Another account with a key on every logic contract, so the fake has all three logic contracts.
  const otherState: FakeAccountState = {
    master: {
      threshold: 1,
      keys: [
        { logic: A.zkVerifier, keyId: 9, weight: 1, zk: { directory: OTHER, n: 1, k: 1, hAudList: 1, anchorWithHash: [1, 2] } },
        { logic: A.addressKeyLogic, keyId: 9, weight: 1, signer: OTHER },
        { logic: A.webAuthnLogic, keyId: 9, weight: 1, webauthn: keyData },
      ],
    },
    tx: { threshold: 0, keys: [] },
  };
  const other = strictResolver(OTHER, () => otherState);

  /** The account a captured call concerns: its target, or the account argument of a typed getter. */
  function accountOf(to: string, data: string): string {
    if (to in states) return to;
    if (data.length === 10 + 3 * 64) {
      return lower(ethers.AbiCoder.defaultAbiCoder().decode(["uint8", "address", "uint256"], "0x" + data.slice(10))[1] as string);
    }
    return A.noCodeAccount; // keyType(), aggregate3: answered the same for every account
  }

  /** The fake's answer as a raw JSON-RPC answer, through its per-call path (what ethers would throw). */
  async function fakeAnswer(to: string, data: string): Promise<{ result?: string; revertData?: unknown }> {
    const account = accountOf(to, data);
    const own = strictResolver(account, () => states[account]);
    const resolve = (address: string): Handler | undefined => own(address) ?? other(address);
    try {
      return { result: await fakeChain(resolve, { multicall: "absent" }).call({ to, data }) };
    } catch (err) {
      return { revertData: (err as { data?: unknown }).data };
    }
  }

  it.each(capture.calls.map((c) => [c.to, c.data, c.response] as const))("%s %s", async (to, data, response) => {
    const fake = await fakeAnswer(to, data);
    if (response.result !== undefined) {
      expect(fake).toEqual({ result: response.result });
    } else {
      expect(response.error?.code).toBe(3);
      expect(fake).toEqual({ revertData: response.error?.data });
    }
  });

  it("agrees on keyType() of every logic contract", () => {
    const keyTypeOf = (logic: string) =>
      Number(BigInt(answers.get(`${logic} ${lower(webAuthnIface.encodeFunctionData("keyType"))}`)!.result!));
    expect(keyTypeOf(A.addressKeyLogic)).toBe(PrimitiveAccountKeyTypes.keyAddress);
    expect(keyTypeOf(A.webAuthnLogic)).toBe(PrimitiveAccountKeyTypes.keyWebAuthn);
    expect(keyTypeOf(A.zkVerifier)).toBe(PrimitiveAccountKeyTypes.keyZkOAuthRS256);
  });
});
