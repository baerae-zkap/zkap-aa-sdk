/**
 * AccountReader tests — provider and call transports.
 *
 * No `ethers` module mock: the transport is injected and every response is
 * encoded with the real ethers coder (see lib/__tests__/helpers/fakeEthCall.ts).
 * The rpcUrl constructor path lives in AccountReader.rpcUrl.test.ts.
 */
import { ethers } from "ethers";
import { AccountReader } from "../AccountReader";
import { AaFetchError, AaFetchErrorCode, AaOperationError, AaOperationErrorCode } from "../../errors";
import { PrimitiveAccountKeyTypes } from "../../types/AccountKey";
import { MULTICALL3_ADDRESS } from "../transport";
import { AccountKeyZkOAuthRS256VerifierABI } from "../../types/abi";
import { originHashOf, rpIdHashOf } from "../../utils/webauthnKey";
import {
  decodeAggregate3Calls,
  fakeChain,
  fakeProvider,
  accountIface,
  strictChain,
  strictResolver,
  vectorKeyData,
  vectorKeyState,
  webAuthnIface,
  webauthnSlot,
  zkapAccount,
  X,
  Y,
} from "../../__tests__/helpers/fakeEthCall";
import type {
  FakeAccountState,
  FakeKey,
  Handler,
  SlotSpec,
  StrictChain,
} from "../../__tests__/helpers/fakeEthCall";
import { loadVectors } from "../../master/__tests__/fixtures/vectors";

const ACCOUNT = "0x" + "11".repeat(20);
const WEBAUTHN_LOGIC = "0x" + "aa".repeat(20);
const ADDRESS_LOGIC = "0x" + "bb".repeat(20);

const RP_ID = "zkap.app";
const ORIGIN_IOS = "https://zkap.app";
const ORIGIN_ANDROID = "android:apk-key-hash:abc123";
const OTHER_RP_ID = "pay.ifez.app";
const OTHER_ORIGIN = "https://pay.ifez.app";

const KEY_TX = 1;

function readerFor(handlers: Record<string, Handler>, opts: Parameters<typeof fakeChain>[1] = {}) {
  const chain = fakeChain(handlers, opts);
  return { chain, reader: new AccountReader({ call: chain.call }) };
}

async function rejectsWith<T>(promise: Promise<T>, ctor: new (...args: never[]) => unknown, code: string) {
  await expect(promise).rejects.toBeInstanceOf(ctor);
  await expect(promise).rejects.toMatchObject({ code });
}

describe("AccountReader", () => {
  describe("constructor", () => {
    it("accepts a provider", () => {
      const chain = fakeChain({});
      expect(() => new AccountReader({ provider: fakeProvider(chain) })).not.toThrow();
    });

    it("accepts a bare eth_call function", () => {
      const chain = fakeChain({});
      expect(() => new AccountReader({ call: chain.call })).not.toThrow();
    });

    it("rejects a config with no transport", () => {
      expect(() => new AccountReader({} as never)).toThrow(AaOperationError);
      expect(() => new AccountReader({} as never)).toThrow(
        expect.objectContaining({ code: AaOperationErrorCode.CONFIG_REQUIRED_FIELD_MISSING }),
      );
    });

    it("rejects more than one transport", () => {
      const chain = fakeChain({});
      expect(() => new AccountReader({ call: chain.call, provider: fakeProvider(chain) } as never)).toThrow(
        expect.objectContaining({ code: AaOperationErrorCode.INPUT_INVALID }),
      );
    });

    it.each([0, 1.5, -1])("rejects maxTxKeys=%p", (maxTxKeys) => {
      const chain = fakeChain({});
      expect(() => new AccountReader({ call: chain.call, maxTxKeys })).toThrow(
        expect.objectContaining({ code: AaOperationErrorCode.INPUT_OUT_OF_RANGE }),
      );
    });
  });

  describe("isDeployed / getBalance", () => {
    it("isDeployed reads eth_getCode through the provider", async () => {
      const chain = fakeChain(zkapAccount(ACCOUNT, []));
      const reader = new AccountReader({ provider: fakeProvider(chain) });
      expect(await reader.isDeployed(ACCOUNT)).toBe(true);
      expect(await reader.isDeployed("0x" + "99".repeat(20))).toBe(false);
    });

    it("getBalance returns the balance as a decimal string", async () => {
      const chain = fakeChain({});
      const reader = new AccountReader({ provider: fakeProvider(chain, BigInt("1000000000000000000")) });
      expect(await reader.getBalance(ACCOUNT)).toBe("1000000000000000000");
      const zero = new AccountReader({ provider: fakeProvider(chain, BigInt(0)) });
      expect(await zero.getBalance(ACCOUNT)).toBe("0");
    });

    it("both throw CONFIG_REQUIRED_FIELD_MISSING in call-only mode", async () => {
      const { reader } = readerFor({});
      await rejectsWith(reader.isDeployed(ACCOUNT), AaOperationError, AaOperationErrorCode.CONFIG_REQUIRED_FIELD_MISSING);
      await expect(reader.isDeployed(ACCOUNT)).rejects.toMatchObject({ operation: "is_deployed" });
      await rejectsWith(reader.getBalance(ACCOUNT), AaOperationError, AaOperationErrorCode.CONFIG_REQUIRED_FIELD_MISSING);
      await expect(reader.getBalance(ACCOUNT)).rejects.toMatchObject({ operation: "get_balance" });
    });
  });

  describe("readTxKeySlots / getTxKeyList", () => {
    it("reports an undeployed account from round 1 alone", async () => {
      const { chain, reader } = readerFor({}); // nothing deployed anywhere
      const slots = await reader.readTxKeySlots(ACCOUNT);
      expect(slots).toEqual({ deployed: false, keys: [], truncated: false, readVia: "multicall" });
      expect(chain.sent).toHaveLength(1);
      expect(await reader.getTxKeyList(ACCOUNT)).toEqual([]);
    });

    it("reports a deployed account with no keys in one round", async () => {
      const { chain, reader } = readerFor(zkapAccount(ACCOUNT, []));
      const slots = await reader.readTxKeySlots(ACCOUNT);
      expect(slots).toEqual({ deployed: true, keys: [], truncated: false, readVia: "multicall" });
      expect(chain.sent).toHaveLength(1);
    });

    it("reads one WebAuthn key in two round trips", async () => {
      const { chain, reader } = readerFor(
        zkapAccount(ACCOUNT, [
          webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 7, credentialId: "cred-a", rpId: RP_ID, origin: ORIGIN_IOS }),
        ]),
      );
      const keys = await reader.getTxKeyList(ACCOUNT);

      expect(chain.sent).toHaveLength(2);
      expect(keys).toEqual([
        {
          index: 0,
          logicContract: ethers.getAddress(WEBAUTHN_LOGIC),
          keyId: 7,
          keyType: "webauthn",
          webauthn: {
            x: X,
            y: Y,
            credentialId: "cred-a",
            allowedOriginHash: originHashOf(ORIGIN_IOS),
            allowedRpIdHash: rpIdHashOf(RP_ID),
          },
        },
      ]);
    });

    it("round 1 asks maxTxKeys+1 slots of the account, all allowFailure; round 2 asks the logic contract", async () => {
      const { chain, reader } = readerFor(
        zkapAccount(ACCOUNT, [
          webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 7, credentialId: "cred-a", rpId: RP_ID, origin: ORIGIN_IOS }),
        ]),
      );
      await reader.getTxKeyList(ACCOUNT);

      expect(chain.sent[0].to).toBe(MULTICALL3_ADDRESS);
      const round1 = decodeAggregate3Calls(chain.sent[0].data);
      expect(round1).toHaveLength(6);
      expect(round1.every((c) => c.allowFailure)).toBe(true);
      expect(round1.every((c) => c.target.toLowerCase() === ACCOUNT)).toBe(true);

      const round2 = decodeAggregate3Calls(chain.sent[1].data);
      expect(round2).toHaveLength(2);
      expect(round2.every((c) => c.target.toLowerCase() === WEBAUTHN_LOGIC)).toBe(true);
      const [purpose, account, keyId] = webAuthnIface.decodeFunctionData("getKeyData", round2[1].callData);
      expect(Number(purpose)).toBe(KEY_TX);
      expect(account.toLowerCase()).toBe(ACCOUNT);
      expect(Number(keyId)).toBe(7);
    });

    it("still takes two round trips for three keys", async () => {
      const { chain, reader } = readerFor(
        zkapAccount(ACCOUNT, [
          webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 0, credentialId: "a", rpId: RP_ID, origin: ORIGIN_IOS }),
          webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 1, credentialId: "b", rpId: RP_ID, origin: ORIGIN_ANDROID }),
          webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 2, credentialId: "c", rpId: OTHER_RP_ID, origin: OTHER_ORIGIN }),
        ]),
      );
      const keys = await reader.getTxKeyList(ACCOUNT);
      expect(chain.sent).toHaveLength(2);
      expect(keys.map((k) => k.webauthn?.credentialId)).toEqual(["a", "b", "c"]);
      expect(keys.map((k) => k.index)).toEqual([0, 1, 2]);
    });

    it.each([
      [PrimitiveAccountKeyTypes.keyAddress, "address"],
      [PrimitiveAccountKeyTypes.keySecp256k1, "secp256k1"],
      [PrimitiveAccountKeyTypes.keySecp256r1, "secp256r1"],
      [PrimitiveAccountKeyTypes.keyOAuthRS256, "oauthRs256"],
      [PrimitiveAccountKeyTypes.keyZkOAuthRS256, "zkOAuth"],
      [99, "unknown"],
    ])("maps keyType() %p to %p without webauthn data", async (primitive, expected) => {
      const { reader } = readerFor(zkapAccount(ACCOUNT, [{ logic: ADDRESS_LOGIC, keyId: 0, keyType: primitive }]));
      const [key] = await reader.getTxKeyList(ACCOUNT);
      expect(key.keyType).toBe(expected);
      expect(key.webauthn).toBeUndefined();
    });

    it("treats a reverting or undecodable keyType() as unknown", async () => {
      const reverting = readerFor(zkapAccount(ACCOUNT, [{ logic: ADDRESS_LOGIC, keyId: 0, keyType: "revert" }]));
      expect((await reverting.reader.getTxKeyList(ACCOUNT))[0].keyType).toBe("unknown");

      const garbage = readerFor(zkapAccount(ACCOUNT, [{ logic: ADDRESS_LOGIC, keyId: 0, keyType: "garbage" }]));
      expect((await garbage.reader.getTxKeyList(ACCOUNT))[0].keyType).toBe("unknown");
    });

    it("leaves webauthn undefined when getKeyData reverts or is undecodable", async () => {
      const webauthn = PrimitiveAccountKeyTypes.keyWebAuthn;
      const reverting = readerFor(
        zkapAccount(ACCOUNT, [{ logic: WEBAUTHN_LOGIC, keyId: 0, keyType: webauthn, keyData: "revert" }]),
      );
      const [k1] = await reverting.reader.getTxKeyList(ACCOUNT);
      expect(k1.keyType).toBe("webauthn");
      expect(k1.webauthn).toBeUndefined();

      const garbage = readerFor(
        zkapAccount(ACCOUNT, [{ logic: WEBAUTHN_LOGIC, keyId: 0, keyType: webauthn, keyData: "garbage" }]),
      );
      const [k2] = await garbage.reader.getTxKeyList(ACCOUNT);
      expect(k2.webauthn).toBeUndefined();
    });

    it("stops at a zero-address sentinel", async () => {
      const { reader } = readerFor(
        zkapAccount(
          ACCOUNT,
          [
            webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 0, credentialId: "a", rpId: RP_ID, origin: ORIGIN_IOS }),
            webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 1, credentialId: "b", rpId: RP_ID, origin: ORIGIN_IOS }),
          ],
          { zeroAt: 1 },
        ),
      );
      const slots = await reader.readTxKeySlots(ACCOUNT);
      expect(slots.keys).toHaveLength(1);
      expect(slots.truncated).toBe(false);
    });

    it("honours maxTxKeys for the round-1 window", async () => {
      const chain = fakeChain(
        zkapAccount(ACCOUNT, [
          webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 0, credentialId: "a", rpId: RP_ID, origin: ORIGIN_IOS }),
        ]),
      );
      const reader = new AccountReader({ call: chain.call, maxTxKeys: 2 });
      await reader.getTxKeyList(ACCOUNT);
      expect(decodeAggregate3Calls(chain.sent[0].data)).toHaveLength(3);
    });

    it("reads the default window of 5 and reports whether the list continues", async () => {
      const five: SlotSpec[] = Array.from({ length: 5 }, (_, i) =>
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: i, credentialId: `c${i}`, rpId: RP_ID, origin: ORIGIN_IOS }),
      );
      const exact = readerFor(zkapAccount(ACCOUNT, five));
      const exactSlots = await exact.reader.readTxKeySlots(ACCOUNT);
      expect(exactSlots.keys).toHaveLength(5);
      expect(exactSlots.truncated).toBe(false);

      const six = [
        ...five,
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 5, credentialId: "c5", rpId: RP_ID, origin: ORIGIN_IOS }),
      ];
      const over = readerFor(zkapAccount(ACCOUNT, six));
      const overSlots = await over.reader.readTxKeySlots(ACCOUNT);
      expect(overSlots.keys).toHaveLength(5);
      expect(overSlots.truncated).toBe(true);
      // The 6th slot is only probed, never detailed.
      expect(decodeAggregate3Calls(over.chain.sent[1].data)).toHaveLength(10);
    });

    it("throws RESPONSE_SHAPE when a slot answers undecodable data", async () => {
      const { reader } = readerFor(
        zkapAccount(
          ACCOUNT,
          [webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 0, credentialId: "a", rpId: RP_ID, origin: ORIGIN_IOS })],
          { garbageAt: 0 },
        ),
      );
      await rejectsWith(reader.getTxKeyList(ACCOUNT), AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
    });

    it("rejects a malformed address before any RPC", async () => {
      const { chain, reader } = readerFor({});
      await rejectsWith(reader.getTxKeyList("not-an-address"), AaOperationError, AaOperationErrorCode.INPUT_INVALID_ADDRESS);
      expect(chain.sent).toHaveLength(0);
    });

    it("throws TRANSPORT when the transport fails — never an empty list", async () => {
      const cause = new Error("ECONNRESET");
      const reader = new AccountReader({
        call: async () => {
          throw cause;
        },
      });
      const promise = reader.getTxKeyList(ACCOUNT);
      await rejectsWith(promise, AaFetchError, AaFetchErrorCode.TRANSPORT);
      await expect(promise).rejects.toMatchObject({ service: "rpc", method: "POST", url: undefined, cause });
    });
  });

  describe("getPasskeys", () => {
    const service = { rpId: RP_ID, origins: [ORIGIN_IOS, ORIGIN_ANDROID] };

    function mixedAccount(): Record<string, Handler> {
      return zkapAccount(ACCOUNT, [
        // 0: my service, iOS origin — and my device
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 0, credentialId: "mine", rpId: RP_ID, origin: ORIGIN_IOS }),
        // 1: my service, Android origin
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 1, credentialId: "android", rpId: RP_ID, origin: ORIGIN_ANDROID }),
        // 2: my rpId but an origin I did not list
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 2, credentialId: "web", rpId: RP_ID, origin: "https://beta.zkap.app" }),
        // 3: another service
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 3, credentialId: "foreign", rpId: OTHER_RP_ID, origin: OTHER_ORIGIN }),
        // 4: not a passkey at all
        { logic: ADDRESS_LOGIC, keyId: 0, keyType: PrimitiveAccountKeyTypes.keyAddress },
      ]);
    }

    it("returns an empty, deployed:false result for an undeployed account", async () => {
      const { reader } = readerFor({});
      const result = await reader.getPasskeys(ACCOUNT, { service, credentialId: "mine" });
      expect(result).toEqual({
        deployed: false,
        truncated: false,
        readVia: "multicall",
        total: 0,
        txKeys: [],
        passkeys: [],
        unreadable: [],
        myService: [],
        sameRpIdOtherOrigin: [],
        otherServices: [],
      });
    });

    it("classifies keys strictly by rpId AND origin, with per-platform origins", async () => {
      const { reader } = readerFor(mixedAccount());
      const result = await reader.getPasskeys(ACCOUNT, { service, credentialId: "mine", knownRpIds: [OTHER_RP_ID] });

      expect(result.deployed).toBe(true);
      expect(result.total).toBe(5);
      expect(result.passkeys).toHaveLength(4);
      expect(result.unreadable).toEqual([]);

      expect(result.myService.map((k) => k.credentialId)).toEqual(["mine", "android"]);
      expect(result.sameRpIdOtherOrigin.map((k) => k.credentialId)).toEqual(["web"]);
      expect(result.otherServices.map((k) => k.credentialId)).toEqual(["foreign"]);

      const mine = result.mine!;
      expect(mine.index).toBe(0);
      expect(mine.isMine).toBe(true);
      expect(mine.isMyService).toBe(true);
      expect(mine.rpIdMatches).toBe(true);
      expect(mine.originMatches).toBe(true);
      expect(mine.rpId).toBe(RP_ID);
      expect(mine.origin).toBe(ORIGIN_IOS);

      const android = result.myService[1];
      expect(android.origin).toBe(ORIGIN_ANDROID);
      expect(android.isMine).toBe(false);

      const web = result.sameRpIdOtherOrigin[0];
      expect(web.rpIdMatches).toBe(true);
      expect(web.originMatches).toBe(false);
      expect(web.isMyService).toBe(false);
      expect(web.rpId).toBe(RP_ID);
      expect(web.origin).toBeUndefined();

      const foreign = result.otherServices[0];
      expect(foreign.rpIdMatches).toBe(false);
      expect(foreign.rpId).toBe(OTHER_RP_ID); // labelled via knownRpIds
      expect(foreign.origin).toBeUndefined();

      expect(result.passkeys.filter((k) => k.isMine)).toHaveLength(1);
      expect(result.myService.length + result.sameRpIdOtherOrigin.length + result.otherServices.length).toBe(
        result.passkeys.length,
      );
    });

    it("accepts a single origin string and labels foreign origins via knownOrigins", async () => {
      const { reader } = readerFor(mixedAccount());
      const result = await reader.getPasskeys(ACCOUNT, {
        service: { rpId: RP_ID, origins: ORIGIN_IOS },
        knownOrigins: [OTHER_ORIGIN],
      });
      expect(result.myService.map((k) => k.credentialId)).toEqual(["mine"]);
      expect(result.sameRpIdOtherOrigin.map((k) => k.credentialId)).toEqual(["android", "web"]);
      expect(result.otherServices[0].origin).toBe(OTHER_ORIGIN);
      expect(result.otherServices[0].rpId).toBeUndefined();
      expect(result.mine).toBeUndefined();
    });

    it("without a service, leaves match flags undefined and the buckets empty", async () => {
      const { reader } = readerFor(mixedAccount());
      const result = await reader.getPasskeys(ACCOUNT);
      expect(result.passkeys).toHaveLength(4);
      for (const key of result.passkeys) {
        expect(key.rpIdMatches).toBeUndefined();
        expect(key.originMatches).toBeUndefined();
        expect(key.isMyService).toBe(false);
        expect(key.isMine).toBe(false);
      }
      expect(result.myService).toEqual([]);
      expect(result.sameRpIdOtherOrigin).toEqual([]);
      expect(result.otherServices).toEqual([]);
      expect(result.mine).toBeUndefined();
    });

    it("exposes every public-key format and the raw slots", async () => {
      const { reader } = readerFor(mixedAccount());
      const result = await reader.getPasskeys(ACCOUNT);
      const key = result.passkeys[0];
      expect(key.publicKey.x).toBe(X);
      expect(key.publicKey.y).toBe(Y);
      expect(key.publicKey.cose).toBe(`0xa5010203262001215820${X.slice(2)}225820${Y.slice(2)}`);
      expect(key.publicKey.jwk).toEqual({
        kty: "EC",
        crv: "P-256",
        x: Buffer.from(X.slice(2), "hex").toString("base64url"),
        y: Buffer.from(Y.slice(2), "hex").toString("base64url"),
      });
      expect(key.rpIdHash).toBe(rpIdHashOf(RP_ID));
      expect(key.originHash).toBe(originHashOf(ORIGIN_IOS));
      expect(result.txKeys).toEqual(await reader.getTxKeyList(ACCOUNT));
    });

    it("lists a WebAuthn slot whose key data could not be read under unreadable", async () => {
      const { reader } = readerFor(
        zkapAccount(ACCOUNT, [
          webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 0, credentialId: "ok", rpId: RP_ID, origin: ORIGIN_IOS }),
          { logic: WEBAUTHN_LOGIC, keyId: 1, keyType: PrimitiveAccountKeyTypes.keyWebAuthn, keyData: "revert" },
        ]),
      );
      const result = await reader.getPasskeys(ACCOUNT, { service });
      expect(result.passkeys.map((k) => k.credentialId)).toEqual(["ok"]);
      expect(result.unreadable).toEqual([1]);
      expect(result.total).toBe(2);
    });

    it("passes truncated and readVia through", async () => {
      const six: SlotSpec[] = Array.from({ length: 6 }, (_, i) =>
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: i, credentialId: `c${i}`, rpId: RP_ID, origin: ORIGIN_IOS }),
      );
      const { reader } = readerFor(zkapAccount(ACCOUNT, six), { multicall: "absent" });
      const result = await reader.getPasskeys(ACCOUNT);
      expect(result.truncated).toBe(true);
      expect(result.readVia).toBe("direct");
    });

    it.each([
      ["empty rpId", { service: { rpId: "", origins: ORIGIN_IOS } }],
      ["empty origins", { service: { rpId: RP_ID, origins: [] } }],
      ["empty origin entry", { service: { rpId: RP_ID, origins: [ORIGIN_IOS, ""] } }],
      ["empty credentialId", { credentialId: "" }],
      ["empty knownRpIds entry", { knownRpIds: [""] }],
      ["empty knownOrigins entry", { knownOrigins: [""] }],
    ])("rejects %s before any RPC", async (_label, opts) => {
      const { chain, reader } = readerFor(mixedAccount());
      await rejectsWith(reader.getPasskeys(ACCOUNT, opts), AaOperationError, AaOperationErrorCode.INPUT_INVALID);
      expect(chain.sent).toHaveLength(0);
    });
  });

  describe("findTxKeysByRpId", () => {
    const slot = (keyId: number, credentialId: string, rpId: string, origin = ORIGIN_IOS) =>
      webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId, credentialId, rpId, origin });

    it("returns matching webauthn keys by rpIdHash", async () => {
      const { reader } = readerFor(zkapAccount(ACCOUNT, [slot(0, "cred-1", RP_ID)]));
      const keys = await reader.findTxKeysByRpId(ACCOUNT, rpIdHashOf(RP_ID));
      expect(keys).toHaveLength(1);
      expect(keys[0].webauthn!.credentialId).toBe("cred-1");
    });

    it("returns an empty array when no rpIdHash matches", async () => {
      const { reader } = readerFor(zkapAccount(ACCOUNT, [slot(0, "cred-1", OTHER_RP_ID)]));
      expect(await reader.findTxKeysByRpId(ACCOUNT, rpIdHashOf(RP_ID))).toHaveLength(0);
    });

    it("returns multiple matching keys", async () => {
      const { reader } = readerFor(zkapAccount(ACCOUNT, [slot(0, "cred-1", RP_ID), slot(1, "cred-2", RP_ID)]));
      const keys = await reader.findTxKeysByRpId(ACCOUNT, rpIdHashOf(RP_ID));
      expect(keys.map((k) => k.webauthn!.credentialId)).toEqual(["cred-1", "cred-2"]);
    });

    it("filters out non-webauthn keys", async () => {
      const { reader } = readerFor(
        zkapAccount(ACCOUNT, [
          { logic: ADDRESS_LOGIC, keyId: 0, keyType: PrimitiveAccountKeyTypes.keyAddress },
          slot(1, "cred-webauthn", RP_ID),
        ]),
      );
      const keys = await reader.findTxKeysByRpId(ACCOUNT, rpIdHashOf(RP_ID));
      expect(keys).toHaveLength(1);
      expect(keys[0].webauthn!.credentialId).toBe("cred-webauthn");
    });

    it("matches rpIdHash case-insensitively", async () => {
      const { reader } = readerFor(zkapAccount(ACCOUNT, [slot(0, "cred-1", RP_ID)]));
      expect(await reader.findTxKeysByRpId(ACCOUNT, rpIdHashOf(RP_ID).toUpperCase().replace("0X", "0x"))).toHaveLength(1);
    });

    it("returns an empty array when no keys exist", async () => {
      const { reader } = readerFor(zkapAccount(ACCOUNT, []));
      expect(await reader.findTxKeysByRpId(ACCOUNT, rpIdHashOf(RP_ID))).toHaveLength(0);
    });
  });

  describe("readKeyState / getMasterKeyInfo (strict fake chain)", () => {
    const vectors = loadVectors();
    const { inputs, outputs } = vectors;
    const { contracts } = inputs;
    const INITIAL_ANCHOR_HASH = BigInt(4242); // test value: the fixture has no on-chain hash for this shape
    const big = (values: string[]) => values.map((v) => BigInt(v));

    const ZK_LOGIC = "0x" + "c1".repeat(20);
    const SIGNER_LOGIC = "0x" + "c2".repeat(20);
    const WA_LOGIC = "0x" + "c3".repeat(20);
    const DIRECTORY = "0x" + "d1".repeat(20);
    const SIGNER = "0x" + "e1".repeat(20);
    const KEY_TYPE_SELECTOR = webAuthnIface.getFunction("keyType")!.selector;

    // Round 1 through direct calls: 2 thresholds + (list + weight) × (window + 1) for both lists.
    const ROUND1_DIRECT = 2 + 2 * 6 + 2 * 6;

    const zkKey = (keyId: number, weight = 1): FakeKey => ({
      logic: ZK_LOGIC,
      keyId,
      weight,
      zk: { directory: DIRECTORY, n: 6, k: 3, hAudList: 77, anchorWithHash: [1, 2, 3] },
    });
    const signerKey = (keyId: number, weight = 1): FakeKey => ({ logic: SIGNER_LOGIC, keyId, weight, signer: SIGNER });
    const waKey = (keyId: number, weight = 1): FakeKey => ({
      logic: WA_LOGIC,
      keyId,
      weight,
      webauthn: vectorKeyData(inputs.passkey),
    });
    const state = (master: FakeKey[], tx: FakeKey[] = [], threshold = 1): FakeAccountState => ({
      master: { threshold, keys: master },
      tx: { threshold: 1, keys: tx },
    });
    const readerOn = (chain: StrictChain, opts: { maxTxKeys?: number; multicallAddress?: false } = {}) =>
      new AccountReader({ call: chain.call, ...opts });

    it("reads the initial master shape (zk + cosigner) through getMasterKeyInfo in two round trips", async () => {
      const chain = strictChain(ACCOUNT, vectorKeyState("initial", { initialAnchorHash: INITIAL_ANCHOR_HASH }));
      const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);

      expect(chain.sent).toHaveLength(2);
      expect(info).toEqual({
        account: ethers.getAddress(ACCOUNT),
        deployed: true,
        threshold: inputs.initialMaster.threshold,
        truncated: false,
        readVia: "multicall",
        keys: [
          {
            index: 0,
            logicContract: ethers.getAddress(contracts.zkVerifier1of1),
            keyId: BigInt(0),
            weight: 1,
            keyType: "zkOAuth",
            zk: {
              directory: ethers.getAddress(contracts.merkleTreeDirectory),
              n: BigInt(inputs.initialMaster.zk.n),
              k: BigInt(inputs.initialMaster.zk.k),
              hAudList: BigInt(inputs.initialMaster.zk.hAudList),
              anchorWithHash: [...big(inputs.initialMaster.zk.anchor), INITIAL_ANCHOR_HASH],
            },
          },
          {
            index: 1,
            logicContract: ethers.getAddress(contracts.addressKeyLogic),
            keyId: BigInt(0),
            weight: 1,
            keyType: "address",
            signer: ethers.getAddress(inputs.cosigner),
          },
        ],
      });
    });

    it("reads the operational shape (zk + cosigner + passkey) and the tx passkey, replaying the fixture's answers", async () => {
      const chain = strictChain(ACCOUNT, vectorKeyState("operational"));
      const keyState = await readerOn(chain).readKeyState(ACCOUNT);

      expect(chain.sent).toHaveLength(2);
      expect(keyState.account).toBe(ethers.getAddress(ACCOUNT));
      expect(keyState.deployed).toBe(true);
      expect(keyState.readVia).toBe("multicall");
      expect(keyState.master.threshold).toBe(inputs.operationalMaster.threshold);
      expect(keyState.master.truncated).toBe(false);
      expect(keyState.master.keys.map((k) => [k.keyType, k.weight])).toEqual([
        ["zkOAuth", 2],
        ["address", 1],
        ["webauthn", 1],
      ]);

      const [zk, cosigner, passkey] = keyState.master.keys;
      // The getData / getAnchor answers come back exactly as the fixture states them.
      expect(zk.zk).toEqual({
        directory: ethers.getAddress(contracts.merkleTreeDirectory),
        n: BigInt(inputs.operationalMaster.zk.n),
        k: BigInt(inputs.operationalMaster.zk.k),
        hAudList: BigInt(inputs.operationalMaster.zk.hAudList),
        anchorWithHash: big(outputs.onchainGetAnchor),
      });
      expect(zk.logicContract).toBe(ethers.getAddress(contracts.zkVerifier3of6));
      expect(zk.signer).toBeUndefined();
      expect(zk.webauthn).toBeUndefined();
      expect(cosigner.signer).toBe(ethers.getAddress(inputs.cosigner));
      expect(cosigner.zk).toBeUndefined();
      const expectedPasskey = {
        x: inputs.passkey.x,
        y: inputs.passkey.y,
        credentialId: inputs.passkey.credentialId,
        allowedOriginHash: originHashOf(inputs.passkey.origin),
        allowedRpIdHash: inputs.passkey.rpIdHash,
      };
      expect(passkey.webauthn).toEqual(expectedPasskey);

      expect(keyState.tx).toEqual({
        threshold: inputs.txKey.threshold,
        truncated: false,
        keys: [
          {
            index: 0,
            logicContract: ethers.getAddress(contracts.webAuthnLogic),
            keyId: BigInt(1),
            weight: 1,
            keyType: "webauthn",
            webauthn: expectedPasskey,
          },
        ],
      });

      const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);
      expect(info).toEqual({ account: ethers.getAddress(ACCOUNT), deployed: true, readVia: "multicall", ...keyState.master });
    });

    it("asks every key's logic for keyType() and all three typed getters under the right purpose", async () => {
      const chain = strictChain(ACCOUNT, state([zkKey(3)], [signerKey(4)]));
      await readerOn(chain).readKeyState(ACCOUNT);

      const round1 = decodeAggregate3Calls(chain.sent[0].data);
      const round2 = decodeAggregate3Calls(chain.sent[1].data);
      expect(round1).toHaveLength(ROUND1_DIRECT);
      expect(round1.every((c) => c.target.toLowerCase() === ACCOUNT && c.allowFailure)).toBe(true);

      // Round 2 repeats round 1's calls first, then asks for the details.
      expect(round2).toHaveLength(ROUND1_DIRECT + 2 * 5);
      expect(round2.slice(0, ROUND1_DIRECT)).toEqual(round1);
      const details = round2.slice(ROUND1_DIRECT);
      expect(details.every((c) => c.allowFailure)).toBe(true);
      const zkIface = new ethers.Interface(AccountKeyZkOAuthRS256VerifierABI);
      const [purposeMaster, account, keyIdMaster] = zkIface.decodeFunctionData("getData", details[1].callData);
      expect([Number(purposeMaster), account.toLowerCase(), keyIdMaster]).toEqual([0, ACCOUNT, BigInt(3)]);
      const [purposeTx, , keyIdTx] = zkIface.decodeFunctionData("getAnchor", details[5 + 2].callData);
      expect([Number(purposeTx), keyIdTx]).toEqual([1, BigInt(4)]);
      expect(details.slice(0, 5).every((c) => c.target.toLowerCase() === ZK_LOGIC)).toBe(true);
      expect(details.slice(5).every((c) => c.target.toLowerCase() === SIGNER_LOGIC)).toBe(true);
    });

    it("reports an undeployed account as deployed:false without throwing, in one round trip", async () => {
      const chain = strictChain(ACCOUNT, undefined);
      const reader = readerOn(chain);
      expect(await reader.getMasterKeyInfo(ACCOUNT)).toEqual({
        account: ethers.getAddress(ACCOUNT),
        deployed: false,
        threshold: 0,
        keys: [],
        truncated: false,
        readVia: "multicall",
      });
      expect(chain.sent).toHaveLength(1);
      expect(await reader.readKeyState(ACCOUNT)).toEqual({
        account: ethers.getAddress(ACCOUNT),
        deployed: false,
        master: { threshold: 0, keys: [], truncated: false },
        tx: { threshold: 0, keys: [], truncated: false },
        readVia: "multicall",
      });
    });

    it("reads a deployed account with no keys in one round trip", async () => {
      const chain = strictChain(ACCOUNT, state([], [], 0));
      const keyState = await readerOn(chain).readKeyState(ACCOUNT);
      expect(keyState).toEqual({
        account: ethers.getAddress(ACCOUNT),
        deployed: true,
        master: { threshold: 0, keys: [], truncated: false },
        tx: { threshold: 1, keys: [], truncated: false },
        readVia: "multicall",
      });
      expect(chain.sent).toHaveLength(1);
    });

    it.each([
      [0, 0, false],
      [1, 1, false],
      [4, 4, false],
      [5, 5, false],
      [6, 5, true],
      [7, 5, true],
    ])("counts %p master keys as %p (truncated=%p)", async (onChain, read, truncated) => {
      const keys = Array.from({ length: onChain }, (_, i) => signerKey(i, i + 1));
      const chain = strictChain(ACCOUNT, state(keys, [waKey(0)]));
      const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);
      expect(info.keys.map((k) => k.index)).toEqual(Array.from({ length: read }, (_, i) => i));
      expect(info.keys.map((k) => k.weight)).toEqual(Array.from({ length: read }, (_, i) => i + 1));
      expect(info.truncated).toBe(truncated);
    });

    it("bounds the tx list by maxTxKeys and reports truncation per list", async () => {
      const chain = strictChain(ACCOUNT, state([zkKey(0)], [waKey(0), waKey(1), waKey(2)]));
      const keyState = await readerOn(chain, { maxTxKeys: 2 }).readKeyState(ACCOUNT);
      expect(keyState.tx.keys.map((k) => k.keyId)).toEqual([BigInt(0), BigInt(1)]);
      expect(keyState.tx.truncated).toBe(true);
      expect(keyState.master.truncated).toBe(false);
    });

    it.each([
      ["keyType() reverts", { ...waKey(0), keyType: "revert" as const }],
      ["keyType() is undecodable", { ...waKey(0), keyType: "garbage" as const }],
    ] as [string, FakeKey][])("throws RESPONSE_SHAPE, never \"unknown\", when %s", async (_label, key) => {
      const master = strictChain(ACCOUNT, state([key]));
      const promise = readerOn(master).getMasterKeyInfo(ACCOUNT);
      await rejectsWith(promise, AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
      await expect(promise).rejects.toThrow("keyType() for master key 0 returned no usable value");
      const tx = strictChain(ACCOUNT, state([], [key]));
      await rejectsWith(readerOn(tx).readKeyState(ACCOUNT), AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
    });

    it.each([
      ["keyType() is unknown", "unknown", 99],
      ["keyType() is another scheme", "secp256k1", PrimitiveAccountKeyTypes.keySecp256k1],
    ])("%s: the key reads as %p with no data", async (_label, expected, keyType) => {
      const chain = strictChain(ACCOUNT, state([{ ...waKey(0), keyType }]));
      const [key] = (await readerOn(chain).getMasterKeyInfo(ACCOUNT)).keys;
      expect(key.keyType).toBe(expected);
      expect(key.zk).toBeUndefined();
      expect(key.signer).toBeUndefined();
      expect(key.webauthn).toBeUndefined();
    });

    it.each([
      ["getData reverts", { ...zkKey(0), fail: { getData: "revert" } }],
      ["getData is undecodable", { ...zkKey(0), fail: { getData: "garbage" } }],
      ["getAnchor reverts", { ...zkKey(0), fail: { getAnchor: "revert" } }],
      ["getAnchor is undecodable", { ...zkKey(0), fail: { getAnchor: "garbage" } }],
      ["getSigner reverts", { ...signerKey(0), fail: { getSigner: "revert" } }],
      ["getSigner is undecodable", { ...signerKey(0), fail: { getSigner: "garbage" } }],
      ["getKeyData reverts", { ...waKey(0), fail: { getKeyData: "revert" } }],
      ["getKeyData is undecodable", { ...waKey(0), fail: { getKeyData: "garbage" } }],
    ] as [string, FakeKey][])("throws RESPONSE_SHAPE when the type's own getter fails: %s", async (_label, key) => {
      const master = strictChain(ACCOUNT, state([key]));
      await rejectsWith(readerOn(master).getMasterKeyInfo(ACCOUNT), AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
      const tx = strictChain(ACCOUNT, state([], [key]));
      await rejectsWith(readerOn(tx).readKeyState(ACCOUNT), AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
    });

    it("names the failing getter and key in the RESPONSE_SHAPE error", async () => {
      const chain = strictChain(ACCOUNT, state([zkKey(0), { ...signerKey(0), fail: { getSigner: "revert" } }]));
      await expect(readerOn(chain).readKeyState(ACCOUNT)).rejects.toMatchObject({
        code: AaFetchErrorCode.RESPONSE_SHAPE,
        operation: "read_key_state",
        message: "AccountReader: getSigner for master key 1 returned no usable value",
      });
    });

    it.each([
      ["a counted key's weight reverts", "masterKeyWeightList", { revert: true as const }],
      ["the threshold is undecodable", "masterKeyThreshold", "0x12"],
      ["a key entry is empty", "masterKeyList", "0x"],
    ])("throws RESPONSE_SHAPE when %s", async (_label, fn, answer) => {
      const keyState = state([zkKey(0)]);
      const resolve = strictResolver(ACCOUNT, () => keyState);
      const selector = accountIface.getFunction(fn)!.selector;
      const chain = fakeChain((address) => {
        const strict = resolve(address);
        if (address.toLowerCase() !== ACCOUNT || !strict) return strict;
        return (data) => (data.startsWith(selector) ? answer : strict(data));
      });
      await rejectsWith(
        new AccountReader({ call: chain.call }).readKeyState(ACCOUNT),
        AaFetchError,
        AaFetchErrorCode.RESPONSE_SHAPE,
      );
    });

    it("rejects a malformed address before any RPC", async () => {
      const chain = strictChain(ACCOUNT, state([zkKey(0)]));
      await rejectsWith(
        readerOn(chain).readKeyState("not-an-address"),
        AaOperationError,
        AaOperationErrorCode.INPUT_INVALID_ADDRESS,
      );
      expect(chain.sent).toHaveLength(0);
    });

    it("reports the account it read, checksummed, in every result", async () => {
      const lower = "0x" + "ab".repeat(20);
      const checksummed = ethers.getAddress(lower);
      expect(checksummed).not.toBe(lower);

      const reader = readerOn(strictChain(lower, state([zkKey(0)])));
      expect((await reader.readKeyState(lower)).account).toBe(checksummed);
      expect((await reader.getMasterKeyInfo(lower)).account).toBe(checksummed);
      expect((await reader.classifyMasterKey(lower, {} as never)).state.account).toBe(checksummed);

      const undeployed = readerOn(strictChain(lower, undefined));
      expect((await undeployed.readKeyState(lower)).account).toBe(checksummed);
    });

    describe("transport failures are errors, never empty data", () => {
      it("TRANSPORT when the node cannot be reached", async () => {
        const reader = new AccountReader({
          call: async () => {
            throw new Error("ECONNRESET");
          },
        });
        await rejectsWith(reader.getMasterKeyInfo(ACCOUNT), AaFetchError, AaFetchErrorCode.TRANSPORT);
      });

      it("TRANSPORT when round 2 fails after round 1 succeeded", async () => {
        const chain = strictChain(ACCOUNT, vectorKeyState("operational"), {
          beforeCall: (index) => {
            if (index === 1) throw new Error("socket hang up");
          },
        });
        await rejectsWith(readerOn(chain).getMasterKeyInfo(ACCOUNT), AaFetchError, AaFetchErrorCode.TRANSPORT);
      });

      it("TRANSPORT on the direct path when a logic call fails without a revert", async () => {
        const chain = strictChain(ACCOUNT, state([zkKey(0)]), {
          multicall: "absent",
          beforeCall: (_index, request) => {
            if (request.to.toLowerCase() === ZK_LOGIC) throw new Error("ETIMEDOUT");
          },
        });
        await rejectsWith(readerOn(chain).readKeyState(ACCOUNT), AaFetchError, AaFetchErrorCode.TRANSPORT);
      });
    });

    describe("direct path (no Multicall3)", () => {
      it.each([
        ["Multicall3 absent", { multicall: "absent" as const }, {}, 1],
        ["multicallAddress:false", {}, { multicallAddress: false as const }, 0],
      ])("%s: same result, round 1 re-read after round 2", async (_label, chainOpts, readerOpts, probes) => {
        const expected = await readerOn(strictChain(ACCOUNT, vectorKeyState("operational"))).readKeyState(ACCOUNT);
        const chain = strictChain(ACCOUNT, vectorKeyState("operational"), chainOpts);
        const keyState = await readerOn(chain, readerOpts).readKeyState(ACCOUNT);

        expect(keyState).toEqual({ ...expected, readVia: "direct" });
        expect(chain.multicallRequests()).toBe(probes);
        expect(chain.sent).toHaveLength(probes + ROUND1_DIRECT + 4 * 5 + ROUND1_DIRECT);
      });

      it("undeployed account: deployed:false from round 1 alone", async () => {
        const chain = strictChain(ACCOUNT, undefined, { multicall: "absent" });
        const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);
        expect(info).toEqual({
          account: ethers.getAddress(ACCOUNT),
          deployed: false,
          threshold: 0,
          keys: [],
          truncated: false,
          readVia: "direct",
        });
        expect(chain.sent).toHaveLength(1 + ROUND1_DIRECT);
      });

      it("re-reads everything once when round 1 changed during round 2", async () => {
        let changed = false;
        const chain: StrictChain = strictChain(ACCOUNT, state([zkKey(0)]), {
          multicall: "absent",
          beforeCall: (_index, request) => {
            if (!changed && request.to.toLowerCase() === ZK_LOGIC && request.data.startsWith(KEY_TYPE_SELECTOR)) {
              changed = true;
              chain.state = state([zkKey(0), signerKey(1)], [], 2);
            }
          },
        });
        const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);
        expect(info.threshold).toBe(2);
        expect(info.keys.map((k) => k.keyType)).toEqual(["zkOAuth", "address"]);
        // attempt 1: probe + round 1 + round 2 (1 key) + re-read; attempt 2: round 1 + round 2 (2 keys) + re-read
        expect(chain.sent).toHaveLength(1 + ROUND1_DIRECT + 5 + ROUND1_DIRECT + ROUND1_DIRECT + 10 + ROUND1_DIRECT);
      });

      it("throws RESPONSE_SHAPE when the re-read differs twice in a row", async () => {
        const chain: StrictChain = strictChain(ACCOUNT, state([zkKey(0)]), {
          multicall: "absent",
          beforeCall: (_index, request) => {
            if (request.to.toLowerCase() === ZK_LOGIC && request.data.startsWith(KEY_TYPE_SELECTOR)) {
              chain.state!.master.threshold += 1;
            }
          },
        });
        const promise = readerOn(chain).getMasterKeyInfo(ACCOUNT);
        await rejectsWith(promise, AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
        await expect(promise).rejects.toThrow("the key lists differ on re-read");
      });
    });

    describe("consistency through Multicall3 (no block numbers involved)", () => {
      it("retries once when the state changed between the two rounds, and returns the fresh state", async () => {
        const chain: StrictChain = strictChain(ACCOUNT, state([zkKey(0), signerKey(0)], [], 2), {
          beforeCall: (index) => {
            // The cosigner key is replaced after round 1; nothing else marks the change.
            if (index === 1) chain.state = state([zkKey(0), signerKey(9)], [], 2);
          },
        });
        const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);
        expect(chain.sent).toHaveLength(4);
        expect(info.keys[1].keyId).toBe(BigInt(9));
        expect(info.keys[1].signer).toBe(ethers.getAddress(SIGNER));
      });

      it("catches a change that only moves a weight or the threshold", async () => {
        const chain: StrictChain = strictChain(ACCOUNT, state([zkKey(0, 1)], [], 1), {
          beforeCall: (index) => {
            if (index === 1) chain.state = state([zkKey(0, 2)], [], 2);
          },
        });
        const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);
        expect(chain.sent).toHaveLength(4);
        expect([info.threshold, info.keys[0].weight]).toEqual([2, 2]);
      });

      it("throws RESPONSE_SHAPE when the state changes again on the retry", async () => {
        const chain: StrictChain = strictChain(ACCOUNT, state([zkKey(0)]), {
          beforeCall: (index) => {
            if (index === 1 || index === 3) chain.state!.master.threshold += 1;
          },
        });
        const promise = readerOn(chain).readKeyState(ACCOUNT);
        await rejectsWith(promise, AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
        await expect(promise).rejects.toThrow(
          "changed between reads twice in a row (the key lists differ between rounds)",
        );
        expect(chain.sent).toHaveLength(4);
      });

      it("does not mistake a key replaced between rounds for missing data", async () => {
        // Round 2 asks for keyId 0, which no longer exists after the change; the
        // replayed round-1 calls must catch it and re-read instead of failing on the revert.
        const chain: StrictChain = strictChain(ACCOUNT, state([signerKey(0)]), {
          beforeCall: (index) => {
            if (index === 1) chain.state = state([signerKey(5)]);
          },
        });
        const info = await readerOn(chain).getMasterKeyInfo(ACCOUNT);
        expect(info.keys.map((k) => k.keyId)).toEqual([BigInt(5)]);
      });

      it("retries through the direct path when Multicall3 stops answering after round 1", async () => {
        // Call-only transport: no eth_getCode to tell a vanished Multicall3 from a lying node.
        let multicall = true;
        const inner = strictChain(ACCOUNT, state([zkKey(0)]));
        const reader = new AccountReader({
          call: async (req) => {
            if (req.to.toLowerCase() === MULTICALL3_ADDRESS.toLowerCase() && !multicall) return "0x";
            const out = await inner.call(req);
            multicall = false;
            return out;
          },
        });
        const keyState = await reader.readKeyState(ACCOUNT);
        expect(keyState.readVia).toBe("direct");
        expect(keyState.master.keys.map((k) => k.keyType)).toEqual(["zkOAuth"]);
      });
    });
  });

  describe("without Multicall3", () => {
    const oneKey = () =>
      zkapAccount(ACCOUNT, [
        webauthnSlot({ logic: WEBAUTHN_LOGIC, keyId: 7, credentialId: "cred-a", rpId: RP_ID, origin: ORIGIN_IOS }),
      ]);

    it("provider mode: confirms absence with eth_getCode, then reads per call with the same result", async () => {
      const present = fakeChain(oneKey());
      const expected = await new AccountReader({ provider: fakeProvider(present) }).readTxKeySlots(ACCOUNT);

      const absent = fakeChain(oneKey(), { multicall: "absent" });
      const reader = new AccountReader({ provider: fakeProvider(absent) });
      const slots = await reader.readTxKeySlots(ACCOUNT);

      expect(slots).toEqual({ ...expected, readVia: "direct" });
      expect(expected.readVia).toBe("multicall");
      expect(absent.multicallRequests()).toBe(1);
      // 6 slot probes + 2 detail calls, all direct
      expect(absent.sent).toHaveLength(1 + 6 + 2);

      // Absence is remembered: no further aggregate3 attempts.
      await reader.readTxKeySlots(ACCOUNT);
      expect(absent.multicallRequests()).toBe(1);
    });

    it("call-only mode: falls back without eth_getCode", async () => {
      const absent = fakeChain(oneKey(), { multicall: "absent" });
      const reader = new AccountReader({ call: absent.call });
      const slots = await reader.readTxKeySlots(ACCOUNT);
      expect(slots.readVia).toBe("direct");
      expect(slots.keys[0].webauthn?.credentialId).toBe("cred-a");
    });

    it("provider mode: a transport that answers 0x for a present Multicall3 is rejected as RESPONSE_SHAPE", async () => {
      const lying = fakeChain(oneKey(), { multicall: "lying" });
      const reader = new AccountReader({ provider: fakeProvider(lying) });
      await rejectsWith(reader.readTxKeySlots(ACCOUNT), AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
    });

    it("multicallAddress:false never touches Multicall3", async () => {
      const chain = fakeChain(oneKey());
      const reader = new AccountReader({ call: chain.call, multicallAddress: false });
      const slots = await reader.readTxKeySlots(ACCOUNT);
      expect(slots.readVia).toBe("direct");
      expect(chain.multicallRequests()).toBe(0);
    });

    it("a custom multicallAddress is used as the aggregate3 target", async () => {
      const custom = "0x" + "77".repeat(20);
      const chain = fakeChain(oneKey(), { multicallAddress: custom });
      const reader = new AccountReader({ call: chain.call, multicallAddress: custom });
      const slots = await reader.readTxKeySlots(ACCOUNT);
      expect(slots.readVia).toBe("multicall");
      expect(chain.sent[0].to).toBe(custom);
    });

    it("garbage from aggregate3 is RESPONSE_SHAPE", async () => {
      const chain = fakeChain(oneKey(), { multicall: "garbage" });
      const reader = new AccountReader({ call: chain.call });
      await rejectsWith(reader.readTxKeySlots(ACCOUNT), AaFetchError, AaFetchErrorCode.RESPONSE_SHAPE);
    });
  });
});
