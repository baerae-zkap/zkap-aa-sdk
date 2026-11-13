/**
 * classifyMasterKey / reconstructOperationalMasterKey — pure functions over an
 * `OnchainKeyState`.
 *
 * A wrong reconstruction (an anchor element dropped, reordered or replaced, a
 * value taken from the wrong place) produces a master key no zk proof can ever
 * satisfy, and the wallet's master key is locked for good. Every caller goes
 * through the same function, so comparing callers with each other cannot catch
 * it. These tests are the guard:
 *
 * - known answers from `fixtures/master-key-cosign-vectors.json`;
 * - a seeded round-trip property (build → simulated on-chain state → rebuild);
 * - a second, independent encoder written here with `AbiCoder` alone;
 * - where every output value comes from;
 * - one precondition broken at a time, each of which must refuse to rebuild.
 */
import { ethers } from "ethers";
import { AaFetchError, AaOperationError } from "../../errors";
import { buildOperationalMasterKey, type PasskeyKeyInput, type UintInput } from "../encoding";
import { decodeKeySet } from "../parsing";
import {
  classifyMasterKey,
  reconstructOperationalMasterKey,
  type MasterKeyClassification,
  type MasterKeyExpectation,
  type MasterKeyKind,
  type ReconstructOperationalMasterKeyParams,
} from "../onchain";
import * as pkg from "../../index";
import type { KeyType, OnchainKeyEntry, OnchainKeySet, OnchainKeyState, WebAuthnKeyData } from "../../reader/types";
import { loadVectors, type VectorPasskey } from "./fixtures/vectors";

const { inputs, outputs } = loadVectors();
const coder = ethers.AbiCoder.defaultAbiCoder();

/** BN254 scalar field size (the order of the curve's prime subgroup). */
const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const UINT256_MAX = (1n << 256n) - 1n;

// ---------------------------------------------------------------------------
// Independent encoding — AbiCoder only, no builder or parser of this package
// ---------------------------------------------------------------------------

interface PlainPasskey {
  x: string;
  y: string;
  credentialId: string;
  /** 32-byte hex. */
  rpIdHash: string;
  origin: string;
}

interface PlainOperationalMaster {
  zkVerifier3of6: string;
  addressKeyLogic: string;
  webAuthnLogic: string;
  merkleTreeDirectory: string;
  hAudList: bigint;
  anchor: bigint[];
  cosigner: string;
  passkey: PlainPasskey;
}

const lower = (address: string) => address.toLowerCase();

function independentPasskeyInitData(p: PlainPasskey): string {
  const key = coder.encode(["tuple(bytes32 x, bytes32 y, string credentialId)"], [[p.x.toLowerCase(), p.y.toLowerCase(), p.credentialId]]);
  return coder.encode(
    ["bytes", "bytes32", "bytes", "bool"],
    [key, p.rpIdHash.toLowerCase(), ethers.toUtf8Bytes(p.origin), false],
  );
}

/** The operational master key layout, written out by hand. */
function independentOperationalMaster(v: PlainOperationalMaster): string {
  const zkKeyData = coder.encode(["uint256", "uint256", "uint256", "uint256[]"], [6n, 3n, v.hAudList, v.anchor]);
  const zkInit = coder.encode(["bytes", "address"], [zkKeyData, lower(v.merkleTreeDirectory)]);
  const cosignerInit = coder.encode(["address"], [lower(v.cosigner)]);
  return coder.encode(
    ["uint8", "address[]", "bytes[]", "uint8[]"],
    [
      3,
      [lower(v.zkVerifier3of6), lower(v.addressKeyLogic), lower(v.webAuthnLogic)],
      [zkInit, cosignerInit, independentPasskeyInitData(v.passkey)],
      [2, 1, 1],
    ],
  );
}

interface DecodedOperational {
  threshold: number;
  logicList: string[];
  weightList: number[];
  directory: string;
  n: bigint;
  k: bigint;
  hAudList: bigint;
  anchor: bigint[];
  signer: string;
  passkeyInitData: string;
}

/** Decode an operational blob with AbiCoder alone (no parser of this package). */
function decodeOperational(blob: string): DecodedOperational {
  const [threshold, logicList, initDataList, weightList] = coder.decode(
    ["uint8", "address[]", "bytes[]", "uint8[]"],
    blob,
  );
  const [zkKeyData, directory] = coder.decode(["bytes", "address"], initDataList[0]);
  const [n, k, hAudList, anchor] = coder.decode(["uint256", "uint256", "uint256", "uint256[]"], zkKeyData);
  const [signer] = coder.decode(["address"], initDataList[1]);
  return {
    threshold: Number(threshold),
    logicList: [...logicList] as string[],
    weightList: [...weightList].map(Number),
    directory: directory as string,
    n: n as bigint,
    k: k as bigint,
    hAudList: hAudList as bigint,
    anchor: [...anchor] as bigint[],
    signer: signer as string,
    passkeyInitData: initDataList[2] as string,
  };
}

const sha256RpId = (rpId: string) => ethers.sha256(ethers.toUtf8Bytes(rpId));
const keccakOrigin = (origin: string) => ethers.keccak256(ethers.toUtf8Bytes(origin));

// ---------------------------------------------------------------------------
// Fixture-based states
// ---------------------------------------------------------------------------

const VECTOR_CONTRACTS = {
  zkVerifier1of1: inputs.contracts.zkVerifier1of1,
  zkVerifier3of6: inputs.contracts.zkVerifier3of6,
  addressKeyLogic: inputs.contracts.addressKeyLogic,
  webAuthnLogic: inputs.contracts.webAuthnLogic,
  merkleTreeDirectory: inputs.contracts.merkleTreeDirectory,
};
const EXPECTED: MasterKeyExpectation = { contracts: VECTOR_CONTRACTS, cosigner: inputs.cosigner };

const xyPasskey = (p: VectorPasskey, rp: "rpId" | "rpIdHash" = "rpId"): PasskeyKeyInput =>
  rp === "rpId"
    ? { x: p.x, y: p.y, credentialId: p.credentialId, origin: p.origin, rpId: p.rpId }
    : { x: p.x, y: p.y, credentialId: p.credentialId, origin: p.origin, rpIdHash: p.rpIdHash };

const params = (passkey: PasskeyKeyInput, expected: MasterKeyExpectation = EXPECTED): ReconstructOperationalMasterKeyParams => ({
  ...expected,
  passkey,
});

const webauthnData = (p: { x: string; y: string; credentialId: string; origin: string; rpIdHash: string }): WebAuthnKeyData => ({
  x: p.x,
  y: p.y,
  credentialId: p.credentialId,
  allowedOriginHash: keccakOrigin(p.origin),
  allowedRpIdHash: p.rpIdHash,
});

function entry(index: number, logicContract: string, keyType: KeyType, weight: number, data: Partial<OnchainKeyEntry> = {}): OnchainKeyEntry {
  return { index, logicContract, keyId: BigInt(index), weight, keyType, ...data };
}

const VECTOR_TX: OnchainKeySet = {
  threshold: 1,
  truncated: false,
  keys: [entry(0, ethers.getAddress(inputs.contracts.webAuthnLogic), "webauthn", 1, { keyId: 1n, webauthn: webauthnData(inputs.passkey) })],
};

/** The fixture wallet after `updateKeys(operationalMaster, txKey)`, as `readKeyState` reports it. */
function vectorOperationalState(): OnchainKeyState {
  const zk = inputs.operationalMaster.zk;
  return {
    account: "0x" + "11".repeat(20),
    deployed: true,
    readVia: "multicall",
    master: {
      threshold: 3,
      truncated: false,
      keys: [
        entry(0, ethers.getAddress(inputs.contracts.zkVerifier3of6), "zkOAuth", 2, {
          zk: {
            directory: ethers.getAddress(inputs.contracts.merkleTreeDirectory),
            n: BigInt(zk.n),
            k: BigInt(zk.k),
            hAudList: BigInt(zk.hAudList),
            anchorWithHash: outputs.onchainGetAnchor.map((a) => BigInt(a)),
          },
        }),
        entry(1, ethers.getAddress(inputs.contracts.addressKeyLogic), "address", 1, { signer: ethers.getAddress(inputs.cosigner) }),
        entry(2, ethers.getAddress(inputs.contracts.webAuthnLogic), "webauthn", 1, { webauthn: webauthnData(inputs.passkey) }),
      ],
    },
    tx: cloneSet(VECTOR_TX),
  };
}

/** Some value standing in for the on-chain hash `getAnchor` appends (the fixture has none for this shape). */
const INITIAL_ANCHOR_HASH = 4242424242424242424242424242n;

/** The fixture wallet right after deployment: initial master, no tx key. */
function vectorInitialState(): OnchainKeyState {
  const zk = inputs.initialMaster.zk;
  return {
    account: "0x" + "11".repeat(20),
    deployed: true,
    readVia: "multicall",
    master: {
      threshold: 2,
      truncated: false,
      keys: [
        entry(0, ethers.getAddress(inputs.contracts.zkVerifier1of1), "zkOAuth", 1, {
          zk: {
            directory: ethers.getAddress(inputs.contracts.merkleTreeDirectory),
            n: BigInt(zk.n),
            k: BigInt(zk.k),
            hAudList: BigInt(zk.hAudList),
            anchorWithHash: [...zk.anchor.map((a) => BigInt(a)), INITIAL_ANCHOR_HASH],
          },
        }),
        entry(1, ethers.getAddress(inputs.contracts.addressKeyLogic), "address", 1, { signer: ethers.getAddress(inputs.cosigner) }),
      ],
    },
    tx: { threshold: 0, truncated: false, keys: [] },
  };
}

const UNDEPLOYED_STATE: OnchainKeyState = {
  account: "0x" + "11".repeat(20),
  deployed: false,
  readVia: "multicall",
  master: { threshold: 0, keys: [], truncated: false },
  tx: { threshold: 0, keys: [], truncated: false },
};

function cloneEntry(e: OnchainKeyEntry): OnchainKeyEntry {
  const copy: OnchainKeyEntry = { ...e };
  if (e.zk) copy.zk = { ...e.zk, anchorWithHash: [...e.zk.anchorWithHash] };
  if (e.webauthn) copy.webauthn = { ...e.webauthn };
  return copy;
}

function cloneSet(s: OnchainKeySet): OnchainKeySet {
  return { ...s, keys: s.keys.map(cloneEntry) };
}

function cloneState(s: OnchainKeyState): OnchainKeyState {
  return { ...s, master: cloneSet(s.master), tx: cloneSet(s.tx) };
}

function withState(base: () => OnchainKeyState, mutate: (s: OnchainKeyState) => void): OnchainKeyState {
  const s = base();
  mutate(s);
  return s;
}

const zkOf = (s: OnchainKeyState) => {
  const zk = s.master.keys[0].zk;
  if (!zk) throw new Error("test setup: master[0] has no zk data");
  return zk;
};

/** Reconstruction must throw an AaOperationError (never a fetch error) and return nothing. */
function expectRefused(state: OnchainKeyState, p: ReconstructOperationalMasterKeyParams): void {
  let returned: unknown;
  let thrown: unknown;
  try {
    returned = reconstructOperationalMasterKey(state, p);
  } catch (err) {
    thrown = err;
  }
  expect(returned).toBeUndefined();
  expect(thrown).toBeInstanceOf(AaOperationError);
  expect(thrown).not.toBeInstanceOf(AaFetchError);
}

function expectReasons(c: MasterKeyClassification): void {
  if (c.kind === "other") {
    expect(c.reasons.length).toBeGreaterThan(0);
    for (const reason of c.reasons) {
      expect(typeof reason).toBe("string");
      expect(reason.length).toBeGreaterThan(0);
    }
  } else {
    expect(c.reasons).toEqual([]);
  }
}

const RANDOM_ADDRESS = "0x" + "5e".repeat(20);

// ---------------------------------------------------------------------------
// Seeded pseudo-random generator (mulberry32) — deterministic, no Math.random
// ---------------------------------------------------------------------------

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  };
}

class Rng {
  private readonly next: () => number;
  constructor(seed: number) {
    this.next = mulberry32(seed);
  }
  int(maxExclusive: number): number {
    return this.next() % maxExclusive;
  }
  pick<T>(values: readonly T[]): T {
    return values[this.int(values.length)];
  }
  bytes(length: number): string {
    let hex = "";
    for (let i = 0; i < length; i++) hex += this.int(256).toString(16).padStart(2, "0");
    return "0x" + hex;
  }
  uint(bytes: number): bigint {
    return bytes === 0 ? 0n : BigInt(this.bytes(bytes));
  }
  /** A field element in [1, FIELD_SIZE), biased towards edge values. */
  fieldElement(): bigint {
    switch (this.int(8)) {
      case 0: return 1n;
      case 1: return FIELD_SIZE - 1n;
      case 2: return FIELD_SIZE - 2n - this.uint(2);
      case 3: return 1n + this.uint(31); // top byte zero
      case 4: return 1n + this.uint(1 + this.int(28)); // several top bytes zero
      case 5: return 1n + this.uint(4); // small
      default: return 1n + (this.uint(32) % (FIELD_SIZE - 1n));
    }
  }
  /** Any uint256: what the verifier appends after the anchor is not range-limited. */
  anyUint256(): bigint {
    switch (this.int(6)) {
      case 0: return UINT256_MAX;
      case 1: return 0n;
      case 2: return FIELD_SIZE;
      default: return this.uint(32);
    }
  }
  /** A non-zero address, as checksummed, lowercase or uppercase hex. */
  address(): string {
    let raw = this.bytes(20);
    while (BigInt(raw) === 0n) raw = this.bytes(20);
    return this.formatAddress(raw);
  }
  formatAddress(address: string): string {
    switch (this.int(3)) {
      case 0: return ethers.getAddress(address);
      case 1: return address.toLowerCase();
      default: return "0x" + address.slice(2).toUpperCase();
    }
  }
  /** Mixed input notation for a builder number: decimal string, 0x hex or bigint. */
  notation(value: bigint): UintInput {
    switch (this.int(4)) {
      case 0: return value.toString(10);
      case 1: return "0x" + value.toString(16);
      case 2: return "0x" + value.toString(16).padStart(64, "0").toUpperCase();
      default: return value;
    }
  }
  base64url(length: number): string {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let out = "";
    for (let i = 0; i < length; i++) out += alphabet[this.int(alphabet.length)];
    return out;
  }
  hex32(): string {
    const value = this.bytes(32);
    return this.int(2) === 0 ? value : "0x" + value.slice(2).toUpperCase();
  }
  passkey(): { input: PasskeyKeyInput; plain: PlainPasskey } {
    const x = this.hex32();
    const y = this.hex32();
    const credentialId = this.base64url(1 + this.int(86));
    const origin = this.pick([
      () => `https://${this.base64url(1 + this.int(12)).toLowerCase()}.example`,
      () => `android:apk-key-hash:${this.base64url(43)}`,
      () => `https://テスト${this.int(1000)}.example`,
    ])();
    if (this.int(2) === 0) {
      const rpId = `${this.base64url(1 + this.int(10)).toLowerCase()}.example`;
      return { input: { x, y, credentialId, origin, rpId }, plain: { x, y, credentialId, origin, rpIdHash: sha256RpId(rpId) } };
    }
    const rpIdHash = this.hex32();
    return { input: { x, y, credentialId, origin, rpIdHash }, plain: { x, y, credentialId, origin, rpIdHash } };
  }
}

interface RoundTripCase {
  index: number;
  /** What the wallet holds on chain, as `readKeyState` reports it. */
  state: OnchainKeyState;
  /** Expectation handed to classify / reconstruct (address case may differ from the state). */
  expected: MasterKeyExpectation;
  passkey: PasskeyKeyInput;
  /** Blob originally built and installed. */
  original: string;
  /** Same values, plain, for the independent encoder. */
  plain: PlainOperationalMaster;
  otherPasskey: { input: PasskeyKeyInput; plain: PlainPasskey };
}

const SEED = 0x5eed2c0;
const CASE_COUNT = 256;

function generateCases(seed: number, count: number): RoundTripCase[] {
  const rng = new Rng(seed);
  const cases: RoundTripCase[] = [];
  for (let index = 0; index < count; index++) {
    const zkVerifier3of6 = rng.address();
    const addressKeyLogic = rng.address();
    const webAuthnLogic = rng.address();
    const merkleTreeDirectory = rng.address();
    const zkVerifier1of1 = rng.address();
    const cosigner = rng.address();
    const hAudList = rng.fieldElement();
    const anchor = [rng.fieldElement(), rng.fieldElement(), rng.fieldElement(), rng.fieldElement()];
    const anchorHash = rng.anyUint256();
    const passkey = rng.passkey();

    const original = buildOperationalMasterKey({
      contracts: { zkVerifier3of6, addressKeyLogic, webAuthnLogic, merkleTreeDirectory },
      zk: { hAudList: rng.notation(hAudList), anchor: anchor.map((a) => rng.notation(a)) },
      cosigner,
      passkey: passkey.input,
    });

    // On chain: addresses as the reader returns them (checksummed) or lowercase.
    const onchain = (address: string) => (rng.int(2) === 0 ? ethers.getAddress(address.toLowerCase()) : address.toLowerCase());
    const txKeyCount = rng.int(4);
    const state: OnchainKeyState = {
      account: "0x" + "11".repeat(20),
      deployed: true,
      readVia: rng.pick(["multicall", "direct"] as const),
      master: {
        threshold: 3,
        truncated: false,
        keys: [
          entry(0, onchain(zkVerifier3of6), "zkOAuth", 2, {
            keyId: rng.uint(rng.int(3)),
            zk: { directory: onchain(merkleTreeDirectory), n: 6n, k: 3n, hAudList, anchorWithHash: [...anchor, anchorHash] },
          }),
          entry(1, onchain(addressKeyLogic), "address", 1, { keyId: rng.uint(rng.int(3)), signer: onchain(cosigner) }),
          entry(2, onchain(webAuthnLogic), "webauthn", 1, {
            keyId: rng.uint(rng.int(3)),
            webauthn: webauthnData({ ...passkey.plain, x: passkey.plain.x.toLowerCase(), y: passkey.plain.y.toLowerCase() }),
          }),
        ],
      },
      tx: {
        threshold: txKeyCount === 0 ? 0 : 1,
        truncated: txKeyCount === 3 && rng.int(2) === 0,
        keys: Array.from({ length: txKeyCount }, (_, i) =>
          entry(i, onchain(webAuthnLogic), "webauthn", 1, { webauthn: webauthnData(rng.passkey().plain) }),
        ),
      },
    };

    // The expectation in yet another notation.
    const expected: MasterKeyExpectation = {
      contracts: {
        zkVerifier1of1: rng.formatAddress(zkVerifier1of1),
        zkVerifier3of6: rng.formatAddress(zkVerifier3of6),
        addressKeyLogic: rng.formatAddress(addressKeyLogic),
        webAuthnLogic: rng.formatAddress(webAuthnLogic),
        merkleTreeDirectory: rng.formatAddress(merkleTreeDirectory),
      },
      cosigner: rng.formatAddress(cosigner),
    };

    cases.push({
      index,
      state,
      expected,
      passkey: passkey.input,
      original,
      plain: { zkVerifier3of6, addressKeyLogic, webAuthnLogic, merkleTreeDirectory, hAudList, anchor, cosigner, passkey: passkey.plain },
      otherPasskey: rng.passkey(),
    });
  }
  return cases;
}

const CASES = generateCases(SEED, CASE_COUNT);

// ---------------------------------------------------------------------------

describe("onchain master key — classify and reconstruct", () => {
  it("is exported from the package entry point", () => {
    expect(pkg.classifyMasterKey).toBe(classifyMasterKey);
    expect(pkg.reconstructOperationalMasterKey).toBe(reconstructOperationalMasterKey);
  });

  describe("independent encoder (sanity check of the second implementation)", () => {
    it("reproduces the fixture's operationalMaster byte for byte", () => {
      const zk = inputs.operationalMaster.zk;
      const p = inputs.passkey;
      expect(
        independentOperationalMaster({
          ...VECTOR_CONTRACTS,
          hAudList: BigInt(zk.hAudList),
          anchor: zk.anchor.map((a) => BigInt(a)),
          cosigner: inputs.cosigner,
          passkey: { x: p.x, y: p.y, credentialId: p.credentialId, rpIdHash: sha256RpId(p.rpId), origin: p.origin },
        }),
      ).toBe(outputs.operationalMaster);
    });

    it("reproduces the fixture's reconstructedMaster byte for byte", () => {
      const zk = inputs.operationalMaster.zk;
      const p = inputs.newPasskey;
      expect(
        independentOperationalMaster({
          ...VECTOR_CONTRACTS,
          hAudList: BigInt(zk.hAudList),
          anchor: outputs.onchainGetAnchor.slice(0, -1).map((a) => BigInt(a)),
          cosigner: inputs.cosigner,
          passkey: { x: p.x, y: p.y, credentialId: p.credentialId, rpIdHash: p.rpIdHash, origin: p.origin },
        }),
      ).toBe(outputs.reconstructedMaster);
    });

    it("decodes the fixture's operationalMaster back to its inputs", () => {
      const decoded = decodeOperational(outputs.operationalMaster);
      expect(decoded.anchor).toEqual(inputs.operationalMaster.zk.anchor.map((a) => BigInt(a)));
      expect(decoded.hAudList).toBe(BigInt(inputs.operationalMaster.zk.hAudList));
      expect(decoded.signer).toBe(ethers.getAddress(inputs.cosigner));
    });
  });

  describe("known answers (fixture vectors)", () => {
    it("rebuilds the fixture's reconstructedMaster from the on-chain state and the new passkey", () => {
      expect(reconstructOperationalMasterKey(vectorOperationalState(), params(xyPasskey(inputs.newPasskey)))).toBe(
        outputs.reconstructedMaster,
      );
    });

    it("gives the same bytes when the new passkey names its relying party by rpIdHash", () => {
      expect(
        reconstructOperationalMasterKey(vectorOperationalState(), params(xyPasskey(inputs.newPasskey, "rpIdHash"))),
      ).toBe(outputs.reconstructedMaster);
    });

    it("rebuilds the installed operationalMaster when given the same passkey", () => {
      expect(reconstructOperationalMasterKey(vectorOperationalState(), params(xyPasskey(inputs.passkey)))).toBe(
        outputs.operationalMaster,
      );
    });

    it("classifies the fixture's operational state as operational", () => {
      expect(classifyMasterKey(vectorOperationalState(), EXPECTED)).toEqual({ kind: "operational", reasons: [] });
    });

    it("classifies the fixture's initial state as initial", () => {
      expect(classifyMasterKey(vectorInitialState(), EXPECTED)).toEqual({ kind: "initial", reasons: [] });
    });

    it("does not modify the state it is given", () => {
      const state = vectorOperationalState();
      const before = cloneState(state);
      reconstructOperationalMasterKey(state, params(xyPasskey(inputs.newPasskey)));
      classifyMasterKey(state, EXPECTED);
      expect(state).toEqual(before);
    });
  });

  describe(`round trip over ${CASE_COUNT} seeded random wallets (seed 0x${SEED.toString(16)})`, () => {
    it("generates distinct cases that cover the edge values", () => {
      const all = CASES.flatMap((c) => [c.plain.hAudList, ...c.plain.anchor]);
      expect(all).toContain(1n);
      expect(all).toContain(FIELD_SIZE - 1n);
      expect(all.some((v) => v > 0n && v < 1n << 248n)).toBe(true);
      const hashes = CASES.map((c) => zkOf(c.state).anchorWithHash[4]);
      expect(hashes).toContain(UINT256_MAX);
      expect(new Set(CASES.map((c) => c.original)).size).toBe(CASE_COUNT);
    });

    it("classifies every simulated wallet as operational", () => {
      const kinds = CASES.map((c) => classifyMasterKey(c.state, c.expected));
      expect(kinds).toEqual(CASES.map(() => ({ kind: "operational", reasons: [] })));
    });

    it("rebuilds the original blob byte for byte from the on-chain state and the same passkey", () => {
      for (const c of CASES) {
        const rebuilt = reconstructOperationalMasterKey(c.state, { ...c.expected, passkey: c.passkey });
        expect({ case: c.index, blob: rebuilt }).toEqual({ case: c.index, blob: c.original });
      }
    });

    it("matches the independent AbiCoder encoding of the same values", () => {
      for (const c of CASES) {
        const rebuilt = reconstructOperationalMasterKey(c.state, { ...c.expected, passkey: c.passkey });
        expect({ case: c.index, blob: rebuilt }).toEqual({ case: c.index, blob: independentOperationalMaster(c.plain) });
      }
    });

    it("with a different passkey, changes initDataList[2] only", () => {
      for (const c of CASES) {
        const original = decodeKeySet(c.original);
        const rebuilt = decodeKeySet(
          reconstructOperationalMasterKey(c.state, { ...c.expected, passkey: c.otherPasskey.input }),
        );
        expect({ case: c.index, threshold: rebuilt.threshold, logicList: rebuilt.logicList, weightList: rebuilt.weightList }).toEqual({
          case: c.index,
          threshold: original.threshold,
          logicList: original.logicList,
          weightList: original.weightList,
        });
        expect({ case: c.index, zk: rebuilt.initDataList[0], cosigner: rebuilt.initDataList[1] }).toEqual({
          case: c.index,
          zk: original.initDataList[0],
          cosigner: original.initDataList[1],
        });
        expect({ case: c.index, passkey: rebuilt.initDataList[2] }).toEqual({
          case: c.index,
          passkey: independentPasskeyInitData(c.otherPasskey.plain),
        });
        expect(rebuilt.initDataList[2]).not.toBe(original.initDataList[2]);
      }
    });
  });

  describe("with a different passkey (fixture)", () => {
    const original = decodeKeySet(outputs.operationalMaster);
    let rebuilt: ReturnType<typeof decodeKeySet>;
    beforeAll(() => {
      rebuilt = decodeKeySet(reconstructOperationalMasterKey(vectorOperationalState(), params(xyPasskey(inputs.newPasskey))));
    });

    it("keeps threshold, logicList and weightList", () => {
      expect([rebuilt.threshold, rebuilt.logicList, rebuilt.weightList]).toEqual([
        original.threshold,
        original.logicList,
        original.weightList,
      ]);
    });

    it("keeps the zk key's and the cosigner's init data byte for byte", () => {
      expect(rebuilt.initDataList.slice(0, 2)).toEqual(original.initDataList.slice(0, 2));
    });

    it("replaces the passkey's init data with the new passkey's", () => {
      expect(rebuilt.initDataList[2]).not.toBe(original.initDataList[2]);
      const p = inputs.newPasskey;
      expect(rebuilt.initDataList[2]).toBe(
        independentPasskeyInitData({ x: p.x, y: p.y, credentialId: p.credentialId, rpIdHash: p.rpIdHash, origin: p.origin }),
      );
    });

    it("ignores the passkey currently registered on chain", () => {
      const state = withState(vectorOperationalState, (s) => {
        s.master.keys[2].webauthn = webauthnData({ ...inputs.newPasskey, x: "0x" + "77".repeat(32) });
      });
      expect(reconstructOperationalMasterKey(state, params(xyPasskey(inputs.passkey)))).toBe(outputs.operationalMaster);
    });
  });

  describe("where each output value comes from", () => {
    const newPasskey = params(xyPasskey(inputs.newPasskey));

    it("takes hAudList from the chain: +1 on chain is +1 in the output", () => {
      const onchain = BigInt(inputs.operationalMaster.zk.hAudList) + 1n;
      const state = withState(vectorOperationalState, (s) => {
        zkOf(s).hAudList = onchain;
      });
      const out = reconstructOperationalMasterKey(state, newPasskey);
      expect(decodeOperational(out).hAudList).toBe(onchain);
      expect(out).not.toBe(outputs.reconstructedMaster);
    });

    it("takes hAudList from the chain: a flipped low bit on chain is flipped in the output", () => {
      const onchain = BigInt(inputs.operationalMaster.zk.hAudList) ^ 1n;
      const state = withState(vectorOperationalState, (s) => {
        zkOf(s).hAudList = onchain;
      });
      expect(decodeOperational(reconstructOperationalMasterKey(state, newPasskey)).hAudList).toBe(onchain);
    });

    it("keeps the on-chain anchor order", () => {
      const anchor = outputs.onchainGetAnchor.slice(0, -1).map((a) => BigInt(a));
      const permuted = [anchor[2], anchor[0], anchor[3], anchor[1]];
      const state = withState(vectorOperationalState, (s) => {
        zkOf(s).anchorWithHash = [...permuted, BigInt(outputs.onchainGetAnchor[4])];
      });
      expect(decodeOperational(reconstructOperationalMasterKey(state, newPasskey)).anchor).toEqual(permuted);
    });

    it("drops the last getAnchor element, not the first", () => {
      const state = withState(vectorOperationalState, (s) => {
        zkOf(s).anchorWithHash = [11n, 22n, 33n, 44n, 55n];
      });
      expect(decodeOperational(reconstructOperationalMasterKey(state, newPasskey)).anchor).toEqual([11n, 22n, 33n, 44n]);
    });

    it("drops the last getAnchor element even when it is outside the field", () => {
      const state = withState(vectorOperationalState, (s) => {
        zkOf(s).anchorWithHash = [FIELD_SIZE - 1n, 1n, 2n, 3n, UINT256_MAX];
      });
      expect(decodeOperational(reconstructOperationalMasterKey(state, newPasskey)).anchor).toEqual([FIELD_SIZE - 1n, 1n, 2n, 3n]);
    });

    it("writes n = 6 and k = 3", () => {
      const out = decodeOperational(reconstructOperationalMasterKey(vectorOperationalState(), newPasskey));
      expect([out.n, out.k]).toEqual([6n, 3n]);
    });

    it("takes the zk verifier, address logic, webauthn logic, directory and cosigner from params (case-insensitive match)", () => {
      // On chain everything is lowercase; params are checksummed.
      const state = withState(vectorOperationalState, (s) => {
        for (const key of s.master.keys) key.logicContract = key.logicContract.toLowerCase();
        zkOf(s).directory = zkOf(s).directory.toLowerCase();
        s.master.keys[1].signer = s.master.keys[1].signer!.toLowerCase();
      });
      const expected: MasterKeyExpectation = {
        contracts: {
          zkVerifier1of1: ethers.getAddress(VECTOR_CONTRACTS.zkVerifier1of1),
          zkVerifier3of6: ethers.getAddress(VECTOR_CONTRACTS.zkVerifier3of6),
          addressKeyLogic: ethers.getAddress(VECTOR_CONTRACTS.addressKeyLogic),
          webAuthnLogic: ethers.getAddress(VECTOR_CONTRACTS.webAuthnLogic),
          merkleTreeDirectory: ethers.getAddress(VECTOR_CONTRACTS.merkleTreeDirectory),
        },
        cosigner: ethers.getAddress(inputs.cosigner),
      };
      expect(classifyMasterKey(state, expected).kind).toBe("operational");
      const out = reconstructOperationalMasterKey(state, params(xyPasskey(inputs.newPasskey), expected));
      expect(out).toBe(outputs.reconstructedMaster);
      const decoded = decodeOperational(out);
      expect(decoded.logicList).toEqual([
        expected.contracts.zkVerifier3of6,
        expected.contracts.addressKeyLogic,
        expected.contracts.webAuthnLogic,
      ]);
      expect(decoded.directory).toBe(expected.contracts.merkleTreeDirectory);
      expect(decoded.signer).toBe(expected.cosigner);
    });

    it("accepts on-chain addresses in uppercase hex against lowercase params", () => {
      const upper = (a: string) => "0x" + a.slice(2).toUpperCase();
      const state = withState(vectorOperationalState, (s) => {
        for (const key of s.master.keys) key.logicContract = upper(key.logicContract);
        zkOf(s).directory = upper(zkOf(s).directory);
        s.master.keys[1].signer = upper(s.master.keys[1].signer!);
      });
      const expected: MasterKeyExpectation = {
        contracts: {
          zkVerifier1of1: VECTOR_CONTRACTS.zkVerifier1of1.toLowerCase(),
          zkVerifier3of6: VECTOR_CONTRACTS.zkVerifier3of6.toLowerCase(),
          addressKeyLogic: VECTOR_CONTRACTS.addressKeyLogic.toLowerCase(),
          webAuthnLogic: VECTOR_CONTRACTS.webAuthnLogic.toLowerCase(),
          merkleTreeDirectory: VECTOR_CONTRACTS.merkleTreeDirectory.toLowerCase(),
        },
        cosigner: inputs.cosigner.toLowerCase(),
      };
      expect(reconstructOperationalMasterKey(state, params(xyPasskey(inputs.newPasskey), expected))).toBe(
        outputs.reconstructedMaster,
      );
    });

    it("does not depend on key ids, the tx key list or the read path", () => {
      const state = withState(vectorOperationalState, (s) => {
        s.master.keys.forEach((key, i) => (key.keyId = BigInt(1000 + i)));
        s.tx = { threshold: 0, keys: [], truncated: false };
        s.readVia = "direct";
      });
      expect(reconstructOperationalMasterKey(state, params(xyPasskey(inputs.newPasskey)))).toBe(outputs.reconstructedMaster);
    });
  });

  // -------------------------------------------------------------------------
  // One precondition broken at a time
  // -------------------------------------------------------------------------

  type Mutation = (s: OnchainKeyState) => void;
  const setWeights = (weights: number[]): Mutation => (s) => s.master.keys.forEach((key, i) => (key.weight = weights[i]));
  const extraAddressKey = (index: number): OnchainKeyEntry =>
    entry(index, ethers.getAddress(inputs.contracts.addressKeyLogic), "address", 1, { keyId: 9n, signer: RANDOM_ADDRESS });

  const OPERATIONAL_VIOLATIONS: [string, Mutation, MasterKeyKind][] = [
    ["2 master keys (passkey missing)", (s) => void s.master.keys.pop(), "other"],
    ["4 master keys", (s) => void s.master.keys.push(extraAddressKey(3)), "other"],
    ["threshold 2", (s) => void (s.master.threshold = 2), "other"],
    ["threshold 4", (s) => void (s.master.threshold = 4), "other"],
    ["weights [1, 2, 1]", setWeights([1, 2, 1]), "other"],
    ["weights [2, 1, 2]", setWeights([2, 1, 2]), "other"],
    ["weights [1, 1, 2]", setWeights([1, 1, 2]), "other"],
    ["weights [2, 1, 0]", setWeights([2, 1, 0]), "other"],
    ["weights [1, 1, 1]", setWeights([1, 1, 1]), "other"],
    [
      "[1] and [2] swapped",
      (s) => {
        const [zk, cosigner, passkey] = s.master.keys;
        s.master.keys = [zk, { ...passkey, index: 1 }, { ...cosigner, index: 2 }];
      },
      "other",
    ],
    ["[0] logic is the 1-of-1 verifier", (s) => void (s.master.keys[0].logicContract = ethers.getAddress(inputs.contracts.zkVerifier1of1)), "other"],
    ["[0] logic is another address", (s) => void (s.master.keys[0].logicContract = RANDOM_ADDRESS), "other"],
    ["[0] directory differs", (s) => void (zkOf(s).directory = RANDOM_ADDRESS), "other"],
    ["[0] n = 1", (s) => void (zkOf(s).n = 1n), "other"],
    ["[0] n = 5", (s) => void (zkOf(s).n = 5n), "other"],
    ["[0] n = 7", (s) => void (zkOf(s).n = 7n), "other"],
    ["[0] k = 1", (s) => void (zkOf(s).k = 1n), "other"],
    ["[0] k = 2", (s) => void (zkOf(s).k = 2n), "other"],
    ["[0] k = 4", (s) => void (zkOf(s).k = 4n), "other"],
    ["[0] getAnchor length 4", (s) => void zkOf(s).anchorWithHash.pop(), "other"],
    ["[0] getAnchor length 6", (s) => void zkOf(s).anchorWithHash.push(99n), "other"],
    ["[0] getAnchor empty", (s) => void (zkOf(s).anchorWithHash = []), "other"],
    [
      "[0] keyType is not zkOAuth",
      (s) => {
        s.master.keys[0].keyType = "secp256k1";
        delete s.master.keys[0].zk;
      },
      "other",
    ],
    [
      "[0] keyType is unknown",
      (s) => {
        s.master.keys[0].keyType = "unknown";
        delete s.master.keys[0].zk;
      },
      "other",
    ],
    ["[0] keyType is not zkOAuth but zk data is present", (s) => void (s.master.keys[0].keyType = "oauthRs256"), "other"],
    ["[0] has no zk data", (s) => void delete s.master.keys[0].zk, "other"],
    ["[1] logic differs", (s) => void (s.master.keys[1].logicContract = RANDOM_ADDRESS), "other"],
    ["[1] signer differs", (s) => void (s.master.keys[1].signer = RANDOM_ADDRESS), "other"],
    ["[1] has no signer", (s) => void delete s.master.keys[1].signer, "other"],
    [
      "[1] keyType is unknown",
      (s) => {
        s.master.keys[1].keyType = "unknown";
        delete s.master.keys[1].signer;
      },
      "other",
    ],
    ["[1] keyType is not address but signer is present", (s) => void (s.master.keys[1].keyType = "secp256k1"), "other"],
    ["[2] logic differs", (s) => void (s.master.keys[2].logicContract = RANDOM_ADDRESS), "other"],
    ["[2] keyType is not webauthn but data is present", (s) => void (s.master.keys[2].keyType = "secp256r1"), "other"],
    [
      "[2] keyType is unknown",
      (s) => {
        s.master.keys[2].keyType = "unknown";
        delete s.master.keys[2].webauthn;
      },
      "other",
    ],
    ["[2] has no webauthn data", (s) => void delete s.master.keys[2].webauthn, "other"],
    ["master read truncated", (s) => void (s.master.truncated = true), "other"],
    [
      "master read truncated with an extra key",
      (s) => {
        s.master.keys.push(extraAddressKey(3));
        s.master.truncated = true;
      },
      "other",
    ],
    ["not deployed", (s) => Object.assign(s, cloneState(UNDEPLOYED_STATE)), "undeployed"],
    ["deployed: false even with key data", (s) => void (s.deployed = false), "undeployed"],
    ["the initial shape", (s) => Object.assign(s, vectorInitialState()), "initial"],
  ];

  type ExpectationMutation = (e: MasterKeyExpectation) => MasterKeyExpectation;
  const withContract = (name: keyof MasterKeyExpectation["contracts"], value: string): ExpectationMutation => (e) => ({
    ...e,
    contracts: { ...e.contracts, [name]: value },
  });

  const EXPECTATION_VIOLATIONS: [string, ExpectationMutation][] = [
    ["expected zkVerifier3of6 differs", withContract("zkVerifier3of6", RANDOM_ADDRESS)],
    ["expected zkVerifier3of6 is the on-chain 1-of-1 verifier", withContract("zkVerifier3of6", inputs.contracts.zkVerifier1of1)],
    ["expected addressKeyLogic differs", withContract("addressKeyLogic", RANDOM_ADDRESS)],
    ["expected webAuthnLogic differs", withContract("webAuthnLogic", RANDOM_ADDRESS)],
    ["expected merkleTreeDirectory differs", withContract("merkleTreeDirectory", RANDOM_ADDRESS)],
    ["expected cosigner differs", (e) => ({ ...e, cosigner: RANDOM_ADDRESS })],
  ];

  describe("refuses to reconstruct unless the state is operational", () => {
    describe.each(OPERATIONAL_VIOLATIONS)("%s", (_label, mutate, kind) => {
      const state = withState(vectorOperationalState, mutate);

      it(`classifies as ${kind}, not operational`, () => {
        const c = classifyMasterKey(state, EXPECTED);
        expect(c.kind).toBe(kind);
        expectReasons(c);
      });

      it("throws AaOperationError and returns nothing", () => {
        expectRefused(state, params(xyPasskey(inputs.newPasskey)));
      });
    });

    describe.each(EXPECTATION_VIOLATIONS)("%s", (_label, mutate) => {
      const expected = mutate(EXPECTED);

      it("classifies as other", () => {
        const c = classifyMasterKey(vectorOperationalState(), expected);
        expect(c.kind).toBe("other");
        expectReasons(c);
      });

      it("throws AaOperationError and returns nothing", () => {
        expectRefused(vectorOperationalState(), params(xyPasskey(inputs.newPasskey), expected));
      });
    });

    it("refuses each of the random wallets once one precondition is broken", () => {
      const rng = new Rng(SEED + 1);
      for (const c of CASES.slice(0, 64)) {
        const [label, mutate] = OPERATIONAL_VIOLATIONS[rng.int(OPERATIONAL_VIOLATIONS.length)];
        const state = cloneState(c.state);
        mutate(state);
        const kind = classifyMasterKey(state, c.expected).kind;
        expect({ case: c.index, label, operational: kind === "operational" }).toEqual({ case: c.index, label, operational: false });
        expectRefused(state, { ...c.expected, passkey: c.passkey });
      }
    });
  });

  // -------------------------------------------------------------------------
  // Classification
  // -------------------------------------------------------------------------

  describe("classifyMasterKey", () => {
    it("undeployed: deployed is false", () => {
      expect(classifyMasterKey(cloneState(UNDEPLOYED_STATE), EXPECTED)).toEqual({ kind: "undeployed", reasons: [] });
    });

    it("initial: the fixture wallet right after deployment", () => {
      expect(classifyMasterKey(vectorInitialState(), EXPECTED)).toEqual({ kind: "initial", reasons: [] });
    });

    it("initial: compares addresses case-insensitively", () => {
      const state = withState(vectorInitialState, (s) => {
        for (const key of s.master.keys) key.logicContract = key.logicContract.toLowerCase();
        zkOf(s).directory = zkOf(s).directory.toLowerCase();
        s.master.keys[1].signer = "0x" + s.master.keys[1].signer!.slice(2).toUpperCase();
      });
      expect(classifyMasterKey(state, EXPECTED).kind).toBe("initial");
    });

    it("operational: the fixture wallet after updateKeys", () => {
      expect(classifyMasterKey(vectorOperationalState(), EXPECTED)).toEqual({ kind: "operational", reasons: [] });
    });

    it.each([
      ["no tx keys", (s: OnchainKeyState) => void (s.tx = { threshold: 0, keys: [], truncated: false })],
      ["a truncated tx list", (s: OnchainKeyState) => void (s.tx.truncated = true)],
      [
        "several tx keys of other types",
        (s: OnchainKeyState) =>
          void (s.tx.keys = [
            entry(0, RANDOM_ADDRESS, "address", 1, { signer: RANDOM_ADDRESS }),
            entry(1, RANDOM_ADDRESS, "unknown", 1),
          ]),
      ],
      ["the direct read path", (s: OnchainKeyState) => void (s.readVia = "direct")],
    ])("operational regardless of the tx keys: %s", (_label, mutate) => {
      expect(classifyMasterKey(withState(vectorOperationalState, mutate), EXPECTED)).toEqual({ kind: "operational", reasons: [] });
    });

    const INITIAL_VIOLATIONS: [string, Mutation][] = [
      ["a tx key is registered", (s) => void (s.tx = cloneSet(VECTOR_TX))],
      ["the tx list is truncated (with no key read)", (s) => void (s.tx.truncated = true)],
      ["getAnchor length 1 (no hash)", (s) => void zkOf(s).anchorWithHash.pop()],
      ["getAnchor length 3", (s) => void zkOf(s).anchorWithHash.push(7n)],
      ["1 master key", (s) => void s.master.keys.pop()],
      ["3 master keys", (s) => void s.master.keys.push(extraAddressKey(2))],
      ["threshold 1", (s) => void (s.master.threshold = 1)],
      ["threshold 3", (s) => void (s.master.threshold = 3)],
      ["weights [2, 1]", setWeights([2, 1])],
      ["weights [1, 2]", setWeights([1, 2])],
      ["[0] logic is the 3-of-6 verifier", (s) => void (s.master.keys[0].logicContract = ethers.getAddress(inputs.contracts.zkVerifier3of6))],
      ["[0] directory differs", (s) => void (zkOf(s).directory = RANDOM_ADDRESS)],
      ["[0] n = 6", (s) => void (zkOf(s).n = 6n)],
      ["[0] k = 3", (s) => void (zkOf(s).k = 3n)],
      ["[0] k = 2", (s) => void (zkOf(s).k = 2n)],
      ["[0] has no zk data", (s) => void delete s.master.keys[0].zk],
      [
        "[0] keyType is not zkOAuth",
        (s) => {
          s.master.keys[0].keyType = "unknown";
          delete s.master.keys[0].zk;
        },
      ],
      ["[1] logic differs", (s) => void (s.master.keys[1].logicContract = RANDOM_ADDRESS)],
      ["[1] signer differs", (s) => void (s.master.keys[1].signer = RANDOM_ADDRESS)],
      ["[1] has no signer", (s) => void delete s.master.keys[1].signer],
      ["[1] keyType is not address", (s) => void (s.master.keys[1].keyType = "secp256k1")],
      ["master read truncated", (s) => void (s.master.truncated = true)],
    ];

    it.each(INITIAL_VIOLATIONS)("other, not initial: %s", (_label, mutate) => {
      const c = classifyMasterKey(withState(vectorInitialState, mutate), EXPECTED);
      expect(c.kind).toBe("other");
      expectReasons(c);
    });

    it.each([
      ["expected zkVerifier1of1 differs", withContract("zkVerifier1of1", RANDOM_ADDRESS)],
      ["expected addressKeyLogic differs", withContract("addressKeyLogic", RANDOM_ADDRESS)],
      ["expected merkleTreeDirectory differs", withContract("merkleTreeDirectory", RANDOM_ADDRESS)],
      ["expected cosigner differs", (e: MasterKeyExpectation) => ({ ...e, cosigner: RANDOM_ADDRESS })],
    ])("other, not initial: %s", (_label, mutate) => {
      const c = classifyMasterKey(vectorInitialState(), mutate(EXPECTED));
      expect(c.kind).toBe("other");
      expectReasons(c);
    });

    it("other: a deployed account with no master keys", () => {
      const c = classifyMasterKey(
        { account: "0x" + "11".repeat(20), deployed: true, readVia: "multicall", master: { threshold: 0, keys: [], truncated: false }, tx: { threshold: 0, keys: [], truncated: false } },
        EXPECTED,
      );
      expect(c.kind).toBe("other");
      expectReasons(c);
    });

    it("other: a single zk key (the pre-cosign layout)", () => {
      const state = withState(vectorInitialState, (s) => {
        s.master.keys = [s.master.keys[0]];
        s.master.threshold = 1;
      });
      const c = classifyMasterKey(state, EXPECTED);
      expect(c.kind).toBe("other");
      expectReasons(c);
    });

    it("reasons are non-empty only for other", () => {
      const results = [
        classifyMasterKey(cloneState(UNDEPLOYED_STATE), EXPECTED),
        classifyMasterKey(vectorInitialState(), EXPECTED),
        classifyMasterKey(vectorOperationalState(), EXPECTED),
        classifyMasterKey(withState(vectorOperationalState, (s) => void (s.master.threshold = 4)), EXPECTED),
      ];
      expect(results.map((r) => r.kind)).toEqual(["undeployed", "initial", "operational", "other"]);
      results.forEach(expectReasons);
    });
  });
});
