/**
 * Captures how the REAL contract bytecode answers the `eth_call`s AccountReader
 * sends, and writes them to lib/reader/__tests__/fixtures/reader-capture.json.
 *
 * Why: a fake chain only tests the reader against the fake's assumptions. Twice
 * a fake shared the reader's mistake (a hand-written ABI fragment, and a list
 * getter assumed to revert with Panic(0x32) where the compiled getter reverts
 * without data), so the tests passed while every real wallet read failed. The
 * replay tests (lib/reader/__tests__/AccountReader.replay.test.ts) feed these
 * raw JSON-RPC answers to a real ethers JsonRpcProvider and check the fake chain
 * against them.
 *
 * How: start a local anvil, put each artifact's `deployedBytecode`
 * (lib/types/abi/*.json) at a fixed address with `anvil_setCode`, and run:
 *   (a) an address without code;
 *   (b) a ZkapAccount that was never initialized (every key list empty);
 *   (c) a ZkapAccount initialized through `initialize(masterKey, txKey)` with an
 *       address key and a WebAuthn key (test values only);
 *   plus `keyType()` and getters for unregistered keys on the key logic
 *   contracts, including the zk verifier, whose library links are filled with
 *   placeholder addresses (it is never registered, so they are never called).
 * The constructors never run, so immutables are zero; the reads do not use them.
 *
 * The output is deterministic: fixed addresses, sorted entries, no timestamps
 * or versions. Re-run it whenever lib/types/abi/*.json changes; the replay test
 * fails while the captured bytecode hashes differ from the artifacts.
 *
 * Usage: node scripts/capture-reader-fixture.mjs   (needs `anvil` from Foundry on PATH)
 */

import { spawn } from "child_process";
import { createHash } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const { ethers } = require("ethers");

const ROOT = new URL("../", import.meta.url);
const ABI_DIR = new URL("lib/types/abi/", ROOT);
const OUT_FILE = fileURLToPath(new URL("lib/reader/__tests__/fixtures/reader-capture.json", ROOT));
const VECTORS_FILE = new URL("fixtures/master-key-cosign-vectors.json", ROOT);

const artifact = (name) => JSON.parse(readFileSync(new URL(`${name}.json`, ABI_DIR), "utf8"));
const ARTIFACTS = {
  ZkapAccount: artifact("ZkapAccount"),
  AccountKeyAddress: artifact("AccountKeyAddress"),
  AccountKeyWebAuthn: artifact("AccountKeyWebAuthn"),
  AccountKeyZkOAuthRS256Verifier: artifact("AccountKeyZkOAuthRS256Verifier"),
};
const MULTICALL3_ABI = artifact("Multicall3");

// Fixed test addresses — nothing here exists on a real chain.
const ADDRESSES = {
  noCodeAccount: "0x00000000000000000000000000000000000a0001",
  uninitializedAccount: "0x00000000000000000000000000000000000a0002",
  initializedAccount: "0x00000000000000000000000000000000000a0003",
  addressKeyLogic: "0x00000000000000000000000000000000000b0001",
  webAuthnLogic: "0x00000000000000000000000000000000000b0002",
  zkVerifier: "0x00000000000000000000000000000000000b0003",
  /** Signer registered in the address key of (c). */
  cosigner: "0x00000000000000000000000000000000000c0001",
  /** Sends the `initialize` transaction of (c) (impersonated). */
  sender: "0x00000000000000000000000000000000000d0001",
  multicall3: "0xca11bde05977b3631167028862be2a173976ca11",
};
/** Stand-ins for the zk verifier's linked libraries, in sorted library order. */
const LIBRARY_PLACEHOLDERS = ["0x00000000000000000000000000000000000e0001", "0x00000000000000000000000000000000000e0002"];

/** Windows the reader reads by default: master 5, tx `maxTxKeys` = 5, each plus one probe slot. */
const LIST_INDICES = [0, 1, 2, 3, 4, 5];
const PURPOSES = [0, 1];
const KEY_IDS = [0, 1];

const accountIface = new ethers.Interface(ARTIFACTS.ZkapAccount.abi);
const addressIface = new ethers.Interface(ARTIFACTS.AccountKeyAddress.abi);
const webAuthnIface = new ethers.Interface(ARTIFACTS.AccountKeyWebAuthn.abi);
const zkIface = new ethers.Interface(ARTIFACTS.AccountKeyZkOAuthRS256Verifier.abi);
const multicallIface = new ethers.Interface(MULTICALL3_ABI);
const coder = ethers.AbiCoder.defaultAbiCoder();

// --- anvil -----------------------------------------------------------------

function startAnvil() {
  const port = 20000 + Math.floor(Math.random() * 30000);
  const child = spawn("anvil", ["--port", String(port), "--silent"], { stdio: ["ignore", "ignore", "pipe"] });
  const ready = new Promise((resolve, reject) => {
    child.once("error", (err) => {
      if (err.code === "ENOENT") {
        reject(
          new Error(
            "anvil was not found on PATH. Install Foundry (https://book.getfoundry.sh/getting-started/installation), " +
              "e.g. `curl -L https://foundry.paradigm.xyz | bash && foundryup`, then re-run this script."
          )
        );
      } else reject(err);
    });
    child.once("exit", (code) => reject(new Error(`anvil exited early (code ${code})`)));
    const url = `http://127.0.0.1:${port}`;
    const poll = async (attempt) => {
      try {
        await rpcAt(url, "eth_chainId", []);
        resolve(url);
      } catch (err) {
        if (attempt > 100) reject(new Error(`anvil did not start on port ${port}: ${err.message}`));
        else setTimeout(() => poll(attempt + 1), 100);
      }
    };
    poll(0);
  });
  return { child, ready };
}

let nextId = 1;
async function rawRpcAt(url, method, params) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  });
  return await response.json();
}

async function rpcAt(url, method, params) {
  const body = await rawRpcAt(url, method, params);
  if (body.error) throw new Error(`${method} failed: ${JSON.stringify(body.error)}`);
  return body.result;
}

// --- setup -----------------------------------------------------------------

/** The zk verifier's deployed bytecode with every library link set to a placeholder address. */
function linkedZkVerifierCode() {
  const { deployedBytecode, deployedLinkReferences } = ARTIFACTS.AccountKeyZkOAuthRS256Verifier;
  let hex = deployedBytecode.slice(2);
  const libraries = Object.entries(deployedLinkReferences)
    .flatMap(([file, libs]) => Object.entries(libs).map(([name, refs]) => ({ id: `${file}:${name}`, refs })))
    .sort((a, b) => a.id.localeCompare(b.id));
  if (libraries.length > LIBRARY_PLACEHOLDERS.length) throw new Error("more linked libraries than placeholders");
  libraries.forEach(({ refs }, i) => {
    for (const { start, length } of refs) {
      hex = hex.slice(0, start * 2) + LIBRARY_PLACEHOLDERS[i].slice(2) + hex.slice((start + length) * 2);
    }
  });
  if (hex.includes("__$")) throw new Error("unlinked placeholder left in the zk verifier bytecode");
  return "0x" + hex;
}

function webAuthnInitData(passkey) {
  const key = coder.encode(["tuple(bytes32,bytes32,string)"], [[passkey.x, passkey.y, passkey.credentialId]]);
  return coder.encode(
    ["bytes", "bytes32", "bytes", "bool"],
    [key, passkey.rpIdHash, ethers.hexlify(ethers.toUtf8Bytes(passkey.origin)), false]
  );
}

function keySet(threshold, logics, initData, weights) {
  return coder.encode(["uint8", "address[]", "bytes[]", "uint8[]"], [threshold, logics, initData, weights]);
}

/** Initialize (c): master [address key, WebAuthn key] threshold 2, tx [WebAuthn key] threshold 1. */
async function initializeAccount(url, passkey) {
  const masterKey = keySet(
    2,
    [ADDRESSES.addressKeyLogic, ADDRESSES.webAuthnLogic],
    [coder.encode(["address"], [ADDRESSES.cosigner]), webAuthnInitData(passkey)],
    [1, 1]
  );
  const txKey = keySet(1, [ADDRESSES.webAuthnLogic], [webAuthnInitData(passkey)], [1]);
  const data = accountIface.encodeFunctionData("initialize", [masterKey, txKey]);
  await rpcAt(url, "anvil_impersonateAccount", [ADDRESSES.sender]);
  await rpcAt(url, "anvil_setBalance", [ADDRESSES.sender, "0x56bc75e2d63100000"]);
  const hash = await rpcAt(url, "eth_sendTransaction", [
    { from: ADDRESSES.sender, to: ADDRESSES.initializedAccount, data, gas: "0x1c9c380" },
  ]);
  let receipt = null;
  for (let attempt = 0; attempt < 50 && !receipt; attempt++) {
    receipt = await rpcAt(url, "eth_getTransactionReceipt", [hash]);
    if (!receipt) await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!receipt || receipt.status !== "0x1") {
    throw new Error(`initialize(masterKey, txKey) on the account did not succeed: ${JSON.stringify(receipt)}`);
  }
  return { masterKey, txKey };
}

// --- requests --------------------------------------------------------------

/** Every account read of `readKeyState` / `readTxKeySlots`, plus a selector the account does not have. */
function accountRequests(account) {
  const requests = [
    { to: account, data: accountIface.encodeFunctionData("masterKeyThreshold") },
    { to: account, data: accountIface.encodeFunctionData("txKeyThreshold") },
    // keyType() is not in the ZkapAccount ABI: how the account answers an unknown selector.
    { to: account, data: webAuthnIface.encodeFunctionData("keyType") },
  ];
  for (const fn of ["masterKeyList", "masterKeyWeightList", "txKeyList", "txKeyWeightList"]) {
    for (const index of LIST_INDICES) requests.push({ to: account, data: accountIface.encodeFunctionData(fn, [index]) });
  }
  return requests;
}

/**
 * The round-2 reads on every key logic contract, for `account`: `keyType()` and
 * all four typed getters (each logic contract has only its own; the others are
 * unknown selectors there) for both purposes and key ids 0 and 1.
 */
function logicRequests(account) {
  const getters = [
    [zkIface, "getData"],
    [zkIface, "getAnchor"],
    [addressIface, "getSigner"],
    [webAuthnIface, "getKeyData"],
  ];
  const requests = [];
  for (const logic of [ADDRESSES.addressKeyLogic, ADDRESSES.webAuthnLogic, ADDRESSES.zkVerifier]) {
    requests.push({ to: logic, data: webAuthnIface.encodeFunctionData("keyType") });
    for (const [iface, fn] of getters) {
      for (const purpose of PURPOSES) {
        for (const keyId of KEY_IDS) {
          requests.push({ to: logic, data: iface.encodeFunctionData(fn, [purpose, account, keyId]) });
        }
      }
    }
  }
  return requests;
}

/** A JSON-RPC answer as received, without `jsonrpc` / `id`. */
function rawAnswer(body) {
  if ("error" in body) return { error: body.error };
  return { result: body.result };
}

async function main() {
  const passkey = JSON.parse(readFileSync(VECTORS_FILE, "utf8")).inputs.passkey;
  const { child, ready } = startAnvil();
  const stop = () => {
    if (child.exitCode === null) child.kill("SIGTERM");
  };
  process.once("SIGINT", () => {
    stop();
    process.exit(130);
  });

  try {
    const url = await ready;
    const chainId = await rpcAt(url, "eth_chainId", []);
    await rpcAt(url, "anvil_setCode", [ADDRESSES.uninitializedAccount, ARTIFACTS.ZkapAccount.deployedBytecode]);
    await rpcAt(url, "anvil_setCode", [ADDRESSES.initializedAccount, ARTIFACTS.ZkapAccount.deployedBytecode]);
    await rpcAt(url, "anvil_setCode", [ADDRESSES.addressKeyLogic, ARTIFACTS.AccountKeyAddress.deployedBytecode]);
    await rpcAt(url, "anvil_setCode", [ADDRESSES.webAuthnLogic, ARTIFACTS.AccountKeyWebAuthn.deployedBytecode]);
    await rpcAt(url, "anvil_setCode", [ADDRESSES.zkVerifier, linkedZkVerifierCode()]);
    const initialized = await initializeAccount(url, passkey);

    const requests = [
      ...accountRequests(ADDRESSES.noCodeAccount),
      ...accountRequests(ADDRESSES.uninitializedAccount),
      ...accountRequests(ADDRESSES.initializedAccount),
      ...logicRequests(ADDRESSES.uninitializedAccount),
      ...logicRequests(ADDRESSES.initializedAccount),
      // The aggregate3 probe on a chain without Multicall3 (anvil has none).
      { to: ADDRESSES.multicall3, data: multicallIface.encodeFunctionData("aggregate3", [[]]) },
    ];

    const calls = [];
    const seen = new Set();
    for (const { to, data } of requests) {
      const key = `${to.toLowerCase()} ${data.toLowerCase()}`;
      if (seen.has(key)) continue; // keyType() does not depend on the account
      seen.add(key);
      const body = await rawRpcAt(url, "eth_call", [{ to, data }, "latest"]);
      calls.push({ to: to.toLowerCase(), data: data.toLowerCase(), response: rawAnswer(body) });
    }
    calls.sort((a, b) => (a.to === b.to ? a.data.localeCompare(b.data) : a.to.localeCompare(b.to)));

    const codeHashes = Object.fromEntries(
      Object.entries(ARTIFACTS).map(([name, a]) => [name, createHash("sha256").update(a.deployedBytecode).digest("hex")])
    );
    const fixture = {
      description:
        "Raw JSON-RPC eth_call answers of the contract bytecode in lib/types/abi/*.json on a local anvil. " +
        "Generated by scripts/capture-reader-fixture.mjs; do not edit by hand.",
      chainId,
      deployedBytecodeSha256: codeHashes,
      addresses: ADDRESSES,
      zkVerifierLibraryPlaceholders: LIBRARY_PLACEHOLDERS,
      initializedAccount: {
        masterKey: initialized.masterKey,
        txKey: initialized.txKey,
        passkey: {
          x: passkey.x,
          y: passkey.y,
          credentialId: passkey.credentialId,
          rpId: passkey.rpId,
          rpIdHash: passkey.rpIdHash,
          origin: passkey.origin,
        },
      },
      multicall3Code: await rpcAt(url, "eth_getCode", [ADDRESSES.multicall3, "latest"]),
      calls,
    };
    writeFileSync(OUT_FILE, JSON.stringify(fixture, null, 2) + "\n");
    console.log(`wrote ${calls.length} captured calls to lib/reader/__tests__/fixtures/reader-capture.json`);
  } finally {
    stop();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
