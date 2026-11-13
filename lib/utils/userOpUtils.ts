import { ethers } from "ethers";
import type { UserOperation, PackedUserOperation, PimlicoUserOperation } from "../types/UserOperation";
import { AaOperationError, AaOperationErrorCode } from "../errors";
import { MASTER_OP_KEY_INDEX_LIST } from "../master/constants";

// ---------------------------------------------------------------------------
// Pack / Unpack UserOperation
// ---------------------------------------------------------------------------

function padTo16Bytes(hex: string): string {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return clean.padStart(32, "0"); // 16 bytes = 32 hex chars
}

/** Strip leading zeros from a hex string to produce minimal encoding (JSON-RPC convention). */
function toMinimalHex(hex: string): string {
  const stripped = hex.replace(/^0x0+/, "0x");
  return stripped === "0x" ? "0x0" : stripped;
}

/**
 * Pack a UserOperation (unpacked SDK format) into a PackedUserOperation (on-chain format).
 * accountGasLimits = verificationGasLimit (16 bytes) || callGasLimit (16 bytes)
 * gasFees          = maxPriorityFeePerGas (16 bytes) || maxFeePerGas (16 bytes)
 * paymasterAndData = paymaster (20 bytes) || pmVerGasLimit (16 bytes) || pmPostOpGasLimit (16 bytes) || paymasterData
 */
export function packUserOperation(userOp: UserOperation): PackedUserOperation {
  const verificationGasLimit = padTo16Bytes(userOp.verificationGasLimit);
  const callGasLimit = padTo16Bytes(userOp.callGasLimit);
  const accountGasLimits = "0x" + verificationGasLimit + callGasLimit;

  const maxPriorityFeePerGas = padTo16Bytes(userOp.maxPriorityFeePerGas);
  const maxFeePerGas = padTo16Bytes(userOp.maxFeePerGas);
  const gasFees = "0x" + maxPriorityFeePerGas + maxFeePerGas;

  let paymasterAndData = "0x";
  const paymaster = userOp.paymaster || ethers.ZeroAddress;
  if (paymaster !== "0x" && paymaster !== ethers.ZeroAddress) {
    const paymasterClean = paymaster.startsWith("0x") ? paymaster.slice(2) : paymaster;
    const pmVerGas = padTo16Bytes(userOp.paymasterVerificationGasLimit || "0x0");
    const pmPostGas = padTo16Bytes(userOp.paymasterPostOpGasLimit || "0x0");
    const pmData = (userOp.paymasterData || "0x").startsWith("0x")
      ? (userOp.paymasterData || "0x").slice(2)
      : (userOp.paymasterData || "");
    paymasterAndData = "0x" + paymasterClean + pmVerGas + pmPostGas + pmData;
  }

  return {
    sender: userOp.sender,
    nonce: userOp.nonce,
    initCode: userOp.initCode,
    callData: userOp.callData,
    accountGasLimits,
    preVerificationGas: userOp.preVerificationGas,
    gasFees,
    paymasterAndData,
    signature: userOp.signature,
  };
}

/**
 * Unpack a PackedUserOperation back into the SDK UserOperation format.
 */
export function unpackUserOperation(packed: PackedUserOperation): UserOperation {
  // accountGasLimits: bytes32 = verificationGasLimit (16 bytes) || callGasLimit (16 bytes)
  const agl = packed.accountGasLimits.replace("0x", "").padStart(64, "0");
  const verificationGasLimit = "0x" + agl.slice(0, 32);
  const callGasLimit = "0x" + agl.slice(32, 64);

  // gasFees: bytes32 = maxPriorityFeePerGas (16 bytes) || maxFeePerGas (16 bytes)
  const gf = packed.gasFees.replace("0x", "").padStart(64, "0");
  const maxPriorityFeePerGas = "0x" + gf.slice(0, 32);
  const maxFeePerGas = "0x" + gf.slice(32, 64);

  // paymasterAndData: paymaster (20 bytes / 40 hex) || pmVerGas (16 bytes / 32 hex) || pmPostGas (16 bytes / 32 hex) || data
  let paymaster = ethers.ZeroAddress;
  let paymasterVerificationGasLimit = "0x0";
  let paymasterPostOpGasLimit = "0x0";
  let paymasterData = "0x";

  const pad = packed.paymasterAndData.replace("0x", "");
  if (pad.length >= 40) {
    paymaster = "0x" + pad.slice(0, 40);
    if (pad.length >= 40 + 64) {
      paymasterVerificationGasLimit = "0x" + pad.slice(40, 40 + 32);
      paymasterPostOpGasLimit = "0x" + pad.slice(40 + 32, 40 + 64);
      paymasterData = pad.length > 40 + 64 ? "0x" + pad.slice(40 + 64) : "0x";
    }
  }

  return {
    sender: packed.sender,
    nonce: packed.nonce,
    initCode: packed.initCode,
    callData: packed.callData,
    callGasLimit,
    verificationGasLimit,
    preVerificationGas: packed.preVerificationGas,
    maxFeePerGas,
    maxPriorityFeePerGas,
    paymaster,
    paymasterData,
    paymasterVerificationGasLimit,
    paymasterPostOpGasLimit,
    signature: packed.signature,
  };
}

/**
 * Convert a PackedUserOperation to Pimlico v0.7/v0.8 JSON-RPC format.
 *
 * Pimlico bundlers expect an unpacked format with separate `factory` and `factoryData`
 * fields instead of the combined `initCode` field used in the on-chain packed format.
 *
 * @param packed - The packed UserOperation (on-chain format)
 * @returns The UserOperation in Pimlico JSON-RPC format
 *
 * @example
 * ```ts
 * const packed = packUserOperation(userOp);
 * const pimlicoFormat = toPimlicoFormat(packed);
 * // Submit to Pimlico bundler
 * await fetch(pimlicoUrl, {
 *   method: 'POST',
 *   body: JSON.stringify({
 *     jsonrpc: '2.0',
 *     method: 'eth_sendUserOperation',
 *     params: [pimlicoFormat, entryPoint],
 *   }),
 * });
 * ```
 */
export function toPimlicoFormat(packed: PackedUserOperation): PimlicoUserOperation {
  const unpacked = unpackUserOperation(packed);

  // Validate and split initCode into factory (20 bytes) and factoryData (rest)
  let factory: string | undefined;
  let factoryData: string | undefined;
  const initCode = unpacked.initCode;
  if (initCode && initCode !== "0x") {
    if (initCode.length < 42) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID_FORMAT,
        operation: "to_pimlico_format",
        message: `Invalid initCode: expected at least 20-byte address (42 hex chars with 0x prefix), got ${initCode.length} chars`,
      });
    }
    factory = "0x" + initCode.slice(2, 42);
    factoryData = initCode.length > 42 ? "0x" + initCode.slice(42) : "0x";
  }

  // Validate paymasterAndData: if paymaster is present, gas fields must also be present
  const paymasterHex = packed.paymasterAndData.replace("0x", "");
  const hasPaymaster =
    unpacked.paymaster &&
    unpacked.paymaster !== "0x" &&
    unpacked.paymaster.toLowerCase() !== ethers.ZeroAddress;
  if (hasPaymaster && paymasterHex.length < 104) {
    throw new AaOperationError({
      code: AaOperationErrorCode.INPUT_INVALID_FORMAT,
      operation: "to_pimlico_format",
      message: `Invalid paymasterAndData: has paymaster address but missing gas fields (expected ≥104 hex chars, got ${paymasterHex.length})`,
    });
  }

  const result: PimlicoUserOperation = {
    sender: unpacked.sender,
    nonce: toMinimalHex(unpacked.nonce),
    callData: unpacked.callData,
    callGasLimit: toMinimalHex(unpacked.callGasLimit),
    verificationGasLimit: toMinimalHex(unpacked.verificationGasLimit),
    preVerificationGas: toMinimalHex(unpacked.preVerificationGas),
    maxFeePerGas: toMinimalHex(unpacked.maxFeePerGas),
    maxPriorityFeePerGas: toMinimalHex(unpacked.maxPriorityFeePerGas),
    signature: unpacked.signature,
  };

  // Add factory fields only if deploying
  if (factory) {
    result.factory = factory;
    result.factoryData = factoryData;
  }

  // Add paymaster fields only if using paymaster
  if (hasPaymaster) {
    result.paymaster = unpacked.paymaster;
    result.paymasterVerificationGasLimit = toMinimalHex(unpacked.paymasterVerificationGasLimit);
    result.paymasterPostOpGasLimit = toMinimalHex(unpacked.paymasterPostOpGasLimit);
    result.paymasterData = unpacked.paymasterData;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Dummy signatures (for gas estimation before autoFillUserOp)
// ---------------------------------------------------------------------------

const MAX = ethers.MaxUint256;
const DUMMY_PROOF_8: bigint[] = [MAX, MAX, MAX, MAX, MAX, MAX, MAX, MAX];

/**
 * Create a dummy ZK signature for gas estimation.
 *
 * This is only the zk entry of `keySignatureList`. Master key operations (`updateKeys`,
 * `updateMasterKey`, `updateTxKey`) are cosigned, so use `createDummyMasterOpSignature`
 * for their full signature instead.
 * @param n - 1 for a single proof (the 1-of-1 key), 3 for 3 proofs (the 3-of-6 key)
 * @returns ABI-encoded dummy ZK proof string (the keySignatureList entry)
 */
export function createDummyZkSignature(n: number): string {
  const count = n >= 3 ? 3 : 1;
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[6]", "uint256[]", "uint256[]", "uint256[8][]"],
    [
      [MAX, MAX, MAX, MAX, MAX, MAX],
      Array.from({ length: count }, () => MAX),
      Array.from({ length: count }, () => MAX),
      Array.from({ length: count }, () => DUMMY_PROOF_8),
    ]
  );
}

/**
 * Create a dummy passkey (WebAuthn) signature for gas estimation.
 * Matches the 7-field ABI encoding in PasskeySigner.signUserOpHash():
 * (authenticatorData, clientDataJSON, signature, typeIndex, challengeIndex, originIndex, originLength)
 * @returns ABI-encoded dummy passkey signature string (the keySignatureList entry)
 */
export function createDummyPasskeySignature(): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes", "bytes", "uint256", "uint256", "uint256", "uint256"],
    [
      ethers.randomBytes(37),  // authenticatorData (typical WebAuthn size)
      ethers.randomBytes(200), // clientDataJSON
      ethers.randomBytes(72),  // DER-encoded secp256r1 signature
      ethers.MaxUint256,       // typeIndex
      ethers.MaxUint256,       // challengeIndex
      ethers.MaxUint256,       // originIndex (originStart)
      ethers.MaxUint256,       // originLength
    ]
  );
}

/**
 * Fixed 65-byte ECDSA signature (`r ‖ s ‖ v`) used as the cosigner's dummy signature.
 * It is a real low-s signature (private key 1 over the zero hash), so ECDSA recovery
 * succeeds and returns an unrelated address instead of reverting on a malformed
 * signature during estimation.
 */
const DUMMY_COSIGN_SIGNATURE =
  "0xa0b37f8fba683cc68f6574cd43b39f0343a50008bf6ccea9d13231d9e7e2e1e4" +
  "11edc8d307254296264aebfc3dc76cd8b668373a072fd64665b50000e9fcce52" +
  "1c";

/**
 * Create a dummy cosigner (address key) signature for gas estimation.
 * @returns 65-byte hex signature (the keySignatureList entry of the cosigner key)
 */
export function createDummyCosignSignature(): string {
  return DUMMY_COSIGN_SIGNATURE;
}

/**
 * Create a full dummy signature for a cosigned master op (`updateKeys` and the other
 * master key operations): `abi.encode(uint8[] [0, 1], bytes[] [zkSignature, cosignerSignature])`.
 *
 * These are the finished `UserOperation.signature` bytes: use them when you assemble
 * a UserOperation yourself, or as a reference for the length and bytes of the
 * signature. `ZkapBuilder.setSignature` takes the index and signature lists instead
 * and encodes them itself; there,
 * `setSignature([...MASTER_OP_KEY_INDEX_LIST], [createDummyZkSignature(n), createDummyCosignSignature()])`
 * produces these same bytes.
 * @param proofCount - 1 for the initial master key (1-of-1 zk key), 3 for the
 *   operational master key (3-of-6 zk key, three proofs)
 * @returns ABI-encoded signature, 1120 bytes for one proof and 1760 bytes for three
 * @throws `AaOperationError` (`INPUT_OUT_OF_RANGE`) when `proofCount` is not 1 or 3
 */
export function createDummyMasterOpSignature(proofCount: 1 | 3): string {
  if (proofCount !== 1 && proofCount !== 3) {
    throw new AaOperationError({
      code: AaOperationErrorCode.INPUT_OUT_OF_RANGE,
      operation: "create_dummy_master_op_signature",
      message: `proofCount must be 1 or 3, got ${String(proofCount)}`,
    });
  }
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint8[]", "bytes[]"],
    [
      [...MASTER_OP_KEY_INDEX_LIST],
      [createDummyZkSignature(proofCount), createDummyCosignSignature()],
    ]
  );
}
