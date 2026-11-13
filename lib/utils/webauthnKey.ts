import { ethers } from "ethers";
import { AaOperationError, AaOperationErrorCode } from "../errors";
import { toURLEncode } from "./base64url";

/** A P-256 public key as the two affine coordinates, hex (with or without `0x`). */
export interface P256Coordinates {
  x: string;
  y: string;
}

/** JSON Web Key for a P-256 public key — what `crypto.subtle.importKey("jwk", …)` takes. */
export interface EcP256Jwk {
  kty: "EC";
  crv: "P-256";
  /** base64url, 32 bytes, no padding. */
  x: string;
  /** base64url, 32 bytes, no padding. */
  y: string;
}

/**
 * COSE_Key header for an ES256 (P-256) public key. The layout is fixed, so the
 * encoder needs no CBOR library:
 *
 * ```
 * a5                     map(5)
 *   01 02                kty : 2   (EC2)
 *   03 26                alg : -7  (ES256)
 *   20 01                crv : 1   (P-256)
 *   21 5820 <x 32 bytes> x
 *   22 5820 <y 32 bytes> y
 * ```
 */
const COSE_ES256_PREFIX = "a5010203262001215820";
const COSE_Y_MARKER = "225820";

/**
 * Normalize a hex value to a canonical 32-byte form: `0x`-prefixed, lowercase,
 * left-padded to 64 hex characters.
 *
 * On-chain coordinates and hashes can reach a caller with leading zeros
 * stripped (e.g. `0x1` for a coordinate that starts with 31 zero bytes) — COSE
 * and JWK need the full 32 bytes, and hash comparison needs one spelling.
 *
 * @throws `AaOperationError` (`INPUT_INVALID_FORMAT`) when the input is empty,
 *   not hex, or longer than 32 bytes.
 */
export function normalizeBytes32(hex: string): string {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (raw.length === 0 || raw.length > 64 || !/^[0-9a-fA-F]+$/.test(raw)) {
    throw new AaOperationError({
      code: AaOperationErrorCode.INPUT_INVALID_FORMAT,
      operation: "normalize_bytes32",
      message: `expected up to 32 bytes of hex, got "${hex}"`,
    });
  }
  return `0x${raw.toLowerCase().padStart(64, "0")}`;
}

/**
 * WebAuthn rpIdHash for a relying-party id: `SHA-256(UTF-8(rpId))`. This is
 * the value `AccountKeyWebAuthn.getKeyData` returns as `allowedRpIdHash`.
 */
export function rpIdHashOf(rpId: string): string {
  return ethers.sha256(ethers.toUtf8Bytes(rpId));
}

/**
 * Origin hash as stored by `AccountKeyWebAuthn.register`:
 * `keccak256(UTF-8(origin))`. Note this is keccak256, not SHA-256 — the
 * contract hashes the origin bytes it receives, so the same function must be
 * used to compare against `allowedOriginHash`.
 */
export function originHashOf(origin: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(origin));
}

/**
 * Encode P-256 coordinates as a COSE_Key (ES256) — the byte format a WebAuthn
 * registration hands back as `credentialPublicKey`, and what
 * `WebAuthnNewKeyParams.credentialPubkey` expects. 77 bytes, `0x`-prefixed hex.
 */
export function toCosePublicKey({ x, y }: P256Coordinates): string {
  return `0x${COSE_ES256_PREFIX}${normalizeBytes32(x).slice(2)}${COSE_Y_MARKER}${normalizeBytes32(y).slice(2)}`;
}

/**
 * Encode P-256 coordinates as a JWK (`{ kty: "EC", crv: "P-256", x, y }` with
 * base64url coordinates), the shape browsers and most WebAuthn libraries
 * consume directly.
 */
export function toJwkPublicKey({ x, y }: P256Coordinates): EcP256Jwk {
  const encode = (coordinate: string): string =>
    toURLEncode(ethers.encodeBase64(ethers.getBytes(normalizeBytes32(coordinate))));
  return { kty: "EC", crv: "P-256", x: encode(x), y: encode(y) };
}

/** Fields of a WebAuthn key registration, with the public key as P-256 coordinates. */
export interface WebAuthnKeyInitFields {
  /** 32-byte hex coordinates. */
  x: string;
  y: string;
  credentialId: string;
  /** 32-byte hex `SHA-256(rpId)`. */
  rpIdHash: string;
  origin: string;
  requireUV: boolean;
}

/**
 * `AccountKeyWebAuthn.register` init data:
 * `abi.encode(bytes abi.encode((bytes32 x, bytes32 y, string credentialId)), bytes32 rpIdHash, bytes origin, bool requireUV)`.
 *
 * The single encoder for a WebAuthn key: the COSE path of `AccountKeyBuilder` and the
 * passkey slots of the master/tx key builders both end here, so the same key always
 * encodes to the same bytes.
 */
export function encodeWebAuthnKeyInitData({
  x,
  y,
  credentialId,
  rpIdHash,
  origin,
  requireUV,
}: WebAuthnKeyInitFields): string {
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const encodedKey = abiCoder.encode(["tuple(bytes32,bytes32,string)"], [[x, y, credentialId]]);
  return abiCoder.encode(
    ["bytes", "bytes32", "bytes", "bool"],
    [
      encodedKey,
      ethers.hexlify(ethers.getBytes(rpIdHash)),
      ethers.hexlify(ethers.toUtf8Bytes(origin)),
      requireUV,
    ]
  );
}
