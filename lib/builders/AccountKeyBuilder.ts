/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-duplicate-enum-values */
import { ethers } from "ethers";
import {
  CompositeAccountKeyTypes,
  KeyInfo,
  KeyData,
  AddressKeyData,
  WebAuthnKeyData,
  OAuthRS256KeyData,
  ZkOAuthRS256KeyData,
  PrimitiveAccountKeyTypes,
  AddressKeyInfo,
  Secp256k1KeyInfo,
  Secp256r1KeyInfo,
  WebAuthnKeyInfo,
  OAuthRS256KeyInfo,
  ZkOAuthRS256KeyInfo,
} from "../types/AccountKey";
import crypto from "../utils/crypto";
import { encodeWebAuthnKeyInitData } from "../utils/webauthnKey";
import { AaOperationError, AaOperationErrorCode } from "../errors";
/* Copied from @simplewebauthn/server/src/helpers/iso/isoCBOR.ts */
import * as tinyCbor from "@levischuck/tiny-cbor";

enum COSEKEYS {
  kty = 1,
  alg = 3,
  // EC2 key parameters
  crv = -1,
  x = -2,
  y = -3,
  // RSA key parameters (intentionally same values as EC2 per COSE spec RFC 8152)
  n = -1,  // same as crv: COSE uses context-dependent integers
  e = -2,  // same as x: distinguish by kty (EC2=2, RSA=3)
}

enum COSEKTY {
  OKP = 1,
  EC2 = 2,
  RSA = 3,
}

enum COSEALG {
  ES256 = -7,
  EdDSA = -8,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
  ES256K = -47,
  RS256 = -257,
  RS384 = -258,
  RS512 = -259,
  RS1 = -65535,
}

type COSEPublicKey = {
  // Getters
  get(key: COSEKEYS.kty): COSEKTY | undefined;
  get(key: COSEKEYS.alg): COSEALG | undefined;
  // Setters
  set(key: COSEKEYS.kty, value: COSEKTY): void;
  set(key: COSEKEYS.alg, value: COSEALG): void;
};

type COSEPublicKeyEC2 = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.crv): number | undefined;
  get(key: COSEKEYS.x): Uint8Array | undefined;
  get(key: COSEKEYS.y): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.crv, value: number): void;
  set(key: COSEKEYS.x, value: Uint8Array): void;
  set(key: COSEKEYS.y, value: Uint8Array): void;
};

export class AccountKeyBuilder {
  private threshold: number;
  private keys: KeyInfo[];
  private encodedKey: string;

  constructor(threshold?: number, keys?: KeyInfo[]) {
    if (threshold === undefined || keys === undefined) {
      // do nothing
      this.threshold = 0;
      this.keys = [];
      this.encodedKey = "";
    } else {
      // Set key values
      this.threshold = threshold;
      this.keys = keys;
      this.checkThreshold();

      this.encodedKey = this.setEncodedKeyData(this.threshold, this.keys);
    }
  }

  /**
   * Decode and return the first item in a sequence of CBOR-encoded values
   *
   * @param input The CBOR data to decode
   * @param asObject (optional) Whether to convert any CBOR Maps into JavaScript Objects. Defaults to
   * `false`
   */
  private decodeCborFirstItem<Type>(input: Uint8Array): Type {
    // Make a copy so we don't mutate the original
    const _input = new Uint8Array(input);
    const decoded = tinyCbor.decodePartialCBOR(_input, 0) as [Type, number];

    const [first] = decoded;

    return first;
  }

  private isCOSEKty(kty: number | undefined): kty is COSEKTY {
    return Object.values(COSEKTY).indexOf(kty as COSEKTY) >= 0;
  }

  private isCOSEPublicKeyEC2(
    cosePublicKey: COSEPublicKey
  ): cosePublicKey is COSEPublicKeyEC2 {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    return this.isCOSEKty(kty) && kty === COSEKTY.EC2;
  }

  private decodeCredentialPublicKey(publicKey: Uint8Array): COSEPublicKey {
    return this.decodeCborFirstItem<COSEPublicKey>(publicKey);
  }

  encodeCall(
    contractInterface: ethers.Interface,
    functionName: string,
    args: readonly unknown[]
  ): string {
    // Encode function signature and arguments
    return contractInterface.encodeFunctionData(functionName, args);
  }

  getEncodedKey(): string {
    return this.encodedKey;
  }

  /**
   * Computes the hAudList value from a list of OAuth audiences.
   * Generates the value to pass to the ZkOAuthRS256KeyData.hAudList field.
   *
   * @param audiences - Array of OAuth audience strings (e.g. ['https://example.com'])
   * @returns ABI-encoded keccak256 hash (uint256 hex string)
   */
  static computeHAudList(audiences: string[]): string {
    if (!audiences || audiences.length === 0) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_OUT_OF_RANGE,
        operation: "compute_h_aud_list",
        message: 'computeHAudList: audiences must be a non-empty array',
      });
    }
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(['string[]'], [audiences])
    );
  }

  // Encodes ZkOAuthRS256 key data matching on-chain abi.decode(bytes,(uint256,uint256,uint256,uint256[]))
  private _encodeZkOAuthRS256Key(
    n: number,
    k: number,
    hAudList: string,
    commitment: string[]
  ): string {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(
      ["uint256", "uint256", "uint256", "uint256[]"],
      [n, k, hAudList, commitment]
    );
    return encoded;
  }

  getEncodedZkOAuthRS256KeyInitData(
    zkOAuthRS256KeyData: ZkOAuthRS256KeyData
  ): string {
    const { commitment, n, k, hAudList, poseidonMerkleTreeDirectory } =
      zkOAuthRS256KeyData;

    if (!hAudList || hAudList.length === 0 || hAudList === '0x') {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID,
        operation: "get_encoded_zk_o_auth_rs256_key_init_data",
        message:
          "ZkOAuthRS256KeyData.hAudList is required and must be a non-zero value. " +
          "Use AccountKeyBuilder.computeHAudList(audiences) to generate the correct value.",
      });
    }

    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = this._encodeZkOAuthRS256Key(n, k, hAudList, commitment);

    // register(KeyPurpose, bytes) initData: abi.encode(bytes encoded, address directory)
    return abiCoder.encode(
      ["bytes", "address"],
      [encoded, poseidonMerkleTreeDirectory]
    );
  }

  getEncodedAddressKeyInitData(addressKeyData: AddressKeyData): string {
    // register(KeyPurpose, bytes) initData: abi.encode(address signer)
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    return abiCoder.encode(["address"], [addressKeyData.signerAddress]);
  }

  getEncodedWebAuthnKeyInitData(webAuthnKeyData: WebAuthnKeyData): string {
    const { credentialPubkey, credentialId, rpIdHash, origin, requireUV = false } = webAuthnKeyData;
    return this.getEncodedWebAuthnKey(credentialPubkey, credentialId, rpIdHash, origin, requireUV);
  }

  setEncodedKeyData(threshold: number, keyInfoList: KeyInfo[]): string {
    // Prepare each list separately
    const logicList: string[] = [];
    const keyInitDataList: string[] = [];
    const weightList: number[] = [];
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();

    // Iterate through the KeyInfo list and add data to each list
    for (const keyInfo of keyInfoList) {
      logicList.push(keyInfo.logicContract);
      weightList.push(keyInfo.weight);
      let keyInitData = "";
      if (keyInfo.keyType === PrimitiveAccountKeyTypes.keyZkOAuthRS256) {
        const zkOAuthRS256KeyData = keyInfo.keyData as ZkOAuthRS256KeyData;
        keyInitData =
          this.getEncodedZkOAuthRS256KeyInitData(zkOAuthRS256KeyData);
      } else if (keyInfo.keyType === PrimitiveAccountKeyTypes.keyAddress) {
        const addressKeyData = keyInfo.keyData as AddressKeyData;
        keyInitData = this.getEncodedAddressKeyInitData(addressKeyData);
      } else if (keyInfo.keyType === PrimitiveAccountKeyTypes.keyWebAuthn) {
        const webAuthnKeyData = keyInfo.keyData as WebAuthnKeyData;
        keyInitData = this.getEncodedWebAuthnKeyInitData(webAuthnKeyData);
      } else {
        throw new AaOperationError({
          code: AaOperationErrorCode.INPUT_UNSUPPORTED,
          operation: "set_encoded_key_data",
          message: `Unsupported key type: ${keyInfo.keyType}`,
        });
      }
      keyInitDataList.push(keyInitData);
    }

    const encoded = abiCoder.encode(
      ["uint8", "address[]", "bytes[]", "uint8[]"],
      [threshold, logicList, keyInitDataList, weightList]
    );

    return encoded;
  }

  setEncodedInitData(threshold: number, keyInfoList: KeyInfo[]): string {
    return this.setEncodedKeyData(threshold, keyInfoList);
  }

  private checkThreshold(): boolean {
    if (this.threshold <= 0) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_THRESHOLD_INVALID,
        operation: "check_threshold",
        message: "Threshold must be greater than 0",
      });
    }
    let weightSum = 0;
    for (const key of this.keys) {
      weightSum += key.weight;
    }
    if (weightSum < this.threshold) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_THRESHOLD_INVALID,
        operation: "check_threshold",
        message: "Threshold is greater than the sum of weights",
      });
    }
    return true;
  }

  getEncodedAddressKey(signerAddress: string): string {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(["address"], [signerAddress]);
    return encoded;
  }

  getEncodedWebAuthnKey(
    credentialPubkey: string,
    credentialId: string,
    rpIdHash: string,
    origin: string,
    // requireUV: false = backward-compat default (UV not required).
    // Set to true to enforce user verification (biometric/PIN required on authenticator).
    requireUV: boolean = false
  ): string {
    const pubkey = this.decodeCredentialPublicKey(
      ethers.getBytes(credentialPubkey)
    );
    if (!this.isCOSEPublicKeyEC2(pubkey)) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_KEY_INVALID,
        operation: "get_encoded_web_authn_key",
        message: "Not EC2",
      });
    }
    const alg = (pubkey as COSEPublicKeyEC2).get(COSEKEYS.alg);
    const crv = (pubkey as COSEPublicKeyEC2).get(COSEKEYS.crv);
    /* istanbul ignore next */
    if (alg !== -7) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_KEY_INVALID,
        operation: "get_encoded_web_authn_key",
        message: `Unsupported COSE algorithm: ${alg}. Expected ES256 (-7).`,
      });
    }
    /* istanbul ignore next */
    if (crv !== 1) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_KEY_INVALID,
        operation: "get_encoded_web_authn_key",
        message: `Unsupported COSE curve: ${crv}. Expected P-256 (1).`,
      });
    }
    const x = (pubkey as COSEPublicKeyEC2).get(COSEKEYS.x) as Uint8Array;
    const y = (pubkey as COSEPublicKeyEC2).get(COSEKEYS.y) as Uint8Array;
    /* istanbul ignore next */
    if (!x || x.length !== 32) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_KEY_INVALID,
        operation: "get_encoded_web_authn_key",
        message: `Invalid COSE public key: x coordinate must be 32 bytes, got ${x?.length}`,
      });
    }
    /* istanbul ignore next */
    if (!y || y.length !== 32) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_KEY_INVALID,
        operation: "get_encoded_web_authn_key",
        message: `Invalid COSE public key: y coordinate must be 32 bytes, got ${y?.length}`,
      });
    }
    return encodeWebAuthnKeyInitData({
      x: ethers.hexlify(x),
      y: ethers.hexlify(y),
      credentialId,
      rpIdHash,
      origin,
      requireUV,
    });
  }

  getEncodedOAuthKey(
    iss: string,
    _kid: string, // reserved, not currently encoded in ABI
    sub: string,
    email: string,
    verifyEmail: boolean,
    verifySub: boolean
  ): string {
    const key = {
      issuer: ethers.hexlify(ethers.toUtf8Bytes(iss)),
      subToVerify: ethers.hexlify(ethers.toUtf8Bytes(sub)),
      emailToVerify: ethers.hexlify(ethers.toUtf8Bytes(email)),
      verifyEmail,
      verifySub,
    };

    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(
      ["tuple(bytes,bytes,bytes,bool,bool)"],
      [
        [
          key.issuer,
          key.subToVerify,
          key.emailToVerify,
          key.verifyEmail,
          key.verifySub,
        ],
      ]
    );
    return encoded;
  }

  private getEncodedEcKey(pubkey: string): string {
    const pubkeyBytes = ethers.getBytes(pubkey);
    /* istanbul ignore next */
    if (pubkeyBytes.length !== 65 || pubkeyBytes[0] !== 0x04) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_KEY_INVALID,
        operation: "get_encoded_ec_key",
        message: `Invalid uncompressed public key: expected 65 bytes with 0x04 prefix, got ${pubkeyBytes.length} bytes`,
      });
    }
    const x = ethers.hexlify(pubkeyBytes.slice(1, 33));
    const y = ethers.hexlify(pubkeyBytes.slice(33, 65));

    // Validate that x, y coordinates are non-zero (invalid public key if zero)
    const xBigInt = BigInt(x);
    const yBigInt = BigInt(y);
    if (xBigInt === 0n || yBigInt === 0n) {
      throw new AaOperationError({
        code: AaOperationErrorCode.SIGNER_KEY_INVALID,
        operation: "get_encoded_ec_key",
        message: "Invalid public key: x and y coordinates must be non-zero",
      });
    }

    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(["uint256", "uint256"], [x, y]);
    return encoded;
  }

  getEncodedSecp256k1Key(pubkey: string): string {
    return this.getEncodedEcKey(pubkey);
  }

  getEncodedSecp256r1Key(pubkey: string): string {
    return this.getEncodedEcKey(pubkey);
  }

  getEncodedZkOAuthRS256Key(userSpecificVk: string[]): string {
    if (userSpecificVk.length !== 16) {
      throw new AaOperationError({
        code: AaOperationErrorCode.CRYPTO_INVALID_LENGTH,
        operation: "get_encoded_zk_o_auth_rs256_key",
        message: "userSpecificVk must be 16 elements",
      });
    }

    const userSpecificVkArray = crypto.userSpecificVkParser(userSpecificVk);

    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(
      [
        "tuple((uint256,uint256,uint256,uint256) g2mu, (uint256,uint256,uint256,uint256) g2muX, (uint256,uint256,uint256,uint256) g2muZ, (uint256,uint256,uint256,uint256) vacc)",
      ],
      [userSpecificVkArray]
    );
    return encoded;
  }

  getEncodedCommitment(commitment: string[]): string {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(["uint256[]"], [commitment]);
    return encoded;
  }
}
