// Type definitions
export * from "./types/UserOperation";
export * from "./types/AccountKey";
export * from "./types/Swap";
export * from "./types/abi";

// Account classes
export { BaseAccount } from "./account/BaseAccount";
export { ZkapAccount } from "./account/ZkapAccount";

// Builder classes
export { BaseAccountBuilder } from "./builders/BaseAccountBuilder";
export { AccountKeyBuilder } from "./builders/AccountKeyBuilder";
export { ZkapBuilder } from "./builders/ZkapBuilder";
export { SwapBuilder } from "./builders/SwapBuilder";
export { CallDataBuilder } from "./builders/CallDataBuilder";
export { ZkapCreator } from "./builders/ZkapCreator";
export { ZkapFactoryBuilder } from "./builders/ZkapFactoryBuilder";
export { OneInchAggregator } from "./builders/aggregators/OneInchAggregator";

// Signer classes
export { AddressKeySigner } from "./signers/AddressKeySigner";
export { PasskeySigner } from "./signers/PasskeySigner";
export { ZkOidcSigner } from "./signers/ZkOidcSigner";

// Paymaster service
export { PaymasterService, PaymasterMode } from "./utils/PaymasterService";
export type { PaymasterServiceConfig, PaymasterDataResponse } from "./utils/PaymasterService";

// Utility functions and interfaces
export * from "./utils/crypto";
export * from "./utils/signature";
export * from "./utils/base64url";
export { IUserOpSigner } from "./utils/IUserOpSigner";
export {
  packUserOperation,
  unpackUserOperation,
  toPimlicoFormat,
  createDummyPasskeySignature,
  createDummyZkSignature,
  createDummyCosignSignature,
  createDummyMasterOpSignature,
} from "./utils/userOpUtils";

// Cosigned master key: fixed layouts, builders and strict parsers
export {
  MASTER_KEY_INDEX,
  INITIAL_MASTER_KEY,
  OPERATIONAL_MASTER_KEY,
  PASSKEY_TX_KEY,
  MASTER_OP_KEY_INDEX_LIST,
  MASTER_OP_SIGNER_KEY_TYPES,
  MASTER_OP_SIGNATURE_LENGTH,
} from "./master/constants";
export type { MasterKeyShape, TxKeyShape } from "./master/constants";
export {
  buildInitialMasterKey,
  buildOperationalMasterKey,
  buildPasskeyTxKey,
  encodePasskeyKeyInitData,
} from "./master/encoding";
export type {
  UintInput,
  ZkKeyInput,
  PasskeyKeyInput,
  InitialMasterKeyContracts,
  OperationalMasterKeyContracts,
  InitialMasterKeyParams,
  OperationalMasterKeyParams,
  PasskeyTxKeyParams,
} from "./master/encoding";
export {
  decodeKeySet,
  parseInitialMasterKey,
  parseOperationalMasterKey,
  parsePasskeyTxKey,
} from "./master/parsing";
export type {
  DecodedKeySet,
  ParsedZkKey,
  ParsedCosignerKey,
  ParsedPasskeyKey,
  ParsedInitialMasterKey,
  ParsedOperationalMasterKey,
  ParsedPasskeyTxKey,
} from "./master/parsing";
export { classifyMasterKey, reconstructOperationalMasterKey } from "./master/onchain";
export type {
  MasterKeyExpectation,
  MasterKeyKind,
  MasterKeyClassification,
  ReconstructOperationalMasterKeyParams,
} from "./master/onchain";
export { computeSalt } from "./utils/salt";
export {
  calcAltoRequiredPvg,
  calibrateBundlerPvg,
  ALTO_DEFAULT_OVERHEADS,
} from "./utils/bundlerPvg";
export type {
  AltoGasOverheads,
  AltoRequiredPvgOptions,
  CalibrateBundlerPvgOptions,
} from "./utils/bundlerPvg";

// Bundler client
export { BundlerClient } from "./client/BundlerClient";
export { Erc4337BundlerProvider } from "./client/BundlerProvider";
export type { Erc4337BundlerProviderConfig } from "./client/BundlerProvider";
export type { BundlerProvider, UserOpStatus, UserOpReceipt } from "./client/types";

// Error model (ZkapAaError hierarchy + catalog + factories)
export * from "./errors";
export { safeStringify } from "./utils/safeStringify";

// Pimlico format (for external bundler integration)
export type { PimlicoUserOperation, PimlicoGasEstimate } from "./types/UserOperation";

// Account reader
export { AccountReader } from "./reader/AccountReader";
export type { AccountReaderConfig, AccountReaderOptions } from "./reader/AccountReader";
export type {
  TxKeySlots,
  ReadVia,
  TxKeyInfo,
  MasterKeyInfo,
  OnchainKeyEntry,
  OnchainKeySet,
  OnchainKeyState,
  OnchainZkKeyData,
  WebAuthnKeyData as AccountWebAuthnKeyData,
  KeyType,
} from "./reader/types";
export { buildPasskeysResult, normalizeOptions as normalizePasskeyOptions } from "./reader/passkeys";
export type {
  GetPasskeysOptions,
  NormalizedPasskeyOptions,
  PasskeyServiceIdentity,
  PasskeyKey,
  PasskeyPublicKey,
  PasskeysResult,
} from "./reader/passkeys";
export { MULTICALL3_ADDRESS, ethCallFromProvider } from "./reader/transport";
export type { EthCall, Call3, Result3, BatchCallerOptions } from "./reader/transport";
export { rpIdHashOf, originHashOf, toCosePublicKey, toJwkPublicKey, normalizeBytes32 } from "./utils/webauthnKey";
export type { P256Coordinates, EcP256Jwk } from "./utils/webauthnKey";

// TxKey helper
export { TxKeyHelper } from "./helper/TxKeyHelper";
export type { WebAuthnNewKeyParams, ExistingKeyEntry } from "./helper/TxKeyHelper";

// Provider config
export { ZkapProviderConfig } from "./config/ZkapProviderConfig";
export type { SocialProvider, ProviderEntry, ZkapProviderConfigOptions } from "./config/ZkapProviderConfig";
export type { ProviderPreset } from "./config/presets";
