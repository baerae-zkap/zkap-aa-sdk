/**
 * Loader for the package's master-key known-answer vectors
 * (`fixtures/master-key-cosign-vectors.json`). Read with `fs` rather than a JSON
 * import: JSON is not a program root of the package build (see tsconfig.json).
 */
import fs from "fs";
import path from "path";

export const VECTORS_PATH = path.resolve(__dirname, "../../../../fixtures/master-key-cosign-vectors.json");

export interface VectorPasskey {
  x: string;
  y: string;
  credentialId: string;
  rpId: string;
  rpIdHash: string;
  origin: string;
  requireUV: boolean;
}

export interface VectorZk {
  n: string;
  k: string;
  hAudList: string;
  anchor: string[];
}

export interface MasterKeyVectors {
  inputs: {
    contracts: {
      zkVerifier1of1: string;
      zkVerifier3of6: string;
      addressKeyLogic: string;
      webAuthnLogic: string;
      merkleTreeDirectory: string;
      factory: string;
      accountImplementation: string;
    };
    initialMaster: { threshold: number; weights: number[]; zk: VectorZk };
    operationalMaster: { threshold: number; weights: number[]; zk: VectorZk };
    txKey: { threshold: number; weights: number[] };
    cosigner: string;
    passkey: VectorPasskey;
    newPasskey: VectorPasskey;
    salt: string;
  };
  outputs: {
    initialMaster: string;
    operationalMaster: string;
    txKey: string;
    reconstructedMaster: string;
    newTxKey: string;
    walletAddress: string;
    onchainGetAnchor: string[];
    signatureLength: { initialMasterOp: number; operationalMasterOp: number };
  };
}

export function readVectorsFile(): Buffer {
  return fs.readFileSync(VECTORS_PATH);
}

export function loadVectors(): MasterKeyVectors {
  return JSON.parse(readVectorsFile().toString("utf8")) as MasterKeyVectors;
}
