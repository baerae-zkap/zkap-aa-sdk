import { BaseAccountBuilder } from "./BaseAccountBuilder";
import { CallDataBuilder } from "./CallDataBuilder";
import { PrimitiveAccountKeyTypes } from "../types/AccountKey";
import { UserOperation } from "../types/UserOperation";
import { AaOperationError, AaOperationErrorCode, AaFetchError, AaFetchErrorCode } from "../errors";
import {
  ERC20ABI,
  ZkapAccountABI,
  ZkapAccountFactoryABI,
} from "../types/abi";
import { ethers } from "ethers";
import { MASTER_OP_SIGNER_KEY_TYPES } from "../master/constants";
import {
  PaymasterService,
  PaymasterServiceConfig,
} from "../utils/PaymasterService";

type BatchCallArg = { target: string; value: bigint; data: string };

export interface ZkapAccountInfo {
  chainId: number;
  entryPoint: string;
  enUrl: string;
  /**
   * Paymaster configuration (enables gas sponsorship)
   * When set, autoFillUserOp will automatically populate paymaster-related data
   */
  paymaster?: PaymasterServiceConfig;
  /**
   * Upper bound for `gasLimit` in internal `eth_estimateGas` calls.
   * Defaults to 15M. Some public RPCs (e.g. Base Sepolia) reject unbounded
   * estimate requests with "intrinsic gas too high" — an explicit cap avoids this.
   * Set to `0n` to disable injection and rely on the node's default behavior
   * (escape hatch for chains with conflicting gas semantics).
   */
  rpcEstimateGasCap?: bigint;
}

export class ZkapBuilder extends BaseAccountBuilder {
  // GAS_BUFFER: covers wallet execute() dispatch overhead and nonce SSTORE
  // for contracts not yet deployed, empirically measured
  static readonly GAS_BUFFER = BigInt(25000);

  static readonly ADDRESS_KEY_VALIDATION_GAS = 15000n;
  static readonly SECP256K1_KEY_VALIDATION_GAS = 15000n;  // secp256k1 ECDSA, ecrecover level
  static readonly SECP256R1_KEY_VALIDATION_GAS = 470000n; // P-256 ECDSA, similar to WebAuthn
  static readonly WEB_AUTHN_KEY_VALIDATION_GAS = 150000n; // mainnet-measured ~97k with the P256VERIFY precompile (EIP-7951) × 1.5 margin; was 470000n from the pre-precompile pure-Solidity path (~450k)
  static readonly OAUTH_RS256_KEY_VALIDATION_GAS = 350000n; // RSA-2048 signature verification
  /**
   * zk-OAuth validation with the shuffled 3-of-6 circuit — the conservative default,
   * used whenever the proof count cannot be determined from the signature.
   * Sepolia-measured `validateUserOp` (EntryPoint v0.8, updateMasterKey / updateTxKey):
   * 753,719–753,790 gas across 6 ops → x1.2 in autoFillUserOp gives a 1,110,000
   * verificationGasLimit (~1.43x measured). Was 1,000,000.
   */
  static readonly ZK_OAUTH_RS256_KEY_VALIDATION_GAS = 900000n;
  /**
   * zk-OAuth validation with a SINGLE proof (1-of-1) — the wallet-deployment signature.
   * Sepolia-measured `validateUserOp`: 250,215 (sponsored) / 278,797 (user-paid).
   * A deploy op's 3-of-6 verification happens inside `updateKeys` EXECUTION (callGasLimit),
   * not in validation, which is why the two profiles differ this much.
   */
  static readonly ZK_OAUTH_RS256_SINGLE_PROOF_VALIDATION_GAS = 400000n;

  /**
   * callGasLimit (before `GAS_BUFFER`) for `updateKeys` sent together with initCode, where
   * the wallet does not exist yet and on-chain estimation is impossible.
   *
   * On a local test chain the smallest callGasLimit with which this `updateKeys` (installing
   * the 3-of-6 zk + cosigner + passkey master key) succeeded was 1,202,822; this keeps
   * roughly 1.5x of that. Under-declaring is the expensive failure: execution reverts
   * on-chain, the op is still charged, and the wallet stays deployed with its initial keys.
   * Over-declaring is cheap but not free: EntryPoint v0.8 charges 10% of the unused
   * callGasLimit as a penalty. Re-measure whenever the contracts are redeployed.
   */
  static readonly UPDATE_KEYS_CALL_GAS = 1_800_000n;

  // Estimated signature sizes per key type (bytes) — used to generate dummy signatures for preVerificationGas estimation
  private static readonly ESTIMATED_SIG_SIZES: Record<number, number> = {
    1: 65,     // keyAddress: ECDSA (r:32 + s:32 + v:1)
    2: 65,     // keySecp256k1: ECDSA
    3: 100,    // keySecp256r1: DER-encoded P-256
    4: 800,    // keyWebAuthn: authenticatorData + clientDataJSON + DER sig + 4x uint256
    5: 300,    // keyOAuthRS256: RSA-2048 signature + metadata
    6: 2000,   // keyZkOAuthRS256: ZK proof (large)
  };

  protected factoryInterface: ethers.Interface = new ethers.Interface(
    ZkapAccountFactoryABI
  );
  protected provider: ethers.JsonRpcProvider;
  protected readonly enUrl: string;
  private signerKeyTypes: number[] | undefined;
  private paymasterService: PaymasterService | undefined;

  constructor({ chainId, entryPoint, enUrl, paymaster, rpcEstimateGasCap }: ZkapAccountInfo) {
    try {
      new URL(enUrl);
    } catch {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID_URL,
        operation: "init_zkap_builder",
        message: `Invalid enUrl: "${enUrl}". Must be a valid URL.`,
      });
    }
    const provider = new ethers.JsonRpcProvider(enUrl);
    super(chainId, entryPoint, provider, rpcEstimateGasCap);
    this.provider = provider;
    this.enUrl = enUrl;

    // Create PaymasterService instance if paymaster config is provided
    if (paymaster) {
      const paymasterServiceConfig: PaymasterServiceConfig = {
        serverUrl: paymaster.serverUrl,
        paymasterAddress: paymaster.paymasterAddress,
        chainId: this.chainId,
        mode: paymaster.mode,
        tokenAddress: paymaster.tokenAddress,
      };
      this.paymasterService = new PaymasterService(paymasterServiceConfig);
      // Set paymaster address
      this.setPaymaster(paymaster.paymasterAddress);
    }
  }

  getRequiredPrefund(): string {
    if (
      !this.userOp.verificationGasLimit ||
      !this.userOp.callGasLimit ||
      !this.userOp.paymasterVerificationGasLimit ||
      !this.userOp.paymasterPostOpGasLimit ||
      !this.userOp.preVerificationGas ||
      !this.userOp.maxFeePerGas
    ) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "get_required_prefund",
        message:
          "Required gas fields not set: verificationGasLimit, callGasLimit, paymasterVerificationGasLimit, paymasterPostOpGasLimit, preVerificationGas, and maxFeePerGas must all be set.",
      });
    }
    const requiredGas =
      BigInt(this.userOp.verificationGasLimit) +
      BigInt(this.userOp.callGasLimit) +
      BigInt(this.userOp.paymasterVerificationGasLimit) +
      BigInt(this.userOp.paymasterPostOpGasLimit) +
      BigInt(this.userOp.preVerificationGas);

    return ethers.toBeHex(
      requiredGas * BigInt(this.userOp.maxFeePerGas)
    );
  }

  private normalizeExecuteBatchArgs(parsedTx: ethers.TransactionDescription): {
    destList: string[];
    valueList: bigint[];
    funcList: string[];
  } {
    if (parsedTx.fragment.inputs.length === 1) {
      // New style: executeBatch({address target, uint256 value, bytes data}[] calls)
      const calls = parsedTx.args[0];
      return {
        destList: calls.map((c: BatchCallArg) => c.target),
        valueList: calls.map((c: BatchCallArg) => c.value),
        funcList: calls.map((c: BatchCallArg) => c.data),
      };
    } else {
      // Old style: executeBatch(address[] dest, uint256[] value, bytes[] func)
      // @deprecated This branch is kept for backward compatibility with older ZkapAccount contracts.
      //             New contracts use the single array argument (BatchCallArg[]) format.
      return {
        destList: parsedTx.args[0],
        valueList: parsedTx.args[1],
        funcList: parsedTx.args[2],
      };
    }
  }

  /**
   * Number of Groth16 proofs carried by the currently set zk-OAuth signature
   * (1 = 1-of-1, 3 = shuffled 3-of-6), or `null` when it cannot be determined.
   *
   * The signature present before `autoFillUserOp()` is a dummy built with the same
   * proof count as the real one (that is what `createDummyZkSignature` is for), so this
   * reads the right profile without a new API. Anything unexpected returns `null` and
   * the caller falls back to the conservative 3-of-6 budget.
   */
  private decodeZkProofCount(): number | null {
    const signature = this.userOp.signature;
    if (!signature || signature === "0x") {
      return null;
    }
    try {
      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
      const [, keySignatureList] = abiCoder.decode(
        ["uint8[]", "bytes[]"],
        signature
      );
      if (!keySignatureList || keySignatureList.length === 0) {
        return null;
      }
      const decodedProof = abiCoder.decode(
        ["uint256[6]", "uint256[]", "uint256[]", "uint256[8][]"],
        keySignatureList[0]
      );
      const proofs = decodedProof[3];
      return proofs.length > 0 ? proofs.length : null;
    } catch {
      return null;
    }
  }

  /** zk-OAuth verification budget for the signature currently set (see the constants). */
  private zkOAuthValidationGas(): bigint {
    return this.decodeZkProofCount() === 1
      ? ZkapBuilder.ZK_OAUTH_RS256_SINGLE_PROOF_VALIDATION_GAS
      : ZkapBuilder.ZK_OAUTH_RS256_KEY_VALIDATION_GAS;
  }

  private async estimateCallGasLimit(): Promise<string> {
    // Check if code exists at the sender address to determine whether it is deployed
    const code = await this.provider.getCode(this.userOp.sender as string);

    if (code !== "0x") {
      // Wallet is already deployed
      const callGasLimit = await this.estimateGasWithCap({
        from: this.entryPoint,
        to: this.userOp.sender,
        data: this.userOp.callData,
        value: ethers.parseEther("0"),
      });
      // updateKeys on a deployed wallet (resuming initialization, replacing the passkey)
      // gets a proportional margin. On a local test chain the plain estimate + GAS_BUFFER was
      // only ~9% (resume: smallest successful limit 1,179,660, node estimate 1,265,437) and
      // ~18% (passkey change: 582,509 / 663,641) above the smallest limit that succeeded;
      // × 1.2 + GAS_BUFFER leaves ~31% / ~41%. An under-declared limit reverts the execution
      // and throws away the zk proof the user just produced.
      // Every other selector keeps the plain estimate.
      const updateKeysSelector = new ethers.Interface(ZkapAccountABI).getFunction("updateKeys")?.selector;
      const callData = this.userOp.callData;
      if (
        updateKeysSelector &&
        typeof callData === "string" &&
        callData.length >= 10 &&
        callData.slice(0, 10).toLowerCase() === updateKeysSelector.toLowerCase()
      ) {
        return ethers.toBeHex(
          (callGasLimit * ZkapBuilder.GAS_ESTIMATE_MULTIPLIER) / ZkapBuilder.GAS_ESTIMATE_DIVISOR +
            ZkapBuilder.GAS_BUFFER
        );
      }
      return ethers.toBeHex(callGasLimit + ZkapBuilder.GAS_BUFFER);
    } else {
      // Wallet is not deployed and no initCode provided — invalid scenario
      if (!this.userOp.initCode || this.userOp.initCode === "0x") {
        throw new AaOperationError({
          code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
          operation: "estimate_call_gas_limit",
          message: "Wallet not deployed and no initCode provided",
        });
      }

      // initCode present but no callData (wallet creation only)
      if (!this.userOp.callData || this.userOp.callData === "0x") {
        const WALLET_CREATION_ONLY_CALL_GAS = 1000n; // minimum callGasLimit for wallet creation only
        return ethers.toBeHex(WALLET_CREATION_ONLY_CALL_GAS);
      }

      // Both initCode and callData are present
      const callData = this.userOp.callData as string;
      const iface = new ethers.Interface(ZkapAccountABI);

      try {
        const parsedTx = iface.parseTransaction({ data: callData });
        if (!parsedTx) {
          throw new AaOperationError({
            code: AaOperationErrorCode.ENCODE_PARSE_FAILED,
            operation: "estimate_call_gas_limit",
            message: "callData could not be parsed. Manual callGasLimit required.",
          });
        }
        switch (parsedTx.name) {
          case "execute": {
            const { dest, value, func } = parsedTx.args;
            const gasEstimate = await this.estimateGasWithCap({
              from: this.entryPoint,
              to: dest,
              data: func,
              value: value,
            });
            return ethers.toBeHex(gasEstimate + ZkapBuilder.GAS_BUFFER);
          }

          case "executeBatch": {
            const { destList, valueList, funcList } = this.normalizeExecuteBatchArgs(parsedTx);

            if (destList.length === 0) {
              return ethers.toBeHex(ZkapBuilder.GAS_BUFFER); // nothing to execute, return buffer only
            }

            const estimationPromises = destList.map((d: string, i: number) =>
              this.estimateGasWithCap({
                from: this.entryPoint,
                to: d,
                data: funcList[i],
                value: valueList[i],
              })
            );

            const estimates = await Promise.all(estimationPromises);
            const totalGas = estimates.reduce(
              (acc, val) => BigInt(acc) + BigInt(val),
              BigInt(0)
            );

            return ethers.toBeHex(totalGas + ZkapBuilder.GAS_BUFFER);
          }

          case "updateKeys": {
            // updateKeys(bytes encodedMasterKey, bytes encodedTxKey) sent with initCode:
            // the wallet is not deployed yet, so use the measured budget (see UPDATE_KEYS_CALL_GAS).
            return ethers.toBeHex(ZkapBuilder.UPDATE_KEYS_CALL_GAS + ZkapBuilder.GAS_BUFFER);
          }

          case "updateMasterKey": {
            // updateMasterKey(bytes encoded)
            // Fallback for cases with initCode (already deployed wallets handled above)
            const UPDATE_MASTER_KEY_GAS = BigInt(1000000);
            return ethers.toBeHex((UPDATE_MASTER_KEY_GAS + ZkapBuilder.GAS_BUFFER).toString());
          }

          case "updateTxKey": {
            // updateTxKey(bytes encoded)
            const UPDATE_TX_KEY_GAS = BigInt(1000000);
            return ethers.toBeHex((UPDATE_TX_KEY_GAS + ZkapBuilder.GAS_BUFFER).toString());
          }

          default:
            // Unsupported function: throw error to require manual handling.
            throw new AaOperationError({
              code: AaOperationErrorCode.ENCODE_PARSE_FAILED,
              operation: "estimate_call_gas_limit",
              message: `Unsupported function for gas estimation: ${parsedTx.name}`,
            });
        }
      } catch (error) {
        if (error instanceof Error) {
          throw error;
        }
        const original = typeof error === 'string' ? error : JSON.stringify(error);
        throw new AaOperationError({
          code: AaOperationErrorCode.ENCODE_PARSE_FAILED,
          operation: "estimate_call_gas_limit",
          message: `callData could not be parsed. Manual callGasLimit required. Original: ${original}`,
        });
      }
    }
  }

  updateUserOpCallDataForPaymasterERC20(
    dest: ethers.AddressLike,
    tokenAddress: ethers.AddressLike,
    value: ethers.BigNumberish
  ): this {
    if (!this.userOp.callData || this.userOp.callData === "0x") {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "update_user_op_call_data_for_paymaster_erc20",
        message: "Call data is not set",
      });
    }

    const callData = this.userOp.callData as string;
    // Determine whether callData is a call to ZkapAccount's execute or executeBatch function
    const iface = new ethers.Interface(ZkapAccountABI);
    const parsedTx = iface.parseTransaction({ data: callData });
    if (parsedTx?.name !== "execute" && parsedTx?.name !== "executeBatch") {
      throw new AaOperationError({
        code: AaOperationErrorCode.ENCODE_PARSE_FAILED,
        operation: "update_user_op_call_data_for_paymaster_erc20",
        message: `Call data is not a valid ZkapAccount function call. Expected 'execute' or 'executeBatch', but found '${parsedTx?.name}'.`,
      });
    }

    // Build callData for the transfer(address to, uint256 value) function call
    const erc20TransferCallData = new ethers.Interface(
      ERC20ABI
    ).encodeFunctionData("transfer", [dest, value]);

    if (parsedTx?.name === "execute") {
      // For an execute call: replace it with executeBatch and prepend the ERC20 transfer to the paymaster account
      const userRequiredDest = parsedTx?.args[0];
      const userRequiredValue = parsedTx?.args[1];
      const userRequiredFunc = parsedTx?.args[2];

      const callDataBuilder = new CallDataBuilder(ZkapAccountABI);
      const callData = callDataBuilder.encode("executeBatch(address[],uint256[],bytes[])", [
        [tokenAddress, userRequiredDest],
        [0, userRequiredValue],
        [erc20TransferCallData, userRequiredFunc],
      ]);
      this.userOp.callData = callData;
    } else if (parsedTx?.name === "executeBatch") {
      const { destList: userRequiredDestList, valueList: userRequiredValueList, funcList: userRequiredFuncList } = this.normalizeExecuteBatchArgs(parsedTx);
      const callDataBuilder = new CallDataBuilder(ZkapAccountABI);
      const callData = callDataBuilder.encode("executeBatch(address[],uint256[],bytes[])", [
        [tokenAddress, ...userRequiredDestList],
        [0, ...userRequiredValueList],
        [erc20TransferCallData, ...userRequiredFuncList],
      ]);
      this.userOp.callData = callData;
    }

    return this;
  }

  /**
   * Automatically fills gas fields of the UserOperation (nonce, callGasLimit, verificationGasLimit, preVerificationGas, maxFeePerGas, etc.).
   * If a Paymaster is configured, paymasterData will also be populated.
   *
   * @warning This method should only be called once per instance. Repeated calls may produce different gas estimates.
   *          Create a new ZkapBuilder instance if a new UserOp is needed.
   */
  async autoFillUserOp(nonceKey?: bigint): Promise<this> {
    /* istanbul ignore next */
    if (!this.provider) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_MISSING_DEPENDENCY,
        operation: "auto_fill_user_op",
        message: "Provider is not set. Please provide a valid RPC URL.",
      });
    }
    if (
      !this.userOp.sender ||
      !ethers.isAddress(this.userOp.sender) ||
      this.userOp.sender === ethers.ZeroAddress
    ) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "auto_fill_user_op",
        message: "Sender is not set or invalid. Please set a non-zero Ethereum address.",
      });
    }
    if (!ethers.isAddress(this.entryPoint) || this.entryPoint === ethers.ZeroAddress) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID_ADDRESS,
        operation: "auto_fill_user_op",
        message: "EntryPoint is invalid. Please provide a valid non-zero EntryPoint address.",
      });
    }
    if (!this.signerKeyTypes || this.signerKeyTypes.length === 0) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "auto_fill_user_op",
        message: "signerKeyTypes is not set. Call setSignerKeyTypes() before autoFillUserOp()",
      });
    }
    const feeData = await this.provider.getFeeData();
    if (!feeData) {
      throw new AaFetchError({
        code: AaFetchErrorCode.RESPONSE_SHAPE,
        operation: "auto_fill_user_op",
        service: "rpc",
        url: this.enUrl,
        method: "POST",
        message: "Failed to get fee data from provider",
      });
    }
    const maxFeePerGas = feeData.maxFeePerGas ?? feeData.gasPrice;
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas ?? feeData.gasPrice;
    /* istanbul ignore next */
    if (maxFeePerGas == null || maxPriorityFeePerGas == null) {
      throw new AaFetchError({
        code: AaFetchErrorCode.RESPONSE_SHAPE,
        operation: "auto_fill_user_op",
        service: "rpc",
        url: this.enUrl,
        method: "POST",
        message: "Failed to get fee data from provider",
      });
    }
    if (this.userOp.nonce === undefined) {
      // Set nonce from entryPoint.getNonce(sender, nonceKey)
      const entryPointContract = new ethers.Contract(
        this.entryPoint,
        ["function getNonce(address,uint192) view returns(uint256)"],
        this.provider
      );
      const nonce = await entryPointContract.getNonce(this.userOp.sender, nonceKey ?? 0n);
      this.userOp.nonce = ethers.toBeHex(nonce);
    }

    this.userOp.maxFeePerGas = ethers.toBeHex(maxFeePerGas);
    this.userOp.maxPriorityFeePerGas = ethers.toBeHex(maxPriorityFeePerGas);

    const estimatedCallGas = await this.estimateCallGasLimit();
    const estimatedCallGasBigInt = BigInt(estimatedCallGas);
    const MIN_CALL_GAS_LIMIT = 21000n;
    this.userOp.callGasLimit = ethers.toBeHex(
      estimatedCallGasBigInt < MIN_CALL_GAS_LIMIT ? MIN_CALL_GAS_LIMIT : estimatedCallGasBigInt
    );

    // Set a temporary verificationGasLimit since packUserOp is needed for preVerificationGas calculation
    if (!this.userOp.verificationGasLimit) {
      this.userOp.verificationGasLimit = ethers.toBeHex("1500000");
    }

    // [PATCH] Set defaults for fields needed by calculatePreVerificationGas → packUserOp → encodeUserOp
    if (!this.userOp.initCode) {
      this.userOp.initCode = "0x";
    }
    if (!this.userOp.preVerificationGas) {
      this.userOp.preVerificationGas = "0x00";
    }
    if (!this.userOp.signature || this.userOp.signature === "0x") {
      this.userOp.signature = this.createDummySignature();
    }
    const preVerificationGas = this.calculatePreVerificationGas(
      this.userOp as UserOperation
    );
    this.userOp.preVerificationGas = ethers.toBeHex(preVerificationGas);
    let verificationGasLimit = 25000n;

    // Calculate gas required for verification -> use predefined values per key type
    if (this.userOp.initCode !== "0x" && this.userOp.initCode !== undefined) {
      const zkapFactory = ethers.dataSlice(this.userOp.initCode, 0, 20);
      const callData = ethers.dataSlice(this.userOp.initCode, 20);
      const walletCreationGasLimit = await this.estimateGasWithCap({
        to: zkapFactory,
        data: callData,
        from: this.entryPoint,  // EntryPoint calls the factory
      });

      verificationGasLimit += BigInt(walletCreationGasLimit);
    }

    const keyTypes = this.signerKeyTypes;

    for (const keyType of keyTypes) {
      if (keyType === PrimitiveAccountKeyTypes.keyAddress) {
        verificationGasLimit += ZkapBuilder.ADDRESS_KEY_VALIDATION_GAS;
      } else if (keyType === PrimitiveAccountKeyTypes.keySecp256k1) {
        verificationGasLimit += ZkapBuilder.SECP256K1_KEY_VALIDATION_GAS;
      } else if (keyType === PrimitiveAccountKeyTypes.keySecp256r1) {
        verificationGasLimit += ZkapBuilder.SECP256R1_KEY_VALIDATION_GAS;
      } else if (keyType === PrimitiveAccountKeyTypes.keyWebAuthn) {
        verificationGasLimit += ZkapBuilder.WEB_AUTHN_KEY_VALIDATION_GAS;
      } else if (keyType === PrimitiveAccountKeyTypes.keyOAuthRS256) {
        verificationGasLimit += ZkapBuilder.OAUTH_RS256_KEY_VALIDATION_GAS;
      } else if (keyType === PrimitiveAccountKeyTypes.keyZkOAuthRS256) {
        verificationGasLimit += this.zkOAuthValidationGas();
      }
    }

    // make verificationGasLimit 20% more
    verificationGasLimit = (verificationGasLimit * ZkapBuilder.GAS_ESTIMATE_MULTIPLIER) / ZkapBuilder.GAS_ESTIMATE_DIVISOR;

    this.userOp.verificationGasLimit = ethers.toBeHex(verificationGasLimit);

    // If paymaster is configured, auto-populate paymaster-related data
    if (this.paymasterService) {
      const MAX_PAYMASTER_PASSES = 3;
      for (let pass = 0; pass < MAX_PAYMASTER_PASSES; pass++) {
        await this.autoFillPaymasterData();
        const newPvg = this.calculatePreVerificationGas(this.userOp as UserOperation);
        const newPvgHex = ethers.toBeHex(newPvg);
        if (newPvgHex === this.userOp.preVerificationGas) {
          break; // preVerificationGas has converged
        }
        this.userOp.preVerificationGas = newPvgHex;
      }
    }

    return this;
  }

  /**
   * Automatically populates paymaster-related data.
   * Only called when PaymasterService is configured.
   */
  private async autoFillPaymasterData(): Promise<void> {
    /* istanbul ignore next */
    if (!this.paymasterService) {
      // error throw
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_MISSING_DEPENDENCY,
        operation: "auto_fill_paymaster_data",
        message: "Paymaster service is not set. Please set a valid paymaster service.",
      });
    }

    // Set paymaster verification and PostOp gas limits
    this.userOp.paymasterVerificationGasLimit = ethers.toBeHex(
      this.paymasterService.estimatePaymasterVerificationGasLimit()
    );
    this.userOp.paymasterPostOpGasLimit = ethers.toBeHex(
      this.paymasterService.estimatePaymasterPostOpGasLimit()
    );

    // Fetch paymaster data
    const userOp = this.getUserOp();
    const paymasterData = await this.paymasterService.getPaymasterData(userOp);
    this.setPaymasterData(paymasterData);
  }

  /**
   * Updates the paymaster configuration.
   * @param paymaster Paymaster configuration
   */
  setPaymasterConfig(paymaster: PaymasterServiceConfig): this {
    const paymasterServiceConfig: PaymasterServiceConfig = {
      serverUrl: paymaster.serverUrl,
      paymasterAddress: paymaster.paymasterAddress,
      chainId: this.chainId,
      mode: paymaster.mode,
      tokenAddress: paymaster.tokenAddress,
    };
    this.paymasterService = new PaymasterService(paymasterServiceConfig);
    this.setPaymaster(paymaster.paymasterAddress);
    return this;
  }

  /**
   * Removes the paymaster configuration (disables gas sponsorship).
   */
  removePaymasterConfig(): this {
    this.paymasterService = undefined;
    this.setPaymaster(ethers.ZeroAddress);
    this.setPaymasterData("0x");
    this.setPaymasterVerificationGasLimit("0x00");
    this.setPaymasterPostOpGasLimit("0x00");
    return this;
  }

  /**
   * Sets the initCode for deploying the wallet on first use.
   * Only needed when the wallet has not been deployed yet.
   * @param zkapFactory Address of the ZkapFactory contract
   * @param salt Deterministic salt (use `computeSalt(aud, sub)`)
   * @param keys Encoded master key and tx key
   */
  setInitCode(
    zkapFactory: string,
    salt: ethers.BigNumberish,
    keys: { encodedMasterKey: string; encodedTxKey: string }
  ): this {
    if (!ethers.isAddress(zkapFactory)) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID_ADDRESS,
        operation: "set_init_code",
        message: `setInitCode: invalid factory address: "${zkapFactory}"`,
      });
    }
    const { encodedMasterKey, encodedTxKey } = keys;
    const callDataBuilder = new CallDataBuilder(ZkapAccountFactoryABI);

    const callData = callDataBuilder.encode("createAccount", [
      salt,
      encodedMasterKey,
      encodedTxKey,
    ]);

    const initCode = ethers.concat([zkapFactory, callData]);

    this.userOp.initCode = initCode;
    return this;
  }

  /**
   * Sets the initCode field directly as a raw hex string.
   * Prefer `setInitCode()` unless you are constructing initCode manually.
   */
  setRawInitCode(initCode: string): this {
    this.userOp.initCode = initCode;
    return this;
  }

  /**
   * Encodes and sets the UserOperation signature.
   *
   * Include only the signatures of the keys needed to reach the key set's threshold.
   * The account subtracts the weight of a key whose signature is valid in form but does
   * not verify (e.g. signed by a different signer), but a MALFORMED signature (an ECDSA
   * signature of the wrong length, an undecodable or invalid zk proof, ...) makes
   * verification itself revert, so the whole op fails even if the remaining signatures
   * would reach the threshold.
   *
   * For master key operations the zk signature belongs to master key index 0 and must be
   * the FIRST element of `keySignatureList`: the gas profile reads the proof count from it.
   *
   * @param keyIndexList Indices of the keys used to sign (e.g. `[0]` for the first key,
   *        `[0, 1]` for a cosigned master op). Must not contain duplicates; order is not enforced.
   * @param keySignatureList Hex-encoded signatures returned by `signer.signUserOpHash()`,
   *        in the same order as `keyIndexList`
   * @throws `AaOperationError` (`INPUT_OUT_OF_RANGE`) when the two lists differ in length,
   *         (`INPUT_INVALID`) when `keyIndexList` contains a duplicate index
   */
  setSignature(keyIndexList: number[], keySignatureList: string[]): this {
    if (keyIndexList.length !== keySignatureList.length) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_OUT_OF_RANGE,
        operation: "set_signature",
        message: `keyIndexList (${keyIndexList.length}) and keySignatureList (${keySignatureList.length}) must have the same length`,
      });
    }
    if (new Set(keyIndexList).size !== keyIndexList.length) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_INVALID,
        operation: "set_signature",
        message: `keyIndexList must not contain duplicate indices: [${keyIndexList.join(", ")}]`,
      });
    }
    const defaultAbiCoder = ethers.AbiCoder.defaultAbiCoder();

    this.userOp.signature = defaultAbiCoder.encode(
      ["uint8[]", "bytes[]"],
      [keyIndexList, keySignatureList]
    );
    return this;
  }

  /**
   * Sets the callData for a tx key update.
   * @param encoded Encoded key data
   * @param signerKeyTypes Signer key types of the master key signature, validated like
   *        `setSignerKeyTypes()`. Defaults to `[keyZkOAuthRS256, keyAddress]` (zk key + cosigner).
   *        Use e.g. `[keyZkOAuthRS256, keyWebAuthn]` when the passkey cosigns, or
   *        `[keyZkOAuthRS256]` for a zk-only master key. Keep keyZkOAuthRS256 FIRST, matching
   *        the zk signature at the head of the signature list.
   * @warning This method overwrites any value previously set via setSignerKeyTypes().
   */
  setUpdateTxKeyCallData(
    encoded: string,
    signerKeyTypes?: number[]
  ): this {
    if (!this.userOp.sender) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "set_update_tx_key_call_data",
        message: "Sender is not set",
      });
    }
    const callDataBuilder = new CallDataBuilder(ZkapAccountABI);
    const callData = callDataBuilder.encode("updateTxKey", [encoded]);
    // Validate the key types before touching callData so a rejected value leaves the builder unchanged.
    this.setSignerKeyTypes(signerKeyTypes ?? [...MASTER_OP_SIGNER_KEY_TYPES]);
    this.setCallDataInternal(callData);
    return this;
  }

  /**
   * Sets the callData for a master key update.
   * @param encoded Encoded key data
   * @param signerKeyTypes Signer key types of the master key signature, validated like
   *        `setSignerKeyTypes()`. Defaults to `[keyZkOAuthRS256, keyAddress]` (zk key + cosigner).
   *        Use e.g. `[keyZkOAuthRS256, keyWebAuthn]` when the passkey cosigns, or
   *        `[keyZkOAuthRS256]` for a zk-only master key. Keep keyZkOAuthRS256 FIRST, matching
   *        the zk signature at the head of the signature list.
   * @warning This method overwrites any value previously set via setSignerKeyTypes().
   */
  setUpdateMasterKeyCallData(
    encoded: string,
    signerKeyTypes?: number[]
  ): this {
    if (!this.userOp.sender) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "set_update_master_key_call_data",
        message: "Sender is not set",
      });
    }
    const callDataBuilder = new CallDataBuilder(ZkapAccountABI);
    const callData = callDataBuilder.encode("updateMasterKey", [encoded]);
    // Validate the key types before touching callData so a rejected value leaves the builder unchanged.
    this.setSignerKeyTypes(signerKeyTypes ?? [...MASTER_OP_SIGNER_KEY_TYPES]);
    this.setCallDataInternal(callData);
    return this;
  }

  /**
   * Sets the callData for simultaneously updating both master key and tx key.
   * @param encodedMasterKey Encoded master key data
   * @param encodedTxKey Encoded tx key data
   * @param signerKeyTypes Signer key types of the master key signature, validated like
   *        `setSignerKeyTypes()`. Defaults to `[keyZkOAuthRS256, keyAddress]` (zk key + cosigner).
   *        Use e.g. `[keyZkOAuthRS256, keyWebAuthn]` when the passkey cosigns, or
   *        `[keyZkOAuthRS256]` for a zk-only master key. Keep keyZkOAuthRS256 FIRST, matching
   *        the zk signature at the head of the signature list.
   * @warning This method overwrites any value previously set via setSignerKeyTypes().
   */
  setUpdateKeysCallData(
    keys: { encodedMasterKey: string; encodedTxKey: string },
    signerKeyTypes?: number[]
  ): this {
    const { encodedMasterKey, encodedTxKey } = keys;
    if (!this.userOp.sender) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "set_update_keys_call_data",
        message: "Sender is not set",
      });
    }
    const callDataBuilder = new CallDataBuilder(ZkapAccountABI);
    const callData = callDataBuilder.encode("updateKeys", [
      encodedMasterKey,
      encodedTxKey,
    ]);
    // Validate the key types before touching callData so a rejected value leaves the builder unchanged.
    this.setSignerKeyTypes(signerKeyTypes ?? [...MASTER_OP_SIGNER_KEY_TYPES]);
    this.setCallDataInternal(callData);
    return this;
  }

  /**
   * Creates a dummy signature for preVerificationGas estimation.
   * Mimics the real signature structure (encode(["uint8[]", "bytes[]"], ...))
   * to enable accurate calldataCost estimation.
   */
  private createDummySignature(): string {
    const keyTypes = this.signerKeyTypes ?? [PrimitiveAccountKeyTypes.keyWebAuthn];
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const indices = keyTypes.map((_, i) => i);
    const dummySigs = keyTypes.map(kt => {
      const size = ZkapBuilder.ESTIMATED_SIG_SIZES[kt] ?? 100;
      return ethers.hexlify(new Uint8Array(size).fill(0xfe));
    });
    return abiCoder.encode(["uint8[]", "bytes[]"], [indices, dummySigs]);
  }

  /**
   * Internal use only: sets callData without validating signerKeyTypes.
   * Used by internal methods such as setExecuteCallData and setExecuteBatchCallData.
   */
  private setCallDataInternal(callData: string): void {
    this.userOp.callData = callData;
  }

  /**
   * Sets the execute callData.
   * @param contractAddress Target contract address
   * @param value ETH to send (in wei)
   * @param data calldata ('0x' for plain ETH transfers)
   * @param signerKeyTypes Array of signer key types (defaults to keyWebAuthn if not specified).
   *        Pass explicitly or override later with setSignerKeyTypes() if a different key type is needed.
   * @warning This method sets signerKeyTypes. Any value previously set via setSignerKeyTypes() will be overwritten.
   */
  setExecuteCallData(
    contractAddress: string,
    value: ethers.BigNumberish,
    data: string,
    signerKeyTypes?: number[]
  ): this {
    const callDataBuilder = new CallDataBuilder(ZkapAccountABI);
    const useropCallData = callDataBuilder.encode("execute", [
      contractAddress,
      value,
      data,
    ]);

    this.setCallDataInternal(useropCallData);
    this.setSignerKeyTypes(signerKeyTypes ?? [PrimitiveAccountKeyTypes.keyWebAuthn]);
    return this;
  }

  /**
   * Sets the executeBatch callData.
   * @param contractAddresses Array of target contract addresses
   * @param values Array of ETH amounts to send (in wei)
   * @param data Array of calldata
   * @param signerKeyTypes Array of signer key types (defaults to keyWebAuthn if not specified).
   *        Pass explicitly or override later with setSignerKeyTypes() if a different key type is needed.
   * @warning This method sets signerKeyTypes. Any value previously set via setSignerKeyTypes() will be overwritten.
   */
  setExecuteBatchCallData(
    contractAddresses: string[],
    values: ethers.BigNumberish[],
    data: string[],
    signerKeyTypes?: number[]
  ): this {
    const callDataBuilder = new CallDataBuilder(ZkapAccountABI);
    const useropCallData = callDataBuilder.encode("executeBatch(address[],uint256[],bytes[])", [
      contractAddresses,
      values,
      data,
    ]);

    this.setCallDataInternal(useropCallData);
    this.setSignerKeyTypes(signerKeyTypes ?? [PrimitiveAccountKeyTypes.keyWebAuthn]);
    return this;
  }

  /**
   * Sets arbitrary callData directly. Requires `setSignerKeyTypes()` to be called first.
   * Prefer `setExecuteCallData()` or `setExecuteBatchCallData()` for standard transfers.
   */
  setCallData(callData: string): this {
    if (!this.signerKeyTypes || this.signerKeyTypes.length === 0) {
      throw new AaOperationError({
        code: AaOperationErrorCode.STATE_FIELD_NOT_SET,
        operation: "set_call_data",
        message: "Signer key types are not set. Please set a valid signer key types.",
      });
    }
    super.setCallData(callData);
    return this;
  }

  /**
   * Sets the key types used to sign this UserOperation.
   * Must match the key type(s) registered on the wallet.
   * @param keyTypes Array of `PrimitiveAccountKeyTypes` values (e.g. `[keyWebAuthn]`)
   */
  setSignerKeyTypes(keyTypes: number[]): this {
    if (!Array.isArray(keyTypes) || keyTypes.length === 0) {
      throw new AaOperationError({
        code: AaOperationErrorCode.INPUT_OUT_OF_RANGE,
        operation: "set_signer_key_types",
        message: "keyTypes must be a non-empty array",
      });
    }
    const validKeyTypes = new Set<number>([
      PrimitiveAccountKeyTypes.keyAddress,
      PrimitiveAccountKeyTypes.keySecp256k1,
      PrimitiveAccountKeyTypes.keySecp256r1,
      PrimitiveAccountKeyTypes.keyWebAuthn,
      PrimitiveAccountKeyTypes.keyOAuthRS256,
      PrimitiveAccountKeyTypes.keyZkOAuthRS256,
    ]);
    for (const kt of keyTypes) {
      if (!Number.isInteger(kt) || kt <= 0 || !validKeyTypes.has(kt)) {
        throw new AaOperationError({
          code: AaOperationErrorCode.INPUT_UNSUPPORTED,
          operation: "set_signer_key_types",
          message: `Invalid keyType: ${kt}. Allowed values: ${[...validKeyTypes].join(", ")}`,
        });
      }
    }
    this.signerKeyTypes = keyTypes;
    return this;
  }

  /**
   * Returns the UserOperation hash scoped to the paymaster context.
   * Used internally by PaymasterService; not needed for typical signing flows.
   *
   * @remarks
   * Must match ZkapPaymaster._getHash() (BaseSingletonPaymaster derivative) byte-for-byte:
   *   userOpHash = keccak256(encodeUserOpForPaymaster(userOp))
   *   return     = keccak256(abi.encode(userOpHash, block.chainid))
   *
   * Cross-chain replay protection is provided by chainid alone. The paymaster
   * address is already committed via paymasterAndData slice inside
   * encodeUserOpForPaymaster, so adding `entryPoint` here would diverge from
   * the on-chain contract and break signature verification.
   */
  getUserOpHashForPaymaster(): string {
    const defaultAbiCoder = ethers.AbiCoder.defaultAbiCoder();

    const userOpHash = ethers.keccak256(
      this.encodeUserOpForPaymaster(this.getPackedUserOp())
    );

    const enc = defaultAbiCoder.encode(
      ["bytes32", "uint256"],
      [userOpHash, this.chainId]
    );
    return ethers.keccak256(enc);
  }
}
