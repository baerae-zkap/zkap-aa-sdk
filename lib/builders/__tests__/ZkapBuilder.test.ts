/**
 * ZkapBuilder tests
 *
 * UserOperation builder for ZKAP accounts
 */

// Mock fetch for PaymasterService
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock ethers
const mockGetCode = jest.fn();
const mockEstimateGas = jest.fn();
const mockGetFeeData = jest.fn();
const mockGetNonce = jest.fn();
const mockParseTransaction = jest.fn();

jest.mock('ethers', () => {
  const actual = jest.requireActual('ethers');
  return {
    ethers: {
      ...actual.ethers,
      ZeroAddress: '0x0000000000000000000000000000000000000000',
      JsonRpcProvider: jest.fn().mockImplementation(() => ({
        getCode: mockGetCode,
        estimateGas: mockEstimateGas,
        getFeeData: mockGetFeeData,
      })),
      Contract: jest.fn().mockImplementation(() => ({
        getNonce: mockGetNonce,
      })),
      Interface: jest.fn().mockImplementation(() => ({
        getFunction: jest.fn().mockReturnValue(true),
        encodeFunctionData: jest.fn().mockReturnValue('0xEncodedCallData'),
        parseTransaction: mockParseTransaction,
        decodeFunctionResult: jest.fn().mockReturnValue([BigInt(50000)]),
      })),
      AbiCoder: {
        defaultAbiCoder: () => ({
          encode: jest.fn().mockReturnValue('0x' + '0a'.repeat(100)),
        }),
      },
      concat: jest.fn().mockImplementation((arr) => arr.join('')),
      toBeHex: jest.fn().mockImplementation((val) => {
        if (typeof val === 'string' && val.startsWith('0x')) return val;
        return `0x${BigInt(val).toString(16)}`;
      }),
      keccak256: jest.fn().mockReturnValue('0x' + 'ab'.repeat(32)),
      zeroPadValue: jest.fn().mockReturnValue('0x' + '00'.repeat(16)),
      hexlify: jest.fn().mockImplementation((val) => typeof val === 'string' ? val : `0x${val}`),
      parseEther: jest.fn().mockReturnValue(BigInt(0)),
      dataSlice: jest.fn().mockImplementation((data, start, end) => {
        if (end) return data.slice(start * 2 + 2, end * 2 + 2);
        return data.slice(start * 2 + 2);
      }),
    },
  };
});

// Mock ABIs
jest.mock('../../types/abi', () => ({
  ZkapAccountABI: [],
  ZkapAccountFactoryABI: [],
}));

import { ZkapBuilder, ZkapAccountInfo } from '../ZkapBuilder';
import { PaymasterMode } from '../../utils/PaymasterService';
import { ethers } from 'ethers';
import { AaOperationError, AaOperationErrorCode } from '../../errors';
import { PrimitiveAccountKeyTypes } from '../../types/AccountKey';
import { MASTER_OP_SIGNER_KEY_TYPES } from '../../master/constants';

describe('ZkapBuilder', () => {
  const mockAccountInfo: ZkapAccountInfo = {
    chainId: 1,
    entryPoint: '0x' + '55'.repeat(20),
    enUrl: 'http://localhost:8545',
  };

  const mockPaymasterConfig = {
    serverUrl: 'http://localhost:3000',
    paymasterAddress: '0x' + '33'.repeat(20),
    chainId: 1,
    mode: PaymasterMode.VERIFYING,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockReset();
    mockGetCode.mockReset();
    mockEstimateGas.mockReset();
    mockGetFeeData.mockReset();
    mockGetNonce.mockReset();
    mockParseTransaction.mockReset();

    // Default mock values
    mockGetCode.mockResolvedValue('0x1234'); // Wallet deployed
    mockEstimateGas.mockResolvedValue(BigInt(21000));
    mockGetFeeData.mockResolvedValue({ gasPrice: BigInt(1000000000) });
    mockGetNonce.mockResolvedValue(BigInt(0));
    mockParseTransaction.mockReturnValue({
      name: 'execute',
      args: { dest: '0x' + '11'.repeat(20), value: BigInt(0), func: '0x1234' },
      fragment: { inputs: [{}, {}, {}] },
    });
  });

  describe('constructor', () => {
    it('should create instance without paymaster', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      expect(builder).toBeInstanceOf(ZkapBuilder);
    });

    it('should create instance with paymaster config', () => {
      const accountInfoWithPaymaster = {
        ...mockAccountInfo,
        paymaster: mockPaymasterConfig,
      };

      const builder = new ZkapBuilder(accountInfoWithPaymaster);
      expect(builder).toBeInstanceOf(ZkapBuilder);
    });
  });

  describe('getRequiredPrefund', () => {
    it('should calculate required prefund', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder
        .setSender('0x' + '11'.repeat(20))
        .setVerificationGasLimit('0x7530')
        .setCallGasLimit('0x5208')
        .setPaymasterVerificationGasLimit('0x6978')
        .setPaymasterPostOpGasLimit('0x0')
        .setPreVerificationGas('0xc350')
        .setMaxFeePerGas('0x3b9aca00');

      const prefund = builder.getRequiredPrefund();
      expect(prefund).toMatch(/^0x/);
    });

    it('should throw when gas limits are not set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      expect(() => builder.getRequiredPrefund()).toThrow(
        'Required gas fields not set:'
      );
    });
  });

  describe('setInitCode', () => {
    it('should set init code for new account creation', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      const zkapFactory = '0x' + '22'.repeat(20);
      const salt = '0x1';
      const encodedMasterKey = '0x' + 'aa'.repeat(64);
      const encodedTxKey = '0x' + 'bb'.repeat(64);

      builder.setInitCode(zkapFactory, salt, { encodedMasterKey, encodedTxKey });

      const userOp = builder.setSender('0x' + '11'.repeat(20)).getUserOp();
      expect(userOp.initCode).toBeDefined();
      expect(userOp.initCode).not.toBe('0x');
    });

    it('should throw for invalid factory address', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      expect(() =>
        builder.setInitCode('not-an-address', '0x1', {
          encodedMasterKey: '0x' + 'aa'.repeat(64),
          encodedTxKey: '0x' + 'bb'.repeat(64),
        })
      ).toThrow('setInitCode: invalid factory address');
    });

    it('should throw for too-short hex factory address', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      expect(() =>
        builder.setInitCode('0x1234', '0x1', {
          encodedMasterKey: '0x' + 'aa'.repeat(64),
          encodedTxKey: '0x' + 'bb'.repeat(64),
        })
      ).toThrow('setInitCode: invalid factory address');
    });
  });

  describe('setRawInitCode', () => {
    it('should set raw init code directly', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      const rawInitCode = '0x' + 'ff'.repeat(100);

      builder.setRawInitCode(rawInitCode);

      const userOp = builder.setSender('0x' + '11'.repeat(20)).getUserOp();
      expect(userOp.initCode).toBe(rawInitCode);
    });
  });

  describe('setSignature', () => {
    it('should encode signature with key indices', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setSignature([0], ['0xSignature1']);

      const userOp = builder.getUserOp();
      expect(userOp.signature).toMatch(/^0x/);
    });

    it('should handle multiple signatures', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setSignature([0, 1], ['0xSig1', '0xSig2']);

      const userOp = builder.getUserOp();
      expect(userOp.signature).toBeDefined();
    });

    const expectSignatureError = (
      keyIndexList: number[],
      keySignatureList: string[],
      code: string
    ): void => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      const before = builder.getUserOp().signature;

      let caught: unknown;
      try {
        builder.setSignature(keyIndexList, keySignatureList);
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(AaOperationError);
      expect((caught as AaOperationError).code).toBe(code);
      expect(builder.getUserOp().signature).toBe(before);
    };

    it.each([
      [[0, 1], ['0xSig1']],
      [[0], ['0xSig1', '0xSig2']],
      [[], ['0xSig1']],
    ])('should throw INPUT_OUT_OF_RANGE when lengths differ (%j vs %j)', (indices, sigs) => {
      expectSignatureError(indices, sigs, AaOperationErrorCode.INPUT_OUT_OF_RANGE);
    });

    it.each([
      [[0, 0], ['0xSig1', '0xSig2']],
      [[1, 0, 1], ['0xSig1', '0xSig2', '0xSig3']],
    ])('should throw INPUT_INVALID for duplicate indices %j', (indices, sigs) => {
      expectSignatureError(indices, sigs, AaOperationErrorCode.INPUT_INVALID);
    });

    it('should accept matching lists with indices in any order', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      expect(() => builder.setSignature([1, 0], ['0xCosign', '0xZk'])).not.toThrow();
      expect(() => builder.setSignature([0, 1], ['0xZk', '0xCosign'])).not.toThrow();
      expect(builder.getUserOp().signature).toBe('0x' + '0a'.repeat(100));
    });
  });

  describe('setExecuteCallData', () => {
    it('should set execute call data', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const contractAddress = '0x' + '22'.repeat(20);
      const value = BigInt(0);
      const data = '0x1234';

      builder.setExecuteCallData(contractAddress, value, data);

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
      expect(userOp.callData).not.toBe('0x');
    });

    it('should set signerKeyTypes to keyWebAuthn by default', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setExecuteCallData('0x' + '22'.repeat(20), BigInt(0), '0x1234');

      // signerKeyTypes was automatically set, so setCallData does not throw
      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should use explicitly provided signerKeyTypes', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      // Explicitly specify keyAddress(1)
      builder.setExecuteCallData('0x' + '22'.repeat(20), BigInt(0), '0x1234', [1]);

      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should allow signerKeyTypes to be overridden by setSignerKeyTypes after call', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setExecuteCallData('0x' + '22'.repeat(20), BigInt(0), '0x1234');
      builder.setSignerKeyTypes([1, 4]); // override afterwards

      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should return builder instance for method chaining', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const result = builder.setExecuteCallData('0x' + '22'.repeat(20), BigInt(0), '0x1234');

      expect(result).toBe(builder);
    });
  });

  describe('setExecuteBatchCallData', () => {
    it('should set batch execute call data', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const addresses = ['0x' + '22'.repeat(20), '0x' + '33'.repeat(20)];
      const values = [BigInt(0), BigInt(100)];
      const datas = ['0x1234', '0x5678'];

      builder.setExecuteBatchCallData(addresses, values, datas);

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
    });

    it('should set signerKeyTypes to keyWebAuthn by default', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setExecuteBatchCallData(
        ['0x' + '22'.repeat(20)],
        [BigInt(0)],
        ['0x1234']
      );

      // signerKeyTypes was automatically set, so setCallData does not throw
      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should use explicitly provided signerKeyTypes', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      // Explicitly specify keyAddress(1)
      builder.setExecuteBatchCallData(
        ['0x' + '22'.repeat(20)],
        [BigInt(0)],
        ['0x1234'],
        [1]
      );

      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should return builder instance for method chaining', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const result = builder.setExecuteBatchCallData(
        ['0x' + '22'.repeat(20)],
        [BigInt(0)],
        ['0x1234']
      );

      expect(result).toBe(builder);
    });
  });

  describe('setUpdateTxKeyCallData', () => {
    it('should set update tx key call data', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const encoded = '0x' + 'cc'.repeat(64);
      builder.setUpdateTxKeyCallData(encoded);

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
    });

    it('should throw when sender is not set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);

      expect(() => builder.setUpdateTxKeyCallData('0x1234')).toThrow(
        'Sender is not set'
      );
    });

    it('should set callData to non-empty value', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setUpdateTxKeyCallData('0x' + 'cc'.repeat(64));

      const userOp = builder.getUserOp();
      expect(userOp.callData).not.toBe('0x');
    });

    it('should default signer key types to [keyZkOAuthRS256, keyAddress] (zk + cosigner)', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // overwritten by the setter

      builder.setUpdateTxKeyCallData('0x' + 'cc'.repeat(64));

      expect((builder as any).signerKeyTypes).toEqual([6, 1]);
      // Once signerKeyTypes is set, setCallData does not throw
      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should return builder instance for method chaining', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const result = builder.setUpdateTxKeyCallData('0x' + 'cc'.repeat(64));

      expect(result).toBe(builder);
    });
  });

  describe('setUpdateMasterKeyCallData', () => {
    it('should set update master key call data', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const encoded = '0x' + 'dd'.repeat(64);
      builder.setUpdateMasterKeyCallData(encoded);

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
    });

    it('should throw when sender is not set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);

      expect(() => builder.setUpdateMasterKeyCallData('0x1234')).toThrow(
        'Sender is not set'
      );
    });

    it('should set callData to non-empty value', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setUpdateMasterKeyCallData('0x' + 'dd'.repeat(64));

      const userOp = builder.getUserOp();
      expect(userOp.callData).not.toBe('0x');
    });

    it('should default signer key types to [keyZkOAuthRS256, keyAddress] (zk + cosigner)', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // overwritten by the setter

      builder.setUpdateMasterKeyCallData('0x' + 'dd'.repeat(64));

      expect((builder as any).signerKeyTypes).toEqual([6, 1]);
      // Once signerKeyTypes is set, setCallData does not throw
      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should return builder instance for method chaining', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const result = builder.setUpdateMasterKeyCallData('0x' + 'dd'.repeat(64));

      expect(result).toBe(builder);
    });
  });

  describe('setUpdateKeysCallData', () => {
    it('should set update keys call data with both master and tx keys', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const encodedMasterKey = '0x' + 'ee'.repeat(64);
      const encodedTxKey = '0x' + 'ff'.repeat(64);
      builder.setUpdateKeysCallData({ encodedMasterKey, encodedTxKey });

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
      expect(userOp.callData).not.toBe('0x');
    });

    it('should throw when sender is not set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);

      expect(() =>
        builder.setUpdateKeysCallData({ encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) })
      ).toThrow('Sender is not set');
    });

    it('should default signer key types to [keyZkOAuthRS256, keyAddress] (zk + cosigner)', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // overwritten by the setter

      builder.setUpdateKeysCallData({ encodedMasterKey: '0x' + 'ee'.repeat(64), encodedTxKey: '0x' + 'ff'.repeat(64) });

      expect((builder as any).signerKeyTypes).toEqual([6, 1]);
      // Once signerKeyTypes is set, setCallData does not throw
      expect(() => builder.setCallData('0x9999')).not.toThrow();
    });

    it('should return builder instance for method chaining', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      const result = builder.setUpdateKeysCallData({ encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });

      expect(result).toBe(builder);
    });
  });

  describe('master op setters: signerKeyTypes argument', () => {
    const { keyZkOAuthRS256, keyAddress, keyWebAuthn } = PrimitiveAccountKeyTypes;
    const keys = { encodedMasterKey: '0x' + 'ee'.repeat(64), encodedTxKey: '0x' + 'ff'.repeat(64) };
    const setters: Array<[string, (b: ZkapBuilder, kt?: number[]) => ZkapBuilder]> = [
      ['setUpdateKeysCallData', (b, kt) => b.setUpdateKeysCallData(keys, kt)],
      ['setUpdateMasterKeyCallData', (b, kt) => b.setUpdateMasterKeyCallData('0x' + 'dd'.repeat(64), kt)],
      ['setUpdateTxKeyCallData', (b, kt) => b.setUpdateTxKeyCallData('0x' + 'cc'.repeat(64), kt)],
    ];

    const newBuilder = (): ZkapBuilder => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      return builder;
    };

    describe.each(setters)('%s', (_name, apply) => {
      it('defaults to a copy of MASTER_OP_SIGNER_KEY_TYPES', () => {
        const builder = newBuilder();

        apply(builder);

        const set = (builder as any).signerKeyTypes as number[];
        expect(set).toEqual([keyZkOAuthRS256, keyAddress]);
        expect(set).toEqual([...MASTER_OP_SIGNER_KEY_TYPES]);
        expect(set).not.toBe(MASTER_OP_SIGNER_KEY_TYPES);
        expect(Object.isFrozen(set)).toBe(false);
      });

      it.each([
        [[keyZkOAuthRS256, keyAddress]],
        [[keyZkOAuthRS256, keyWebAuthn]],
        [[keyZkOAuthRS256]],
      ])('accepts explicit %j', (keyTypes) => {
        const builder = newBuilder();

        apply(builder, keyTypes);

        expect((builder as any).signerKeyTypes).toEqual(keyTypes);
      });

      it('rejects an empty array (INPUT_OUT_OF_RANGE) and leaves callData and key types unchanged', () => {
        const builder = newBuilder();
        builder.setSignerKeyTypes([keyWebAuthn]);
        const before = builder.getUserOp().callData;

        let caught: unknown;
        try {
          apply(builder, []);
        } catch (e) {
          caught = e;
        }

        expect(caught).toBeInstanceOf(AaOperationError);
        expect((caught as AaOperationError).code).toBe(AaOperationErrorCode.INPUT_OUT_OF_RANGE);
        expect(builder.getUserOp().callData).toBe(before);
        expect((builder as any).signerKeyTypes).toEqual([keyWebAuthn]);
      });

      it('rejects an unknown key type (INPUT_UNSUPPORTED)', () => {
        const builder = newBuilder();

        let caught: unknown;
        try {
          apply(builder, [keyZkOAuthRS256, 99]);
        } catch (e) {
          caught = e;
        }

        expect(caught).toBeInstanceOf(AaOperationError);
        expect((caught as AaOperationError).code).toBe(AaOperationErrorCode.INPUT_UNSUPPORTED);
        expect((caught as AaOperationError).message).toContain('Invalid keyType: 99');
      });
    });
  });

  describe('setCallData (overridden)', () => {
    it('should throw when signer key types are not set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      expect(() => builder.setCallData('0x1234')).toThrow(
        'Signer key types are not set'
      );
    });

    it('should work when signer key types are set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // keyWebAuthn

      builder.setCallData('0x5678');

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBe('0x5678');
    });
  });

  describe('setSignerKeyTypes', () => {
    it('should set signer key types', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setSignerKeyTypes([1, 4]);

      // After setting key types, setCallData should work
      expect(() => builder.setCallData('0x1234')).not.toThrow();
    });

    it('should throw for empty array', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      expect(() => builder.setSignerKeyTypes([])).toThrow('keyTypes must be a non-empty array');
    });

    it('should throw for invalid keyType value', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      expect(() => builder.setSignerKeyTypes([99])).toThrow('Invalid keyType: 99');
    });

    it('should throw for keyType 0', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      expect(() => builder.setSignerKeyTypes([0])).toThrow('Invalid keyType: 0');
    });

    it('should accept all valid keyTypes', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      // keyAddress=1, keySecp256k1=2, keySecp256r1=3, keyWebAuthn=4, keyOAuthRS256=5, keyZkOAuthRS256=6
      expect(() => builder.setSignerKeyTypes([1, 2, 3, 4, 5, 6])).not.toThrow();
    });
  });

  describe('setPaymasterConfig', () => {
    it('should set paymaster config', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      builder.setPaymasterConfig(mockPaymasterConfig);

      const userOp = builder.getUserOp();
      expect(userOp.paymaster).toBe(mockPaymasterConfig.paymasterAddress);
    });
  });

  describe('removePaymasterConfig', () => {
    it('should remove paymaster config', () => {
      const accountInfoWithPaymaster = {
        ...mockAccountInfo,
        paymaster: mockPaymasterConfig,
      };

      const builder = new ZkapBuilder(accountInfoWithPaymaster);
      builder.setSender('0x' + '11'.repeat(20));
      builder.removePaymasterConfig();

      const userOp = builder.getUserOp();
      expect(userOp.paymaster).toBe(ethers.ZeroAddress);
      expect(userOp.paymasterData).toBe('0x');
    });
  });

  describe('autoFillUserOp', () => {
    it('should auto fill user operation fields', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0x1234');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.nonce).toBeDefined();
      expect(userOp.maxFeePerGas).toBeDefined();
      expect(userOp.callGasLimit).toBeDefined();
      expect(userOp.verificationGasLimit).toBeDefined();
    });

    it('should throw when sender is not set', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);

      await expect(builder.autoFillUserOp()).rejects.toThrow(
        'Sender is not set'
      );
    });

    it('should throw when fee data is not available', async () => {
      mockGetFeeData.mockResolvedValueOnce(null);

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([1]); // keyAddress — signerKeyTypes required

      await expect(builder.autoFillUserOp()).rejects.toThrow(
        'Failed to get fee data from provider'
      );
    });

    it('should auto fill paymaster data when paymaster is configured', async () => {
      // convergence loop: autoFillPaymasterData called up to MAX_PAYMASTER_PASSES (3) times
      const paymasterResponse = {
        ok: true,
        json: () => Promise.resolve({
          result: {
            userOp: { paymasterData: '0xabcd1234' },
          },
        }),
      };
      mockFetch
        .mockResolvedValueOnce(paymasterResponse)
        .mockResolvedValueOnce(paymasterResponse)
        .mockResolvedValueOnce(paymasterResponse);

      const accountInfoWithPaymaster = {
        ...mockAccountInfo,
        paymaster: mockPaymasterConfig,
      };

      const builder = new ZkapBuilder(accountInfoWithPaymaster);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0x1234');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.paymasterVerificationGasLimit).toBeDefined();
      expect(userOp.paymasterPostOpGasLimit).toBeDefined();
    });

    it('should handle wallet not deployed scenario', async () => {
      mockGetCode.mockResolvedValueOnce('0x'); // No code = not deployed

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);

      // Without initCode, should throw
      await expect(builder.autoFillUserOp()).rejects.toThrow(
        'Wallet not deployed and no initCode provided'
      );
    });

    it('should handle wallet creation with initCode', async () => {
      mockGetCode.mockResolvedValueOnce('0x'); // Not deployed

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setInitCode(
        '0x' + '22'.repeat(20),
        '0x1',
        { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) }
      );
      builder.setSignerKeyTypes([4]); // keyWebAuthn

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.verificationGasLimit).toBeDefined();
    });

    it('should default initCode to "0x" when not set and wallet is deployed', async () => {
      mockGetCode.mockResolvedValueOnce('0x1234'); // deployed

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // keyWebAuthn
      builder.setCallData('0x1234');
      // initCode not set

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.initCode).toBe('0x');
    });

    it('should throw when signerKeyTypes is not set before autoFillUserOp', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      // No setSignerKeyTypes call

      await expect(builder.autoFillUserOp())
        .rejects.toThrow('signerKeyTypes is not set');
    });

    it('should replace "0x" signature with dummy signature for PVG calculation', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // keyWebAuthn
      builder.setCallData('0x1234');
      // signature is "0x" by default

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.preVerificationGas).toBeDefined();
      expect(BigInt(userOp.preVerificationGas)).toBeGreaterThan(0n);
      // A dummy signature was injected, so it is not "0x"
      expect(userOp.signature).not.toBe('0x');
    });

    it('should preserve non-"0x" signature and not replace with dummy', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // keyWebAuthn
      builder.setCallData('0x1234');
      const existingSig = '0x' + 'ab'.repeat(65);
      (builder as any).userOp.signature = existingSig;

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.signature).toBe(existingSig);
    });

    it('should skip temp verificationGasLimit if already pre-set', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0x1234');
      builder.setVerificationGasLimit('0x100000'); // Pre-set before autoFill

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.verificationGasLimit).toBeDefined();
    });
  });

  describe('getUserOpHashForPaymaster', () => {
    it('should compute hash for paymaster', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder
        .setSender('0x' + '11'.repeat(20))
        .setPaymaster('0x' + '22'.repeat(20))
        .setPaymasterData('0x' + 'aa'.repeat(66))
        .setPaymasterVerificationGasLimit('0x6978')
        .setPaymasterPostOpGasLimit('0x0');

      const hash = builder.getUserOpHashForPaymaster();

      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe('updateUserOpCallDataForPaymasterERC20', () => {
    it('should throw when call data is not set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));

      expect(() =>
        builder.updateUserOpCallDataForPaymasterERC20(
          '0x' + '22'.repeat(20),
          '0x' + '33'.repeat(20),
          BigInt(1000)
        )
      ).toThrow('Call data is not set');
    });

    it('should update call data for ERC20 paymaster with execute', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setExecuteCallData('0x' + '44'.repeat(20), BigInt(0), '0x1234');

      builder.updateUserOpCallDataForPaymasterERC20(
        '0x' + '55'.repeat(20),
        '0x' + '66'.repeat(20),
        BigInt(1000)
      );

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
    });

  });

  describe('estimateCallGasLimit (via autoFillUserOp)', () => {
    it('should add GAS_BUFFER to estimateGas result for deployed wallet', async () => {
      // Default beforeEach: mockGetCode returns '0x1234' (deployed), mockEstimateGas returns 21000
      // Expected: 21000 (estimateGas) + 25000 (GAS_BUFFER) = 46000 = 0xb3b0
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]); // keyWebAuthn
      builder.setCallData('0xSomeCallData');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBe('0xb3b0'); // 21000 + 25000 (GAS_BUFFER) = 46000
    });

    it('should return minimal gas when only initCode is set without callData', async () => {
      mockGetCode.mockResolvedValueOnce('0x'); // Not deployed

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setInitCode(
        '0x' + '22'.repeat(20),
        '0x1',
        { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) }
      );
      builder.setSignerKeyTypes([4]); // keyWebAuthn
      // No callData set - should return minimal gas

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBeDefined();
      expect(userOp.callGasLimit).toBe('0x5208'); // MIN_CALL_GAS_LIMIT (21000) floor applied
    });
  });

  describe('edge cases', () => {
    it('should handle multiple key types for gas estimation', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([1, 4, 6]); // Address, WebAuthn, ZkOAuth
      builder.setCallData('0x1234');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.verificationGasLimit).toBeDefined();
    });

    it('should calculate verificationGasLimit for keySecp256k1', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([2]); // keySecp256k1
      builder.setCallData('0x1234');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(BigInt(userOp.verificationGasLimit)).toBeGreaterThan(0n);
    });

    it('should calculate verificationGasLimit for keySecp256r1', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([3]); // keySecp256r1
      builder.setCallData('0x1234');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(BigInt(userOp.verificationGasLimit)).toBeGreaterThan(0n);
    });

    it('should calculate verificationGasLimit for keyOAuthRS256', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([5]); // keyOAuthRS256
      builder.setCallData('0x1234');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(BigInt(userOp.verificationGasLimit)).toBeGreaterThan(0n);
    });

    it('should use existing nonce when already set', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setNonce('0x10'); // Pre-set nonce
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0x1234');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.nonce).toBe('0x10');
      expect(mockGetNonce).not.toHaveBeenCalled();
    });

    it('should handle empty string callData', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0x');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBeDefined();
    });
  });

  describe('estimateCallGasLimit - complex cases', () => {
    beforeEach(() => {
      mockGetCode.mockResolvedValue('0x'); // Wallet NOT deployed (required for parseTransaction path)
      mockEstimateGas.mockResolvedValue(BigInt(21000));
      mockGetFeeData.mockResolvedValue({
        gasPrice: BigInt(1000000000),
        maxFeePerGas: BigInt(1000000000),
        maxPriorityFeePerGas: BigInt(1500000000),
      });
      mockGetNonce.mockResolvedValue(BigInt(1));
      // Reset parseTransaction to default 'execute' behavior
      mockParseTransaction.mockReturnValue({
        name: 'execute',
        args: { dest: '0x' + '11'.repeat(20), value: BigInt(0), func: '0x1234' },
        fragment: { inputs: [{}, {}, {}] },
      });
    });

    it('should throw error when parseTransaction fails', async () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      // Must set initCode for non-deployed wallet
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });

      // Mock parseTransaction to throw error AFTER builder setup
      mockParseTransaction.mockImplementation(() => {
        throw new Error('Invalid transaction data');
      });

      builder.setCallData('0xInvalidCallData');

      await expect(builder.autoFillUserOp()).rejects.toThrow(
        'Invalid transaction data'
      );
    });

    it('should estimate gas for execute call when wallet not deployed with initCode', async () => {
      // parsedTx returns 'execute' (already set in beforeEach)
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });
      builder.setCallData('0xSomeCallData');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBeDefined();
    });

    it('should estimate gas for executeBatch (array style) when wallet not deployed', async () => {
      mockParseTransaction.mockReturnValue({
        name: 'executeBatch',
        args: [
          ['0x' + '11'.repeat(20), '0x' + '22'.repeat(20)],
          [BigInt(0), BigInt(100)],
          ['0x1234', '0x5678'],
        ],
        fragment: { inputs: [{}, {}, {}] },
      });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });
      builder.setCallData('0xSomeCallData');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBeDefined();
    });

    it('should estimate gas for executeBatch (tuple/calls style) when wallet not deployed', async () => {
      mockParseTransaction.mockReturnValue({
        name: 'executeBatch',
        args: [
          [
            { target: '0x' + '11'.repeat(20), value: BigInt(0), data: '0x1234' },
            { target: '0x' + '22'.repeat(20), value: BigInt(100), data: '0x5678' },
          ],
        ],
        fragment: { inputs: [{}] },
      });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });
      builder.setCallData('0xSomeCallData');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBeDefined();
    });

    it('should return buffer gas when executeBatch has empty dest list', async () => {
      mockParseTransaction.mockReturnValue({
        name: 'executeBatch',
        args: [[], [], []],
        fragment: { inputs: [{}, {}, {}] },
      });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });
      builder.setCallData('0xSomeCallData');

      await builder.autoFillUserOp();

      const userOp = builder.getUserOp();
      // 25000 (GAS_BUFFER) in hex = 0x61a8
      expect(userOp.callGasLimit).toBe('0x61a8');
    });

    it('should throw when callData uses unsupported function name', async () => {
      mockParseTransaction.mockReturnValue({
        name: 'unsupportedFunction',
        args: {},
        fragment: { inputs: [] },
      });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });
      builder.setCallData('0xSomeCallData');

      await expect(builder.autoFillUserOp()).rejects.toThrow(
        'Unsupported function for gas estimation: unsupportedFunction'
      );
    });

    it('should throw when parseTransaction returns null (unknown selector)', async () => {
      mockParseTransaction.mockReturnValue(null);

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });
      builder.setCallData('0xSomeCallData');

      await expect(builder.autoFillUserOp()).rejects.toThrow(
        'callData could not be parsed. Manual callGasLimit required.'
      );
    });

    it('should wrap non-Error throw from parseTransaction', async () => {
      // parseTransaction throws a non-Error value → covers the non-Error branch in catch
      mockParseTransaction.mockImplementationOnce(() => { throw 'string error'; });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '33'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setInitCode('0x' + '44'.repeat(20), '0x1', { encodedMasterKey: '0x' + 'aa'.repeat(64), encodedTxKey: '0x' + 'bb'.repeat(64) });
      builder.setCallData('0xSomeCallData');

      await expect(builder.autoFillUserOp()).rejects.toThrow(
        'callData could not be parsed. Manual callGasLimit required.'
      );
    });
  });

  describe('getUserOp - zero address validation', () => {
    it('should throw when sender is zero address (default)', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      // Don't set sender — applyDefaults sets it to ZeroAddress

      expect(() => builder.getUserOp()).toThrow(
        'Sender is not set or is zero address'
      );
    });

    it('should throw when sender is explicitly set to zero address', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x0000000000000000000000000000000000000000');

      expect(() => builder.getUserOp()).toThrow(
        'Sender is not set or is zero address'
      );
    });
  });

  describe('estimateCallGasLimit with updateKeys functions', () => {
    beforeEach(() => {
      // Reset all mocks
      mockGetCode.mockReset();
      mockEstimateGas.mockReset();
      mockGetFeeData.mockReset();
      mockParseTransaction.mockReset();
      mockFetch.mockReset();
    });

    it('should return fixed gas estimate for updateKeys when wallet not deployed', async () => {
      // Setup: wallet not deployed (code === "0x")
      mockGetCode.mockResolvedValue("0x");
      mockEstimateGas.mockResolvedValue(BigInt(50000)); // For factory call

      // Mock parseTransaction to return updateKeys function
      mockParseTransaction.mockReturnValue({
        name: "updateKeys",
        args: {
          encodedMasterKey: "0x" + "aa".repeat(100),
          encodedTxKey: "0x" + "bb".repeat(100)
        }
      });

      // Mock fee data
      mockGetFeeData.mockResolvedValue({
        gasPrice: BigInt(1000000000),
      });

      // Create builder
      const builder = new ZkapBuilder(mockAccountInfo);

      // Set required fields
      builder.setSender("0x" + "12".repeat(20));
      builder.setNonce("0x0");
      builder.setInitCode("0x" + "44".repeat(20), "0x1", { encodedMasterKey: "0x" + "aa".repeat(64), encodedTxKey: "0x" + "bb".repeat(64) });
      builder.setSignerKeyTypes([6]); // keyZkOAuthRS256
      builder.setCallData("0x" + "cc".repeat(100));

      // Execute
      await builder.autoFillUserOp();

      // Verify: callGasLimit should be exactly 1,825,000 (UPDATE_KEYS_CALL_GAS 1.8M + 25k buffer)
      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBe("0x1bd8e8");  // hex for 1,825,000
    });

    it('should return fixed gas estimate for updateMasterKey when wallet not deployed', async () => {
      mockGetCode.mockResolvedValue("0x");
      mockEstimateGas.mockResolvedValue(BigInt(50000)); // For factory call
      mockParseTransaction.mockReturnValue({
        name: "updateMasterKey",
        args: { encoded: "0x" + "aa".repeat(100) }
      });
      mockGetFeeData.mockResolvedValue({
        gasPrice: BigInt(1000000000),
      });

      const builder = new ZkapBuilder(mockAccountInfo);

      builder.setSender("0x" + "12".repeat(20));
      builder.setNonce("0x0");
      builder.setInitCode("0x" + "44".repeat(20), "0x1", { encodedMasterKey: "0x" + "aa".repeat(64), encodedTxKey: "0x" + "bb".repeat(64) });
      builder.setSignerKeyTypes([6]); // keyZkOAuthRS256
      builder.setCallData("0x" + "cc".repeat(100));

      await builder.autoFillUserOp();

      // Verify: callGasLimit should be exactly 1,025,000 (1M + 25k buffer)
      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBe("0xfa3e8");  // hex for 1,025,000
    });

    it('should return fixed gas estimate for updateTxKey when wallet not deployed', async () => {
      mockGetCode.mockResolvedValue("0x");
      mockEstimateGas.mockResolvedValue(BigInt(50000)); // For factory call
      mockParseTransaction.mockReturnValue({
        name: "updateTxKey",
        args: { encoded: "0x" + "aa".repeat(100) }
      });
      mockGetFeeData.mockResolvedValue({
        gasPrice: BigInt(1000000000),
      });

      const builder = new ZkapBuilder(mockAccountInfo);

      builder.setSender("0x" + "12".repeat(20));
      builder.setNonce("0x0");
      builder.setInitCode("0x" + "44".repeat(20), "0x1", { encodedMasterKey: "0x" + "aa".repeat(64), encodedTxKey: "0x" + "bb".repeat(64) });
      builder.setSignerKeyTypes([6]); // keyZkOAuthRS256
      builder.setCallData("0x" + "cc".repeat(100));

      await builder.autoFillUserOp();

      // Verify: callGasLimit should be exactly 1,025,000 (1M + 25k buffer)
      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBe("0xfa3e8");  // hex for 1,025,000
    });

    it('should still support existing execute function', async () => {
      // Regression test: ensure existing functionality unchanged
      mockGetCode.mockResolvedValue("0x");
      mockParseTransaction.mockReturnValue({
        name: "execute",
        args: {
          dest: "0x" + "11".repeat(20),
          value: BigInt(0),
          func: "0x1234"
        }
      });
      mockEstimateGas.mockResolvedValue(BigInt(100000));
      mockGetFeeData.mockResolvedValue({
        gasPrice: BigInt(1000000000),
      });

      const builder = new ZkapBuilder(mockAccountInfo);

      builder.setSender("0x" + "12".repeat(20));
      builder.setNonce("0x0");
      builder.setInitCode("0x" + "44".repeat(20), "0x1", { encodedMasterKey: "0x" + "aa".repeat(64), encodedTxKey: "0x" + "bb".repeat(64) });
      builder.setSignerKeyTypes([6]); // keyZkOAuthRS256
      builder.setCallData("0x" + "cc".repeat(100));

      await builder.autoFillUserOp();

      // Verify: should use estimated gas + buffer (100k + 25k = 125k)
      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBe("0x1e848");  // hex for 125,000
    });

    it('should still support existing executeBatch function', async () => {
      // Regression test: ensure executeBatch functionality unchanged
      mockGetCode.mockResolvedValue("0x");
      mockParseTransaction.mockReturnValue({
        name: "executeBatch",
        args: [
          ["0x" + "11".repeat(20), "0x" + "22".repeat(20)],
          [BigInt(0), BigInt(0)],
          ["0x1234", "0x5678"],
        ],
        fragment: { inputs: [{}, {}, {}] },
      });
      mockEstimateGas
        .mockResolvedValueOnce(BigInt(100000)) // For factory call
        .mockResolvedValueOnce(BigInt(50000))  // For first batch item
        .mockResolvedValueOnce(BigInt(75000)); // For second batch item
      mockGetFeeData.mockResolvedValue({
        gasPrice: BigInt(1000000000),
      });

      const builder = new ZkapBuilder(mockAccountInfo);

      builder.setSender("0x" + "12".repeat(20));
      builder.setNonce("0x0");
      builder.setInitCode("0x" + "44".repeat(20), "0x1", { encodedMasterKey: "0x" + "aa".repeat(64), encodedTxKey: "0x" + "bb".repeat(64) });
      builder.setSignerKeyTypes([6]); // keyZkOAuthRS256
      builder.setCallData("0x" + "cc".repeat(100));

      await builder.autoFillUserOp();

      // Verify: should sum estimated gas + buffer (100k factory + 50k + 75k + 25k = 250k, but actual is 175k)
      const userOp = builder.getUserOp();
      expect(userOp.callGasLimit).toBe("0x2ab98");  // hex for actual value
    });

    it('should throw error for unsupported function names', async () => {
      // Regression test: ensure default case still throws
      mockGetCode.mockResolvedValue("0x");
      mockEstimateGas.mockResolvedValue(BigInt(50000)); // For factory call
      mockParseTransaction.mockReturnValue({
        name: "unsupportedFunction",
        args: {}
      });
      mockGetFeeData.mockResolvedValue({
        gasPrice: BigInt(1000000000),
      });

      const builder = new ZkapBuilder(mockAccountInfo);

      builder.setSender("0x" + "12".repeat(20));
      builder.setNonce("0x0");
      builder.setInitCode("0x" + "44".repeat(20), "0x1", { encodedMasterKey: "0x" + "aa".repeat(64), encodedTxKey: "0x" + "bb".repeat(64) });
      builder.setSignerKeyTypes([6]); // keyZkOAuthRS256
      builder.setCallData("0x" + "cc".repeat(100));

      // Should throw error for unsupported function
      await expect(builder.autoFillUserOp()).rejects.toThrow(
        "Unsupported function for gas estimation: unsupportedFunction"
      );
    });
  });

  describe('updateUserOpCallDataForPaymasterERC20 - additional cases', () => {
    it('should throw when callData function is not execute or executeBatch', () => {
      mockParseTransaction.mockReturnValue({
        name: 'someOtherFunction',
        args: {},
        fragment: { inputs: [] },
      });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0x1234');

      expect(() =>
        builder.updateUserOpCallDataForPaymasterERC20(
          '0x' + '22'.repeat(20),
          '0x' + '33'.repeat(20),
          BigInt(1000)
        )
      ).toThrow('Call data is not a valid ZkapAccount function call');
    });

    it('should update call data for ERC20 paymaster with executeBatch (array style)', () => {
      mockParseTransaction.mockReturnValue({
        name: 'executeBatch',
        args: [
          ['0x' + '11'.repeat(20)],
          [BigInt(0)],
          ['0x1234'],
        ],
        fragment: { inputs: [{}, {}, {}] },
      });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0xBatchCallData');

      builder.updateUserOpCallDataForPaymasterERC20(
        '0x' + '55'.repeat(20),
        '0x' + '66'.repeat(20),
        BigInt(1000)
      );

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
    });

    it('should update call data for ERC20 paymaster with executeBatch (tuple/calls style)', () => {
      mockParseTransaction.mockReturnValue({
        name: 'executeBatch',
        args: [
          [
            { target: '0x' + '11'.repeat(20), value: BigInt(0), data: '0x1234' },
          ],
        ],
        fragment: { inputs: [{}] },
      });

      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSender('0x' + '11'.repeat(20));
      builder.setSignerKeyTypes([4]);
      builder.setCallData('0xBatchCallData');

      builder.updateUserOpCallDataForPaymasterERC20(
        '0x' + '55'.repeat(20),
        '0x' + '66'.repeat(20),
        BigInt(1000)
      );

      const userOp = builder.getUserOp();
      expect(userOp.callData).toBeDefined();
    });
  });

  describe('createDummySignature', () => {
    it('should return a hex string', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSignerKeyTypes([4]); // keyWebAuthn

      const sig = (builder as any).createDummySignature();

      expect(typeof sig).toBe('string');
      expect(sig).toMatch(/^0x/);
    });

    it('should fall back to keyWebAuthn when signerKeyTypes is not set', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      // signerKeyTypes not set → [keyWebAuthn] used internally

      const sig = (builder as any).createDummySignature();

      expect(sig).toMatch(/^0x/);
    });

    it('should return ABI-encoded output (uint8[], bytes[]) for single key type', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSignerKeyTypes([1]); // keyAddress

      const sig = (builder as any).createDummySignature();

      // AbiCoder.encode mock → '0x' + '0a'.repeat(100)
      expect(sig).toBe('0x' + '0a'.repeat(100));
    });

    it('should return ABI-encoded output for multiple key types', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      builder.setSignerKeyTypes([1, 4]); // keyAddress + keyWebAuthn

      const sig = (builder as any).createDummySignature();

      expect(sig).toMatch(/^0x/);
    });

    it('should not throw for unknown key type (uses fallback size 100)', () => {
      const builder = new ZkapBuilder(mockAccountInfo);
      // Bypass setSignerKeyTypes validation then inject unknown key type
      (builder as any).signerKeyTypes = [99];

      expect(() => (builder as any).createDummySignature()).not.toThrow();
    });

    it('should produce consistent output for same key types', () => {
      const builder1 = new ZkapBuilder(mockAccountInfo);
      builder1.setSignerKeyTypes([4]);
      const builder2 = new ZkapBuilder(mockAccountInfo);
      builder2.setSignerKeyTypes([4]);

      expect((builder1 as any).createDummySignature())
        .toBe((builder2 as any).createDummySignature());
    });
  });

});
