# Contributing to @baerae/zkap-aa

Thanks for your interest in contributing.

## Getting started

```bash
git clone https://github.com/baerae-zkap/zkap-aa-sdk.git
cd zkap-aa-sdk
npm install
```

## Development workflow

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Type check (no emit)
npx tsc --noEmit

# Lint (note: `npm run lint` carries --fix and rewrites files)
npx eslint "lib/**/*.ts"

# Build
npm run build
```

## Project structure

```
lib/
├── account/          # ZkapAccount, BaseAccount
├── builders/         # ZkapBuilder, CallDataBuilder, AccountKeyBuilder, ...
│   └── aggregators/  # DEX aggregator (1inch)
├── client/           # BundlerClient, BundlerProvider
├── config/           # ZkapProviderConfig
├── helper/           # TxKeyHelper
├── master/           # Cosigned master key: layouts, builders, parsers, on-chain classification
├── reader/           # AccountReader, passkeys (classification), transport (Multicall3), types
├── signers/          # PasskeySigner, ZkOidcSigner, AddressKeySigner
├── types/            # TypeScript types and ABI JSON
└── utils/            # crypto, signature, base64url, webauthnKey, salt, ...
```

## Adding a new signer

1. Create `lib/signers/YourSigner.ts` implementing `IUserOpSigner`:

```typescript
import { IUserOpSigner } from '../utils/IUserOpSigner';

export class YourSigner implements IUserOpSigner {
  public readonly keyTypes: number[] = [/* your key type constant */];

  async signUserOpHash(userOpHash: string): Promise<string[]> {
    // return hex-encoded signatures
  }
}
```

2. Export from `lib/index.ts`.
3. Write tests in `lib/signers/__tests__/YourSigner.test.ts`.

## Testing guidelines

- Tests live in `lib/**/__tests__/` next to the source files they test
- Keep test coverage above 95% for statements and functions
- Use `jest.fn()` for external calls (network, WebAuthn, proof servers)
- Do not mock internal utilities — test them directly

### Captured contract answers (AccountReader)

`lib/reader/__tests__/fixtures/reader-capture.json` holds the raw `eth_call`
answers of the contract bytecode in `lib/types/abi/*.json`, captured on a local
anvil. The replay tests read it without anvil; nothing in CI starts a chain.
Whenever the contract artifacts in `lib/types/abi/` change, regenerate it
(needs `anvil` from [Foundry](https://book.getfoundry.sh/getting-started/installation)
on `PATH`) and commit the result:

```bash
node scripts/capture-reader-fixture.mjs
```

The output is deterministic — running it twice gives the same file. The replay
test fails while the captured bytecode hashes differ from the artifacts.

## Pull request checklist

- [ ] `npx tsc --noEmit` passes with zero errors
- [ ] `npm test` passes
- [ ] New public APIs have JSDoc comments
- [ ] CHANGELOG.md updated — under `## [Unreleased]`, or under a new versioned
      heading when the PR is the release itself (the house pattern for releases)

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(signers): add AppleSigner for Sign in with Apple
fix(builder): correct gas estimation for batch calls
docs(readme): add ZkOidcSigner quick start example
```

## Reporting issues

Open a GitHub issue: [baerae-zkap/zkap-aa-sdk/issues](https://github.com/baerae-zkap/zkap-aa-sdk/issues)

For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.
