const tsPlugin = require('@typescript-eslint/eslint-plugin');
const tsParser = require('@typescript-eslint/parser');

/** @type {import('eslint').Linter.Config[]} */
module.exports = [
  { ignores: ['dist/**', 'node_modules/**', 'eslint.config.js'] },
  ...tsPlugin.configs['flat/recommended'],
  {
    files: ['lib/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: './tsconfig.eslint.json',
        tsconfigRootDir: __dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'error',
      '@typescript-eslint/no-empty-function': 'error',
    },
  },
  {
    // Hand-written ABI fragments once drifted from the deployed contracts and the
    // reader silently returned empty data — while tests declaring the same wrong
    // fragment kept passing. Contract reads and their tests use the generated ABI.
    files: ['lib/reader/**/*.ts', 'lib/master/**/*.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: 'Literal[value=/^\\s*function\\s+\\w+\\s*\\(/]',
          message:
            'Hand-written ABI fragment. Use the generated ABI from lib/types/abi (synced from the contract artifacts) — a fragment can drift from the deployed contract without any test noticing.',
        },
        {
          selector: 'TemplateLiteral[quasis.0.value.raw=/^\\s*function\\s+\\w+\\s*\\(/]',
          message:
            'Hand-written ABI fragment. Use the generated ABI from lib/types/abi (synced from the contract artifacts) — a fragment can drift from the deployed contract without any test noticing.',
        },
      ],
    },
  },
];
