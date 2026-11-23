'use strict';
const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  {ignores: ['node_modules/', 'coverage/', 'data/', 'uploads/']},
  js.configs.recommended,
  {
    // Server, scripts, tests and this config: Node.js CommonJS.
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'commonjs',
      globals: globals.node,
    },
    rules: {
      eqeqeq: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-unused-vars': ['error', {caughtErrors: 'none'}],
    },
  },
  {
    // Public site scripts run in the browser as classic scripts.
    files: ['script.js', 'documents.js'],
    languageOptions: {
      sourceType: 'script',
      globals: globals.browser,
    },
  },
];
